use anyhow::Context as _;
use std::io::Read as _;

pub fn register() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Register)
}

pub fn login() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Login)
}

pub fn unlock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Unlock)
}

pub fn unlocked() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::CheckLock)
}

pub fn sync() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Sync)
}

pub fn lock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Lock)
}

pub fn quit() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let pidfile = rbw::dirs::pid_file();
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let pid = nix::unistd::Pid::from_raw(pid.parse()?);
            sock.send(&rbw::protocol::Request {
                tty: nix::unistd::ttyname(0)
                    .ok()
                    .and_then(|p| p.to_str().map(std::string::ToString::to_string)),
                action: rbw::protocol::Action::Quit,
            })?;
            wait_for_exit(pid);
            Ok(())
        }
        Err(e) => match e.kind() {
            // if the socket doesn't exist, or the socket exists but nothing
            // is listening on it, the agent must already be not running
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

pub fn decrypt(
    cipherstring: &str,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request {
        tty: nix::unistd::ttyname(0)
            .ok()
            .and_then(|p| p.to_str().map(std::string::ToString::to_string)),
        action: rbw::protocol::Action::Decrypt {
            cipherstring: cipherstring.to_string(),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    })?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Decrypt { plaintext } => Ok(plaintext),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt: {}", error))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
    }
}

pub fn encrypt(
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request {
        tty: nix::unistd::ttyname(0)
            .ok()
            .and_then(|p| p.to_str().map(std::string::ToString::to_string)),
        action: rbw::protocol::Action::Encrypt {
            plaintext: plaintext.to_string(),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    })?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Encrypt { cipherstring } => Ok(cipherstring),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to encrypt: {}", error))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
    }
}

pub fn version() -> anyhow::Result<u32> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request {
        tty: nix::unistd::ttyname(0)
            .ok()
            .and_then(|p| p.to_str().map(std::string::ToString::to_string)),
        action: rbw::protocol::Action::Version,
    })?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Version { version } => Ok(version),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to get version: {}", error))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
    }
}

fn simple_action(action: rbw::protocol::Action) -> anyhow::Result<()> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request {
        tty: nix::unistd::ttyname(0)
            .ok()
            .and_then(|p| p.to_str().map(std::string::ToString::to_string)),
        action,
    })?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("{}", error))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
    }
}

fn connect() -> anyhow::Result<crate::sock::Sock> {
    crate::sock::Sock::connect().with_context(|| {
        let log = rbw::dirs::agent_stderr_file();
        format!(
            "failed to connect to rbw-agent \
            (this often means that the agent failed to start; \
            check {} for agent logs)",
            log.display()
        )
    })
}

fn wait_for_exit(pid: nix::unistd::Pid) {
    loop {
        if nix::sys::signal::kill(pid, None).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
