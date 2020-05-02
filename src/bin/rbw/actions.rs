use anyhow::Context as _;
use std::io::Read as _;

pub fn login() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Login, "login")
}

pub fn unlock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Unlock, "unlock")
}

pub fn sync() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Sync, "sync")
}

pub fn lock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Lock, "lock")
}

pub fn quit() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let runtime_dir = rbw::dirs::runtime_dir();
            let pidfile = runtime_dir.join("pidfile");
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let pid = nix::unistd::Pid::from_raw(pid.parse()?);
            sock.send(&rbw::protocol::Request {
                tty: std::env::var("TTY").ok(),
                action: rbw::protocol::Action::Quit,
            })?;
            wait_for_exit(pid)?;
            Ok(())
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                Ok(())
            } else {
                Err(e.into())
            }
        }
    }
}

pub fn decrypt(
    cipherstring: &str,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = crate::sock::Sock::connect()
        .context("failed to connect to rbw-agent")?;
    sock.send(&rbw::protocol::Request {
        tty: std::env::var("TTY").ok(),
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
    let mut sock = crate::sock::Sock::connect()
        .context("failed to connect to rbw-agent")?;
    sock.send(&rbw::protocol::Request {
        tty: std::env::var("TTY").ok(),
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
    let mut sock = crate::sock::Sock::connect()
        .context("failed to connect to rbw-agent")?;
    sock.send(&rbw::protocol::Request {
        tty: std::env::var("TTY").ok(),
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

fn simple_action(
    action: rbw::protocol::Action,
    desc: &str,
) -> anyhow::Result<()> {
    let mut sock = crate::sock::Sock::connect()
        .context("failed to connect to rbw-agent")?;

    sock.send(&rbw::protocol::Request {
        tty: std::env::var("TTY").ok(),
        action,
    })?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to {}: {}", desc, error))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
    }
}

fn wait_for_exit(pid: nix::unistd::Pid) -> anyhow::Result<()> {
    loop {
        if nix::sys::signal::kill(pid, None).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}
