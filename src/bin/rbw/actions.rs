use std::{io::Read as _, os::unix::ffi::OsStringExt as _};

use anyhow::Context as _;

pub fn register(account: Option<&str>) -> anyhow::Result<()> {
    simple_action(account, rbw::protocol::Action::Register)
}

pub fn login(account: Option<&str>) -> anyhow::Result<()> {
    simple_action(account, rbw::protocol::Action::Login)
}

pub fn login_passkey(account: Option<&str>) -> anyhow::Result<()> {
    simple_action(account, rbw::protocol::Action::LoginPasskey)
}

pub fn yubikey_enroll(
    account: Option<&str>,
    label: Option<&str>,
) -> anyhow::Result<()> {
    simple_action(
        account,
        rbw::protocol::Action::YubikeyEnroll {
            label: label.map(std::string::ToString::to_string),
        },
    )
}

pub fn delete_touchid_key(
    account: Option<&str>,
    server: Option<&str>,
    email: Option<&str>,
) -> anyhow::Result<()> {
    simple_action(
        account,
        rbw::protocol::Action::DeleteTouchIdKey {
            server: server.map(std::string::ToString::to_string),
            email: email.map(std::string::ToString::to_string),
        },
    )
}

pub fn unlock(account: Option<&str>) -> anyhow::Result<()> {
    simple_action(account, rbw::protocol::Action::Unlock)
}

pub fn unlocked(account: Option<&str>) -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::new_for_account(
                get_environment(),
                account.map(std::string::ToString::to_string),
                rbw::protocol::Action::CheckLock,
            ))?;

            let res = recv_final(&mut sock)?;
            match res {
                rbw::protocol::Response::Ack => Ok(()),
                rbw::protocol::Response::Error { error } => {
                    Err(anyhow::anyhow!("{error}"))
                }
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
            ) {
                anyhow::bail!("agent not running");
            }
            Err(e.into())
        }
    }
}

pub fn sync(account: Option<&str>) -> anyhow::Result<()> {
    simple_action(account, rbw::protocol::Action::Sync)
}

pub fn lock(account: Option<&str>) -> anyhow::Result<()> {
    simple_action(account, rbw::protocol::Action::Lock)
}

pub fn lock_all() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::LockAll,
            ))?;

            let res = recv_final(&mut sock)?;
            match res {
                rbw::protocol::Response::Ack => Ok(()),
                rbw::protocol::Response::Error { error } => {
                    Err(anyhow::anyhow!("{error}"))
                }
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

pub fn account_states() -> anyhow::Result<Vec<rbw::config::AccountKey>> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::AccountStates,
            ))?;

            let res = recv_final(&mut sock)?;
            match res {
                rbw::protocol::Response::AccountStates { unlocked } => {
                    Ok(unlocked)
                }
                rbw::protocol::Response::Error { error } => {
                    Err(anyhow::anyhow!("{error}"))
                }
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(Vec::new()),
            _ => Err(e.into()),
        },
    }
}

pub fn evict_account(server: &str, email: &str) -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::EvictAccount {
                    server: server.to_string(),
                    email: email.to_string(),
                },
            ))?;

            let res = recv_final(&mut sock)?;
            match res {
                rbw::protocol::Response::Ack => Ok(()),
                rbw::protocol::Response::Error { error } => {
                    Err(anyhow::anyhow!("{error}"))
                }
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

pub fn quit() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let pidfile = rbw::dirs::pid_file();
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let Some(pid) =
                rustix::process::Pid::from_raw(pid.trim_end().parse()?)
            else {
                anyhow::bail!("failed to read pid from pidfile");
            };
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::Quit,
            ))?;
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
    account: Option<&str>,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new_for_account(
        get_environment(),
        account.map(std::string::ToString::to_string),
        rbw::protocol::Action::Decrypt {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = recv_final(&mut sock)?;
    match res {
        rbw::protocol::Response::Decrypt { plaintext } => Ok(plaintext),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn encrypt(
    account: Option<&str>,
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new_for_account(
        get_environment(),
        account.map(std::string::ToString::to_string),
        rbw::protocol::Action::Encrypt {
            plaintext: plaintext.to_string(),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = recv_final(&mut sock)?;
    match res {
        rbw::protocol::Response::Encrypt { cipherstring } => Ok(cipherstring),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to encrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn clipboard_store(text: &str) -> anyhow::Result<()> {
    simple_action(
        None,
        rbw::protocol::Action::ClipboardStore {
            text: text.to_string(),
        },
    )
}

pub fn version() -> anyhow::Result<u32> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Version,
    ))?;

    let res = recv_final(&mut sock)?;
    match res {
        rbw::protocol::Response::Version { version } => Ok(version),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to get version: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn simple_action(
    account: Option<&str>,
    action: rbw::protocol::Action,
) -> anyhow::Result<()> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request::new_for_account(
        get_environment(),
        account.map(std::string::ToString::to_string),
        action,
    ))?;

    let res = recv_final(&mut sock)?;
    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("{error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn recv_final(
    sock: &mut crate::sock::Sock,
) -> anyhow::Result<rbw::protocol::Response> {
    loop {
        match sock.recv()? {
            rbw::protocol::Response::Status { message } => {
                if is_terminal::is_terminal(std::io::stderr()) {
                    eprintln!("{message}");
                }
            }
            other => return Ok(other),
        }
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

fn wait_for_exit(pid: rustix::process::Pid) {
    loop {
        if rustix::process::test_kill_process(pid).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn get_environment() -> rbw::protocol::Environment {
    let tty = std::env::var_os("RBW_TTY").or_else(|| {
        rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .map(|p| std::ffi::OsString::from_vec(p.as_bytes().to_vec()))
    });

    let env_vars = std::env::vars_os()
        .filter(|(var_name, _)| {
            (*rbw::protocol::ENVIRONMENT_VARIABLES_OS).contains(var_name)
        })
        .collect();
    rbw::protocol::Environment::new(tty, env_vars)
}
