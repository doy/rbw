use anyhow::Context as _;

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
            sock.send(&rbw::protocol::Request {
                tty: std::env::var("TTY").ok(),
                action: rbw::protocol::Action::Quit,
            })?;
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

pub fn decrypt(cipherstring: &str) -> anyhow::Result<String> {
    let mut sock = crate::sock::Sock::connect()
        .context("failed to connect to rbw-agent")?;
    sock.send(&rbw::protocol::Request {
        tty: std::env::var("TTY").ok(),
        action: rbw::protocol::Action::Decrypt {
            cipherstring: cipherstring.to_string(),
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
