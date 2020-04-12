use anyhow::Context as _;
use std::io::{BufRead as _, Write as _};

pub struct Sock(std::os::unix::net::UnixStream);

impl Sock {
    pub fn connect() -> anyhow::Result<Self> {
        Ok(Self(
            std::os::unix::net::UnixStream::connect(
                rbw::dirs::runtime_dir().join("socket"),
            )
            .context("failed to connect to rbw-agent")?,
        ))
    }

    pub fn send(&mut self, msg: &rbw::agent::Request) -> anyhow::Result<()> {
        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(msg)
                .context("failed to serialize message to agent")?
                .as_bytes(),
        )
        .context("failed to send message to agent")?;
        sock.write_all(b"\n")
            .context("failed to send message to agent")?;
        Ok(())
    }

    pub fn recv(&mut self) -> anyhow::Result<rbw::agent::Response> {
        let Self(sock) = self;
        let mut buf = std::io::BufReader::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line)
            .context("failed to read message from agent")?;
        Ok(serde_json::from_str(&line)
            .context("failed to parse message from agent")?)
    }
}
