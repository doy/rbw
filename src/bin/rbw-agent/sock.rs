use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

pub struct Sock(tokio::net::UnixStream);

impl Sock {
    pub fn new(s: tokio::net::UnixStream) -> Self {
        Self(s)
    }

    pub async fn send(
        &mut self,
        res: &rbw::protocol::Response,
    ) -> anyhow::Result<()> {
        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(res)
                .context("failed to serialize message")?
                .as_bytes(),
        )
        .await
        .context("failed to write message to socket")?;
        sock.write_all(b"\n")
            .await
            .context("failed to write message to socket")?;
        Ok(())
    }

    pub async fn recv(&mut self) -> anyhow::Result<rbw::protocol::Request> {
        let Self(sock) = self;
        let mut buf = tokio::io::BufStream::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line)
            .await
            .context("failed to read message from socket")?;
        Ok(serde_json::from_str(&line).context("failed to parse message")?)
    }
}

pub fn listen() -> anyhow::Result<tokio::net::UnixListener> {
    let runtime_dir = rbw::dirs::runtime_dir();
    std::fs::create_dir_all(&runtime_dir)
        .context("failed to create runtime dir")?;

    let path = runtime_dir.join("socket");
    // if the socket already doesn't exist, that's fine
    let _ = std::fs::remove_file(&path);
    let sock = tokio::net::UnixListener::bind(&path)
        .context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}
