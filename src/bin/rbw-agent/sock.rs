use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

pub struct Sock(tokio::net::UnixStream);

impl Sock {
    pub fn new(s: tokio::net::UnixStream) -> Self {
        Self(s)
    }

    pub async fn send(&mut self, res: &rbw::agent::Response) {
        let Self(sock) = self;
        sock.write_all(serde_json::to_string(res).unwrap().as_bytes())
            .await
            .unwrap();
        sock.write_all(b"\n").await.unwrap();
    }

    pub async fn recv(&mut self) -> rbw::agent::Request {
        let Self(sock) = self;
        let mut buf = tokio::io::BufStream::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

pub fn listen() -> anyhow::Result<tokio::net::UnixListener> {
    let runtime_dir = rbw::dirs::runtime_dir();
    std::fs::create_dir_all(&runtime_dir)?;

    let path = runtime_dir.join("socket");
    std::fs::remove_file(&path)?;
    let sock = tokio::net::UnixListener::bind(&path)?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}
