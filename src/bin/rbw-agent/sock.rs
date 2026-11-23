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
        if let rbw::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

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

    pub async fn recv(
        &mut self,
    ) -> anyhow::Result<std::result::Result<rbw::protocol::Request, String>>
    {
        let Self(sock) = self;
        let mut buf = tokio::io::BufStream::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line)
            .await
            .context("failed to read message from socket")?;
        Ok(serde_json::from_str(&line).map_err(|e| {
            format!("failed to parse message '{}': {e}", quote_start(&line))
        }))
    }
}

// a request can be megabytes long (a batch decryption of a large vault), and
// the error that quotes it goes to the agent log and back to the client, so
// only quote the start of it
fn quote_start(line: &str) -> std::borrow::Cow<'_, str> {
    const MAX_LEN: usize = 200;
    let line = line.trim_end();
    if line.len() <= MAX_LEN {
        return line.into();
    }
    let mut end = MAX_LEN;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes)", &line[..end], line.len()).into()
}

pub fn listen() -> anyhow::Result<tokio::net::UnixListener> {
    let path = rbw::dirs::socket_file();
    // if the socket already doesn't exist, that's fine
    let _ = std::fs::remove_file(&path);
    let sock = tokio::net::UnixListener::bind(&path)
        .context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::quote_start;

    #[test]
    fn short_requests_are_quoted_whole() {
        assert_eq!(
            quote_start("{\"type\":\"Nope\"}\n"),
            "{\"type\":\"Nope\"}"
        );
    }

    #[test]
    fn long_requests_are_cut_on_a_char_boundary() {
        let line = format!("{}{}", "a".repeat(199), "é".repeat(1000));
        let quoted = quote_start(&line);
        assert!(quoted.starts_with(&"a".repeat(199)));
        assert!(quoted.ends_with(&format!("... ({} bytes)", line.len())));
        assert!(quoted.len() < 250);
    }
}
