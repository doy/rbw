use std::io::{BufRead as _, Write as _};

use anyhow::Context as _;

pub struct Sock(std::io::BufReader<std::os::unix::net::UnixStream>);

impl Sock {
    // not returning anyhow::Result here because we want to be able to handle
    // specific kinds of std::io::Results differently
    pub fn connect() -> std::io::Result<Self> {
        Ok(Self(std::io::BufReader::new(
            std::os::unix::net::UnixStream::connect(rbw::dirs::socket_file())?,
        )))
    }

    pub fn send(
        &mut self,
        msg: &rbw::protocol::Request,
    ) -> anyhow::Result<()> {
        let Self(sock) = self;
        let stream = sock.get_mut();
        stream
            .write_all(
                serde_json::to_string(msg)
                    .context("failed to serialize message to agent")?
                    .as_bytes(),
            )
            .context("failed to send message to agent")?;
        stream
            .write_all(b"\n")
            .context("failed to send message to agent")?;
        Ok(())
    }

    pub fn recv(&mut self) -> anyhow::Result<rbw::protocol::Response> {
        let Self(buf) = self;
        let mut line = String::new();
        buf.read_line(&mut line)
            .context("failed to read message from agent")?;
        serde_json::from_str(&line)
            .context("failed to parse message from agent")
    }
}

#[test]
fn test_sock_recv_preserves_buffered_messages() {
    let (mut writer, reader) =
        std::os::unix::net::UnixStream::pair().unwrap();
    let payload = format!(
        "{}\n{}\n{}\n",
        serde_json::to_string(&rbw::protocol::Response::Status {
            message: "step 1".to_string()
        })
        .unwrap(),
        serde_json::to_string(&rbw::protocol::Response::Status {
            message: "step 2".to_string()
        })
        .unwrap(),
        serde_json::to_string(&rbw::protocol::Response::Ack).unwrap(),
    );
    writer.write_all(payload.as_bytes()).unwrap();
    drop(writer);

    let mut sock = Sock(std::io::BufReader::new(reader));
    match sock.recv().unwrap() {
        rbw::protocol::Response::Status { message } => {
            assert_eq!(message, "step 1");
        }
        other => panic!("unexpected response: {other:?}"),
    }
    match sock.recv().unwrap() {
        rbw::protocol::Response::Status { message } => {
            assert_eq!(message, "step 2");
        }
        other => panic!("unexpected response: {other:?}"),
    }
    assert!(matches!(sock.recv().unwrap(), rbw::protocol::Response::Ack));
}
