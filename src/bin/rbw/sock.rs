use std::io::{BufRead as _, Write as _};

pub struct Sock(std::os::unix::net::UnixStream);

impl Sock {
    pub fn connect() -> Self {
        Self(
            std::os::unix::net::UnixStream::connect(
                rbw::dirs::runtime_dir().join("socket"),
            )
            .unwrap(),
        )
    }

    pub fn send(&mut self, msg: &rbw::agent::Request) {
        let Self(sock) = self;
        sock.write_all(serde_json::to_string(msg).unwrap().as_bytes())
            .unwrap();
        sock.write_all(b"\n").unwrap();
    }

    pub fn recv(&mut self) -> rbw::agent::Response {
        let Self(sock) = self;
        let mut buf = std::io::BufReader::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
}
