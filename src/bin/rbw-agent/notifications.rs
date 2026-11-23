use futures_util::{SinkExt as _, StreamExt as _};

#[derive(Clone, Copy, Debug)]
pub enum Message {
    Sync,
    Logout,
}

pub struct Handler {
    write: Option<
        futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::Message,
        >,
    >,
    read_handle: Option<tokio::task::JoinHandle<()>>,
    sending_channels: std::sync::Arc<
        tokio::sync::RwLock<Vec<tokio::sync::mpsc::UnboundedSender<Message>>>,
    >,
}

impl Handler {
    pub fn new() -> Self {
        Self {
            write: None,
            read_handle: None,
            sending_channels: std::sync::Arc::new(tokio::sync::RwLock::new(
                Vec::new(),
            )),
        }
    }

    pub async fn connect(
        &mut self,
        url: String,
        extra_headers: axum::http::HeaderMap,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.is_connected() {
            self.disconnect().await?;
        }

        let (write, read_handle) = subscribe_to_notifications(
            url,
            extra_headers,
            self.sending_channels.clone(),
        )
        .await?;

        self.write = Some(write);
        self.read_handle = Some(read_handle);
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.write.is_some()
            && self.read_handle.is_some()
            && !self.read_handle.as_ref().unwrap().is_finished()
    }

    pub async fn disconnect(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.sending_channels.write().await.clear();
        if let Some(mut write) = self.write.take() {
            write
                .send(tokio_tungstenite::tungstenite::Message::Close(None))
                .await?;
            write.close().await?;
            self.read_handle.take().unwrap().await?;
        }
        self.write = None;
        self.read_handle = None;
        Ok(())
    }

    pub async fn get_channel(
        &self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<Message> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.sending_channels.write().await.push(tx);
        rx
    }
}

async fn subscribe_to_notifications(
    url: String,
    extra_headers: axum::http::HeaderMap,
    sending_channels: std::sync::Arc<
        tokio::sync::RwLock<Vec<tokio::sync::mpsc::UnboundedSender<Message>>>,
    >,
) -> Result<
    (
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::Message,
        >,
        tokio::task::JoinHandle<()>,
    ),
    Box<dyn std::error::Error>,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let url = url::Url::parse(url.as_str())?;
    // a proxy in front of the server may check these on the websocket
    // handshake too
    let mut request = url.into_client_request()?;
    request.headers_mut().extend(extra_headers);
    let (ws_stream, _response) =
        tokio_tungstenite::connect_async(request).await?;
    let (mut write, read) = ws_stream.split();

    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "{\"protocol\":\"messagepack\",\"version\":1}\x1e".into(),
        ))
        .await
        .unwrap();

    let read_future = async move {
        let sending_channels = &sending_channels;
        read.for_each(|message| async move {
            match message {
                Ok(message) => {
                    if let Some(message) = parse_message(message) {
                        let sending_channels = sending_channels.read().await;
                        let sending_channels = sending_channels.as_slice();
                        for channel in sending_channels {
                            channel.send(message).unwrap();
                        }
                    }
                }
                Err(e) => {
                    eprintln!("websocket error: {e:?}");
                }
            }
        })
        .await;
    };

    Ok((write, tokio::spawn(read_future)))
}

fn parse_message(
    message: tokio_tungstenite::tungstenite::Message,
) -> Option<Message> {
    let tokio_tungstenite::tungstenite::Message::Binary(data) = message
    else {
        return None;
    };

    // the first few bytes with the 0x80 bit set, plus one byte terminating the length contain the length of the message
    let len_buffer_length = data.iter().position(|&x| (x & 0x80) == 0)? + 1;

    let unpacked_messagepack =
        rmpv::decode::read_value(&mut &data[len_buffer_length..]).ok()?;

    let unpacked_message = unpacked_messagepack.as_array()?;
    let message_type = unpacked_message.first()?.as_u64()?;
    // invocation
    if message_type != 1 {
        return None;
    }
    let target = unpacked_message.get(3)?.as_str()?;
    if target != "ReceiveMessage" {
        return None;
    }

    let args = unpacked_message.get(4)?.as_array()?;
    let map = args.first()?.as_map()?;
    for (k, v) in map {
        if k.as_str()? == "Type" {
            let ty = v.as_i64()?;
            return match ty {
                11 => Some(Message::Logout),
                _ => Some(Message::Sync),
            };
        }
    }

    None
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn websocket_handshake_sends_extra_headers() {
        use tokio::io::AsyncReadExt as _;

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // reads the handshake and hangs up without answering
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut chunk = [0; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&chunk[..n]);
            }
            String::from_utf8_lossy(&head).to_lowercase()
        });

        let mut extra_headers = axum::http::HeaderMap::new();
        extra_headers.insert(
            "X-Proxy-Token",
            axum::http::HeaderValue::from_static("abc"),
        );
        let result = super::subscribe_to_notifications(
            format!("ws://{addr}/notifications/hub"),
            extra_headers,
            std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        )
        .await;
        assert!(result.is_err());

        let head = server.await.unwrap();
        assert!(head.starts_with("get /notifications/hub "));
        assert!(head.contains("\r\nx-proxy-token: abc\r\n"));
        assert!(head.contains("\r\nupgrade: websocket\r\n"));
    }
}
