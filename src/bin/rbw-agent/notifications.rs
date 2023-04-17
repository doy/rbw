use futures::{stream::SplitSink};
use tokio::{net::{TcpStream}, task::JoinHandle};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message, WebSocketStream, MaybeTlsStream};
use futures_util::{StreamExt, SinkExt};

#[derive(Copy, Clone)]
pub enum NotificationMessage {
    SyncCipherUpdate,
    SyncCipherCreate,
    SyncLoginDelete,
    SyncFolderDelete,
    SyncCiphers,

    SyncVault,
    SyncOrgKeys,
    SyncFolderCreate,
    SyncFolderUpdate,
    SyncCipherDelete,
    SyncSettings,

    Logout,
}



fn parse_messagepack(data: &[u8]) -> Option<NotificationMessage> {
    // the first few bytes with the 0x80 bit set, plus one byte terminating the length contain the length of the message
    let len_buffer_length = data.iter().position(|&x| (x & 0x80) == 0 )? + 1;

    let unpacked_messagepack = rmpv::decode::read_value(&mut &data[len_buffer_length..]).ok()?;
    if !unpacked_messagepack.is_array() {
        return None;
    }

    let unpacked_message = unpacked_messagepack.as_array().unwrap();
    let message_type = unpacked_message.iter().next().unwrap().as_u64().unwrap();

    let message = match message_type {
        0  => Some(NotificationMessage::SyncCipherUpdate),
        1  => Some(NotificationMessage::SyncCipherCreate),
        2  => Some(NotificationMessage::SyncLoginDelete),
        3  => Some(NotificationMessage::SyncFolderDelete),
        4  => Some(NotificationMessage::SyncCiphers),
        5  => Some(NotificationMessage::SyncVault),
        6  => Some(NotificationMessage::SyncOrgKeys),
        7  => Some(NotificationMessage::SyncFolderCreate),
        8  => Some(NotificationMessage::SyncFolderUpdate),
        9  => Some(NotificationMessage::SyncCipherDelete),
        10 => Some(NotificationMessage::SyncSettings),
        11 => Some(NotificationMessage::Logout),
        _ => None
    };

    return message;
}

pub struct NotificationsHandler {
    write: Option<futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>>,
    read_handle: Option<tokio::task::JoinHandle<()>>,
    sending_channels : std::sync::Arc<tokio::sync::RwLock<Vec<tokio::sync::mpsc::UnboundedSender<NotificationMessage>>>>,
}

impl NotificationsHandler {
    pub fn new() -> Self {
        Self {
            write: None,
            read_handle: None,
            sending_channels: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    pub async fn connect(&mut self, url: String) ->  Result<(), Box<dyn std::error::Error>> {
        if self.is_connected() {
            self.disconnect().await?;
        }

        let (write, read_handle) = subscribe_to_notifications(url, self.sending_channels.clone()).await?;
         
        self.write = Some(write);
        self.read_handle = Some(read_handle);
        return Ok(());
    }

    pub fn is_connected(&self) -> bool {
        self.write.is_some()
    }

    pub async fn disconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.sending_channels.write().await.clear();
        if let Some(mut write) = self.write.take() {
            write.send(Message::Close(None)).await?;
            write.close().await?;
            self.read_handle.take().unwrap().await?;
        }
        Ok(())
    }

    pub async fn get_channel(&mut self) -> tokio::sync::mpsc::UnboundedReceiver<NotificationMessage> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<NotificationMessage>();
        self.sending_channels.write().await.push(tx);
        return rx;
    }

}

async fn subscribe_to_notifications(url: String, sending_channels: std::sync::Arc<tokio::sync::RwLock<Vec<tokio::sync::mpsc::UnboundedSender<NotificationMessage>>>>) -> Result<(SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>, JoinHandle<()>), Box<dyn std::error::Error>> {
    let url = url::Url::parse(url.as_str())?;
    let (ws_stream, _response) = connect_async(url).await?;
    let (mut write, read) = ws_stream.split();

    write.send(Message::Text("{\"protocol\":\"messagepack\",\"version\":1}\n".to_string())).await.unwrap();

    let read_future = async move {
        read.map(|message| {
            (message, sending_channels.clone())
        }).for_each(|(message, a)| async move {
            let a = a.read().await;

            match message {
                Ok(Message::Binary(binary)) => {
                    let msgpack = parse_messagepack(&binary);
                    if let Some(msg) = msgpack {
                        for channel in a.iter() {
                            let res = channel.send(msg);
                            if res.is_err() {
                                println!("error sending websocket message to channel");
                            }
                        }
                    }
                },
                Err(e) => {
                    println!("websocket error: {:?}", e);
                },
                _ => {}
            }
        }).await;
    };

    return Ok((write, tokio::spawn(read_future)));
}