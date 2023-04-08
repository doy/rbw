use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{StreamExt, SinkExt};

struct SyncCipherUpdate {
    id: String
}

struct SyncCipherCreate {
    id: String
}

enum NotificationMessage {
    SyncCipherUpdate(SyncCipherUpdate),
    SyncCipherCreate(SyncCipherCreate),
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

    SyncSendCreate,
    SyncSendUpdate,
    SyncSendDelete,

    AuthRequest,
    AuthRequestResponse,

    None,
}

fn parse_messagepack(data: &[u8]) -> Option<NotificationMessage> {
    if data.len() < 2 {
        return None;
    }

    // the first few bytes with th 0x80 bit set, plus one byte terminating the length contain the length of the message
    let len_buffer_length = data.iter().position(|&x| (x & 0x80) == 0 )? + 1;

    println!("len_buffer_length: {:?}", len_buffer_length);
    println!("data: {:?}", data);
    let unpacked_messagepack = rmpv::decode::read_value(&mut &data[len_buffer_length..]).ok().unwrap();
    println!("unpacked_messagepack: {:?}", unpacked_messagepack);
    if !unpacked_messagepack.is_array() {
        return None;
    }
    let unpacked_message = unpacked_messagepack.as_array().unwrap();
    println!("unpacked_message: {:?}", unpacked_message);
    let message_type = unpacked_message.iter().next()?.as_u64()?;
    let message = unpacked_message.iter().skip(4).next()?.as_array()?.first()?.as_map()?;
    let payload = message.iter().filter(|x| x.0.as_str().unwrap() == "Payload").next()?.1.as_map()?;
    println!("message_type: {:?}", message_type);
    println!("payload: {:?}", payload);

    let message = match message_type {
        0  => {
            let id = payload.iter().filter(|x| x.0.as_str().unwrap() == "Id").next()?.1.as_str()?;

            Some(NotificationMessage::SyncCipherUpdate(
                SyncCipherUpdate {
                    id: id.to_string()
                }
            ))
        },
        1  => {
            let id = payload.iter().filter(|x| x.0.as_str().unwrap() == "Id").next()?.1.as_str()?;

            Some(NotificationMessage::SyncCipherCreate(
                SyncCipherCreate {
                    id: id.to_string()
                }
            ))
        },
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
        12 => Some(NotificationMessage::SyncSendCreate),
        13 => Some(NotificationMessage::SyncSendUpdate),
        14 => Some(NotificationMessage::SyncSendDelete),
        15 => Some(NotificationMessage::AuthRequest),
        16 => Some(NotificationMessage::AuthRequestResponse),
        100 => Some(NotificationMessage::None),
        _ => None
    };

    return message;
}

pub async fn subscribe_to_notifications(url: String) {
    let url = url::Url::parse(url.as_str()).unwrap();

    let (ws_stream, _response) = connect_async(url).await.expect("Failed to connect");

    let (mut write, read) = ws_stream.split();

    write.send(Message::Text("{\"protocol\":\"messagepack\",\"version\":1}\n".to_string())).await.unwrap();

    let read_future = read.for_each(|message| async {
        match message {
            Ok(Message::Binary(binary)) => {
                let msg = parse_messagepack(&binary);
                match msg {
                    Some(NotificationMessage::SyncCipherUpdate(update)) => {
                        println!("Websocket sent SyncCipherUpdate for id: {:?}", update.id);
                        crate::actions::sync(None).await.unwrap();
                        println!("Synced")
                    },
                    Some(NotificationMessage::SyncCipherCreate(update)) => {
                        println!("Websocket sent SyncCipherUpdate for id: {:?}", update.id);
                        crate::actions::sync(None).await.unwrap();
                        println!("Synced")
                    },
                    Some(NotificationMessage::SyncLoginDelete) => {
                        crate::actions::sync(None).await.unwrap();
                    },
                    Some(NotificationMessage::SyncFolderDelete) => {
                        crate::actions::sync(None).await.unwrap();
                    },
                    Some(NotificationMessage::SyncCiphers) => {
                        crate::actions::sync(None).await.unwrap();
                    },
                    Some(NotificationMessage::SyncVault) => {
                        crate::actions::sync(None).await.unwrap();
                    },
                    Some(NotificationMessage::SyncOrgKeys) => {
                        crate::actions::sync(None).await.unwrap();
                    },
                    Some(NotificationMessage::SyncFolderCreate) => {
                        crate::actions::sync(None).await.unwrap();
                    },
                    Some(NotificationMessage::SyncFolderUpdate) => {
                        crate::actions::sync(None).await.unwrap();
                    },
                    Some(NotificationMessage::SyncCipherDelete) => {
                        crate::actions::sync(None).await.unwrap();
                    },
                    Some(NotificationMessage::Logout) => {
                        println!("Websocket sent Logout");
                        // todo: proper logout?
                        std::process::exit(0);
                    },
                    _ => {}
                }
            },
            Err(e) => {
                println!("websocket error: {:?}", e);
            },
            _ => {}
        }
    });

    read_future.await;
}
