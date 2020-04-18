#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    pub tty: Option<String>,
    pub action: Action,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    Login,
    Unlock,
    Lock,
    Sync,
    Decrypt { cipherstring: String },
    Encrypt { plaintext: String },
    Quit,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    Error { error: String },
    Decrypt { plaintext: String },
    Encrypt { cipherstring: String },
}
