#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Message {
    pub tty: Option<String>,
    pub action: Action,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    Login,
    Unlock,
    Sync,
    Decrypt { cipherstring: String },
    // add
    // update
    // remove
}
