// https://github.com/rust-lang/rust-clippy/issues/6902
#![allow(clippy::use_self)]

// eventually it would be nice to make this a const function so that we could
// just get the version from a variable directly, but this is fine for now
#[must_use]
pub fn version() -> u32 {
    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");

    major.parse::<u32>().unwrap() * 1_000_000
        + minor.parse::<u32>().unwrap() * 1_000
        + patch.parse::<u32>().unwrap()
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    pub tty: Option<String>,
    pub action: Action,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    Login,
    Register,
    Unlock,
    CheckLock,
    Lock,
    Sync,
    Decrypt {
        cipherstring: String,
        org_id: Option<String>,
    },
    Encrypt {
        plaintext: String,
        org_id: Option<String>,
    },
    Quit,
    Version,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    Error { error: String },
    Decrypt { plaintext: String },
    Encrypt { cipherstring: String },
    Version { version: u32 },
}
