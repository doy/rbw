#[derive(Debug, snafu::Snafu)]
#[snafu(visibility = "pub")]
pub enum Error {
    #[snafu(display("email address not set"))]
    ConfigMissingEmail,

    #[snafu(display("failed to create block mode decryptor"))]
    CreateBlockMode {
        source: block_modes::InvalidKeyIvLength,
    },

    #[snafu(display("failed to create directory"))]
    CreateDirectory { source: std::io::Error },

    #[snafu(display("failed to decrypt"))]
    Decrypt { source: block_modes::BlockModeError },

    #[snafu(display("failed to parse pinentry output ({:?})", out))]
    FailedToParsePinentry { out: String },

    #[snafu(display(
        "failed to run editor {}: {:?}",
        editor.to_string_lossy(),
        res
    ))]
    FailedToRunEditor {
        editor: std::path::PathBuf,
        res: std::process::ExitStatus,
    },

    #[snafu(display("failed to expand with hkdf"))]
    HkdfExpand,

    #[snafu(display("username or password incorrect"))]
    IncorrectPassword,

    #[snafu(display("invalid base64"))]
    InvalidBase64 { source: base64::DecodeError },

    #[snafu(display("invalid cipherstring"))]
    InvalidCipherString,

    #[snafu(display("invalid value for $EDITOR: {}", editor.to_string_lossy()))]
    InvalidEditor { editor: std::ffi::OsString },

    #[snafu(display("invalid mac"))]
    InvalidMac,

    #[snafu(display("failed to parse JSON"))]
    JSON {
        source: serde_path_to_error::Error<serde_json::Error>,
    },

    #[snafu(display("failed to load config"))]
    LoadConfig { source: std::io::Error },

    #[snafu(display("failed to load config"))]
    LoadConfigAsync { source: tokio::io::Error },

    #[snafu(display("failed to load config"))]
    LoadConfigJson { source: serde_json::Error },

    #[snafu(display("failed to load db"))]
    LoadDb { source: std::io::Error },

    #[snafu(display("failed to load db"))]
    LoadDbAsync { source: tokio::io::Error },

    #[snafu(display("failed to load db"))]
    LoadDbJson { source: serde_json::Error },

    #[snafu(display("openssl error"))]
    OpenSSL { source: openssl::error::ErrorStack },

    #[snafu(display("pbkdf2 requires at least 1 iteration (got 0)"))]
    Pbkdf2ZeroIterations,

    #[snafu(display("pinentry cancelled"))]
    PinentryCancelled,

    #[snafu(display("pinentry error: {}", error))]
    PinentryErrorMessage { error: String },

    #[snafu(display("error reading pinentry output"))]
    PinentryReadOutput { source: tokio::io::Error },

    #[snafu(display("error waiting for pinentry to exit"))]
    PinentryWait { source: tokio::io::Error },

    #[snafu(display("failed to remove db"))]
    RemoveDb { source: std::io::Error },

    #[snafu(display("api request returned error: {}", status))]
    RequestFailed { status: u16 },

    #[snafu(display("api request unauthorized"))]
    RequestUnauthorized,

    #[snafu(display("error making api request"))]
    Reqwest { source: reqwest::Error },

    #[snafu(display("failed to save config"))]
    SaveConfig { source: std::io::Error },

    #[snafu(display("failed to save config"))]
    SaveConfigJson { source: serde_json::Error },

    #[snafu(display("failed to save db"))]
    SaveDb { source: std::io::Error },

    #[snafu(display("failed to save db"))]
    SaveDbAsync { source: tokio::io::Error },

    #[snafu(display("failed to save db"))]
    SaveDbJson { source: serde_json::Error },

    #[snafu(display("error spawning pinentry"))]
    Spawn { source: tokio::io::Error },

    #[snafu(display("error writing to pinentry stdin"))]
    WriteStdin { source: tokio::io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;
