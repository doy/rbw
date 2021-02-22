#[derive(Debug, snafu::Snafu)]
#[snafu(visibility = "pub")]
pub enum Error {
    #[snafu(display("email address not set"))]
    ConfigMissingEmail,

    #[snafu(display("failed to create block mode decryptor"))]
    CreateBlockMode {
        source: block_modes::InvalidKeyIvLength,
    },

    #[snafu(display("failed to create directory at {}", file.display()))]
    CreateDirectory {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

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

    #[snafu(display("{}", message))]
    IncorrectPassword { message: String },

    #[snafu(display("invalid base64"))]
    InvalidBase64 { source: base64::DecodeError },

    #[snafu(display("invalid cipherstring: {}", reason))]
    InvalidCipherString { reason: String },

    #[snafu(display("invalid value for $EDITOR: {}", editor.to_string_lossy()))]
    InvalidEditor { editor: std::ffi::OsString },

    #[snafu(display("invalid mac"))]
    InvalidMac,

    #[snafu(display("invalid two factor provider type: {}", ty))]
    InvalidTwoFactorProvider { ty: String },

    #[snafu(display("failed to parse JSON"))]
    JSON {
        source: serde_path_to_error::Error<serde_json::Error>,
    },

    #[snafu(display("failed to load config from {}", file.display()))]
    LoadConfig {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to load config from {}", file.display()))]
    LoadConfigAsync {
        source: tokio::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to load config from {}", file.display()))]
    LoadConfigJson {
        source: serde_json::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to load db from {}", file.display()))]
    LoadDb {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to load db from {}", file.display()))]
    LoadDbAsync {
        source: tokio::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to load db from {}", file.display()))]
    LoadDbJson {
        source: serde_json::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("openssl error"))]
    OpenSSL { source: openssl::error::ErrorStack },

    #[snafu(display("failed to parse match type {}", s))]
    ParseMatchType { s: String },

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

    #[snafu(display("failed to remove db at {}", file.display()))]
    RemoveDb {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("api request returned error: {}", status))]
    RequestFailed { status: u16 },

    #[snafu(display("api request unauthorized"))]
    RequestUnauthorized,

    #[snafu(display("error making api request"))]
    Reqwest { source: reqwest::Error },

    #[snafu(display("failed to save config to {}", file.display()))]
    SaveConfig {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to save config to {}", file.display()))]
    SaveConfigJson {
        source: serde_json::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to save db to {}", file.display()))]
    SaveDb {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to save db to {}", file.display()))]
    SaveDbAsync {
        source: tokio::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to save db to {}", file.display()))]
    SaveDbJson {
        source: serde_json::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("error spawning pinentry"))]
    Spawn { source: tokio::io::Error },

    #[snafu(display("two factor required"))]
    TwoFactorRequired {
        providers: Vec<crate::api::TwoFactorProviderType>,
    },

    #[snafu(display("unimplemented cipherstring type: {}", ty))]
    UnimplementedCipherStringType { ty: String },

    #[snafu(display("error writing to pinentry stdin"))]
    WriteStdin { source: tokio::io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;
