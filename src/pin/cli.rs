#[cfg(feature = "pin")]
#[derive(Debug, clap::Parser)]
pub enum Pin {
    #[command(about = "Set up the PIN for local unlock")]
    Set {
        #[arg(
            long,
            default_value_t = false
        )]
        /// Whether to allow using an empty pin.
        ///
        /// Only recommended for a device + user input bound local secret
        /// e.g Using age backend with the plugins `yubikey, se`
        empty_pin: bool,
        #[arg(long, value_enum, help = "Backend to store local_secret")]
        backend: crate::pin::backend::Backend,
    },
    #[command(about = "Clear the PIN")]
    Clear,

    #[command(about = "Show status of PIN")]
    Status,
}

impl Pin {
    pub fn subcommand_name(&self) -> String {
        match self {
            Self::Set { .. } => "set",
            Self::Status => "status",
            Self::Clear => "clear",
        }
        .to_string()
    }
}
