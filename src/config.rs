use crate::prelude::*;

use std::io::{Read as _, Write as _};
use tokio::io::AsyncReadExt as _;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Config {
    pub email: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
}

pub fn default_lock_timeout() -> u64 {
    3600
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let mut fh = std::fs::File::open(crate::dirs::config_file())
            .context(crate::error::LoadConfig)?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .context(crate::error::LoadConfig)?;
        let mut slf: Self = serde_json::from_str(&json)
            .context(crate::error::LoadConfigJson)?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let mut fh = tokio::fs::File::open(crate::dirs::config_file())
            .await
            .context(crate::error::LoadConfigAsync)?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .await
            .context(crate::error::LoadConfigAsync)?;
        let mut slf: Self = serde_json::from_str(&json)
            .context(crate::error::LoadConfigJson)?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        let filename = crate::dirs::config_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(filename.parent().unwrap())
            .context(crate::error::SaveConfig)?;
        let mut fh = std::fs::File::create(filename)
            .context(crate::error::SaveConfig)?;
        fh.write_all(
            serde_json::to_string(self)
                .context(crate::error::SaveConfigJson)?
                .as_bytes(),
        )
        .context(crate::error::SaveConfig)?;
        Ok(())
    }

    pub fn validate() -> Result<()> {
        let config = Self::load()?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| format!("{}/api", url),
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| format!("{}/identity", url),
            )
        })
    }

    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }
}
