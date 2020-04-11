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

fn default_lock_timeout() -> u64 {
    3600
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let mut fh = std::fs::File::open(Self::filename())
            .context(crate::error::LoadConfig)?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .context(crate::error::LoadConfig)?;
        let slf: Self = serde_json::from_str(&json)
            .context(crate::error::LoadConfigJson)?;
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let mut fh = tokio::fs::File::open(Self::filename())
            .await
            .context(crate::error::LoadConfigAsync)?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .await
            .context(crate::error::LoadConfigAsync)?;
        let slf: Self = serde_json::from_str(&json)
            .context(crate::error::LoadConfigJson)?;
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        let filename = Self::filename();
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

    fn filename() -> std::path::PathBuf {
        crate::dirs::config_dir().join("config.json")
    }
}
