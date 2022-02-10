use crate::prelude::*;

use std::io::{Read as _, Write as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    pub email: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            base_url: None,
            identity_url: None,
            lock_timeout: default_lock_timeout(),
            pinentry: default_pinentry(),
            device_id: None,
        }
    }
}

#[must_use]
pub fn default_lock_timeout() -> u64 {
    3600
}

#[must_use]
pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

impl Config {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh = std::fs::File::open(&file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.clone(),
            })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadConfigAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        let file = crate::dirs::config_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveConfig {
                source,
                file: file.clone(),
            },
        )?;
        let mut fh = std::fs::File::create(&file).map_err(|source| {
            Error::SaveConfig {
                source,
                file: file.clone(),
            }
        })?;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveConfigJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .map_err(|source| Error::SaveConfig { source, file })?;
        Ok(())
    }

    pub fn validate() -> Result<()> {
        let config = Self::load()?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    #[must_use]
    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| format!("{}/api", url.trim_end_matches('/')),
        )
    }

    #[must_use]
    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| format!("{}/identity", url.trim_end_matches('/')),
            )
        })
    }

    #[must_use]
    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }
}

pub async fn device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    if let Ok(mut fh) = tokio::fs::File::open(&file).await {
        let mut s = String::new();
        fh.read_to_string(&mut s)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        Ok(s.trim().to_string())
    } else {
        let id = config.device_id.as_ref().map_or_else(
            || uuid::Uuid::new_v4().to_hyphenated().to_string(),
            String::to_string,
        );
        let mut fh = tokio::fs::File::create(&file).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        fh.write_all(id.as_bytes()).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        Ok(id)
    }
}
