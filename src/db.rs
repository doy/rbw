use crate::prelude::*;

use std::io::{Read as _, Write as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    pub iterations: Option<u32>,
    pub protected_key: Option<String>,

    pub ciphers: Vec<crate::api::Cipher>,
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(email: &str) -> Result<Self> {
        let mut fh = std::fs::File::open(Self::filename(email))
            .context(crate::error::LoadDb)?;
        let mut json = String::new();
        fh.read_to_string(&mut json).context(crate::error::LoadDb)?;
        let slf: Self =
            serde_json::from_str(&json).context(crate::error::LoadDbJson)?;
        Ok(slf)
    }

    pub async fn load_async(email: &str) -> Result<Self> {
        let mut fh = tokio::fs::File::open(Self::filename(email))
            .await
            .context(crate::error::LoadDbAsync)?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .await
            .context(crate::error::LoadDbAsync)?;
        let slf: Self =
            serde_json::from_str(&json).context(crate::error::LoadDbJson)?;
        Ok(slf)
    }

    // XXX need to make this atomic
    pub fn save(&self, email: &str) -> Result<()> {
        let filename = Self::filename(email);
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(filename.parent().unwrap())
            .context(crate::error::SaveDb)?;
        let mut fh =
            std::fs::File::create(filename).context(crate::error::SaveDb)?;
        fh.write_all(
            serde_json::to_string(self)
                .context(crate::error::SaveDbJson)?
                .as_bytes(),
        )
        .context(crate::error::SaveDb)?;
        Ok(())
    }

    // XXX need to make this atomic
    pub async fn save_async(&self, email: &str) -> Result<()> {
        let filename = Self::filename(email);
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        tokio::fs::create_dir_all(filename.parent().unwrap())
            .await
            .context(crate::error::SaveDbAsync)?;
        let mut fh = tokio::fs::File::create(filename)
            .await
            .context(crate::error::SaveDbAsync)?;
        fh.write_all(
            serde_json::to_string(self)
                .context(crate::error::SaveDbJson)?
                .as_bytes(),
        )
        .await
        .context(crate::error::SaveDbAsync)?;
        Ok(())
    }

    pub fn remove(email: &str) -> Result<()> {
        let filename = Self::filename(email);
        std::fs::remove_file(filename).context(crate::error::RemoveDb)?;
        Ok(())
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || self.refresh_token.is_none()
            || self.iterations.is_none()
            || self.protected_key.is_none()
    }

    fn filename(email: &str) -> std::path::PathBuf {
        crate::dirs::cache_dir().join(format!("{}.json", email))
    }
}
