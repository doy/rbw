use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::AsyncReadExt as _;

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Entry {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<Field>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<crate::attachment::Attachment>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
}

impl Entry {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
}

// backwards compatibility
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrUri;
        impl<'de> serde::de::Visitor<'de> for StringOrUri {
            type Value = Uri;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("uri")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Uri {
                    uri: value.to_string(),
                    match_type: None,
                })
            }

            fn visit_map<M>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut uri = None;
                let mut match_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "uri" => {
                            if uri.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field("uri"),
                                );
                            }
                            uri = Some(map.next_value()?);
                        }
                        "match_type" => {
                            if match_type.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field(
                                        "match_type",
                                    ),
                                );
                            }
                            match_type = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| Ok(Self::Value { uri, match_type }),
                )
            }
        }

        deserializer.deserialize_any(StringOrUri)
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub enum EntryData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Vec<Uri>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Field {
    pub ty: Option<crate::api::FieldType>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub linked_id: Option<crate::api::LinkedIdType>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct HistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    pub kdf: Option<crate::api::KdfType>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
    pub protected_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_org_keys: std::collections::HashMap<String, String>,

    pub entries: Vec<Entry>,
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            std::fs::File::open(&file).map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub async fn load_async(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadDbAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadDbAsync {
                source,
                file: file.clone(),
            }
        })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub fn save(&self, server: &str, email: &str) -> Result<()> {
        self.save_at(crate::dirs::db_file(server, email))
    }

    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        self.save_at_async(crate::dirs::db_file(server, email))
            .await
    }

    fn save_at(&self, file: std::path::PathBuf) -> Result<()> {
        let data =
            serde_json::to_vec(self).map_err(|source| Error::SaveDbJson {
                source,
                file: file.clone(),
            })?;
        write_atomic(&file, &data)
            .map_err(|source| Error::SaveDb { source, file })
    }

    async fn save_at_async(&self, file: std::path::PathBuf) -> Result<()> {
        let data =
            serde_json::to_vec(self).map_err(|source| Error::SaveDbJson {
                source,
                file: file.clone(),
            })?;
        let task_file = file.clone();
        // Map a filesystem error separately from a blocking-task failure.
        // The old cache remains readable until the completed file is renamed.
        tokio::task::spawn_blocking(move || write_atomic(&task_file, &data))
            .await
            .map_err(|source| Error::SaveDbAsync {
                source: std::io::Error::other(source),
                file: file.clone(),
            })?
            .map_err(|source| Error::SaveDbAsync { source, file })
    }

    pub fn remove(server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let res = std::fs::remove_file(&file);
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        res.map_err(|source| Error::RemoveDb { source, file })?;
        Ok(())
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || self.refresh_token.is_none()
            || self.iterations.is_none()
            || self.kdf.is_none()
            || self.protected_key.is_none()
    }
}

/// Publish a complete private cache snapshot without truncating readers' inode.
fn write_atomic(file: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let parent = file.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache path requires a parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(data)?;
    temporary.as_file().sync_all()?;
    temporary.persist(file).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod atomic_cache_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn snapshot(marker: char) -> Db {
        Db {
            access_token: Some(marker.to_string().repeat(64 * 1024)),
            refresh_token: Some(marker.to_string()),
            ..Db::default()
        }
    }

    #[tokio::test]
    async fn both_save_paths_preserve_open_readers_and_private_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("cache.json");
        let old = snapshot('a');
        let new = snapshot('b');
        old.save_at(file.clone()).unwrap();
        let mut old_reader = std::fs::File::open(&file).unwrap();
        new.save_at_async(file.clone()).await.unwrap();
        let mut old_bytes = Vec::new();
        old_reader.read_to_end(&mut old_bytes).unwrap();
        assert_eq!(old_bytes, serde_json::to_vec(&old).unwrap());
        assert_eq!(
            std::fs::read(&file).unwrap(),
            serde_json::to_vec(&new).unwrap()
        );

        let mut new_reader = std::fs::File::open(&file).unwrap();
        old.save_at(file.clone()).unwrap();
        let mut new_bytes = Vec::new();
        new_reader.read_to_end(&mut new_bytes).unwrap();
        assert_eq!(new_bytes, serde_json::to_vec(&new).unwrap());
        assert_eq!(
            std::fs::read(&file).unwrap(),
            serde_json::to_vec(&old).unwrap()
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_readers_only_observe_complete_cache_snapshots() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("cache.json");
        snapshot('a').save_at(file.clone()).unwrap();
        let stopped = std::sync::Arc::new(AtomicBool::new(false));
        let stop_reader = stopped.clone();
        let reader_file = file.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let reader = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let mut reads = 0;
            while !stop_reader.load(Ordering::Acquire) {
                let value: Db = serde_json::from_slice(
                    &std::fs::read(&reader_file).unwrap(),
                )
                .unwrap();
                let marker = value.refresh_token.unwrap();
                let token = value.access_token.unwrap();
                assert!(marker == "a" || marker == "b");
                assert_eq!(token, marker.repeat(64 * 1024));
                reads += 1;
            }
            reads
        });
        ready.await.unwrap();
        for index in 0..32 {
            let value = snapshot(if index % 2 == 0 { 'a' } else { 'b' });
            if index % 2 == 0 {
                value.save_at_async(file.clone()).await.unwrap();
            } else {
                value.save_at(file.clone()).unwrap();
            }
        }
        stopped.store(true, Ordering::Release);
        assert!(reader.await.unwrap() > 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_publication_preserves_destination_and_removes_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("cache.json");
        std::fs::create_dir(&destination).unwrap();
        let sentinel = destination.join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        assert!(write_atomic(&destination, b"new cache").is_err());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"unchanged");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
