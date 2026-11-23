use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
    // the encrypted sha256 of the uri, which the official clients check
    // before they show the uri of an entry that has its own key. sync
    // doesn't store it, so that older versions can still read the db: rbw
    // sets it only on uris it encrypts for a request, and an edit takes the
    // checksums of unchanged uris from the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_checksum: Option<String>,
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
                    uri_checksum: None,
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
                let mut uri_checksum = None;
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
                        "uri_checksum" => {
                            if uri_checksum.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field(
                                        "uri_checksum",
                                    ),
                                );
                            }
                            uri_checksum = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type", "uri_checksum"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| {
                        Ok(Self::Value {
                            uri,
                            match_type,
                            uri_checksum,
                        })
                    },
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

    pub user_id: Option<String>,

    pub entries: Vec<Entry>,
}

// A temporary file in the same directory as the db, so that renaming it over
// the db is atomic. Unique per process and per save.
fn temp_file(file: &std::path::Path) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // unwrap is safe here because the db file always has a file name
    let mut name = file.file_name().unwrap().to_os_string();
    name.push(format!(".{}.{n}.tmp", std::process::id()));
    file.with_file_name(name)
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

    // Writes to a temporary file next to the db and renames it into place,
    // so the agent and the command line, which both read and write the db,
    // never see a partly written file.
    pub fn save(&self, server: &str, email: &str) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = crate::dirs::db_file(server, email);
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveDbJson {
                source,
                file: file.clone(),
            }
        })?;
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveDb {
                source,
                file: file.clone(),
            },
        )?;
        let temp = temp_file(&file);
        let res = (|| {
            let mut fh = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            fh.write_all(json.as_bytes())?;
            fh.sync_all()?;
            std::fs::rename(&temp, &file)
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        res.map_err(|source| Error::SaveDb { source, file })
    }

    // See save.
    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveDbJson {
                source,
                file: file.clone(),
            }
        })?;
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        tokio::fs::create_dir_all(file.parent().unwrap())
            .await
            .map_err(|source| Error::SaveDbAsync {
                source,
                file: file.clone(),
            })?;
        let temp = temp_file(&file);
        let res = async {
            let mut fh = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .await?;
            fh.write_all(json.as_bytes()).await?;
            fh.sync_all().await?;
            tokio::fs::rename(&temp, &file).await
        }
        .await;
        if res.is_err() {
            let _ = tokio::fs::remove_file(&temp).await;
        }
        res.map_err(|source| Error::SaveDbAsync { source, file })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_checksum_stays_out_of_the_db() {
        let uri = Uri {
            uri: "2.uri".to_string(),
            match_type: None,
            uri_checksum: None,
        };
        let json = serde_json::to_string(&uri).unwrap();
        assert_eq!(json, r#"{"uri":"2.uri","match_type":null}"#);
        assert_eq!(serde_json::from_str::<Uri>(&json).unwrap(), uri);

        let uri = Uri {
            uri_checksum: Some("2.checksum".to_string()),
            ..uri
        };
        let json = serde_json::to_string(&uri).unwrap();
        assert_eq!(serde_json::from_str::<Uri>(&json).unwrap(), uri);
        assert_eq!(
            serde_json::from_str::<Uri>(r#""2.uri""#).unwrap().uri,
            "2.uri"
        );
    }
}
