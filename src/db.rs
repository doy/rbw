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
    #[serde(default)]
    pub last_sync: Option<u64>,
    #[serde(default)]
    pub last_error: Option<StatusError>,
    #[serde(default)]
    pub recovery: Recovery,
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
        let file = crate::dirs::db_file(server, email);
        let bytes = serde_json::to_vec(self).map_err(|source| {
            Error::SaveDbJson { source, file: file.clone() }
        })?;
        atomic_save(&file, &bytes)
            .map_err(|source| Error::SaveDb { source, file })
    }

    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let bytes = serde_json::to_vec(self).map_err(|source| {
            Error::SaveDbJson { source, file: file.clone() }
        })?;
        let destination = file.clone();
        tokio::task::spawn_blocking(move || atomic_save(&destination, &bytes))
            .await
            .map_err(|source| Error::SaveDbAsync {
                source: std::io::Error::other(source), file: file.clone(),
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

// A unique, owner-only file on the destination filesystem; neither a failed
// write nor a failed rename can truncate the previous encrypted vault.
fn atomic_save(file: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = file.parent().ok_or_else(|| {
        std::io::Error::other("database path has no parent")
    })?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(file).map_err(|error| error.error)?;
    // Persist the renamed directory entry, not just the new file's contents.
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn replacement_is_complete_private_and_does_not_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("db.json");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"old").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();
        atomic_save(&target, br#"{"refresh_token":"rotated"}"#).unwrap();
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"old");
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(saved["refresh_token"], "rotated");
        // Also replace a regular file with a shorter complete snapshot.
        atomic_save(&target, b"{}").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn rename_failure_preserves_destination_and_cleans_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("db.json");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("cached"), b"preserved").unwrap();
        assert!(atomic_save(&target, b"replacement").is_err());
        assert_eq!(std::fs::read(target.join("cached")).unwrap(), b"preserved");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

/// Closed vocabulary: never persist or print server/pinentry text.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StatusError {
    SyncFailed,
    TokenRejected,
    InvalidPassword,
    TwoFactorRequired,
    ChallengeRequired,
    PinentryCancelled,
    PinentryUnavailable,
    NetworkUnavailable,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Status {
    pub locked: bool,
    pub last_sync: Option<u64>,
    pub access_token_expires_at: Option<u64>,
    pub refresh_token_expires_at: Option<u64>,
    pub last_error: Option<StatusError>,
}

impl Db {
    pub fn status(&self, locked: bool) -> Status {
        Status {
            locked,
            last_sync: self.last_sync,
            access_token_expires_at: token_expiry(self.access_token.as_deref()),
            refresh_token_expires_at: token_expiry(self.refresh_token.as_deref()),
            last_error: self.last_error,
        }
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

// Untrusted display hint, never an authorization decision. Limit decoded data.
fn token_expiry(token: Option<&str>) -> Option<u64> {
    use base64::Engine as _;
    let token = token?;
    if token.len() > 16384 { return None; }
    let mut parts = token.split('.');
    parts.next()?;
    let payload = parts.next()?;
    parts.next()?;
    if parts.next().is_some() || payload.len() > 8192 { return None; }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    #[derive(serde::Deserialize)]
    struct Claims { exp: u64 }
    serde_json::from_slice::<Claims>(&bytes).ok().map(|claims| claims.exp)
}

#[cfg(test)]
mod status_tests {
    use super::*;
    #[test]
    fn status_is_bounded_and_handles_opaque_tokens() {
        let mut db = Db::new();
        db.access_token = Some(format!("header.{}.signature", crate::base64::encode_url_safe_no_pad(
            br#"{"exp":12345,"secret":"MUST_NOT_APPEAR"}"#,
        )));
        db.refresh_token = Some("opaque-MUST_NOT_APPEAR".into());
        db.last_sync = Some(42);
        db.last_error = Some(StatusError::SyncFailed);
        let status = db.status(false);
        assert_eq!(status.access_token_expires_at, Some(12345));
        assert_eq!(status.refresh_token_expires_at, None);
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 5);
        assert_eq!(json["locked"], false);
        assert_eq!(json["last_sync"], 42);
        assert_eq!(json["last_error"], "sync_failed");
        assert!(!json.to_string().contains("MUST_NOT_APPEAR"));
        for token in ["bad", "a.%%%.c", "a.e30.c", "a.eyJleHAiOi0xfQ.c", "a.eyJleHAiOiJzZWNyZXQifQ.c"] {
            assert_eq!(token_expiry(Some(token)), None);
        }
        assert_eq!(token_expiry(Some(&"x".repeat(16385))), None);
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Recovery {
    pub pending: bool,
    pub last_attempt: Option<u64>,
    pub stopped: bool,
    #[serde(default)]
    pub pending_kdf: Option<LoginKdf>,
}

impl Recovery {
    // Persist this reservation before contacting pinentry/the server. A clock
    // moving backwards must not grant extra attempts after a restart.
    pub fn reserve(&mut self, now: u64) -> bool {
        if !self.pending || self.stopped || self.last_attempt
            .is_some_and(|last| now.saturating_sub(last) < 3600) {
            return false;
        }
        self.last_attempt = Some(now);
        true
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn persisted_budget_obeys_hour_boundary_and_clock_rollback() {
        let mut db = Db::new();
        db.recovery.pending = true;
        assert!(db.recovery.reserve(10000));
        let mut restored: Db = serde_json::from_slice(&serde_json::to_vec(&db).unwrap()).unwrap();
        assert!(!restored.recovery.reserve(10000));
        assert!(!restored.recovery.reserve(9000));
        assert!(!restored.recovery.reserve(13599));
        assert!(restored.recovery.reserve(13600));
        restored.recovery.stopped = true;
        let mut stopped: Db = serde_json::from_slice(&serde_json::to_vec(&restored).unwrap()).unwrap();
        assert!(!stopped.recovery.reserve(1000000));
        // Existing caches without metadata retain the original login predicate.
        let old: Db = serde_json::from_value(serde_json::json!({
            "access_token":"access", "refresh_token":"refresh", "kdf":0,
            "iterations":1, "protected_key":"key", "protected_org_keys":{}, "entries":[]
        })).unwrap();
        assert!(!old.recovery.pending);
        assert!(!old.needs_login());
    }
}

// Stage new login KDF parameters until the corresponding vault snapshot is
// saved. A successful login followed by a failed sync must not break the old
// cached vault's offline decryption, including after an agent restart.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct LoginKdf {
    pub kdf: crate::api::KdfType,
    pub iterations: u32,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}
