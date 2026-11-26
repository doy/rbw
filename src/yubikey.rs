use crate::prelude::*;

use std::{
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
};

use rand::Rng as _;
use zeroize::Zeroize as _;

pub const LOCAL_RP_ID: &str = "rbw.local";
const STORE_VERSION: u32 = 1;

pub enum AuthOutcome {
    Authenticated {
        credential_id: String,
        master_keys: crate::locked::Keys,
    },
    Fallback,
    Cancelled,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct EnrolledKey {
    pub label: String,
    pub credential_id: String,
    pub aaguid: String,
    pub salt: String,
    pub uv: bool,
    pub wrapped_key: String,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct YubikeyStore {
    pub version: u32,
    pub rp_id: String,
    pub keys: Vec<EnrolledKey>,
}

impl Default for YubikeyStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            rp_id: LOCAL_RP_ID.to_string(),
            keys: Vec::new(),
        }
    }
}

pub fn load_store(server: &str, email: &str) -> Result<Option<YubikeyStore>> {
    let path = crate::dirs::yubikey_file(server, email);
    load_store_from_path(&path)
}

fn load_store_from_path(
    path: &std::path::Path,
) -> Result<Option<YubikeyStore>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => {
            return Err(Error::YubikeyStorage {
                message: format!("failed to read {}: {e}", path.display()),
            });
        }
    };
    let store: YubikeyStore =
        serde_json::from_str(&contents).map_err(|e| {
            Error::YubikeyStorage {
                message: format!("failed to parse {}: {e}", path.display()),
            }
        })?;
    Ok(Some(store))
}

fn save_store_to_path(
    path: &std::path::Path,
    store: &YubikeyStore,
) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(Error::YubikeyStorage {
            message: format!("invalid store path {}", path.display()),
        });
    };
    std::fs::create_dir_all(parent).map_err(|e| Error::YubikeyStorage {
        message: format!(
            "failed to create directory {}: {e}",
            parent.display()
        ),
    })?;
    let _ = std::fs::set_permissions(
        parent,
        std::fs::Permissions::from_mode(0o700),
    );

    let json = serde_json::to_string_pretty(store).map_err(|e| {
        Error::YubikeyStorage {
            message: format!("failed to serialize YubiKey store: {e}"),
        }
    })?;

    let tmp_name = format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("yubikey"),
        uuid::Uuid::new_v4()
    );
    let tmp_path = parent.join(tmp_name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| Error::YubikeyStorage {
            message: format!("failed to create {}: {e}", tmp_path.display()),
        })?;
    if let Err(e) = file
        .write_all(json.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(Error::YubikeyStorage {
            message: format!("failed to write {}: {e}", tmp_path.display()),
        });
    }
    drop(file);

    std::fs::set_permissions(
        &tmp_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        Error::YubikeyStorage {
            message: format!(
                "failed to set permissions on {}: {e}",
                tmp_path.display()
            ),
        }
    })?;

    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        Error::YubikeyStorage {
            message: format!("failed to replace {}: {e}", path.display()),
        }
    })?;

    Ok(())
}

pub fn has_keys(server: &str, email: &str) -> bool {
    load_store(server, email)
        .ok()
        .flatten()
        .is_some_and(|s| !s.keys.is_empty())
}

pub fn delete_keys(server: &str, email: &str) -> Result<()> {
    let path = crate::dirs::yubikey_file(server, email);
    delete_keys_at_path(&path)
}

fn delete_keys_at_path(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::YubikeyStorage {
            message: format!("failed to remove {}: {e}", path.display()),
        }),
    }
}

pub fn remove_key(server: &str, email: &str, selector: &str) -> Result<bool> {
    let path = crate::dirs::yubikey_file(server, email);
    remove_key_at_path(&path, selector)
}

fn remove_key_at_path(
    path: &std::path::Path,
    selector: &str,
) -> Result<bool> {
    if selector.is_empty() {
        return Ok(false);
    }
    let Some(mut store) = load_store_from_path(path)? else {
        return Ok(false);
    };
    let before = store.keys.len();
    store.keys.retain(|k| {
        k.credential_id != selector
            && !k.credential_id.starts_with(selector)
            && k.label != selector
    });
    if store.keys.len() == before {
        return Ok(false);
    }
    if store.keys.is_empty() {
        delete_keys_at_path(path)?;
    } else {
        save_store_to_path(path, &store)?;
    }
    Ok(true)
}

pub fn derive_wrapping_key(
    salt: &[u8; 32],
    hmac_secret: &[u8; 32],
) -> Result<crate::locked::Keys> {
    if hmac_secret.iter().all(|b| *b == 0) {
        return Err(Error::Fido2 {
            message: "authenticator returned an all-zero hmac-secret"
                .to_string(),
        });
    }

    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), hmac_secret);
    let mut raw = crate::locked::Vec::new();
    raw.extend(std::iter::repeat_n(0_u8, crate::locked::KEYS_LEN));
    hkdf.expand(b"rbw-yubikey-enc", &mut raw.data_mut()[0..32])
        .map_err(|_| Error::HkdfExpand)?;
    hkdf.expand(b"rbw-yubikey-mac", &mut raw.data_mut()[32..64])
        .map_err(|_| Error::HkdfExpand)?;
    Ok(crate::locked::Keys::new(raw))
}

pub fn wrap_master_keys(
    master_keys: &crate::locked::Keys,
    salt: &[u8; 32],
    hmac_secret: &[u8; 32],
) -> Result<String> {
    let wrapping_key = derive_wrapping_key(salt, hmac_secret)?;
    let cipherstring = crate::cipherstring::CipherString::encrypt_symmetric(
        &wrapping_key,
        master_keys.as_bytes(),
    )?;
    Ok(cipherstring.to_string())
}

pub fn unwrap_master_keys(
    wrapped_key: &str,
    salt: &[u8; 32],
    hmac_secret: &[u8; 32],
) -> Result<crate::locked::Keys> {
    let wrapping_key = derive_wrapping_key(salt, hmac_secret)?;
    let cipherstring = crate::cipherstring::CipherString::new(wrapped_key)?;
    let raw =
        cipherstring.decrypt_locked_symmetric_unpadded(&wrapping_key)?;
    crate::locked::Keys::from_bytes(raw.data()).ok_or_else(|| {
        Error::YubikeyStorage {
            message: format!(
                "unwrapped key has invalid length ({})",
                raw.data().len()
            ),
        }
    })
}

pub fn decode_credential_ids(store: &YubikeyStore) -> Vec<Vec<u8>> {
    store
        .keys
        .iter()
        .filter_map(|k| crate::base64::decode_url_safe(&k.credential_id).ok())
        .collect()
}

pub fn decode_salt(salt_b64: &str) -> Result<[u8; 32]> {
    let bytes = crate::base64::decode_url_safe(salt_b64)
        .map_err(|source| Error::InvalidBase64 { source })?;
    bytes.try_into().map_err(|_| Error::YubikeyStorage {
        message: "stored YubiKey salt has invalid length".to_string(),
    })
}

pub fn enroll(
    profile: &str,
    server: &str,
    email: &str,
    label: Option<&str>,
    require_uv: bool,
    pin: Option<&str>,
    master_keys: &crate::locked::Keys,
) -> Result<EnrolledKey> {
    let path = crate::dirs::yubikey_file(server, email);
    let mut store = load_store_from_path(&path)?.unwrap_or_default();

    let mut user_id = [0_u8; 32];
    rand::rng().fill_bytes(&mut user_id);
    let user_name = format!("{profile}:{email}");
    let uv_policy = if require_uv {
        crate::fido2::UvPolicy::Required
    } else {
        crate::fido2::UvPolicy::Discouraged
    };

    let created = crate::fido2::make_hmac_secret_credential(
        &store.rp_id,
        &user_id,
        &user_name,
        uv_policy,
        pin,
    )?;

    let mut salt = [0_u8; 32];
    rand::rng().fill_bytes(&mut salt);

    let hmac_res = crate::fido2::get_hmac_secret(
        &store.rp_id,
        std::slice::from_ref(&created.credential_id),
        &salt,
        created.uv,
        pin,
    )?;

    let wrapped_key = wrap_master_keys(master_keys, &salt, &hmac_res.secret)?;

    let cred_id_b64 =
        crate::base64::encode_url_safe_no_pad(&created.credential_id);
    let salt_b64 = crate::base64::encode_url_safe_no_pad(salt);
    salt.zeroize();

    let entry = EnrolledKey {
        label: label
            .filter(|s| !s.trim().is_empty())
            .map_or(created.product_string, std::string::ToString::to_string),
        credential_id: cred_id_b64.clone(),
        aaguid: created.aaguid,
        salt: salt_b64,
        uv: created.uv,
        wrapped_key,
    };

    store.keys.retain(|k| k.credential_id != cred_id_b64);
    store.keys.push(entry.clone());
    save_store_to_path(&path, &store)?;

    Ok(entry)
}

pub fn unlock_entry(
    rp_id: &str,
    entry: &EnrolledKey,
    pin: Option<&str>,
) -> Result<crate::locked::Keys> {
    let cred_id = crate::base64::decode_url_safe(&entry.credential_id)
        .map_err(|source| Error::InvalidBase64 { source })?;
    let mut salt = decode_salt(&entry.salt)?;
    let res = crate::fido2::get_hmac_secret(
        rp_id,
        &[cred_id],
        &salt,
        entry.uv,
        pin,
    );
    let hmac_res = match res {
        Ok(r) => r,
        Err(e) => {
            salt.zeroize();
            return Err(e);
        }
    };
    let unwrapped =
        unwrap_master_keys(&entry.wrapped_key, &salt, &hmac_res.secret);
    salt.zeroize();
    unwrapped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_and_unwrap_master_keys_roundtrip() {
        let master_keys = crate::locked::Keys::from_bytes(
            &[0x5a_u8; crate::locked::KEYS_LEN],
        )
        .unwrap();
        let salt = [0x11_u8; 32];
        let secret = [0x22_u8; 32];
        let wrong_secret = [0x33_u8; 32];

        let wrapped = wrap_master_keys(&master_keys, &salt, &secret).unwrap();
        let unwrapped = unwrap_master_keys(&wrapped, &salt, &secret).unwrap();
        assert_eq!(unwrapped.as_bytes(), master_keys.as_bytes());

        let err = unwrap_master_keys(&wrapped, &salt, &wrong_secret);
        assert!(matches!(err, Err(Error::InvalidMac)));

        assert!(derive_wrapping_key(&salt, &[0_u8; 32]).is_err());
    }

    #[test]
    fn test_store_atomic_persistence_permissions_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default:user@example.com.yubikey.json");

        assert!(load_store_from_path(&path).unwrap().is_none());

        let store = YubikeyStore {
            version: STORE_VERSION,
            rp_id: LOCAL_RP_ID.to_string(),
            keys: vec![
                EnrolledKey {
                    label: "primary".to_string(),
                    credential_id: "cred_primary_1234".to_string(),
                    aaguid: "00".repeat(16),
                    salt: crate::base64::encode_url_safe_no_pad(
                        [0x11_u8; 32],
                    ),
                    uv: false,
                    wrapped_key: "2.a|b|c".to_string(),
                },
                EnrolledKey {
                    label: "backup".to_string(),
                    credential_id: "cred_backup_5678".to_string(),
                    aaguid: "ff".repeat(16),
                    salt: crate::base64::encode_url_safe_no_pad(
                        [0x22_u8; 32],
                    ),
                    uv: true,
                    wrapped_key: "2.d|e|f".to_string(),
                },
            ],
        };

        save_store_to_path(&path, &store).unwrap();
        let mode =
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let loaded = load_store_from_path(&path).unwrap().unwrap();
        assert_eq!(loaded, store);

        // Remove by label
        assert!(remove_key_at_path(&path, "primary").unwrap());
        let after_first = load_store_from_path(&path).unwrap().unwrap();
        assert_eq!(after_first.keys.len(), 1);
        assert_eq!(after_first.keys[0].label, "backup");

        // Empty and non-existent selectors must not delete anything
        assert!(!remove_key_at_path(&path, "").unwrap());
        assert!(!remove_key_at_path(&path, "missing").unwrap());

        // Remove last key by credential_id prefix deletes the file cleanly
        assert!(remove_key_at_path(&path, "cred_backup").unwrap());
        assert!(!path.exists());
        assert!(load_store_from_path(&path).unwrap().is_none());
    }
}
