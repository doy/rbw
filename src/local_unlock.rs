use crate::prelude::*;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore as _;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::env;
use zeroize::Zeroizing;

const AEAD_NAME: &str = "xchacha20poly1305";
const KEYRING_SERVICE_PREFIX: &str = "rbw";
const KEYRING_LOCAL_SECRET: &str = "local-secret@v1";
const KEYRING_PIN_METADATA: &str = "pin-metadata@v1";
const KDF_OUT_LEN: u32 = 32;
const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ITERATIONS: u32 = 4;
const DEFAULT_PARALLELISM: u32 = 2;

#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq,
)]
pub enum KeyringStrength {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "os-protected")]
    OsProtected,
    #[serde(rename = "weak")]
    Weak,
    #[serde(rename = "unavailable")]
    Unavailable,
}

impl Default for KeyringStrength {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct KeyringInfo {
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub strength: KeyringStrength,
}

#[derive(Debug, Clone)]
struct PolicyContext {
    config: crate::config::PinUnlockConfig,
    keyring: KeyringInfo,
}

fn current_unix_seconds() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InvalidWrappedMaster {
            reason: "system clock",
        })?
        .as_secs() as i64)
}

fn compute_expiry(created_at: i64, ttl_secs: Option<u64>) -> Option<i64> {
    ttl_secs.and_then(|ttl| {
        let bounded = ttl.min(i64::MAX as u64);
        created_at.checked_add(bounded as i64)
    })
}

fn detect_keyring_info() -> KeyringInfo {
    let mut info = KeyringInfo::default();
    #[cfg(target_os = "macos")]
    {
        info.backend = "macos-keychain".to_string();
        info.strength = KeyringStrength::OsProtected;
    }
    #[cfg(target_os = "windows")]
    {
        info.backend = "windows-credential-manager".to_string();
        info.strength = KeyringStrength::OsProtected;
    }
    #[cfg(target_os = "linux")]
    {
        info.backend = "secret-service".to_string();
        let has_dbus = env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
        let runtime_dir = env::var_os("XDG_RUNTIME_DIR").is_some();
        info.strength = if has_dbus || runtime_dir {
            KeyringStrength::OsProtected
        } else {
            KeyringStrength::Weak
        };
    }
    if info.backend.is_empty() {
        info.backend = "unknown".to_string();
    }
    info
}

fn load_policy_context() -> Result<PolicyContext> {
    let config = crate::config::Config::load()?;
    let keyring = detect_keyring_info();
    Ok(PolicyContext {
        config: config.pin_unlock.clone(),
        keyring,
    })
}

fn effective_keyring_info(
    policy: &PolicyContext,
    metadata: &PinMetadata,
) -> KeyringInfo {
    metadata
        .keyring
        .as_ref()
        .cloned()
        .unwrap_or_else(|| policy.keyring.clone())
}

fn ensure_keyring_allowed(
    policy: &PolicyContext,
    metadata: &PinMetadata,
) -> Result<KeyringInfo> {
    let info = effective_keyring_info(policy, metadata);
    if !policy.config.allow_weak_keyring
        && matches!(
            info.strength,
            KeyringStrength::Weak
                | KeyringStrength::Unavailable
                | KeyringStrength::Unknown
        )
    {
        return Err(Error::PinBackendWeak {
            backend: info.backend.clone(),
        });
    }
    Ok(info)
}

fn build_wrapped_blob(
    pin: &crate::locked::Password,
    keys: &crate::locked::Keys,
    profile: &str,
    params: &KdfParams,
    counter: u64,
    created_at: i64,
    expires_at: Option<i64>,
    local_secret: &[u8],
    rng: &mut rand::rngs::OsRng,
) -> Result<WrappedBlobV1> {
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let kek = derive_kek(pin.password(), &salt, params, local_secret)?;

    let mut nonce_bytes = [0u8; 24];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let mut dek = Zeroizing::new([0u8; 64]);
    dek[..32].copy_from_slice(keys.enc_key());
    dek[32..].copy_from_slice(keys.mac_key());

    let mut blob = WrappedBlobV1 {
        version: 1,
        aead: AEAD_NAME.to_string(),
        profile: profile.to_string(),
        created_at,
        counter,
        nonce: crate::base64::encode(nonce_bytes),
        salt: crate::base64::encode(salt),
        kdf: params.clone(),
        expires_at,
        ciphertext: String::new(),
    };

    let aad = serialize_aad(&blob)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &dek[..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::PinEncrypt)?;
    blob.ciphertext = crate::base64::encode(ciphertext);
    Ok(blob)
}

/// Memory and time cost parameters for Argon2 derivation when wrapping keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub outlen: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m: DEFAULT_MEMORY_KIB,
            t: DEFAULT_ITERATIONS,
            p: DEFAULT_PARALLELISM,
            outlen: KDF_OUT_LEN,
        }
    }
}

/// Metadata describing the encrypted wrapper file persisted on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WrappedBlobV1 {
    pub version: u8,
    pub aead: String,
    pub profile: String,
    pub created_at: i64,
    pub counter: u64,
    pub nonce: String,
    pub salt: String,
    pub kdf: KdfParams,
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub ciphertext: String,
}

#[derive(serde::Serialize)]
struct MetadataAad<'a> {
    version: u8,
    aead: &'a str,
    profile: &'a str,
    created_at: i64,
    counter: u64,
    nonce: &'a str,
    salt: &'a str,
    kdf: &'a KdfParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
}

impl<'a> From<&'a WrappedBlobV1> for MetadataAad<'a> {
    fn from(value: &'a WrappedBlobV1) -> Self {
        Self {
            version: value.version,
            aead: &value.aead,
            profile: &value.profile,
            created_at: value.created_at,
            counter: value.counter,
            nonce: &value.nonce,
            salt: &value.salt,
            kdf: &value.kdf,
            expires_at: value.expires_at,
        }
    }
}

/// Persisted metadata stored alongside the local key-encryption secret.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PinMetadata {
    #[serde(default)]
    pub fail_count: u32,
    #[serde(default)]
    pub last_seen_counter: u64,
    #[serde(default)]
    pub keyring: Option<KeyringInfo>,
}

impl Default for PinMetadata {
    fn default() -> Self {
        Self {
            fail_count: 0,
            last_seen_counter: 0,
            keyring: None,
        }
    }
}

pub struct Status {
    pub blob_present: bool,
    pub created_at: Option<i64>,
    pub counter: Option<u64>,
    pub kdf: Option<KdfParams>,
    pub fail_count: u32,
    pub expires_at: Option<i64>,
    pub keyring: Option<KeyringInfo>,
    pub last_seen_counter: u64,
}

pub fn set_pin(
    pin: &crate::locked::Password,
    keys: &crate::locked::Keys,
    profile: &str,
) -> Result<()> {
    if pin.password().is_empty() {
        return Err(Error::PinTooShort);
    }

    crate::dirs::make_all()?;

    let policy = load_policy_context()?;
    if !policy.config.enabled {
        return Err(Error::PinBackendUnavailable);
    }

    let mut metadata = load_pin_metadata(profile)?;
    let keyring_info = ensure_keyring_allowed(&policy, &metadata)?;

    let mut rng = rand::rngs::OsRng;
    let local_secret = ensure_local_secret(profile, &mut rng)?;
    let params = KdfParams::default();

    let counter = metadata.last_seen_counter.saturating_add(1);
    let created_at = current_unix_seconds()?;
    let expires_at = compute_expiry(created_at, policy.config.ttl_secs);

    let blob_path = crate::dirs::wrapped_master_file();
    let blob = build_wrapped_blob(
        pin,
        keys,
        profile,
        &params,
        counter,
        created_at,
        expires_at,
        local_secret.as_ref(),
        &mut rng,
    )?;

    write_blob(&blob_path, &blob)?;

    metadata.fail_count = 0;
    metadata.last_seen_counter = counter;
    metadata.keyring = Some(keyring_info);
    save_pin_metadata(profile, &metadata)?;

    Ok(())
}

pub fn unlock_with_pin(
    pin: &crate::locked::Password,
    profile: &str,
) -> Result<crate::locked::Keys> {
    let blob_path = crate::dirs::wrapped_master_file();
    let blob_bytes = match fs::read(&blob_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::PinNotSet)
        }
        Err(source) => {
            return Err(Error::LoadWrappedMaster {
                source,
                file: blob_path,
            })
        }
    };

    let blob: WrappedBlobV1 =
        serde_json::from_slice(&blob_bytes).map_err(|source| {
            Error::WrappedMasterJson {
                source,
                file: crate::dirs::wrapped_master_file(),
            }
        })?;

    if blob.version != 1 || blob.aead != AEAD_NAME {
        return Err(Error::InvalidWrappedMaster {
            reason: "unsupported blob version",
        });
    }

    let policy = load_policy_context()?;
    if !policy.config.enabled {
        return Err(Error::PinBackendUnavailable);
    }

    let mut pin_metadata = load_pin_metadata(profile)?;
    let keyring_info = ensure_keyring_allowed(&policy, &pin_metadata)?;

    let now = current_unix_seconds()?;

    if let Some(expiry) = blob.expires_at {
        if expiry <= now {
            return Err(Error::PinExpired);
        }
    }

    let local_secret =
        load_local_secret(profile)?.ok_or(Error::PinMissingLocalSecret)?;

    let salt = decode_field(&blob.salt, 16, "salt")?;
    let nonce_bytes = decode_field(&blob.nonce, 24, "nonce")?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext =
        crate::base64::decode(&blob.ciphertext).map_err(|_| {
            Error::InvalidWrappedMaster {
                reason: "ciphertext",
            }
        })?;

    let kek = derive_kek(pin.password(), &salt, &blob.kdf, &local_secret)?;
    let aad = serialize_aad(&blob)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let plaintext = match cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext.as_ref(),
            aad: &aad,
        },
    ) {
        Ok(plaintext) => Zeroizing::new(plaintext), // ASK_AI: should this not be a locked type (like the stuff defined in locked.rs)?
        Err(_) => {
            pin_metadata.fail_count =
                pin_metadata.fail_count.saturating_add(1);
            if pin_metadata.fail_count >= 3 {
                clear_pin(profile)?;
                return Err(Error::PinTooManyFailures);
            }
            save_pin_metadata(profile, &pin_metadata)?;
            return Err(Error::PinIncorrect);
        }
    };

    if plaintext.len() != 64 {
        return Err(Error::InvalidWrappedMaster {
            reason: "unexpected plaintext length",
        });
    }

    let mut vec = crate::locked::Vec::new();
    vec.extend(plaintext.iter().copied());
    let keys = crate::locked::Keys::new(vec);

    let mut counter = blob.counter;

    if blob.counter < pin_metadata.last_seen_counter {
        counter = pin_metadata.last_seen_counter.saturating_add(1);
        let mut rng = rand::rngs::OsRng;
        let rewrap_params = blob.kdf.clone();
        let created_at = current_unix_seconds()?;
        let expires_at = compute_expiry(created_at, policy.config.ttl_secs);
        let blob = build_wrapped_blob(
            pin,
            &keys,
            profile,
            &rewrap_params,
            counter,
            created_at,
            expires_at,
            local_secret.as_ref(),
            &mut rng,
        )?;
        write_blob(&blob_path, &blob)?;
    }

    pin_metadata.fail_count = 0;
    pin_metadata.last_seen_counter = counter;
    pin_metadata.keyring = Some(keyring_info);
    save_pin_metadata(profile, &pin_metadata)?;

    Ok(keys)
}

pub fn clear_pin(profile: &str) -> Result<()> {
    let blob_path = crate::dirs::wrapped_master_file();
    if let Err(err) = std::fs::remove_file(&blob_path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(Error::RemoveWrappedMaster {
                source: err,
                file: blob_path,
            });
        }
    }

    if let Err(err) =
        keyring_entry(profile, KEYRING_LOCAL_SECRET)?.delete_password()
    {
        if !matches!(err, keyring::Error::NoEntry) {
            return Err(Error::Keyring { source: err });
        }
    }
    if let Err(err) =
        keyring_entry(profile, KEYRING_PIN_METADATA)?.delete_password()
    {
        if !matches!(err, keyring::Error::NoEntry) {
            return Err(Error::Keyring { source: err });
        }
    }

    Ok(())
}

pub fn status(profile: &str) -> Result<Status> {
    let meta = load_pin_metadata(profile)?;
    let blob_path = crate::dirs::wrapped_master_file();
    let mut status = Status {
        blob_present: false,
        created_at: None,
        counter: None,
        kdf: None,
        fail_count: meta.fail_count,
        expires_at: None,
        keyring: meta.keyring.clone(),
        last_seen_counter: meta.last_seen_counter,
    };

    match std::fs::read(&blob_path) {
        Ok(bytes) => {
            let blob: WrappedBlobV1 = serde_json::from_slice(&bytes)
                .map_err(|source| Error::WrappedMasterJson {
                    source,
                    file: blob_path.clone(),
                })?;
            status.blob_present = true;
            status.created_at = Some(blob.created_at);
            status.counter = Some(blob.counter);
            status.kdf = Some(blob.kdf);
            status.expires_at = blob.expires_at;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::LoadWrappedMaster {
                source,
                file: blob_path,
            });
        }
    }

    if status.keyring.is_none() {
        status.keyring = Some(detect_keyring_info());
    }

    Ok(status)
}

fn serialize_aad(blob: &WrappedBlobV1) -> Result<Vec<u8>> {
    serde_json::to_vec(&MetadataAad::from(blob))
        .map_err(|source| Error::WrappedMasterAad { source })
}

struct BlobLock {
    path: std::path::PathBuf,
}

impl BlobLock {
    fn acquire(target: &std::path::Path) -> Result<Self> {
        let lock_path = lock_path(target);
        let mut needs_retry = false;
        let mut attempt = 0;
        loop {
            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&lock_path)
            {
                Ok(mut fh) => {
                    let pid = std::process::id();
                    let ts = current_unix_seconds()?;
                    let _ = writeln!(fh, "pid={pid} ts={ts}");
                    let _ = fh.sync_all();
                    return Ok(Self { path: lock_path });
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    if needs_retry {
                        return Err(Error::SaveWrappedMaster {
                            source: err,
                            file: lock_path.clone(),
                        });
                    }
                    needs_retry = true;
                    attempt += 1;
                    if let Ok(metadata) = fs::metadata(&lock_path) {
                        if let Ok(modified) = metadata.modified() {
                            if modified
                                .elapsed()
                                .map(|elapsed| {
                                    elapsed > Duration::from_secs(300)
                                })
                                .unwrap_or(false)
                            {
                                let _ = fs::remove_file(&lock_path);
                                continue;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(50 * attempt));
                }
                Err(err) => {
                    return Err(Error::SaveWrappedMaster {
                        source: err,
                        file: lock_path.clone(),
                    });
                }
            }
        }
    }
}

impl Drop for BlobLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn write_blob(path: &std::path::Path, blob: &WrappedBlobV1) -> Result<()> {
    let _lock = BlobLock::acquire(path)?;
    let data = serde_json::to_vec_pretty(blob)
        .map_err(|source| Error::WrappedMasterAad { source })?;
    let tmp = path.with_extension("tmp");

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|source| Error::SaveWrappedMaster {
            source,
            file: tmp.clone(),
        })?;
    file.write_all(&data)
        .map_err(|source| Error::SaveWrappedMaster {
            source,
            file: tmp.clone(),
        })?;
    file.sync_all().map_err(|source| Error::SaveWrappedMaster {
        source,
        file: tmp.clone(),
    })?;
    drop(file);
    fs::rename(&tmp, path).map_err(|source| Error::SaveWrappedMaster {
        source,
        file: path.to_path_buf(),
    })?;
    ensure_file_perms(path)?;
    fsync_parent(path)?;
    Ok(())
}

fn lock_path(path: &std::path::Path) -> std::path::PathBuf {
    path.with_extension("lock")
}

fn fsync_parent(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = fs::File::open(parent).map_err(|source| {
            Error::SaveWrappedMaster {
                source,
                file: parent.to_path_buf(),
            }
        })?;
        dir.sync_all().map_err(|source| Error::SaveWrappedMaster {
            source,
            file: parent.to_path_buf(),
        })?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_file_perms(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata =
        fs::metadata(path).map_err(|source| Error::SaveWrappedMaster {
            source,
            file: path.to_path_buf(),
        })?;
    let mut perms = metadata.permissions();
    if perms.mode() & 0o777 != 0o600 {
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).map_err(|source| {
            Error::SaveWrappedMaster {
                source,
                file: path.to_path_buf(),
            }
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_file_perms(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_from_bytes(bytes: &[u8]) -> crate::locked::Password {
        let mut vec = crate::locked::Vec::new();
        vec.extend(bytes.iter().copied());
        crate::locked::Password::new(vec)
    }

    fn keys_from_bytes(bytes: &[u8; 64]) -> crate::locked::Keys {
        let mut vec = crate::locked::Vec::new();
        vec.extend(bytes.iter().copied());
        crate::locked::Keys::new(vec)
    }

    fn decrypt_blob(
        blob: &WrappedBlobV1,
        pin: &crate::locked::Password,
        local_secret: &[u8],
    ) -> Result<Vec<u8>> {
        let salt = decode_field(&blob.salt, 16, "salt")?;
        let nonce = decode_field(&blob.nonce, 24, "nonce")?;
        let ciphertext =
            crate::base64::decode(&blob.ciphertext).map_err(|_| {
                Error::InvalidWrappedMaster {
                    reason: "ciphertext",
                }
            })?;
        let kek = derive_kek(pin.password(), &salt, &blob.kdf, local_secret)?;
        let aad = serialize_aad(blob)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::PinEncrypt)?;
        Ok(plaintext)
    }

    #[test]
    fn expiry_calculation_respects_ttl() {
        assert_eq!(compute_expiry(10, None), None);
        assert_eq!(compute_expiry(10, Some(5)), Some(15));
        assert_eq!(
            compute_expiry(i64::MAX - 1, Some(10)),
            None,
            "overflow should yield None"
        );
    }

    #[test]
    fn aad_binding_detects_metadata_changes() {
        let pin = password_from_bytes(b"123456");
        let mut key_material = [0u8; 64];
        for (idx, byte) in key_material.iter_mut().enumerate() {
            *byte = idx as u8;
        }
        let keys = keys_from_bytes(&key_material);
        let params = KdfParams {
            m: DEFAULT_MEMORY_KIB,
            t: DEFAULT_ITERATIONS,
            p: DEFAULT_PARALLELISM,
            outlen: KDF_OUT_LEN,
        };
        let mut rng = rand::rngs::OsRng;
        let local_secret = [7u8; 32];
        let blob = build_wrapped_blob(
            &pin,
            &keys,
            "default",
            &params,
            1,
            1_700_000_000,
            None,
            &local_secret,
            &mut rng,
        )
        .expect("wrap blob");

        let plaintext =
            decrypt_blob(&blob, &pin, &local_secret).expect("decrypt blob");
        assert_eq!(plaintext.len(), 64);

        let mut tampered = blob.clone();
        tampered.profile = "tampered".to_string();
        assert!(decrypt_blob(&tampered, &pin, &local_secret).is_err());
    }

    #[test]
    fn default_kdf_params_match_constants() {
        let params = KdfParams::default();
        assert_eq!(params.m, DEFAULT_MEMORY_KIB);
        assert_eq!(params.t, DEFAULT_ITERATIONS);
        assert_eq!(params.p, DEFAULT_PARALLELISM);
        assert_eq!(params.outlen, KDF_OUT_LEN);
    }
}

fn decode_field(
    input: &str,
    expected_len: usize,
    label: &'static str,
) -> Result<Vec<u8>> {
    let bytes = crate::base64::decode(input)
        .map_err(|_| Error::InvalidWrappedMaster { reason: label })?;
    if bytes.len() != expected_len {
        return Err(Error::InvalidWrappedMaster { reason: label });
    }
    Ok(bytes)
}

fn derive_kek(
    pin: &[u8],
    salt: &[u8],
    params: &KdfParams,
    local_secret: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    use hmac::Mac as _;

    let mut mac =
        <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(local_secret)
            .map_err(|_| Error::PinPepper)?;
    mac.update(b"rbw:kek:v1");
    mac.update(pin);
    let prehash = Zeroizing::new(mac.finalize().into_bytes().to_vec());

    let out_len = params.outlen as usize;
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m, params.t, params.p, Some(out_len))
            .map_err(|_| Error::Argon2)?,
    );

    let mut output = [0u8; 32];
    argon2::Argon2::hash_password_into(
        &argon2,
        prehash.as_slice(),
        salt,
        &mut output,
    )
    .map_err(|_| Error::Argon2)?;
    Ok(Zeroizing::new(output))
}

fn ensure_local_secret(
    profile: &str,
    rng: &mut rand::rngs::OsRng,
) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(secret) = load_local_secret(profile)? {
        return Ok(secret);
    }

    let mut secret = Zeroizing::new(vec![0u8; 32]);
    rng.fill_bytes(secret.as_mut_slice());
    save_local_secret(profile, secret.as_slice())?;
    Ok(secret)
}

fn load_local_secret(profile: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match keyring_entry(profile, KEYRING_LOCAL_SECRET)?.get_password() {
        Ok(secret) => {
            let bytes = crate::base64::decode(&secret).map_err(|_| {
                Error::InvalidWrappedMaster {
                    reason: "local secret",
                }
            })?;
            Ok(Some(Zeroizing::new(bytes)))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(source) => Err(Error::Keyring { source }),
    }
}

fn save_local_secret(profile: &str, secret: &[u8]) -> Result<()> {
    keyring_entry(profile, KEYRING_LOCAL_SECRET)?
        .set_password(&crate::base64::encode(secret))
        .map_err(|source| Error::Keyring { source })
}

fn load_pin_metadata(profile: &str) -> Result<PinMetadata> {
    match keyring_entry(profile, KEYRING_PIN_METADATA)?.get_password() {
        Ok(bytes) => {
            let meta: PinMetadata = serde_json::from_str(&bytes)
                .map_err(|source| Error::PinMetadataJson { source })?;
            Ok(meta)
        }
        Err(keyring::Error::NoEntry) => Ok(PinMetadata::default()),
        Err(source) => Err(Error::Keyring { source }),
    }
}

fn save_pin_metadata(profile: &str, metadata: &PinMetadata) -> Result<()> {
    let payload = serde_json::to_string(metadata)
        .map_err(|source| Error::PinMetadataJson { source })?;
    keyring_entry(profile, KEYRING_PIN_METADATA)?
        .set_password(&payload)
        .map_err(|source| Error::Keyring { source })
}

fn keyring_entry(profile: &str, account: &str) -> Result<keyring::Entry> {
    let profile = if profile.is_empty() {
        crate::dirs::profile()
    } else {
        profile.to_string()
    };
    keyring::Entry::new(
        &format!("{KEYRING_SERVICE_PREFIX}/{profile}/pin"),
        account,
    )
    .map_err(|source| Error::Keyring { source })
}
