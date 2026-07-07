use anyhow::{anyhow, Context as _, Result};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{from_slice, from_value, json, to_vec, Value};
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aes::Aes256;
use cbc::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use hmac::{Hmac, Mac};
use rand::Rng as _;
use rand_8 as rand;
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;

#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Browser {
    Firefox,
    Chrome,
    Chromium,
    Brave,
    Vivaldi,
    #[value(name = "librewolf")]
    LibreWolf,
    Waterfox,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncString {
    #[serde(rename = "encryptionType")]
    enc_type: i32,
    data: String,
    iv: String,
    mac: String,
}

impl EncString {
    pub fn new(data: &[u8], iv: &[u8; 16], mac: &[u8; 32]) -> Self {
        Self {
            enc_type: 2,
            data: rbw::base64::encode(data),
            iv: rbw::base64::encode(iv),
            mac: rbw::base64::encode(mac),
        }
    }

    pub fn data(&self) -> Result<Vec<u8>> {
        rbw::base64::decode(&self.data)
            .map_err(|e| anyhow!("failed to decode data: {e:?}"))
    }

    pub fn iv(&self) -> Result<Vec<u8>> {
        rbw::base64::decode(&self.iv)
            .map_err(|e| anyhow!("failed to decode iv: {e:?}"))
    }

    pub fn mac(&self) -> Result<Vec<u8>> {
        rbw::base64::decode(&self.mac)
            .map_err(|e| anyhow!("failed to decode mac: {e:?}"))
    }
}

impl std::fmt::Display for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}|{}|{}",
            self.enc_type, self.iv, self.data, self.mac
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct EncryptedMessage {
    command: String,
    #[serde(rename = "messageId")]
    message_id: i64,
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ResponseData {
    Number(i32),
    Bool(bool),
}

impl Serialize for ResponseData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Number(n) => serializer.serialize_i32(*n),
            Self::Bool(b) => serializer.serialize_bool(*b),
        }
    }
}

impl From<i32> for ResponseData {
    fn from(n: i32) -> Self {
        Self::Number(n)
    }
}

impl From<bool> for ResponseData {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseMessage {
    timestamp: u64,
    command: String,
    #[serde(rename = "messageId")]
    message_id: i64,
    response: ResponseData,
    #[serde(rename = "userKeyB64")]
    key: Option<String>,
}

impl ResponseMessage {
    pub fn new<T: Into<ResponseData>>(
        command: &str,
        message_id: i64,
        response: T,
    ) -> Self {
        Self::with_key(command, message_id, response, None)
    }

    pub fn with_key<T: Into<ResponseData>>(
        command: &str,
        message_id: i64,
        response: T,
        key: Option<String>,
    ) -> Self {
        Self {
            timestamp: u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
            command: command.to_string(),
            message_id,
            response: response.into(),
            key,
        }
    }
}

impl Drop for ResponseMessage {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

struct Aes256CbcHmacKey {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl Drop for Aes256CbcHmacKey {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl Aes256CbcHmacKey {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        let enc_key = rng.gen();
        let mac_key = rng.gen();
        Self { enc_key, mac_key }
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut key_vec = Vec::with_capacity(64);
        key_vec.extend_from_slice(&self.enc_key);
        key_vec.extend_from_slice(&self.mac_key);
        key_vec
    }

    fn decrypt(&self, iv: &[u8], mac: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // Verify MAC
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.mac_key)?;
        hmac.update(iv);
        hmac.update(data);
        hmac.verify_slice(mac)
            .map_err(|_| anyhow!("MAC verification failed"))?;

        // Decrypt
        let decryptor =
            cbc::Decryptor::<Aes256>::new_from_slices(&self.enc_key, iv)
                .map_err(|e| anyhow!("invalid key or IV length: {e}"))?;
        let decrypted = decryptor
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|e| anyhow!("AES decrypt error: {e:?}"))?;
        Ok(decrypted)
    }

    fn encrypt(&self, msg: &[u8]) -> Result<EncString> {
        let iv = rand::thread_rng().gen::<[u8; 16]>();
        let encryptor =
            cbc::Encryptor::<Aes256>::new(&self.enc_key.into(), &iv.into());
        let data = encryptor.encrypt_padded_vec_mut::<Pkcs7>(msg);

        // Generate MAC
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.mac_key)?;
        hmac.update(&iv);
        hmac.update(&data);
        let mac: [u8; 32] = hmac.finalize().into_bytes().into();

        Ok(EncString::new(&data, &iv, &mac))
    }
}

pub fn rsa_encrypt(public_key_b64: &str, message: &[u8]) -> Result<String> {
    let public_key = rbw::base64::decode(public_key_b64)
        .map_err(|e| anyhow!("failed to decode public key: {e:?}"))?;
    let public_key = RsaPublicKey::from_public_key_der(&public_key)?;
    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<Sha1>();
    let ct = public_key.encrypt(&mut rng, padding, message)?;
    Ok(rbw::base64::encode(&ct))
}

const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

pub fn host() -> Result<()> {
    use zeroize::Zeroize as _;

    let mut session_key: Option<Aes256CbcHmacKey> = None;
    let mut r = BufReader::new(io::stdin());

    send_msg(&json!({
        "command": "connected",
        "app_id": "com.8bit.bitwarden"
    }))?;

    while let Some(msg_buf) = read_message(&mut r)? {
        let msg = from_slice::<Value>(&msg_buf)?;
        let app_id = msg
            .get("appId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Missing 'appId' field"))?;

        let message_field = msg
            .get("message")
            .ok_or_else(|| anyhow!("Missing 'message' field"))?;

        if let Some(command) =
            message_field.get("command").and_then(Value::as_str)
        {
            if command == "setupEncryption" {
                let public_key_b64 = message_field
                    .get("publicKey")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("Missing 'publicKey' field"))?;

                let key = Aes256CbcHmacKey::new();
                let mut raw_key = key.to_vec();
                let encrypted_secret_res =
                    rsa_encrypt(public_key_b64, &raw_key);
                raw_key.zeroize();
                let encrypted_secret = encrypted_secret_res?;

                session_key = Some(key);

                send_msg(&json!({
                    "command": "setupEncryption",
                    "appId": app_id,
                    "sharedSecret": encrypted_secret
                }))?;
                continue;
            }
        }

        // Encrypted message
        let key = session_key
            .as_ref()
            .ok_or_else(|| anyhow!("Session not initialized"))?;
        let enc_str: EncString = from_value(message_field.clone())?;
        if enc_str.enc_type != 2 {
            anyhow::bail!("unsupported encryption type: {}", enc_str.enc_type);
        }

        let mut decrypted_bytes =
            key.decrypt(&enc_str.iv()?, &enc_str.mac()?, &enc_str.data()?)?;

        let decrypted_msg_res =
            from_slice::<EncryptedMessage>(&decrypted_bytes);
        decrypted_bytes.zeroize();
        let decrypted_msg = decrypted_msg_res?;

        let response_message = handle_decrypted_message(&decrypted_msg)?;

        // Encrypt the response message
        let mut serialized_response = to_vec(&response_message)?;
        let encrypted_response_res = key.encrypt(&serialized_response);
        serialized_response.zeroize();
        let encrypted_response_str = encrypted_response_res?;

        send_msg(&json!({
            "appId": app_id,
            "messageId": decrypted_msg.message_id,
            "message": {
                "encryptedString": encrypted_response_str.to_string()
            }
        }))?;
    }

    Ok(())
}

fn send_msg(msg: &Value) -> Result<()> {
    let serialized = to_vec(msg)?;
    io::stdout()
        .write_all(&u32::try_from(serialized.len()).unwrap().to_ne_bytes())?;
    io::stdout().write_all(&serialized)?;
    io::stdout().flush()?;
    Ok(())
}

fn read_message<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let mut read_len = 0;
    while read_len < 4 {
        match reader.read(&mut len_buf[read_len..]) {
            Ok(0) if read_len == 0 => return Ok(None), // Clean EOF
            Ok(0) => {
                return Err(
                    io::Error::from(io::ErrorKind::UnexpectedEof).into()
                )
            }
            Ok(n) => read_len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let len = u32::from_ne_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("message size {len} exceeds maximum allowed size");
    }
    let mut msg_buf = vec![0u8; usize::try_from(len)?];
    reader.read_exact(&mut msg_buf)?;
    Ok(Some(msg_buf))
}

fn extract_jwt_sub(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload_bytes = rbw::base64::decode_url_safe_no_pad(payload_b64).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("sub")?.as_str().map(str::to_string)
}

fn db_matches_user(user_id: Option<&str>) -> bool {
    let Ok(config) = rbw::config::Config::load() else {
        return false;
    };
    let Some(email) = config.email.as_ref() else {
        return false;
    };
    let server = config.server_name();
    if !rbw::dirs::db_file(&server, email).exists() {
        return false;
    }
    if let Some(expected_user_id) = user_id.filter(|s| !s.is_empty()) {
        if let Ok(db) = rbw::db::Db::load(&server, email) {
            if let Some(sub) =
                db.access_token.as_deref().and_then(extract_jwt_sub)
            {
                if !sub.eq_ignore_ascii_case(expected_user_id) {
                    return false;
                }
            }
        }
    }
    true
}

fn handle_decrypted_message(
    msg: &EncryptedMessage,
) -> Result<ResponseMessage> {
    match msg.command.as_str() {
        "getBiometricsStatus" => {
            Ok(ResponseMessage::new(
                "getBiometricsStatus",
                msg.message_id,
                true, // biometrics available
            ))
        }
        "authenticateWithBiometrics" => Ok(ResponseMessage::new(
            "authenticateWithBiometrics",
            msg.message_id,
            true,
        )),
        "getBiometricsStatusForUser" => {
            let available = db_matches_user(msg.user_id.as_deref());

            Ok(ResponseMessage::new(
                "getBiometricsStatusForUser",
                msg.message_id,
                if available { 0 } else { 4 }, // 0 = Available, 4 = Not Configured
            ))
        }
        "unlockWithBiometricsForUser" => {
            if !db_matches_user(msg.user_id.as_deref()) {
                return Ok(ResponseMessage::new(
                    "unlockWithBiometricsForUser",
                    msg.message_id,
                    false,
                ));
            }
            get_master_key_from_agent().map_or_else(
                |e| {
                    log::warn!(
                        "failed to unlock with master key from agent: {e:#}"
                    );
                    Ok(ResponseMessage::new(
                        "unlockWithBiometricsForUser",
                        msg.message_id,
                        false,
                    ))
                },
                |key| {
                    Ok(ResponseMessage::with_key(
                        "unlockWithBiometricsForUser",
                        msg.message_id,
                        true,
                        Some(key),
                    ))
                },
            )
        }
        _ => Err(anyhow!("unsupported command: {cmd}", cmd = msg.command)),
    }
}

fn get_master_key_from_agent() -> Result<String> {
    crate::commands::unlock()?;

    let mut sock = crate::actions::connect()?;
    let environment = crate::actions::get_environment();

    let request = rbw::protocol::Request::new(
        environment,
        rbw::protocol::Action::GetMasterKey,
    );

    sock.send(&request)?;
    match sock.recv()? {
        rbw::protocol::Response::MasterKey { key } => Ok(key),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow!("agent error: {error}"))
        }
        r => Err(anyhow!("unexpected response from agent: {r:?}")),
    }
}

struct BrowserConfig {
    browser: Browser,
    name: &'static str,
    manifest_dir: PathBuf,
    is_firefox: bool,
}

fn get_browsers() -> Result<Vec<BrowserConfig>> {
    let base_dirs = directories::BaseDirs::new()
        .context("failed to find home directory")?;
    let home = base_dirs.home_dir();
    let mut browsers = Vec::new();

    #[cfg(target_os = "linux")]
    {
        browsers.push(BrowserConfig {
            browser: Browser::Firefox,
            name: "firefox",
            manifest_dir: home.join(".mozilla/native-messaging-hosts"),
            is_firefox: true,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Chrome,
            name: "chrome",
            manifest_dir: home
                .join(".config/google-chrome/NativeMessagingHosts"),
            is_firefox: false,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Chromium,
            name: "chromium",
            manifest_dir: home.join(".config/chromium/NativeMessagingHosts"),
            is_firefox: false,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Brave,
            name: "brave",
            manifest_dir: home.join(
                ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
            ),
            is_firefox: false,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Vivaldi,
            name: "vivaldi",
            manifest_dir: home.join(".config/vivaldi/NativeMessagingHosts"),
            is_firefox: false,
        });
        browsers.push(BrowserConfig {
            browser: Browser::LibreWolf,
            name: "librewolf",
            manifest_dir: home.join(".librewolf/native-messaging-hosts"),
            is_firefox: true,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Waterfox,
            name: "waterfox",
            manifest_dir: home.join(".waterfox/native-messaging-hosts"),
            is_firefox: true,
        });
    }

    #[cfg(target_os = "macos")]
    {
        browsers.push(BrowserConfig {
            browser: Browser::Firefox,
            name: "firefox",
            manifest_dir: home.join(
                "Library/Application Support/Mozilla/NativeMessagingHosts",
            ),
            is_firefox: true,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Chrome,
            name: "chrome",
            manifest_dir: home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts"),
            is_firefox: false,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Chromium,
            name: "chromium",
            manifest_dir: home.join(
                "Library/Application Support/Chromium/NativeMessagingHosts",
            ),
            is_firefox: false,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Brave,
            name: "brave",
            manifest_dir: home.join("Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            is_firefox: false,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Vivaldi,
            name: "vivaldi",
            manifest_dir: home.join(
                "Library/Application Support/Vivaldi/NativeMessagingHosts",
            ),
            is_firefox: false,
        });
        browsers.push(BrowserConfig {
            browser: Browser::LibreWolf,
            name: "librewolf",
            manifest_dir: home.join(
                "Library/Application Support/LibreWolf/NativeMessagingHosts",
            ),
            is_firefox: true,
        });
        browsers.push(BrowserConfig {
            browser: Browser::Waterfox,
            name: "waterfox",
            manifest_dir: home.join(
                "Library/Application Support/Waterfox/NativeMessagingHosts",
            ),
            is_firefox: true,
        });
    }

    Ok(browsers)
}

fn get_target_browsers(
    browser: Option<Browser>,
) -> Result<Vec<BrowserConfig>> {
    let all_browsers = get_browsers()?;
    if let Some(b) = browser {
        Ok(all_browsers
            .into_iter()
            .filter(|bc| bc.browser == b)
            .collect())
    } else {
        Ok(all_browsers
            .into_iter()
            .filter(|bc| {
                let config_root = bc.manifest_dir.parent().unwrap();
                config_root.exists() || bc.manifest_dir.exists()
            })
            .collect())
    }
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn resolve_without_symlinks(path: &Path) -> Result<String> {
    let abs = std::path::absolute(path)?;
    Ok(normalize_lexical(&abs).to_string_lossy().into_owned())
}

fn resolve_in_path(cmd: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            if let Ok(resolved) = resolve_without_symlinks(&candidate) {
                return Some(resolved);
            }
        }
    }
    None
}

fn resolve_executable_path(rbw_path: Option<&str>) -> Result<String> {
    if let Some(path) = rbw_path {
        let path_obj = Path::new(path);
        if path_obj.components().count() > 1 {
            resolve_without_symlinks(path_obj)
                .context("failed to resolve explicit rbw path")
        } else {
            Ok(path.to_string())
        }
    } else {
        let argv0 =
            std::env::args().next().context("failed to get argv[0]")?;
        let argv0_path = Path::new(&argv0);
        if argv0_path.components().count() > 1 {
            resolve_without_symlinks(argv0_path)
                .context("failed to resolve current executable path")
        } else {
            Ok(resolve_in_path(&argv0).unwrap_or(argv0))
        }
    }
}

pub fn install(
    browser: Option<Browser>,
    force: bool,
    rbw_path: Option<&str>,
) -> Result<()> {
    let resolved_path = resolve_executable_path(rbw_path)?;

    println!("Using rbw executable path: {resolved_path}");

    let target_browsers = get_target_browsers(browser)?;

    if target_browsers.is_empty() {
        println!("No installed browsers detected.");
        return Ok(());
    }

    for bc in target_browsers {
        println!("Installing integration for {}...", bc.name);

        fs::create_dir_all(&bc.manifest_dir).context(format!(
            "failed to create manifest directory for {}",
            bc.name
        ))?;

        let manifest_file = bc.manifest_dir.join("com.8bit.bitwarden.json");
        let wrapper_file = bc.manifest_dir.join("rbw-browser-bridge");

        if manifest_file.exists() && !force {
            let existing_manifest = fs::read_to_string(&manifest_file)
                .context("failed to read existing manifest")?;
            if !existing_manifest.contains("rbw-browser-bridge") {
                anyhow::bail!(
                    "A native messaging manifest already exists for {name} and does not seem to belong to rbw.\n\
                    Use --force to overwrite it.",
                    name = bc.name
                );
            }
        }

        let escaped_path = resolved_path.replace('\'', "'\\''");
        let wrapper_content = format!(
            "#!/bin/sh\nexec '{escaped_path}' browser-integration host \"$@\"\n"
        );
        fs::write(&wrapper_file, wrapper_content)
            .context("failed to write wrapper script")?;

        let mut perms = fs::metadata(&wrapper_file)?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        fs::set_permissions(&wrapper_file, perms)?;

        let manifest_json = if bc.is_firefox {
            json!({
                "name": "com.8bit.bitwarden",
                "description": "Bitwarden desktop <-> browser bridge (rbw)",
                "path": wrapper_file.to_string_lossy(),
                "type": "stdio",
                "allowed_extensions": [
                    "{446900e4-71c2-419f-a6a7-df9c091e268b}"
                ]
            })
        } else {
            json!({
                "name": "com.8bit.bitwarden",
                "description": "Bitwarden desktop <-> browser bridge (rbw)",
                "path": wrapper_file.to_string_lossy(),
                "type": "stdio",
                "allowed_origins": [
                    "chrome-extension://nngcebflmdojfhhmbhghlhiedafojfal/",
                    "chrome-extension://jbkfoedcorcdjbeocggbefkkoptjpcif/"
                ]
            })
        };

        let manifest_content = serde_json::to_string_pretty(&manifest_json)?;
        fs::write(&manifest_file, manifest_content)
            .context("failed to write manifest file")?;

        println!(
            "Successfully installed integration for {name}.",
            name = bc.name
        );
    }

    Ok(())
}

pub fn uninstall(browser: Option<Browser>) -> Result<()> {
    let target_browsers = get_target_browsers(browser)?;

    for bc in target_browsers {
        let manifest_file = bc.manifest_dir.join("com.8bit.bitwarden.json");
        let wrapper_file = bc.manifest_dir.join("rbw-browser-bridge");

        if manifest_file.exists() {
            let existing_manifest = fs::read_to_string(&manifest_file)
                .context("failed to read existing manifest")?;
            if existing_manifest.contains("rbw-browser-bridge") {
                println!("Uninstalling integration for {}...", bc.name);
                fs::remove_file(&manifest_file)
                    .context("failed to remove manifest file")?;
                if wrapper_file.exists() {
                    fs::remove_file(&wrapper_file)
                        .context("failed to remove wrapper script")?;
                }
                println!(
                    "Successfully uninstalled integration for {}.",
                    bc.name
                );
            } else {
                println!(
                    "Manifest for {} does not belong to rbw, skipping.",
                    bc.name
                );
            }
        } else {
            println!("Integration for {} not installed, skipping.", bc.name);
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decrypt_validates_iv_length() {
        let key = Aes256CbcHmacKey::new();

        // Invalid IV length (8 bytes instead of 16) — previously panicked
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&key.mac_key).expect("valid key");
        mac.update(&[0u8; 8]);
        mac.update(&[0u8; 16]);
        let tag = mac.finalize().into_bytes();

        let err = key.decrypt(&[0u8; 8], &tag, &[0u8; 16]).unwrap_err();
        assert!(err.to_string().contains("invalid key or IV length"));
    }

    #[test]
    fn test_read_message_limits_and_eof() {
        // Clean EOF returns Ok(None)
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_message(&mut empty).unwrap().is_none());

        // Truncated header returns Err
        let mut short_hdr = std::io::Cursor::new(vec![1u8, 2]);
        assert!(read_message(&mut short_hdr).is_err());

        // Oversized frame (> MAX_MESSAGE_SIZE) returns Err without allocating
        let oversized_len = (MAX_MESSAGE_SIZE + 1).to_ne_bytes();
        let mut oversized = std::io::Cursor::new(oversized_len.to_vec());
        let err = read_message(&mut oversized).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum allowed size"));

        // Valid frame round-trips
        let payload = br#"{"command":"ping"}"#;
        let mut valid = Vec::new();
        valid.extend_from_slice(
            &u32::try_from(payload.len()).unwrap().to_ne_bytes(),
        );
        valid.extend_from_slice(payload);
        let mut cursor = std::io::Cursor::new(valid);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), payload);
    }

    #[test]
    fn test_extract_jwt_sub() {
        // Header: {"alg":"none"}, Payload: {"sub":"user-1234"}
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEyMzQifQ.sig";
        assert_eq!(extract_jwt_sub(token).as_deref(), Some("user-1234"));
    }

    #[test]
    fn test_normalize_lexical() {
        let p = Path::new("/home/user/./bin/../.nix-profile/bin/rbw");
        assert_eq!(
            normalize_lexical(p),
            PathBuf::from("/home/user/.nix-profile/bin/rbw")
        );
    }
}
