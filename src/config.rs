use crate::prelude::*;

use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
pub struct AccountKey {
    pub server: String,
    pub email: String,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct AccountConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinentry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub touchid: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yubikey: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yubikey_uv: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_login: Option<bool>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct GlobalConfig {
    pub lock_timeout: u64,
    pub sync_interval: u64,
    pub pinentry: String,
    #[cfg_attr(
        not(target_os = "macos"),
        serde(skip_serializing_if = "std::ops::Not::not")
    )]
    pub touchid: bool,
    pub yubikey: bool,
    pub yubikey_uv: bool,
    pub passkey_login: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ConfigFile {
    // Legacy flat fields (kept for backwards compatibility when `accounts` is
    // empty; migrated into `accounts` once multi-account commands are used)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications_url: Option<String>,

    // Global defaults (inherited by accounts unless overridden per-account)
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<std::path::PathBuf>,
    #[serde(default)]
    #[cfg_attr(
        not(target_os = "macos"),
        serde(skip_serializing_if = "std::ops::Not::not")
    )]
    pub touchid: bool,
    #[serde(default)]
    pub yubikey: bool,
    #[serde(default)]
    pub yubikey_uv: bool,
    #[serde(default)]
    pub passkey_login: bool,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_account: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub accounts: BTreeMap<String, AccountConfig>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: default_lock_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            client_cert_path: None,
            touchid: false,
            yubikey: false,
            yubikey_uv: false,
            passkey_login: false,
            device_id: None,
            active_account: None,
            accounts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccountEntry {
    pub name: String,
    pub config: Config,
    pub active: bool,
    pub is_legacy: bool,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct Config {
    pub email: Option<String>,
    pub sso_id: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    pub ui_url: Option<String>,
    pub notifications_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    pub client_cert_path: Option<std::path::PathBuf>,
    #[serde(default)]
    #[cfg_attr(
        not(target_os = "macos"),
        serde(skip_serializing_if = "std::ops::Not::not")
    )]
    pub touchid: bool,
    #[serde(default)]
    pub yubikey: bool,
    #[serde(default)]
    pub yubikey_uv: bool,
    #[serde(default)]
    pub passkey_login: bool,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: default_lock_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            client_cert_path: None,
            touchid: false,
            yubikey: false,
            yubikey_uv: false,
            passkey_login: false,
            device_id: None,
        }
    }
}

pub fn default_lock_timeout() -> u64 {
    3600
}

pub fn default_sync_interval() -> u64 {
    3600
}

pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

pub fn server_name_from_base_url(base_url: Option<&str>) -> String {
    base_url.map_or_else(|| "default".to_string(), str::to_string)
}

pub fn server_display_name_from_base_url(base_url: Option<&str>) -> String {
    let Some(raw) = base_url else {
        return "bitwarden.com".to_string();
    };
    let clean = raw.trim_end_matches('/');
    if clean.eq_ignore_ascii_case("https://api.bitwarden.com")
        || clean.eq_ignore_ascii_case("https://vault.bitwarden.com")
        || clean.eq_ignore_ascii_case("https://bitwarden.com")
    {
        return "bitwarden.com".to_string();
    }
    if clean.eq_ignore_ascii_case("https://api.bitwarden.eu")
        || clean.eq_ignore_ascii_case("https://vault.bitwarden.eu")
        || clean.eq_ignore_ascii_case("https://bitwarden.eu")
    {
        return "bitwarden.eu".to_string();
    }
    if let Ok(parsed) = url::Url::parse(clean)
        && let Some(host) = parsed.host_str()
    {
        let mut out = parsed.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        );
        let path = parsed.path().trim_end_matches('/');
        if !path.is_empty() && path != "/" {
            out.push_str(path);
        }
        return out;
    }
    clean.to_string()
}

pub fn normalize_server_input(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "default"
        | "us"
        | "bitwarden.com"
        | "vault.bitwarden.com"
        | "api.bitwarden.com"
        | "https://bitwarden.com"
        | "https://vault.bitwarden.com"
        | "https://api.bitwarden.com" => None,
        "eu"
        | "bitwarden.eu"
        | "vault.bitwarden.eu"
        | "api.bitwarden.eu"
        | "https://bitwarden.eu"
        | "https://vault.bitwarden.eu"
        | "https://api.bitwarden.eu" => {
            Some("https://api.bitwarden.eu".to_string())
        }
        _ => {
            if lower.starts_with("http://") || lower.starts_with("https://") {
                Some(trimmed.to_string())
            } else {
                Some(format!("https://{trimmed}"))
            }
        }
    }
}

fn canonical_server_key(base_url: Option<&str>) -> String {
    let normalized = base_url.and_then(normalize_server_input);
    normalized
        .map_or_else(|| "default".to_string(), |s| s.to_ascii_lowercase())
}

pub fn validate_account_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'-' | b'_' | b'.' | b'@')
        })
    {
        return Err(Error::InvalidAccountName {
            name: name.to_string(),
        });
    }
    Ok(())
}

pub fn sanitize_account_name(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@')
            {
                c
            } else {
                '-'
            }
        })
        .collect();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "default".to_string()
    } else if out.len() > 128 {
        out.chars().take(128).collect()
    } else {
        out
    }
}

impl ConfigFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        Self::load_from_path(&file)
    }

    pub fn load_from_path(file: &std::path::Path) -> Result<Self> {
        let mut fh = std::fs::File::open(file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.to_path_buf(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.to_path_buf(),
            })?;
        Self::from_json(&json, file.to_path_buf())
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
        Self::from_json(&json, file)
    }

    fn from_json(json: &str, file: std::path::PathBuf) -> Result<Self> {
        let mut slf: Self = serde_json::from_str(json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        for account in slf.accounts.values_mut() {
            if account.lock_timeout == Some(0) {
                log::warn!("lock_timeout must be greater than 0");
                account.lock_timeout = Some(default_lock_timeout());
            }
        }
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        let file = crate::dirs::config_file();
        self.save_to_path(&file)
    }

    pub fn save_to_path(&self, file: &std::path::Path) -> Result<()> {
        // unwrap is safe here because config_file is explicitly constructed
        // as a filename in a directory
        let parent = file.parent().unwrap();
        std::fs::create_dir_all(parent).map_err(|source| {
            Error::SaveConfig {
                source,
                file: file.to_path_buf(),
            }
        })?;

        let serialized = serde_json::to_string(self).map_err(|source| {
            Error::SaveConfigJson {
                source,
                file: file.to_path_buf(),
            }
        })?;

        let tmp_name = format!(
            ".{}.tmp-{}",
            file.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("config.json"),
            uuid::Uuid::new_v4()
        );
        let tmp_path = parent.join(tmp_name);
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|source| Error::SaveConfig {
                source,
                file: file.to_path_buf(),
            })?;
        if let Err(source) = fh
            .write_all(serialized.as_bytes())
            .and_then(|()| fh.sync_all())
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::SaveConfig {
                source,
                file: file.to_path_buf(),
            });
        }
        drop(fh);

        if let Err(source) = std::fs::set_permissions(
            &tmp_path,
            std::fs::Permissions::from_mode(0o600),
        ) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::SaveConfig {
                source,
                file: file.to_path_buf(),
            });
        }

        std::fs::rename(&tmp_path, file).map_err(|source| {
            let _ = std::fs::remove_file(&tmp_path);
            Error::SaveConfig {
                source,
                file: file.to_path_buf(),
            }
        })?;
        Ok(())
    }

    pub fn global_defaults(&self) -> GlobalConfig {
        GlobalConfig {
            lock_timeout: self.lock_timeout,
            sync_interval: self.sync_interval,
            pinentry: self.pinentry.clone(),
            touchid: self.touchid,
            yubikey: self.yubikey,
            yubikey_uv: self.yubikey_uv,
            passkey_login: self.passkey_login,
        }
    }

    pub fn has_legacy_account(&self) -> bool {
        self.accounts.is_empty()
            && (self.email.is_some()
                || self.base_url.is_some()
                || self.identity_url.is_some()
                || self.ui_url.is_some()
                || self.notifications_url.is_some()
                || self.sso_id.is_some()
                || self.client_cert_path.is_some())
    }

    pub fn is_multi_account(&self) -> bool {
        !self.accounts.is_empty()
    }

    pub fn legacy_account_name(&self) -> String {
        sanitize_account_name(&server_display_name_from_base_url(
            self.base_url.as_deref(),
        ))
    }

    pub fn migrate_legacy_if_needed(&mut self) -> Option<String> {
        if !self.has_legacy_account() {
            return None;
        }
        let name = self.legacy_account_name();
        let account = AccountConfig {
            email: self.email.take(),
            sso_id: self.sso_id.take(),
            base_url: self.base_url.take(),
            identity_url: self.identity_url.take(),
            ui_url: self.ui_url.take(),
            notifications_url: self.notifications_url.take(),
            lock_timeout: None,
            sync_interval: None,
            pinentry: None,
            client_cert_path: self.client_cert_path.take(),
            touchid: None,
            yubikey: None,
            yubikey_uv: None,
            passkey_login: None,
        };
        self.accounts.insert(name.clone(), account);
        self.active_account = Some(name.clone());
        Some(name)
    }

    fn resolve_legacy_config(&self) -> Config {
        Config {
            email: self.email.clone(),
            sso_id: self.sso_id.clone(),
            base_url: self.base_url.clone(),
            identity_url: self.identity_url.clone(),
            ui_url: self.ui_url.clone(),
            notifications_url: self.notifications_url.clone(),
            lock_timeout: if self.lock_timeout == 0 {
                default_lock_timeout()
            } else {
                self.lock_timeout
            },
            sync_interval: self.sync_interval,
            pinentry: self.pinentry.clone(),
            client_cert_path: self.client_cert_path.clone(),
            touchid: self.touchid,
            yubikey: self.yubikey,
            yubikey_uv: self.yubikey_uv,
            passkey_login: self.passkey_login,
            device_id: self.device_id.clone(),
        }
    }

    fn resolve_account_config(&self, account: &AccountConfig) -> Config {
        let lock_timeout = account.lock_timeout.unwrap_or(self.lock_timeout);
        Config {
            email: account.email.clone(),
            sso_id: account.sso_id.clone(),
            base_url: account.base_url.clone(),
            identity_url: account.identity_url.clone(),
            ui_url: account.ui_url.clone(),
            notifications_url: account.notifications_url.clone(),
            lock_timeout: if lock_timeout == 0 {
                default_lock_timeout()
            } else {
                lock_timeout
            },
            sync_interval: account
                .sync_interval
                .unwrap_or(self.sync_interval),
            pinentry: account
                .pinentry
                .clone()
                .unwrap_or_else(|| self.pinentry.clone()),
            client_cert_path: account
                .client_cert_path
                .clone()
                .or_else(|| self.client_cert_path.clone()),
            touchid: account.touchid.unwrap_or(self.touchid),
            yubikey: account.yubikey.unwrap_or(self.yubikey),
            yubikey_uv: account.yubikey_uv.unwrap_or(self.yubikey_uv),
            passkey_login: account
                .passkey_login
                .unwrap_or(self.passkey_login),
            device_id: self.device_id.clone(),
        }
    }

    pub fn effective_active_account_name(&self) -> Option<String> {
        if !self.accounts.is_empty() {
            if let Some(active) = &self.active_account
                && self.accounts.contains_key(active)
            {
                return Some(active.clone());
            }
            return self.accounts.keys().next().cloned();
        }
        if self.has_legacy_account() {
            return Some(self.legacy_account_name());
        }
        None
    }

    pub fn entries(&self) -> Vec<AccountEntry> {
        if !self.accounts.is_empty() {
            let active_name = self.effective_active_account_name();
            return self
                .accounts
                .iter()
                .map(|(name, account)| AccountEntry {
                    name: name.clone(),
                    config: self.resolve_account_config(account),
                    active: active_name.as_deref() == Some(name.as_str()),
                    is_legacy: false,
                })
                .collect();
        }
        if self.has_legacy_account() {
            return vec![AccountEntry {
                name: self.legacy_account_name(),
                config: self.resolve_legacy_config(),
                active: true,
                is_legacy: true,
            }];
        }
        Vec::new()
    }

    pub fn resolve_matches(&self, selector: &str) -> Vec<AccountEntry> {
        let entries = self.entries();
        if entries.is_empty() {
            return Vec::new();
        }

        // 1. Exact account name match
        if let Some(entry) = entries.iter().find(|e| e.name == selector) {
            return vec![entry.clone()];
        }

        // 2. Case-insensitive account name match
        let ci_name: Vec<_> = entries
            .iter()
            .filter(|e| e.name.eq_ignore_ascii_case(selector))
            .cloned()
            .collect();
        if !ci_name.is_empty() {
            return ci_name;
        }

        // 3. Exact `<email>@<server_display>` or `<email>:<server_display>`
        let composite: Vec<_> = entries
            .iter()
            .filter(|e| {
                let Some(email) = e.config.email.as_deref() else {
                    return false;
                };
                let server = e.config.server_display_name();
                format!("{email}@{server}").eq_ignore_ascii_case(selector)
                    || format!("{email}:{server}")
                        .eq_ignore_ascii_case(selector)
            })
            .cloned()
            .collect();
        if !composite.is_empty() {
            return composite;
        }

        // 4. Exact email match (case-insensitive)
        let by_email: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.config
                    .email
                    .as_deref()
                    .is_some_and(|em| em.eq_ignore_ascii_case(selector))
            })
            .cloned()
            .collect();
        if !by_email.is_empty() {
            return by_email;
        }

        // 5. Server display name or normalized URL match
        let selector_server_key =
            canonical_server_key(normalize_server_input(selector).as_deref());
        let by_server: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.config
                    .server_display_name()
                    .eq_ignore_ascii_case(selector)
                    || canonical_server_key(e.config.base_url.as_deref())
                        == selector_server_key
            })
            .cloned()
            .collect();
        if !by_server.is_empty() {
            return by_server;
        }

        Vec::new()
    }

    pub fn find_by_filters(
        &self,
        selector: Option<&str>,
        email: Option<&str>,
        server: Option<&str>,
    ) -> Vec<AccountEntry> {
        let mut candidates = selector
            .map_or_else(|| self.entries(), |sel| self.resolve_matches(sel));

        if let Some(email_filter) = email {
            candidates.retain(|e| {
                e.config
                    .email
                    .as_deref()
                    .is_some_and(|em| em.eq_ignore_ascii_case(email_filter))
            });
        }

        if let Some(server_filter) = server {
            let filter_key = canonical_server_key(
                normalize_server_input(server_filter).as_deref(),
            );
            candidates.retain(|e| {
                e.config
                    .server_display_name()
                    .eq_ignore_ascii_case(server_filter)
                    || canonical_server_key(e.config.base_url.as_deref())
                        == filter_key
            });
        }

        candidates
    }

    pub fn resolve_config(
        &self,
        selector: Option<&str>,
    ) -> Result<(Option<String>, Config)> {
        if let Some(sel) = selector {
            let matches = self.resolve_matches(sel);
            return match matches.as_slice() {
                [] => Err(Error::AccountNotFound {
                    account: sel.to_string(),
                }),
                [entry] => {
                    Ok((Some(entry.name.clone()), entry.config.clone()))
                }
                many => Err(Error::AccountAmbiguous {
                    selector: sel.to_string(),
                    matches: format_account_matches(many),
                }),
            };
        }

        if !self.accounts.is_empty() {
            let Some(active) = self.effective_active_account_name() else {
                return Err(Error::NoAccountsConfigured);
            };
            let account = &self.accounts[&active];
            return Ok((Some(active), self.resolve_account_config(account)));
        }

        Ok((None, self.resolve_legacy_config()))
    }

    pub fn find_by_key(
        &self,
        key: &AccountKey,
    ) -> Option<(Option<String>, Config)> {
        self.entries().into_iter().find_map(|entry| {
            if entry.config.account_key().as_ref() == Some(key) {
                Some(((!entry.is_legacy).then_some(entry.name), entry.config))
            } else {
                None
            }
        })
    }

    pub fn suggest_account_name(
        &self,
        email: &str,
        base_url: Option<&str>,
    ) -> String {
        let server = sanitize_account_name(
            &server_display_name_from_base_url(base_url),
        );
        if !self.accounts.contains_key(&server) {
            return server;
        }
        let with_email = sanitize_account_name(&format!("{email}@{server}"));
        if !self.accounts.contains_key(&with_email) {
            return with_email;
        }
        for idx in 2_u32.. {
            let candidate = format!("{with_email}-{idx}");
            if !self.accounts.contains_key(&candidate) {
                return candidate;
            }
        }
        unreachable!()
    }

    pub fn find_duplicate_identity(
        &self,
        ignore_name: Option<&str>,
        base_url: Option<&str>,
        email: Option<&str>,
    ) -> Option<String> {
        let email = email.map(str::trim).filter(|e| !e.is_empty())?;
        let target_server = canonical_server_key(base_url);
        let target_email = email.to_ascii_lowercase();
        for entry in self.entries() {
            if ignore_name == Some(entry.name.as_str()) {
                continue;
            }
            if let Some(existing_email) = entry.config.email.as_deref()
                && existing_email.trim().to_ascii_lowercase() == target_email
                && canonical_server_key(entry.config.base_url.as_deref())
                    == target_server
            {
                return Some(entry.name);
            }
        }
        None
    }

    pub fn check_duplicate_identity(
        &self,
        ignore_name: Option<&str>,
        base_url: Option<&str>,
        email: Option<&str>,
    ) -> Result<()> {
        if let Some(existing) =
            self.find_duplicate_identity(ignore_name, base_url, email)
        {
            return Err(Error::AccountDuplicateIdentity {
                email: email.unwrap_or_default().trim().to_string(),
                server: server_display_name_from_base_url(base_url),
                existing,
            });
        }
        Ok(())
    }

    pub fn add_account(
        &mut self,
        name: Option<&str>,
        account: AccountConfig,
        set_active: bool,
    ) -> Result<String> {
        let Some(email) = account
            .email
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
        else {
            return Err(Error::ConfigMissingEmail);
        };

        self.migrate_legacy_if_needed();

        let final_name = match name {
            Some(name) => {
                validate_account_name(name)?;
                if self.accounts.contains_key(name) {
                    return Err(Error::AccountAlreadyExists {
                        account: name.to_string(),
                    });
                }
                name.to_string()
            }
            None => {
                self.suggest_account_name(email, account.base_url.as_deref())
            }
        };

        self.check_duplicate_identity(
            None,
            account.base_url.as_deref(),
            Some(email),
        )?;

        self.accounts.insert(final_name.clone(), account);
        if set_active || self.active_account.is_none() {
            self.active_account = Some(final_name.clone());
        }
        Ok(final_name)
    }

    pub fn switch_account(&mut self, name: &str) -> Result<bool> {
        if self.has_legacy_account() {
            let legacy_name = self.legacy_account_name();
            if legacy_name == name {
                self.migrate_legacy_if_needed();
                return Ok(false);
            }
            return Err(Error::AccountNotFound {
                account: name.to_string(),
            });
        }
        if !self.accounts.contains_key(name) {
            return Err(Error::AccountNotFound {
                account: name.to_string(),
            });
        }
        let changed =
            self.effective_active_account_name().as_deref() != Some(name);
        self.active_account = Some(name.to_string());
        Ok(changed)
    }

    pub fn remove_account(
        &mut self,
        name: &str,
    ) -> Result<(Config, Option<String>)> {
        if !self.accounts.is_empty() {
            let Some(account) = self.accounts.get(name) else {
                return Err(Error::AccountNotFound {
                    account: name.to_string(),
                });
            };
            let removed_config = self.resolve_account_config(account);
            self.accounts.remove(name);
            if self.active_account.as_deref() == Some(name) {
                self.active_account = self.accounts.keys().next().cloned();
            }
            return Ok((removed_config, self.active_account.clone()));
        }

        if self.has_legacy_account() && self.legacy_account_name() == name {
            let removed_config = self.resolve_legacy_config();
            self.email = None;
            self.sso_id = None;
            self.base_url = None;
            self.identity_url = None;
            self.ui_url = None;
            self.notifications_url = None;
            self.client_cert_path = None;
            return Ok((removed_config, None));
        }

        Err(Error::AccountNotFound {
            account: name.to_string(),
        })
    }

    pub fn rename_account(&mut self, old: &str, new: &str) -> Result<()> {
        validate_account_name(new)?;
        self.migrate_legacy_if_needed();

        if old == new {
            if !self.accounts.contains_key(old) {
                return Err(Error::AccountNotFound {
                    account: old.to_string(),
                });
            }
            return Ok(());
        }

        if self.accounts.contains_key(new) {
            return Err(Error::AccountAlreadyExists {
                account: new.to_string(),
            });
        }

        let Some(account) = self.accounts.remove(old) else {
            return Err(Error::AccountNotFound {
                account: old.to_string(),
            });
        };
        self.accounts.insert(new.to_string(), account);
        if self.active_account.as_deref() == Some(old) {
            self.active_account = Some(new.to_string());
        }
        Ok(())
    }
}

pub fn format_account_matches(matches: &[AccountEntry]) -> String {
    matches
        .iter()
        .map(|entry| {
            let email = entry.config.email.as_deref().unwrap_or("<no email>");
            let server = entry.config.server_display_name();
            format!("{} ({email} @ {server})", entry.name)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        Self::load_account(None)
    }

    pub fn load_account(account: Option<&str>) -> Result<Self> {
        let (_, config) = Self::resolve_account(account)?;
        Ok(config)
    }

    pub fn resolve_account(
        account: Option<&str>,
    ) -> Result<(Option<String>, Self)> {
        let file = ConfigFile::load()?;
        file.resolve_config(account)
    }

    pub async fn load_async() -> Result<Self> {
        Self::load_account_async(None).await
    }

    pub async fn load_account_async(account: Option<&str>) -> Result<Self> {
        let (_, config) = Self::resolve_account_async(account).await?;
        Ok(config)
    }

    pub async fn resolve_account_async(
        account: Option<&str>,
    ) -> Result<(Option<String>, Self)> {
        let file = ConfigFile::load_async().await?;
        file.resolve_config(account)
    }

    pub fn save(&self) -> Result<()> {
        let file = ConfigFile {
            email: self.email.clone(),
            sso_id: self.sso_id.clone(),
            base_url: self.base_url.clone(),
            identity_url: self.identity_url.clone(),
            ui_url: self.ui_url.clone(),
            notifications_url: self.notifications_url.clone(),
            lock_timeout: self.lock_timeout,
            sync_interval: self.sync_interval,
            pinentry: self.pinentry.clone(),
            client_cert_path: self.client_cert_path.clone(),
            touchid: self.touchid,
            yubikey: self.yubikey,
            yubikey_uv: self.yubikey_uv,
            passkey_login: self.passkey_login,
            device_id: self.device_id.clone(),
            active_account: None,
            accounts: BTreeMap::new(),
        };
        file.save()
    }

    pub fn validate() -> Result<()> {
        Self::validate_account(None)
    }

    pub fn validate_account(account: Option<&str>) -> Result<()> {
        let config = Self::load_account(account)?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://api.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/api")
                }
            },
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            )
        })
    }

    pub fn ui_url(&self) -> String {
        self.ui_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            )
        })
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            )
        })
    }

    pub fn client_cert_path(&self) -> Option<&std::path::Path> {
        self.client_cert_path.as_deref()
    }

    pub fn server_name(&self) -> String {
        server_name_from_base_url(self.base_url.as_deref())
    }

    pub fn server_display_name(&self) -> String {
        server_display_name_from_base_url(self.base_url.as_deref())
    }

    pub fn account_key(&self) -> Option<AccountKey> {
        self.email.as_ref().map(|email| AccountKey {
            server: self.server_name(),
            email: email.clone(),
        })
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
            || uuid::Uuid::new_v4().hyphenated().to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_touchid_serde() {
        let old_json = r#"{"email":"user@example.com"}"#;
        let config: Config = serde_json::from_str(old_json).unwrap();
        assert!(!config.touchid);
        assert!(!config.yubikey);
        assert!(!config.yubikey_uv);
        assert!(!config.passkey_login);

        let enabled_json = r#"{"email":"user@example.com","touchid":true,"yubikey":true,"yubikey_uv":true,"passkey_login":true}"#;
        let config: Config = serde_json::from_str(enabled_json).unwrap();
        assert!(config.touchid);
        assert!(config.yubikey);
        assert!(config.yubikey_uv);
        assert!(config.passkey_login);

        let serialized = serde_json::to_string(&config).unwrap();
        assert!(serialized.contains("\"touchid\":true"));
        assert!(serialized.contains("\"yubikey\":true"));
        assert!(serialized.contains("\"yubikey_uv\":true"));
        assert!(serialized.contains("\"passkey_login\":true"));
    }

    #[test]
    fn test_legacy_config_compat_and_migration() {
        let legacy_json = r#"{
            "email": "dat.nguyen@bitbytelab.io",
            "base_url": "https://vault.nullbyte.ninja/",
            "lock_timeout": 1800,
            "touchid": true
        }"#;
        let mut cf =
            ConfigFile::from_json(legacy_json, "config.json".into()).unwrap();
        assert!(cf.has_legacy_account());
        assert!(!cf.is_multi_account());

        let (name, resolved) = cf.resolve_config(None).unwrap();
        assert!(name.is_none());
        assert_eq!(
            resolved.email.as_deref(),
            Some("dat.nguyen@bitbytelab.io")
        );
        // Verbatim base_url preserved for legacy DB & keychain compatibility
        assert_eq!(
            resolved.base_url.as_deref(),
            Some("https://vault.nullbyte.ninja/")
        );
        assert_eq!(resolved.server_display_name(), "vault.nullbyte.ninja");
        assert_eq!(resolved.lock_timeout, 1800);
        assert!(resolved.touchid);

        // Duplicate detection catches legacy account even before migration
        assert_eq!(
            cf.find_duplicate_identity(
                None,
                Some("https://vault.nullbyte.ninja"),
                Some("dat.nguyen@bitbytelab.io"),
            )
            .as_deref(),
            Some("vault.nullbyte.ninja")
        );
        assert!(
            cf.find_duplicate_identity(
                None,
                None,
                Some("dat.nguyen@bitbytelab.io"),
            )
            .is_none()
        );

        // Adding a second account with the SAME email on bitwarden.com
        let added = cf
            .add_account(
                None,
                AccountConfig {
                    email: Some("dat.nguyen@bitbytelab.io".to_string()),
                    base_url: normalize_server_input("bitwarden.com"),
                    passkey_login: Some(true),
                    ..AccountConfig::default()
                },
                true,
            )
            .unwrap();
        assert_eq!(added, "bitwarden.com");
        assert!(cf.is_multi_account());
        assert!(cf.email.is_none());
        assert!(cf.base_url.is_none());
        assert_eq!(cf.active_account.as_deref(), Some("bitwarden.com"));

        // Migrated legacy account still preserves verbatim base_url and global defaults
        let (migrated_name, migrated_cfg) =
            cf.resolve_config(Some("vault.nullbyte.ninja")).unwrap();
        assert_eq!(migrated_name.as_deref(), Some("vault.nullbyte.ninja"));
        assert_eq!(
            migrated_cfg.base_url.as_deref(),
            Some("https://vault.nullbyte.ninja/")
        );
        assert_eq!(migrated_cfg.lock_timeout, 1800);
        assert!(migrated_cfg.touchid);
        assert!(!migrated_cfg.passkey_login);

        // New account inherits global touchid/lock_timeout and overrides passkey_login
        let (active_name, active_cfg) = cf.resolve_config(None).unwrap();
        assert_eq!(active_name.as_deref(), Some("bitwarden.com"));
        assert!(active_cfg.base_url.is_none());
        assert_eq!(active_cfg.server_name(), "default");
        assert_eq!(active_cfg.lock_timeout, 1800);
        assert!(active_cfg.touchid);
        assert!(active_cfg.passkey_login);

        // Distinct AccountKeys despite identical email
        assert_ne!(migrated_cfg.account_key(), active_cfg.account_key());
    }

    #[test]
    fn test_duplicate_identity_and_selector_resolution() {
        let mut cf = ConfigFile::new();
        cf.add_account(
            Some("nullbyte"),
            AccountConfig {
                email: Some("dat.nguyen@bitbytelab.io".to_string()),
                base_url: normalize_server_input("vault.nullbyte.ninja"),
                ..AccountConfig::default()
            },
            true,
        )
        .unwrap();
        cf.add_account(
            Some("bw"),
            AccountConfig {
                email: Some("dat.nguyen@bitbytelab.io".to_string()),
                base_url: normalize_server_input(
                    "https://vault.bitwarden.com",
                ),
                ..AccountConfig::default()
            },
            false,
        )
        .unwrap();

        // Duplicate (server, email) with URL variants rejected
        let dup = cf.add_account(
            Some("bw2"),
            AccountConfig {
                email: Some("DAT.NGUYEN@BITBYTELAB.IO".to_string()),
                base_url: None,
                ..AccountConfig::default()
            },
            false,
        );
        assert!(matches!(dup, Err(Error::AccountDuplicateIdentity { .. })));

        let dup_self_hosted = cf.add_account(
            Some("nb2"),
            AccountConfig {
                email: Some("dat.nguyen@bitbytelab.io".to_string()),
                base_url: Some("https://vault.nullbyte.ninja/".to_string()),
                ..AccountConfig::default()
            },
            false,
        );
        assert!(matches!(
            dup_self_hosted,
            Err(Error::AccountDuplicateIdentity { .. })
        ));

        // Ambiguous email selector
        let ambig = cf.resolve_config(Some("dat.nguyen@bitbytelab.io"));
        assert!(matches!(ambig, Err(Error::AccountAmbiguous { .. })));

        // Disambiguated via alias, host, or email@host
        assert_eq!(
            cf.resolve_config(Some("bw")).unwrap().0.as_deref(),
            Some("bw")
        );
        assert_eq!(
            cf.resolve_config(Some("bitwarden.com"))
                .unwrap()
                .0
                .as_deref(),
            Some("bw")
        );
        assert_eq!(
            cf.resolve_config(Some(
                "dat.nguyen@bitbytelab.io@vault.nullbyte.ninja"
            ))
            .unwrap()
            .0
            .as_deref(),
            Some("nullbyte")
        );
        assert_eq!(
            cf.find_by_filters(
                None,
                Some("dat.nguyen@bitbytelab.io"),
                Some("bitwarden.com")
            )
            .len(),
            1
        );
    }

    #[test]
    fn test_switch_rename_remove_and_atomic_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let mut cf = ConfigFile::new();
        cf.add_account(
            Some("a"),
            AccountConfig {
                email: Some("a@example.com".to_string()),
                ..AccountConfig::default()
            },
            true,
        )
        .unwrap();
        cf.add_account(
            Some("b"),
            AccountConfig {
                email: Some("b@example.com".to_string()),
                base_url: normalize_server_input("eu"),
                ..AccountConfig::default()
            },
            false,
        )
        .unwrap();

        assert!(!cf.switch_account("a").unwrap());
        assert!(cf.switch_account("b").unwrap());
        assert_eq!(cf.active_account.as_deref(), Some("b"));

        cf.rename_account("b", "eu-work").unwrap();
        assert_eq!(cf.active_account.as_deref(), Some("eu-work"));
        assert!(cf.accounts.contains_key("eu-work"));
        assert!(!cf.accounts.contains_key("b"));

        cf.save_to_path(&path).unwrap();
        let mode =
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let loaded = ConfigFile::load_from_path(&path).unwrap();
        assert_eq!(loaded.active_account.as_deref(), Some("eu-work"));
        assert_eq!(loaded.accounts.len(), 2);

        // Removing active account promotes remaining account
        let mut loaded = loaded;
        let (removed_cfg, next_active) =
            loaded.remove_account("eu-work").unwrap();
        assert_eq!(removed_cfg.email.as_deref(), Some("b@example.com"));
        assert_eq!(next_active.as_deref(), Some("a"));
        assert_eq!(loaded.active_account.as_deref(), Some("a"));
    }

    #[test]
    fn test_server_normalization_and_display() {
        assert_eq!(normalize_server_input("bitwarden.com"), None);
        assert_eq!(
            normalize_server_input("https://vault.bitwarden.com/"),
            None
        );
        assert_eq!(
            normalize_server_input("eu").as_deref(),
            Some("https://api.bitwarden.eu")
        );
        assert_eq!(
            normalize_server_input("vault.nullbyte.ninja/").as_deref(),
            Some("https://vault.nullbyte.ninja")
        );
        assert_eq!(server_display_name_from_base_url(None), "bitwarden.com");
        assert_eq!(
            server_display_name_from_base_url(Some(
                "https://api.bitwarden.eu"
            )),
            "bitwarden.eu"
        );
        assert_eq!(
            server_display_name_from_base_url(Some(
                "https://vault.nullbyte.ninja:8443/bw/"
            )),
            "vault.nullbyte.ninja:8443/bw"
        );
        assert!(validate_account_name("work-1_foo@bar.com").is_ok());
        assert!(validate_account_name("").is_err());
        assert!(validate_account_name("has space").is_err());
        assert!(validate_account_name("a/b").is_err());
    }
}
