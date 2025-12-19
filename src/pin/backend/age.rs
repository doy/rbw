use std::fs;
use std::io::{BufReader, Read, Write};

use crate::dirs;
use crate::locked::Vec;
use crate::pin;
use crate::pin::backend::{BackendConfig, PinBackend};
use age::{plugin, Decryptor};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub const SUPPORTED_AGE_PLUGINS: [&str; 3] = [
    "yubikey", // https://github.com/str4d/age-plugin-yubikey
    "tpm",     // https://github.com/Foxboron/age-plugin-tpm
    "se",      // https://github.com/remko/age-plugin-se
];

#[derive(Serialize, Deserialize)]
pub struct AgePinBackend;

#[derive(Serialize, Deserialize, Debug)]
pub struct AgeConfig {
    #[serde(rename = "age_identity_file_path")]
    pub identity_file_path: PathBuf,
}

impl Default for AgeConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl AgeConfig {
    pub fn new() -> Self {
        Self {
            identity_file_path: "".into(),
        }
    }
    fn _validate(&self) -> anyhow::Result<()> {
        match fs::exists::<&PathBuf>(&self.identity_file_path) {
            Ok(_) => Ok(()),
            Err(_) => Err(anyhow!("Age identity file not found")),
        }

        // TODO check if the file is parseable and the plugin is supported
        // this is enough for now
    }
}

impl BackendConfig for AgeConfig {}

impl PinBackend for AgePinBackend {
    type Config = AgeConfig;
    fn retrieve_local_secret(
        &self,
        config: &AgeConfig,
    ) -> anyhow::Result<Vec> {
        let age_file_path = dirs::pin_age_wrapped_local_secret_file();

        let (identity, _) = age_identity(config).context("could not parse age identity")?;
        let reader = BufReader::new(File::open(age_file_path)?);
        let decryptor = Decryptor::new(reader)?;

        // let identities: [&dyn age::Identity; 1] = [&identity.as_ref()];
        let mut decrypted_reader = decryptor
            .decrypt(std::iter::once(identity.as_ref()))
            .context("Failed to decrypt age wrapped local secret")?;

        let mut kek = Vec::new();
        kek.extend(std::iter::repeat_n(0, pin::crypto::KEK_LEN));

        decrypted_reader.read_exact(kek.data_mut())?;

        Ok(kek)
    }


    fn store_local_secret(
        &self,
        local_secret: &Vec,
        config: &AgeConfig,
    ) -> anyhow::Result<()> {
        let (_, recipient) = age_identity(config)?;
        let final_path = dirs::pin_age_wrapped_local_secret_file();
        let parent_dir = final_path.parent().context("No parent dir")?;

        let mut temp_file = tempfile::NamedTempFile::new_in(parent_dir)?;
        fs::set_permissions(temp_file.path(), fs::Permissions::from_mode(0o600))?;

        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient.as_ref()))?;
        
        let mut writer = encryptor.wrap_output(temp_file.as_file_mut())?;
        writer.write_all(local_secret.data())?;
        writer.finish()?;

        temp_file.as_file().sync_all()?;

        // Atomic swap (replaces old file only if everything above succeeded)
        temp_file.persist(final_path).map_err(|e| e.error)?;

        Ok(())
    }

    fn clear_local_secret(&self) -> anyhow::Result<()> {
        fs::remove_file(dirs::pin_age_wrapped_local_secret_file())
            .context("Failed to remove the age wrapped local secret.")?;
        Ok(())
    }
}

fn age_identity(
    config: &pin::backend::age::AgeConfig,
) -> anyhow::Result<(Box<dyn age::Identity>, Box<dyn age::Recipient>)> {
    let age_identity_str = fs::read_to_string(&config.identity_file_path)?;
    let cleaned_string: String = age_identity_str
        .lines()
        .filter(|s| !s.trim_start().starts_with('#'))
        .filter(|s| !s.trim().is_empty())
        .map(str::trim)
        .collect::<std::vec::Vec<_>>()
        .join("\n");

    if let Ok(identity) = cleaned_string.parse::<plugin::Identity>() {
        if SUPPORTED_AGE_PLUGINS.iter().any(|&x| x == identity.plugin()) {
            let id_plugin = plugin::IdentityPluginV1::new(
                identity.plugin(),
                std::slice::from_ref(&identity),
                age::NoCallbacks,
            ).context("Failed to initialize age plugin identity")?;
            
            let rec_plugin = plugin::RecipientPluginV1::new(
                identity.plugin(),
                &[], // no extra recipients
                std::slice::from_ref(&identity),
                age::NoCallbacks,
            ).context("Failed to initialize age plugin recipient")?;

            return Ok((Box::new(id_plugin), Box::new(rec_plugin)));
        }
        anyhow::bail!("Plugin '{}' is not supported", identity.plugin());
    }

    // Fallback parse a regular age identity during tests
    #[cfg(test)]
    {
        if let Ok(standard_id) = cleaned_string.parse::<age::x25519::Identity>() {
            let recipient = standard_id.to_public();
            return Ok((Box::new(standard_id), Box::new(recipient)));
        }
    }

    anyhow::bail!("Invalid age-plugin identity file")
}
#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::Config;

    const TEST_IDENTITY: &str = "AGE-SECRET-KEY-1J6CR00H6EZHNT6R7PP0RM2ADCV2F49Z32XFJLP89VGK6Z4NJRHYQV82S8U";

    fn create_temp_file_of_contents(
        contents: &[u8],
    ) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file
    }

    fn create_vec(bytes: &[u8]) -> crate::locked::Vec {
        let mut vec = crate::locked::Vec::new();
        vec.extend(bytes.iter().copied());
        vec
    }

    #[test]
    fn pin_age_parse_identity_file() {
        let identity_file =
            create_temp_file_of_contents(TEST_IDENTITY.as_bytes());

        let pin_config = pin::backend::PinBackendConfig {
            enable_pin: true,
            keyring: None,
            age: Some(AgeConfig {
                identity_file_path: identity_file.path().into(),
            }),
            kdf_params: Some(pin::crypto::Argon2Params::new()),
        };

        match age_identity(&pin_config.age.unwrap()) {
            Ok(_) => (),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn pin_age_plugin_store_retrieve() {
        let identity_file =
            create_temp_file_of_contents(TEST_IDENTITY.as_bytes());
        let config = Config {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: 60 * 60 * 24,
            sync_interval: 1000,
            pinentry: "".to_string(),
            client_cert_path: None,
            device_id: None,
            pin_config: Some(pin::backend::PinBackendConfig {
                enable_pin: true,
                keyring: None,
                age: Some(AgeConfig {
                    identity_file_path: identity_file.path().into(),
                }),
                kdf_params: Some(pin::crypto::Argon2Params::new()),
            }),
        };

        let dummy_kek = create_vec(&[b'0'; 32]);

        let backend = AgePinBackend;

        let age_config = config.pin_config.unwrap().age.unwrap();

        backend.store_local_secret(&dummy_kek, &age_config).unwrap();

        let decrypted_kek =
            backend.retrieve_local_secret(&age_config).unwrap();

        assert_eq!(decrypted_kek.data(), [b'0'; 32].as_ref())
    }
}
