#![cfg(feature = "pin")]
use crate::config::Config;
use crate::error::Error;
use crate::locked::{Keys, Password, Vec};
use crate::pin::backend::{Backend, PinBackend, PinState};
use crate::pin::crypto::Argon2Params;
use crate::{dirs, error, pin};
use anyhow::Context;
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;

pub fn status() -> anyhow::Result<()> {
    let state_exists =
        std::fs::exists(dirs::pin_state_file()).is_ok_and(|b| b);

    let enabled_msg = format!("Pin enabled: {state_exists}");

    let mut backend_msg = String::new();
    if let Ok(pin_state) = load_pin_state() {
        let backend = pin_state.backend;
        let backend_name = match backend {
            Backend::Age => "age",
            Backend::OSKeyring => "keyring",
        };
        backend_msg.push_str(format!("Backend: {backend_name}").as_str());
    }
    let parts = [enabled_msg, backend_msg];
    let msg = parts.join("\n");
    println!("{msg}");
    Ok(())
}

pub fn unlock_with_pin(
    pin: Option<&Password>,
    pin_state: &PinState,
    config: Config,
) -> error::Result<(Keys, HashMap<String, Keys>)> {
    let (wrapped_key, wrapped_org_keys, salt, kdf_params, _, backend) =
        pin_state.unpack().map_err(|_| Error::PinError {
            message: "couldn't deserialize pin state".into(),
        })?;

    let pin_config = config.pin_config.ok_or_else(|| Error::PinError {
        message: "pin config not set".to_string(),
    })?;
    let local_secret =
        backend.retrieve_local_secret(&pin_config).map_err(|e| {
            Error::PinError {
                message: format!("couldn't retrieve local secret: {}", e).into(),
            }
        })?;

    let kek = pin::crypto::derive_kek_from_pin(
        pin,
        &local_secret,
        &salt,
        &kdf_params,
    )?;

    let (keys, org_keys) =
        pin::crypto::unwrap_dek(&kek, &wrapped_key, &wrapped_org_keys)?;

    Ok((keys, org_keys))
}

pub fn register<S: ::std::hash::BuildHasher>(
    keys: &Keys,
    org_keys: &HashMap<String, Keys, S>,
    pin: Option<&Password>,
    config: &Config,
    backend: Backend,
) -> anyhow::Result<()> {
    let pin_config = config
        .pin_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Pin Config not set"))?;

    pin_config
        .enable_pin
        .then_some(())
        .ok_or_else(|| anyhow::anyhow!("enable_pin not set in config"))?;

    let local_secret = generate_local_secret(OsRng);
    backend.store_local_secret(&local_secret, pin_config)?;

    let default_kdf_params = Argon2Params::new();
    let kdf_params = if let Some(pin_config) = config.pin_config.as_ref() {
        &pin_config.kdf_params.clone().unwrap_or(default_kdf_params)
    } else {
        &default_kdf_params
    };

    let salt = SaltString::generate(&mut OsRng);
    let kek = pin::crypto::derive_kek_from_pin(
        pin,
        &local_secret,
        &salt,
        kdf_params,
    )?;

    let (wrapped_keys, wrapped_org_keys) =
        pin::crypto::wrap_dek(&kek, keys, org_keys)?;

    let state_to_save = PinState::new(
        wrapped_keys,
        wrapped_org_keys,
        &salt,
        kdf_params.clone(),
        pin.is_none(),
        backend,
    )?;

    state_to_save.write_to_file(dirs::pin_state_file())?;

    Ok(())
}

pub fn clear() -> anyhow::Result<()> {
    // Try to clear the secret if we can read the state.
    if let Ok(state) = load_pin_state().context("reading pin state file") {
        state
            .backend
            .clear_local_secret()
            .context("clearing local secret")?;
    }

    match std::fs::remove_file(dirs::pin_state_file()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing pin state file"),
    }
}

pub fn empty_pin() -> bool {
    load_pin_state().map(|s| s.empty_pin).unwrap_or(false)
}

// simply generate 32 bytes
fn generate_local_secret<T: RngCore + CryptoRng>(mut rng: T) -> Vec {
    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(0, 32));
    rng.fill_bytes(buf.data_mut());
    buf
}

pub fn load_pin_state() -> anyhow::Result<PinState> {
    let pin_state = PinState::read_from_file(dirs::pin_state_file())?;

    Ok(pin_state)
}
