#![cfg(feature = "pin")]
/*
This module implements cryptography operations relating to the PIN feature.

PIN cryptography: derive a key-encryption key (KEK) from a user PIN and wrap/unwrap the
per-profile data-encryption keys (DEKs).

# Overview
This module enables an optional low-entropy PIN to protect the locally-stored DEK material.
A KEK is derived using Argon2id from:
- the user PIN (may be absent),
- a device-local secret (`local_secret`) mixed in as an Argon2 "secret",
- a random salt,
- and caller-supplied Argon2 parameters.

The derived KEK (32 bytes) is then used with XChaCha20-Poly1305 to wrap (`encrypt_in_place`) the
DEK bytes (concatenated `enc_key || mac_key`). The AEAD additional authenticated data (AAD) is
a `context` string that binds the wrapped keys to the intended profile (and org, for org keys).

# Threat model / security properties
- Protects DEK material at rest against an attacker who reads storage but does not know the PIN.
- The `local_secret` strengthens the construction by device-binding the KDF input. Offline
  guessing is infeasible without this secret.
*/
use crate::error::{Error, Result};
use crate::locked::{Keys, Password, Vec};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2,
};
use std::collections::HashMap;

use chacha20poly1305::{
    aead::{AeadCore, Buffer, KeyInit},
    AeadInPlace, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};

pub const KEK_LEN: usize = 32;

#[derive(Serialize, Deserialize, Clone)]
pub struct WrappedKey {
    #[serde(with = "base64")]
    wrapped_keys: std::vec::Vec<u8>,
    #[serde(with = "base64")]
    nonce: [u8; 24],
    // Bind the key to the correct profile
    context: String,
}

impl WrappedKey {
    pub fn bytes(&self) -> &[u8] {
        self.wrapped_keys.as_slice()
    }
    pub fn new(wrapped_keys: std::vec::Vec<u8>, nonce: XNonce, context: String) -> Self {
        Self {
            wrapped_keys,
            nonce: (*nonce.as_slice()).try_into().expect("XNonce is defined to be 24 bytes"),
            context,
        }
    }
    fn nonce(&self) -> XNonce {
        (self.nonce).into()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Argon2Params {
    #[serde(rename = "argon2_memory")]
    pub memory: u32,
    #[serde(rename = "argon2_iterations")]
    pub iterations: u32,
    #[serde(rename = "argon2_parallelism")]
    pub parallelism: u32,
}

impl Argon2Params {
    pub fn new() -> Self {
        Self {
            memory: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
    pub fn to_params(&self) -> Result<argon2::Params> {
        argon2::Params::new(
            self.memory,
            self.iterations,
            self.parallelism,
            Some(KEK_LEN), // Size of the derived key
        )
        .map_err(|_| Error::Argon2)
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::new()
    }
}

pub fn derive_kek_from_pin(
    pin: Option<&Password>,
    local_secret: &Vec,
    salt: &SaltString,
    kdf_params: &Argon2Params,
) -> Result<Vec> {
    let argon2_config = Argon2::new_with_secret(
        local_secret.data(),
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        kdf_params.to_params()?,
    )
    .map_err(|_| Error::Argon2)?;

    let mut pin_key = Vec::new();
    pin_key.extend(std::iter::repeat_n(0, KEK_LEN));

    Argon2::hash_password_into(
        &argon2_config,
        pin.as_ref().map_or(&[], |pin| pin.password()),
        salt.as_str().as_bytes(),
        pin_key.data_mut(),
    )
    .map_err(|_| Error::Argon2)?;

    Ok(pin_key)
}

fn wrap_single_key(
    cipher: &XChaCha20Poly1305,
    keys: &Keys,
    context: &String,
) -> Result<WrappedKey> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = {
        let mut buf = Vec::new();
        buf.extend(keys.enc_key().iter().copied());
        buf.extend(keys.mac_key().iter().copied());

        cipher
            .encrypt_in_place(&nonce, context.as_bytes(), &mut buf)
            .map_err(|e| Error::PinError {
                message: e.to_string(),
            })?;

        buf.data().to_vec()
    };

    Ok(WrappedKey::new(ciphertext, nonce, context.to_owned()))
}
pub fn wrap_dek<S: ::std::hash::BuildHasher>(
    pin_key: &Vec,
    keys: &Keys,
    org_keys: &HashMap<String, Keys, S>,
) -> Result<(WrappedKey, HashMap<String, WrappedKey>)> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(pin_key.data()).map_err(|_| {
            Error::PinError {
                message: "Kek has invalid length".to_string(),
            }
        })?;

    let context_string =
        format!("pin-wrapped-dek|profile={}", crate::dirs::profile());
    let wrapped_keys = wrap_single_key(&cipher, keys, &context_string)?;

    let wrapped_org_keys: HashMap<String, WrappedKey> = org_keys
        .iter()
        .map(|(org, k)| {
            let context_string_org =
                format!("{}|org={}", context_string.clone(), org.as_str());
            wrap_single_key(&cipher, k, &context_string_org)
                .map(|wk| (org.clone(), wk))
        })
        .collect::<std::result::Result<_, Error>>()?;

    Ok((wrapped_keys, wrapped_org_keys))
}

// Need to implement the below traits
// in order to decrypt in place (to not have to allocate secret to an insecure buffer)
impl AsRef<[u8]> for Vec {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsMut<[u8]> for Vec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}
impl Buffer for Vec {
    fn extend_from_slice(
        &mut self,
        other: &[u8],
    ) -> chacha20poly1305::aead::Result<()> {
        self.extend(other.iter().copied());
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.truncate(len);
    }
}

fn unwrap_single_key(
    cipher: &XChaCha20Poly1305,
    wrapped_keys: &WrappedKey,
) -> Result<Keys> {
    let mut key = Vec::new();
    key.extend(wrapped_keys.bytes().to_vec().into_iter());

    cipher
        .decrypt_in_place(
            &wrapped_keys.nonce(),
            wrapped_keys.context.as_bytes(),
            &mut key,
        )
        .map_err(|_| Error::IncorrectPassword {
            message: "incorrect pin".to_string(),
        })?;

    Ok(Keys::new(key))
}

pub fn unwrap_dek<S: ::std::hash::BuildHasher>(
    pin_key: &Vec,
    wrapped_keys: &WrappedKey,
    wrapped_org_keys: &HashMap<String, WrappedKey, S>,
) -> Result<(Keys, HashMap<String, Keys>)> {
    let cipher = XChaCha20Poly1305::new_from_slice(pin_key.data()).map_err(
        |_| Error::PinError {
            message:
                "invalid keylen; couldn't initialize chacha20poly1305 cipher"
                    .into(),
        },
    )?;

    let keys = unwrap_single_key(&cipher, wrapped_keys)?;

    let wrapped_org_keys: HashMap<String, Keys> = wrapped_org_keys
        .iter()
        .map(|(org, k)| {
            unwrap_single_key(&cipher, k).map(|wk| (org.clone(), wk))
        })
        .collect::<std::result::Result<_, Error>>()?;

    Ok((keys, wrapped_org_keys))
}

// Enables serde to (de)serialize with base64
mod base64 {
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(
        v: &T,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let base64 = crate::base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
    {
        let base64 = String::deserialize(d)?;

        let bytes: Vec<u8> = crate::base64::decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)?;

        T::try_from(bytes).map_err(|_e| {
            serde::de::Error::custom("Error deserializing pin state")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_vec(bytes: &[u8]) -> Vec {
        let mut vec = Vec::new();
        vec.extend(bytes.iter().copied());
        vec
    }

    fn concat_key_bytes(a: &[u8], b: &[u8]) -> zeroize::Zeroizing<std::vec::Vec<u8>> {
        let mut out =
            zeroize::Zeroizing::new(std::vec::Vec::with_capacity(a.len() + b.len()));
        out.extend_from_slice(a);
        out.extend_from_slice(b);
        out
    }

    #[test]
    fn pin_encrypt_decrypt() {
        let key_content = [b'0'; 64];
        let dek = Keys::new(create_vec(&key_content));

        let org_keys: HashMap<String, Keys> =
            [("test_corp".to_string(), dek.clone())]
                .into_iter()
                .collect();

        let pin = Password::new(create_vec(b"1234".as_ref()));
        let local_secret = create_vec([b'0'; 32].as_ref());
        let salt = SaltString::generate(&mut OsRng);
        let kdf_params = Argon2Params {
            memory: 128,
            iterations: 1,
            parallelism: 1,
        };
        let derived_kek = derive_kek_from_pin(
            Some(&pin),
            &local_secret,
            &salt,
            &kdf_params,
        )
        .unwrap();

        let (wrapped_dek, wrapped_org_keys) =
            wrap_dek(&derived_kek, &dek, &org_keys).unwrap();

        let (key_to_test, org_keys_to_test) =
            unwrap_dek(&derived_kek, &wrapped_dek, &wrapped_org_keys)
                .unwrap();

        let key_to_test_raw =
            concat_key_bytes(key_to_test.enc_key(), key_to_test.mac_key());
        assert_eq!(key_to_test_raw.as_slice(), &key_content);

        let key_to_test_raw2 = {
            let key = org_keys_to_test.get("test_corp").unwrap();
            concat_key_bytes(key.enc_key(), key.mac_key())
        };
        assert_eq!(key_to_test_raw2.as_slice(), &key_content)
    }
}
