use crate::prelude::*;

use zeroize::Zeroize as _;

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Attachment {
    #[serde(rename = "Id", alias = "id")]
    pub id: String,
    #[serde(rename = "Url", alias = "url", default)]
    pub url: String,
    #[serde(rename = "FileName", alias = "fileName")]
    pub file_name: String,
    #[serde(rename = "Key", alias = "key")]
    pub key: Option<String>,
    #[serde(rename = "Size", alias = "size")]
    pub size: Option<String>,
}

/// Decrypt an attachment without converting its plaintext into UTF-8.
/// Keys stay inside the agent: user/organization -> item -> attachment.
pub fn decrypt(
    data: &[u8],
    keys: &crate::locked::Keys,
    item_key: Option<&str>,
    attachment_key: Option<&str>,
) -> Result<Vec<u8>> {
    let item_key = item_key.map(|key| decrypt_key(key, keys)).transpose()?;
    let keys = item_key.as_ref().unwrap_or(keys);
    let attachment_key = attachment_key
        .map(|key| decrypt_key(key, keys))
        .transpose()?;
    let keys = attachment_key.as_ref().unwrap_or(keys);

    // Bitwarden's type-2 binary format is type || IV || MAC || ciphertext.
    // Check every slice before indexing, and require a complete AES block.
    if data.len() < 65 || data[0] != 2 || (data.len() - 49) % 16 != 0 {
        return Err(Error::InvalidAttachment {
            reason: "unsupported or truncated encrypted file".to_string(),
        });
    }
    let cipher = crate::cipherstring::CipherString::Symmetric {
        iv: data[1..17].to_vec(),
        mac: Some(data[17..49].to_vec()),
        ciphertext: data[49..].to_vec(),
    };
    cipher.decrypt_symmetric(keys, None)
}

fn decrypt_key(
    key: &str,
    keys: &crate::locked::Keys,
) -> Result<crate::locked::Keys> {
    // Unlike the legacy text parser, wrapped attachment/item keys must be
    // authenticated type-2 cipherstrings with correctly sized components.
    if !key.starts_with("2.") {
        return Err(Error::InvalidAttachment {
            reason: "unsupported wrapped encryption key".to_string(),
        });
    }
    let cipher = crate::cipherstring::CipherString::new(key)?;
    if !matches!(&cipher,
        crate::cipherstring::CipherString::Symmetric { iv, ciphertext, mac: Some(mac) }
        if iv.len() == 16 && mac.len() == 32 && !ciphertext.is_empty() && ciphertext.len() % 16 == 0
    ) {
        return Err(Error::InvalidAttachment {
            reason: "malformed or unauthenticated encryption key".to_string(),
        });
    }
    let mut bytes = cipher.decrypt_symmetric(keys, None)?;
    if bytes.len() != 64 {
        bytes.zeroize();
        return Err(Error::InvalidAttachment {
            reason: "encryption key must contain 64 bytes".to_string(),
        });
    }
    let mut locked = crate::locked::Vec::new();
    locked.extend(bytes.iter().copied());
    bytes.zeroize();
    Ok(crate::locked::Keys::new(locked))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(byte: u8) -> crate::locked::Keys {
        let mut data = crate::locked::Vec::new();
        data.extend(std::iter::repeat_n(byte, 64));
        crate::locked::Keys::new(data)
    }

    fn encrypted(data: &[u8], keys: &crate::locked::Keys) -> Vec<u8> {
        match crate::cipherstring::CipherString::encrypt_symmetric(keys, data)
            .unwrap()
        {
            crate::cipherstring::CipherString::Symmetric {
                iv,
                ciphertext,
                mac,
            } => {
                let mut result = vec![2];
                result.extend(iv);
                result.extend(mac.unwrap());
                result.extend(ciphertext);
                result
            }
            crate::cipherstring::CipherString::Asymmetric { .. } => {
                unreachable!()
            }
        }
    }

    #[test]
    fn personal_legacy_attachment_is_binary_and_can_be_empty() {
        let key = keys(1);
        for bytes in [&[][..], &[0, 255, 128, 0, 10, 13][..]] {
            assert_eq!(
                decrypt(&encrypted(bytes, &key), &key, None, None).unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn item_and_attachment_keys_are_unwrapped_in_order() {
        let org_key = keys(1);
        let item_key = keys(2);
        let attachment_key = keys(3);
        let wrapped_item =
            crate::cipherstring::CipherString::encrypt_symmetric(
                &org_key, &[2; 64],
            )
            .unwrap()
            .to_string();
        let wrapped_attachment =
            crate::cipherstring::CipherString::encrypt_symmetric(
                &item_key, &[3; 64],
            )
            .unwrap()
            .to_string();
        let bytes: Vec<_> = (0..=255).cycle().take(1024 * 1024 + 7).collect();
        let data = encrypted(&bytes, &attachment_key);
        assert_eq!(
            decrypt(
                &data,
                &org_key,
                Some(&wrapped_item),
                Some(&wrapped_attachment)
            )
            .unwrap(),
            bytes
        );
        assert!(decrypt(
            &data,
            &keys(4),
            Some(&wrapped_item),
            Some(&wrapped_attachment)
        )
        .is_err());
        assert!(decrypt(&data, &org_key, None, Some(&wrapped_attachment))
            .is_err());
        assert!(decrypt(&data, &org_key, Some(&wrapped_item), None).is_err());
    }

    #[test]
    fn separate_attachment_key_without_item_key() {
        let key = keys(1);
        let file_key = keys(2);
        let wrapped = crate::cipherstring::CipherString::encrypt_symmetric(
            &key, &[2; 64],
        )
        .unwrap()
        .to_string();
        assert_eq!(
            decrypt(
                &encrypted(b"file", &file_key),
                &key,
                None,
                Some(&wrapped)
            )
            .unwrap(),
            b"file"
        );
    }

    #[test]
    fn malformed_wrapped_keys_return_errors_without_panicking() {
        let key = keys(1);
        let data = encrypted(b"file", &key);
        for len in [0, 1, 31, 32, 63, 65, 80] {
            let wrapped =
                crate::cipherstring::CipherString::encrypt_symmetric(
                    &key,
                    &vec![1; len],
                )
                .unwrap()
                .to_string();
            assert!(
                decrypt(&data, &key, Some(&wrapped), None).is_err(),
                "item key length {len}"
            );
            assert!(
                decrypt(&data, &key, None, Some(&wrapped)).is_err(),
                "attachment key length {len}"
            );
        }
        for wrapped in ["", "\0.", "0.a|b", "2.AA==|AA==|AA==", "2.AA==|AA=="]
        {
            assert!(decrypt(&data, &key, None, Some(wrapped)).is_err());
        }
    }

    #[test]
    fn malformed_and_unauthenticated_files_are_rejected() {
        let key = keys(1);
        let data = encrypted(b"file", &key);
        for end in 0..data.len() {
            assert!(
                decrypt(&data[..end], &key, None, None).is_err(),
                "truncation {end}"
            );
        }
        for index in [0, 1, 16, 17, 48, 49, data.len() - 1] {
            let mut damaged = data.clone();
            damaged[index] ^= 1;
            assert!(
                decrypt(&damaged, &key, None, None).is_err(),
                "corruption {index}"
            );
        }
        let mut trailing = data;
        trailing.push(0);
        assert!(decrypt(&trailing, &key, None, None).is_err());
    }

    #[test]
    fn independent_openssl_vector_preserves_non_utf8_bytes() {
        let mut key = crate::locked::Vec::new();
        key.extend(0..64);
        let key = crate::locked::Keys::new(key);
        let data = crate::base64::decode("AhAREhMUFRYXGBkaGxwdHh9vt+rp1gbWDtTyHF768l/ZniKr/Uba0JJ2rU9Kk+KzfrsximOTSD3cIgSf+zRob58=").unwrap();
        assert_eq!(
            decrypt(&data, &key, None, None).unwrap(),
            [0, 255, 128, 1, 10, 13, 0]
        );
    }

    #[test]
    fn cached_entries_without_attachments_remain_readable() {
        let entry: crate::db::Entry = serde_json::from_value(serde_json::json!({
            "id":"entry", "org_id":null, "folder":null, "folder_id":null,
            "name":"encrypted", "data":"SecureNote", "fields":[],
            "notes":null, "history":[], "key":null, "master_password_reprompt":0
        })).unwrap();
        assert_eq!(entry.attachments, []);
        assert!(serde_json::to_value(entry)
            .unwrap()
            .get("attachments")
            .is_none());
    }
}
