use crate::prelude::*;

use aes::cipher::{
    BlockModeDecrypt as _, BlockModeEncrypt as _, KeyIvInit as _,
};
use hmac::{KeyInit as _, Mac as _};
use pkcs8::DecodePrivateKey as _;
use rand::Rng as _;
use zeroize::Zeroize as _;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AsymmetricAlgorithm {
    // ty: 4 / 6 (RSA_2048_OAEP_SHA1)
    RsaOaepSha1,
    // ty: 3 / 5 (RSA_2048_OAEP_SHA256)
    RsaOaepSha256,
}

pub enum CipherString {
    Symmetric {
        // ty: 2 (AES_256_CBC_HMAC_SHA256)
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Option<Vec<u8>>,
    },
    Asymmetric {
        algorithm: AsymmetricAlgorithm,
        ciphertext: Vec<u8>,
    },
}

impl CipherString {
    pub fn new(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidCipherString {
                reason: "couldn't find type".to_string(),
            });
        }

        let ty = parts[0].as_bytes();
        if ty.len() != 1 {
            return Err(Error::UnimplementedCipherStringType {
                ty: parts[0].to_string(),
            });
        }

        let ty = ty[0] - b'0';
        let contents = parts[1];

        match ty {
            2 => {
                let parts: Vec<&str> = contents.split('|').collect();
                if parts.len() < 2 || parts.len() > 3 {
                    return Err(Error::InvalidCipherString {
                        reason: format!(
                            "type 2 cipherstring with {} parts",
                            parts.len()
                        ),
                    });
                }

                let iv = crate::base64::decode(parts[0])
                    .map_err(|source| Error::InvalidBase64 { source })?;
                let ciphertext = crate::base64::decode(parts[1])
                    .map_err(|source| Error::InvalidBase64 { source })?;
                let mac =
                    if parts.len() > 2 {
                        Some(crate::base64::decode(parts[2]).map_err(
                            |source| Error::InvalidBase64 { source },
                        )?)
                    } else {
                        None
                    };

                Ok(Self::Symmetric {
                    iv,
                    ciphertext,
                    mac,
                })
            }
            3 | 5 => {
                // RSA_2048_OAEP_SHA256 (3) / RSA_2048_OAEP_SHA256_HMAC_SHA256 (5)
                let contents = contents.split('|').next().unwrap();
                let ciphertext = crate::base64::decode(contents)
                    .map_err(|source| Error::InvalidBase64 { source })?;
                Ok(Self::Asymmetric {
                    algorithm: AsymmetricAlgorithm::RsaOaepSha256,
                    ciphertext,
                })
            }
            4 | 6 => {
                // the only difference between 4 and 6 is the HMAC256
                // signature appended at the end
                // https://github.com/bitwarden/jslib/blob/785b681f61f81690de6df55159ab07ae710bcfad/src/enums/encryptionType.ts#L8
                // format is: <cipher_text_b64>|<hmac_sig>
                let contents = contents.split('|').next().unwrap();
                let ciphertext = crate::base64::decode(contents)
                    .map_err(|source| Error::InvalidBase64 { source })?;
                Ok(Self::Asymmetric {
                    algorithm: AsymmetricAlgorithm::RsaOaepSha1,
                    ciphertext,
                })
            }
            _ => {
                if ty < 6 {
                    Err(Error::TooOldCipherStringType { ty: ty.to_string() })
                } else {
                    Err(Error::UnimplementedCipherStringType {
                        ty: ty.to_string(),
                    })
                }
            }
        }
    }

    pub fn encrypt_symmetric(
        keys: &crate::locked::Keys,
        plaintext: &[u8],
    ) -> Result<Self> {
        let iv = random_iv();

        let cipher = cbc::Encryptor::<aes::Aes256>::new_from_slices(
            keys.enc_key(),
            &iv,
        )
        .map_err(|source| Error::CreateBlockMode { source })?;
        let ciphertext =
            cipher.encrypt_padded_vec::<block_padding::Pkcs7>(plaintext);

        let mut digest =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(keys.mac_key())
                .map_err(|source| Error::CreateHmac { source })?;
        digest.update(&iv);
        digest.update(&ciphertext);
        let mac = digest.finalize().into_bytes().as_slice().to_vec();

        Ok(Self::Symmetric {
            iv,
            ciphertext,
            mac: Some(mac),
        })
    }

    pub fn decrypt_symmetric(
        &self,
        keys: &crate::locked::Keys,
        entry_key: Option<&crate::locked::Keys>,
    ) -> Result<Vec<u8>> {
        if let Self::Symmetric {
            iv,
            ciphertext,
            mac,
        } = self
        {
            let cipher = decrypt_common_symmetric(
                entry_key.unwrap_or(keys),
                iv,
                ciphertext,
                mac.as_deref(),
            )?;
            cipher
                .decrypt_padded_vec::<block_padding::Pkcs7>(ciphertext)
                .map_err(|source| Error::Decrypt { source })
        } else {
            Err(Error::InvalidCipherString {
                reason:
                    "found an asymmetric cipherstring, expecting symmetric"
                        .to_string(),
            })
        }
    }

    pub fn decrypt_locked_symmetric(
        &self,
        keys: &crate::locked::Keys,
    ) -> Result<crate::locked::Vec> {
        if let Self::Symmetric {
            iv,
            ciphertext,
            mac,
        } = self
        {
            let mut res = crate::locked::Vec::new();
            res.extend(ciphertext.iter().copied());
            let cipher = decrypt_common_symmetric(
                keys,
                iv,
                ciphertext,
                mac.as_deref(),
            )?;
            cipher
                .decrypt_padded::<block_padding::Pkcs7>(res.data_mut())
                .map_err(|source| Error::Decrypt { source })?;
            Ok(res)
        } else {
            Err(Error::InvalidCipherString {
                reason:
                    "found an asymmetric cipherstring, expecting symmetric"
                        .to_string(),
            })
        }
    }

    pub fn decrypt_locked_symmetric_unpadded(
        &self,
        keys: &crate::locked::Keys,
    ) -> Result<crate::locked::Vec> {
        let mut res = self.decrypt_locked_symmetric(keys)?;
        let unpadded_len = pkcs7_unpad(res.data()).ok_or(Error::Padding)?.len();
        res.data_mut()[unpadded_len..].zeroize();
        res.truncate(unpadded_len);
        Ok(res)
    }

    pub fn decrypt_locked_asymmetric(
        &self,
        private_key: &crate::locked::PrivateKey,
    ) -> Result<crate::locked::Vec> {
        if let Self::Asymmetric {
            algorithm,
            ciphertext,
        } = self
        {
            let privkey_data = private_key.private_key();
            let pkey = rsa::PrivateKey::from_pkcs8_der(privkey_data).or_else(
                |_| {
                    let unpadded =
                        pkcs7_unpad(privkey_data).ok_or(Error::Padding)?;
                    rsa::PrivateKey::from_pkcs8_der(unpadded)
                        .map_err(|source| Error::RsaPkcs8 { source })
                },
            )?;
            let mut bytes = match algorithm {
                AsymmetricAlgorithm::RsaOaepSha1 => pkey
                    .decrypt(rsa::Oaep::<sha1::Sha1>::new(), ciphertext)
                    .map_err(|source| Error::Rsa { source })?,
                AsymmetricAlgorithm::RsaOaepSha256 => pkey
                    .decrypt(rsa::Oaep::<sha2::Sha256>::new(), ciphertext)
                    .map_err(|source| Error::Rsa { source })?,
            };

            // XXX it'd be great if the rsa crate would let us decrypt
            // into a preallocated buffer directly to avoid the
            // intermediate vec that needs to be manually zeroized, etc
            let mut res = crate::locked::Vec::new();
            res.extend(bytes.iter().copied());
            bytes.zeroize();

            Ok(res)
        } else {
            Err(Error::InvalidCipherString {
                reason:
                    "found a symmetric cipherstring, expecting asymmetric"
                        .to_string(),
            })
        }
    }
}

fn decrypt_common_symmetric(
    keys: &crate::locked::Keys,
    iv: &[u8],
    ciphertext: &[u8],
    mac: Option<&[u8]>,
) -> Result<cbc::Decryptor<aes::Aes256>> {
    if let Some(mac) = mac {
        let mut key =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(keys.mac_key())
                .map_err(|source| Error::CreateHmac { source })?;
        key.update(iv);
        key.update(ciphertext);

        if key.verify_slice(mac).is_err() {
            return Err(Error::InvalidMac);
        }
    }

    cbc::Decryptor::<aes::Aes256>::new_from_slices(keys.enc_key(), iv)
        .map_err(|source| Error::CreateBlockMode { source })
}

impl std::fmt::Display for CipherString {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Symmetric {
                iv,
                ciphertext,
                mac,
            } => {
                let iv = crate::base64::encode(iv);
                let ciphertext = crate::base64::encode(ciphertext);
                if let Some(mac) = &mac {
                    let mac = crate::base64::encode(mac);
                    write!(f, "2.{iv}|{ciphertext}|{mac}")
                } else {
                    write!(f, "2.{iv}|{ciphertext}")
                }
            }
            Self::Asymmetric {
                algorithm,
                ciphertext,
            } => {
                let ciphertext = crate::base64::encode(ciphertext);
                let ty = match algorithm {
                    AsymmetricAlgorithm::RsaOaepSha256 => 3,
                    AsymmetricAlgorithm::RsaOaepSha1 => 4,
                };
                write!(f, "{ty}.{ciphertext}")
            }
        }
    }
}

fn random_iv() -> Vec<u8> {
    let mut iv = vec![0_u8; 16];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut iv);
    iv
}

// XXX this should ideally just be block_padding::Pkcs7::unpad, but i can't
// figure out how to get the generic types to work out
fn pkcs7_unpad(b: &[u8]) -> Option<&[u8]> {
    if b.is_empty() {
        return None;
    }

    let padding_val = b[b.len() - 1];
    if padding_val == 0 {
        return None;
    }

    let padding_len = usize::from(padding_val);
    if padding_len > b.len() {
        return None;
    }

    for c in b.iter().copied().skip(b.len() - padding_len) {
        if c != padding_val {
            return None;
        }
    }

    Some(&b[..b.len() - padding_len])
}

#[test]
fn test_pkcs7_unpad() {
    let tests = [
        (&[][..], None),
        (&[0x01][..], Some(&[][..])),
        (&[0x02, 0x02][..], Some(&[][..])),
        (&[0x03, 0x03, 0x03][..], Some(&[][..])),
        (&[0x69, 0x01][..], Some(&[0x69][..])),
        (&[0x69, 0x02, 0x02][..], Some(&[0x69][..])),
        (&[0x69, 0x03, 0x03, 0x03][..], Some(&[0x69][..])),
        (&[0x02][..], None),
        (&[0x03][..], None),
        (&[0x69, 0x69, 0x03, 0x03][..], None),
        (&[0x00][..], None),
        (&[0x02, 0x00][..], None),
    ];
    for (input, expected) in tests {
        let got = pkcs7_unpad(input);
        assert_eq!(got, expected);
    }
}

#[test]
fn test_asymmetric_oaep_sha1_and_sha256() {
    use pkcs8::EncodePrivateKey as _;

    let rsa_priv = rsa::PrivateKey::new(&mut rand::rng(), 2048).unwrap();
    let rsa_pub = rsa_priv.to_public_key();
    let der = rsa_priv.to_pkcs8_der().unwrap();
    let mut locked_der = crate::locked::Vec::new();
    locked_der.extend(der.as_bytes().iter().copied());
    let private_key = crate::locked::PrivateKey::new(locked_der);

    let secret = [0x42_u8; crate::locked::KEYS_LEN];

    let ct_sha1 = rsa_pub
        .encrypt(&mut rand::rng(), rsa::Oaep::<sha1::Sha1>::new(), &secret)
        .unwrap();
    let cs4 = CipherString::new(&format!(
        "4.{}",
        crate::base64::encode(&ct_sha1)
    ))
    .unwrap();
    assert_eq!(
        cs4.decrypt_locked_asymmetric(&private_key).unwrap().data(),
        &secret
    );
    let cs6 = CipherString::new(&format!(
        "6.{}|AA==",
        crate::base64::encode(&ct_sha1)
    ))
    .unwrap();
    assert_eq!(
        cs6.decrypt_locked_asymmetric(&private_key).unwrap().data(),
        &secret
    );

    let ct_sha256 = rsa_pub
        .encrypt(
            &mut rand::rng(),
            rsa::Oaep::<sha2::Sha256>::new(),
            &secret,
        )
        .unwrap();
    let cs3 = CipherString::new(&format!(
        "3.{}",
        crate::base64::encode(&ct_sha256)
    ))
    .unwrap();
    assert_eq!(
        cs3.decrypt_locked_asymmetric(&private_key).unwrap().data(),
        &secret
    );
    assert!(cs3.to_string().starts_with("3."));

    let cs5 = CipherString::new(&format!(
        "5.{}|AA==",
        crate::base64::encode(&ct_sha256)
    ))
    .unwrap();
    assert_eq!(
        cs5.decrypt_locked_asymmetric(&private_key).unwrap().data(),
        &secret
    );
}

#[test]
fn test_decrypt_locked_symmetric_unpadded() {
    let keys =
        crate::locked::Keys::from_bytes(&[0x33_u8; crate::locked::KEYS_LEN])
            .unwrap();
    let plaintext = [0x7a_u8; crate::locked::KEYS_LEN];
    let cs = CipherString::encrypt_symmetric(&keys, &plaintext).unwrap();
    let decrypted = cs.decrypt_locked_symmetric_unpadded(&keys).unwrap();
    assert_eq!(decrypted.data(), &plaintext);
}
