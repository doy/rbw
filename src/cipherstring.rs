use crate::prelude::*;

use aes::cipher::{
    BlockDecryptMut as _, BlockEncryptMut as _, KeyIvInit as _,
};
use hmac::Mac as _;
use pkcs8::DecodePrivateKey as _;
use rand::RngCore as _;
use zeroize::Zeroize as _;

pub enum CipherString {
    Symmetric {
        // ty: 2 (AES_256_CBC_HMAC_SHA256)
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Option<Vec<u8>>,
    },
    Asymmetric {
        // ty: 4 (RSA_2048_OAEP_SHA1)
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
            4 | 6 => {
                // the only difference between 4 and 6 is the HMAC256
                // signature appended at the end
                // https://github.com/bitwarden/jslib/blob/785b681f61f81690de6df55159ab07ae710bcfad/src/enums/encryptionType.ts#L8
                // format is: <cipher_text_b64>|<hmac_sig>
                let contents = contents.split('|').next().unwrap();
                let ciphertext = crate::base64::decode(contents)
                    .map_err(|source| Error::InvalidBase64 { source })?;
                Ok(Self::Asymmetric { ciphertext })
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

        let cipher = cbc::Encryptor::<aes::Aes256>::new(
            keys.enc_key().into(),
            iv.as_slice().into(),
        );
        let ciphertext =
            cipher.encrypt_padded_vec_mut::<block_padding::Pkcs7>(plaintext);

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
    ) -> Result<Vec<u8>> {
        if let Self::Symmetric {
            iv,
            ciphertext,
            mac,
        } = self
        {
            let cipher = decrypt_common_symmetric(
                keys,
                iv,
                ciphertext,
                mac.as_deref(),
            )?;
            cipher
                .decrypt_padded_vec_mut::<block_padding::Pkcs7>(ciphertext)
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
                .decrypt_padded_mut::<block_padding::Pkcs7>(res.data_mut())
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

    pub fn decrypt_locked_asymmetric(
        &self,
        private_key: &crate::locked::PrivateKey,
    ) -> Result<crate::locked::Vec> {
        if let Self::Asymmetric { ciphertext } = self {
            let privkey_data = private_key.private_key();
            let privkey_data =
                pkcs7_unpad(privkey_data).ok_or(Error::Padding)?;
            let pkey = rsa::RsaPrivateKey::from_pkcs8_der(privkey_data)
                .map_err(|source| Error::RsaPkcs8 { source })?;
            let mut bytes = pkey
                .decrypt(rsa::Oaep::new::<sha1::Sha1>(), ciphertext)
                .map_err(|source| Error::Rsa { source })?;

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

        if key.verify(mac.into()).is_err() {
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
            Self::Asymmetric { ciphertext } => {
                let ciphertext = crate::base64::encode(ciphertext);
                write!(f, "4.{ciphertext}")
            }
        }
    }
}

fn random_iv() -> Vec<u8> {
    let mut iv = vec![0_u8; 16];
    let mut rng = rand::thread_rng();
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
