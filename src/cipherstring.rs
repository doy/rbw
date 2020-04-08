use crate::prelude::*;

use block_modes::BlockMode as _;
use hmac::Mac as _;

pub struct CipherString {
    ty: u8,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    mac: Option<Vec<u8>>,
}

impl CipherString {
    pub fn new(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidCipherString);
        }

        let ty = parts[0].as_bytes();
        if ty.len() != 1 {
            return Err(Error::InvalidCipherString);
        }

        let ty = ty[0] - b'0';
        let contents = parts[1];

        let parts: Vec<&str> = contents.split('|').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(Error::InvalidCipherString);
        }

        let iv =
            base64::decode(parts[0]).context(crate::error::InvalidBase64)?;
        let ciphertext =
            base64::decode(parts[1]).context(crate::error::InvalidBase64)?;
        let mac = if parts.len() > 2 {
            Some(
                base64::decode(parts[2])
                    .context(crate::error::InvalidBase64)?,
            )
        } else {
            None
        };

        Ok(Self {
            ty,
            iv,
            ciphertext,
            mac,
        })
    }

    pub fn decrypt(&self, keys: &crate::locked::Keys) -> Result<Vec<u8>> {
        let cipher = self.decrypt_common(keys)?;
        cipher
            .decrypt_vec(&self.ciphertext)
            .context(crate::error::Decrypt)
    }

    pub fn decrypt_locked(
        &self,
        keys: &crate::locked::Keys,
    ) -> Result<crate::locked::Vec> {
        let mut res = crate::locked::Vec::new();
        res.extend(self.ciphertext.iter().copied());
        let cipher = self.decrypt_common(keys)?;
        cipher
            .decrypt(res.data_mut())
            .context(crate::error::Decrypt)?;
        Ok(res)
    }

    fn decrypt_common(
        &self,
        keys: &crate::locked::Keys,
    ) -> Result<
        block_modes::Cbc<aes::Aes256, block_modes::block_padding::Pkcs7>,
    > {
        if self.ty != 2 {
            unimplemented!()
        }

        if let Some(mac) = &self.mac {
            let mut digest =
                hmac::Hmac::<sha2::Sha256>::new_varkey(keys.mac_key())
                    .map_err(|_| Error::InvalidMacKey)?;
            digest.input(&self.iv);
            digest.input(&self.ciphertext);
            let calculated_mac = digest.result().code();

            if !macs_equal(mac, &calculated_mac, keys.mac_key())? {
                return Err(Error::InvalidMac);
            }
        }

        Ok(block_modes::Cbc::<
            aes::Aes256,
            block_modes::block_padding::Pkcs7,
        >::new_var(keys.enc_key(), &self.iv)
        .context(crate::error::CreateBlockMode)?)
    }
}

fn macs_equal(mac1: &[u8], mac2: &[u8], mac_key: &[u8]) -> Result<bool> {
    let mut digest = hmac::Hmac::<sha2::Sha256>::new_varkey(mac_key)
        .map_err(|_| Error::InvalidMacKey)?;
    digest.input(mac1);
    let hmac1 = digest.result().code();

    let mut digest = hmac::Hmac::<sha2::Sha256>::new_varkey(mac_key)
        .map_err(|_| Error::InvalidMacKey)?;
    digest.input(mac2);
    let hmac2 = digest.result().code();

    Ok(hmac1 == hmac2)
}
