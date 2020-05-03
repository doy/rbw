use crate::prelude::*;

use block_modes::BlockMode as _;
use rand::RngCore as _;

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

    pub fn encrypt(
        keys: &crate::locked::Keys,
        plaintext: &[u8],
    ) -> Result<Self> {
        let iv = random_iv();

        // ring doesn't currently support CBC ciphers, so we have to do it
        // manually. see https://github.com/briansmith/ring/issues/588
        let cipher = block_modes::Cbc::<
            aes::Aes256,
            block_modes::block_padding::Pkcs7,
        >::new_var(keys.enc_key(), &iv)
        .context(crate::error::CreateBlockMode)?;
        let ciphertext = cipher.encrypt_vec(plaintext);

        let mut digest = ring::hmac::Context::with_key(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, keys.mac_key()),
        );
        digest.update(&iv);
        digest.update(&ciphertext);
        let mac = digest.sign().as_ref().to_vec();

        Ok(Self {
            ty: 2,
            iv,
            ciphertext,
            mac: Some(mac),
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
            let key =
                ring::hmac::Key::new(ring::hmac::HMAC_SHA256, keys.mac_key());
            // it'd be nice to not have to pull this into a vec, but ring
            // doesn't currently support non-contiguous verification. see
            // https://github.com/briansmith/ring/issues/615
            let data: Vec<_> = self
                .iv
                .iter()
                .chain(self.ciphertext.iter())
                .copied()
                .collect();

            if ring::hmac::verify(&key, &data, mac).is_err() {
                return Err(Error::InvalidMac);
            }
        }

        // ring doesn't currently support CBC ciphers, so we have to do it
        // manually. see https://github.com/briansmith/ring/issues/588
        Ok(block_modes::Cbc::<
            aes::Aes256,
            block_modes::block_padding::Pkcs7,
        >::new_var(keys.enc_key(), &self.iv)
        .context(crate::error::CreateBlockMode)?)
    }
}

impl std::fmt::Display for CipherString {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let iv = base64::encode(&self.iv);
        let ciphertext = base64::encode(&self.ciphertext);
        if let Some(mac) = &self.mac {
            let mac = base64::encode(&mac);
            write!(f, "{}.{}|{}|{}", self.ty, iv, ciphertext, mac)
        } else {
            write!(f, "{}.{}|{}", self.ty, iv, ciphertext)
        }
    }
}

fn random_iv() -> Vec<u8> {
    let mut iv = vec![0_u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    iv
}
