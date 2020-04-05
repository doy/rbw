use crate::prelude::*;

pub struct Identity {
    pub email: String,
    pub enc_key: Vec<u8>,
    pub mac_key: Vec<u8>,
    pub master_password_hash: Vec<u8>,
}

impl Identity {
    pub fn new(email: &str, password: &str, iterations: u32) -> Result<Self> {
        let mut key = vec![0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            password.as_bytes(),
            email.as_bytes(),
            iterations as usize,
            &mut key,
        );

        let mut hash = vec![0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            &key,
            password.as_bytes(),
            1,
            &mut hash,
        );

        let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(&key)
            .map_err(|_| Error::HkdfFromPrk)?;
        hkdf.expand(b"enc", &mut key)
            .map_err(|_| Error::HkdfExpand)?;

        let mut mac_key = vec![0u8; 32];
        hkdf.expand(b"mac", &mut mac_key)
            .map_err(|_| Error::HkdfExpand)?;

        Ok(Self {
            email: email.to_string(),
            enc_key: key,
            mac_key,
            master_password_hash: hash,
        })
    }
}
