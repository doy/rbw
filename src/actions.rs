use crate::prelude::*;

pub async fn login(
    email: &str,
    password: &str,
) -> Result<(String, u32, String)> {
    let client =
        crate::api::Client::new_self_hosted("https://bitwarden.tozt.net");

    let iterations = client.prelogin(&email).await?;
    let identity =
        crate::identity::Identity::new(&email, &password, iterations)?;

    let (access_token, _refresh_token, protected_key) = client
        .login(&identity.email, &identity.master_password_hash)
        .await?;

    Ok((access_token, iterations, protected_key))
}

pub async fn unlock(
    email: &str,
    password: &str,
    iterations: u32,
    protected_key: String,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let identity =
        crate::identity::Identity::new(&email, &password, iterations)?;

    let protected_key =
        crate::cipherstring::CipherString::new(&protected_key)?;
    let master_key =
        protected_key.decrypt(&identity.enc_key, &identity.mac_key)?;

    let enc_key = &master_key[0..32];
    let mac_key = &master_key[32..64];

    Ok((enc_key.to_vec(), mac_key.to_vec()))
}

pub async fn sync(
    access_token: &str,
) -> Result<(String, Vec<crate::api::Cipher>)> {
    let client =
        crate::api::Client::new_self_hosted("https://bitwarden.tozt.net");
    client.sync(access_token).await
}
