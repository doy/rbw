use crate::prelude::*;

pub async fn login(
    email: &str,
    password: &crate::locked::Password,
) -> Result<(
    String,
    u32,
    crate::cipherstring::CipherString,
    crate::locked::Keys,
)> {
    let client =
        crate::api::Client::new_self_hosted("https://bitwarden.tozt.net");

    let iterations = client.prelogin(email).await?;
    let identity =
        crate::identity::Identity::new(email, password, iterations)?;

    let (access_token, _refresh_token, protected_key) = client
        .login(&identity.email, &identity.master_password_hash)
        .await?;
    let protected_key =
        crate::cipherstring::CipherString::new(&protected_key)?;
    let master_keys = protected_key.decrypt_locked(&identity.keys)?;

    Ok((
        access_token,
        iterations,
        protected_key,
        crate::locked::Keys::new(master_keys),
    ))
}

pub async fn unlock(
    email: &str,
    password: &crate::locked::Password,
    iterations: u32,
    protected_key: &crate::cipherstring::CipherString,
) -> Result<crate::locked::Keys> {
    let identity =
        crate::identity::Identity::new(email, password, iterations)?;

    let master_keys = protected_key.decrypt_locked(&identity.keys)?;

    Ok(crate::locked::Keys::new(master_keys))
}

pub async fn sync(
    access_token: &str,
) -> Result<(String, Vec<crate::api::Cipher>)> {
    let client =
        crate::api::Client::new_self_hosted("https://bitwarden.tozt.net");
    client.sync(access_token).await
}
