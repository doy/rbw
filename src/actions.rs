use crate::prelude::*;

pub async fn register(
    email: &str,
    apikey: crate::locked::ApiKey,
) -> Result<()> {
    let (client, config) = api_client_async().await?;

    client
        .register(email, &crate::config::device_id(&config).await?, &apikey)
        .await?;

    Ok(())
}

pub async fn login(
    email: &str,
    password: crate::locked::Password,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<crate::api::TwoFactorProviderType>,
) -> Result<(
    String,
    String,
    crate::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let (client, config) = api_client_async().await?;
    let (kdf, iterations, memory, parallelism) =
        client.prelogin(email).await?;

    let identity = crate::identity::Identity::new(
        email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;
    let (access_token, refresh_token, protected_key) = client
        .login(
            email,
            config.sso_id.as_deref(),
            &crate::config::device_id(&config).await?,
            &identity.master_password_hash,
            two_factor_token,
            two_factor_provider,
        )
        .await?;

    Ok((
        access_token,
        refresh_token,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
    ))
}

pub async fn webauthn_login_assertion_options()
-> Result<crate::api::WebAuthnLoginAssertionOptionsRes> {
    let (client, _) = api_client_async().await?;
    client.webauthn_login_assertion_options().await
}

pub async fn login_webauthn(
    token: &str,
    device_response: &str,
) -> Result<crate::api::WebAuthnLoginRes> {
    let (client, config) = api_client_async().await?;
    client
        .login_webauthn(
            &crate::config::device_id(&config).await?,
            token,
            device_response,
        )
        .await
}

pub async fn send_two_factor_email(
    email: &str,
    sso_email_2fa_session_token: &str,
) -> Result<()> {
    let (client, config) = api_client_async().await?;
    client
        .send_email_login(
            email,
            &crate::config::device_id(&config).await?,
            sso_email_2fa_session_token,
        )
        .await
}

pub fn unlock<S: std::hash::BuildHasher>(
    email: &str,
    password: &crate::locked::Password,
    kdf: crate::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: &str,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let identity = crate::identity::Identity::new(
        email,
        password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;

    unlock_with_master_keys(
        &identity.keys,
        protected_key,
        protected_private_key,
        protected_org_keys,
    )
}

pub fn unlock_with_master_keys<S: std::hash::BuildHasher>(
    master_keys: &crate::locked::Keys,
    protected_key: &str,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let protected_key =
        crate::cipherstring::CipherString::new(protected_key)?;
    let key = match protected_key.decrypt_locked_symmetric(master_keys) {
        Ok(user_key) => crate::locked::Keys::new(user_key),
        Err(Error::InvalidMac) => {
            return Err(Error::IncorrectPassword {
                message: "Password is incorrect. Try again.".to_string(),
            });
        }
        Err(e) => return Err(e),
    };

    unlock_with_user_key(key, protected_private_key, protected_org_keys)
}

pub fn unlock_with_user_key<S: std::hash::BuildHasher>(
    key: crate::locked::Keys,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let protected_private_key =
        crate::cipherstring::CipherString::new(protected_private_key)?;
    let private_key = crate::locked::PrivateKey::new(
        protected_private_key.decrypt_locked_symmetric(&key)?,
    );

    let mut org_keys = std::collections::HashMap::new();
    for (org_id, protected_org_key) in protected_org_keys {
        let protected_org_key =
            crate::cipherstring::CipherString::new(protected_org_key)?;
        let org_key = crate::locked::Keys::new(
            protected_org_key.decrypt_locked_asymmetric(&private_key)?,
        );
        org_keys.insert(org_id.clone(), org_key);
    }

    Ok((key, org_keys))
}

pub fn derive_prf_keys(prf_output: &[u8; 32]) -> Result<crate::locked::Keys> {
    if prf_output.iter().all(|b| *b == 0) {
        return Err(Error::Fido2 {
            message: "authenticator returned an all-zero PRF output"
                .to_string(),
        });
    }

    let mut keys = crate::locked::Vec::new();
    keys.extend(std::iter::repeat_n(0, crate::locked::KEYS_LEN));
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(prf_output)
        .map_err(|_| Error::HkdfExpand)?;
    hkdf.expand(b"enc", &mut keys.data_mut()[0..32])
        .map_err(|_| Error::HkdfExpand)?;
    hkdf.expand(b"mac", &mut keys.data_mut()[32..64])
        .map_err(|_| Error::HkdfExpand)?;
    Ok(crate::locked::Keys::new(keys))
}

pub fn decrypt_user_key_with_prf(
    prf_output: &[u8; 32],
    encrypted_private_key: &str,
    encrypted_user_key: &str,
) -> Result<crate::locked::Keys> {
    let prf_keys = derive_prf_keys(prf_output)?;
    let encrypted_private_key =
        crate::cipherstring::CipherString::new(encrypted_private_key)?;
    let private_key = crate::locked::PrivateKey::new(
        encrypted_private_key.decrypt_locked_symmetric(&prf_keys)?,
    );

    let encrypted_user_key =
        crate::cipherstring::CipherString::new(encrypted_user_key)?;
    let user_key_vec =
        encrypted_user_key.decrypt_locked_asymmetric(&private_key)?;
    crate::locked::Keys::from_bytes(user_key_vec.data()).ok_or_else(|| {
        Error::Fido2 {
            message: format!(
                "decrypted user key has unexpected length ({})",
                user_key_vec.data().len()
            ),
        }
    })
}

pub async fn sync(
    access_token: &str,
    refresh_token: &str,
) -> Result<(
    Option<String>,
    (
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
    ),
)> {
    with_exchange_refresh_token_async(
        access_token,
        refresh_token,
        |access_token| {
            let access_token = access_token.to_string();
            Box::pin(async move { sync_once(&access_token).await })
        },
    )
    .await
}

async fn sync_once(
    access_token: &str,
) -> Result<(
    String,
    String,
    std::collections::HashMap<String, String>,
    Vec<crate::db::Entry>,
)> {
    let (client, _) = api_client_async().await?;
    client.sync(access_token).await
}

pub fn add(
    access_token: &str,
    refresh_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        add_once(access_token, name, data, notes, folder_id)
    })
}

fn add_once(
    access_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.add(access_token, name, data, notes, folder_id)?;
    Ok(())
}

pub fn edit(
    access_token: &str,
    refresh_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        edit_once(
            access_token,
            id,
            org_id,
            name,
            data,
            fields,
            notes,
            folder_uuid,
            history,
        )
    })
}

fn edit_once(
    access_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<()> {
    let (client, _) = api_client()?;
    client.edit(
        access_token,
        id,
        org_id,
        name,
        data,
        fields,
        notes,
        folder_uuid,
        history,
    )?;
    Ok(())
}

pub fn remove(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        remove_once(access_token, id)
    })
}

fn remove_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.remove(access_token, id)?;
    Ok(())
}

pub fn list_folders(
    access_token: &str,
    refresh_token: &str,
) -> Result<(Option<String>, Vec<(String, String)>)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        list_folders_once(access_token)
    })
}

fn list_folders_once(access_token: &str) -> Result<Vec<(String, String)>> {
    let (client, _) = api_client()?;
    client.folders(access_token)
}

pub fn create_folder(
    access_token: &str,
    refresh_token: &str,
    name: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        create_folder_once(access_token, name)
    })
}

fn create_folder_once(access_token: &str, name: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.create_folder(access_token, name)
}

fn with_exchange_refresh_token<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(&str) -> Result<T>,
{
    match f(access_token) {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token = exchange_refresh_token(refresh_token)?;
            let t = f(&access_token)?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

async fn with_exchange_refresh_token_async<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T>> + Send>,
        > + Send
        + Sync,
    T: Send,
{
    match f(access_token).await {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let t = f(&access_token).await?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

fn exchange_refresh_token(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.exchange_refresh_token(refresh_token)
}

async fn exchange_refresh_token_async(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.exchange_refresh_token_async(refresh_token).await
}

fn api_client() -> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load()?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}

async fn api_client_async()
-> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load_async().await?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}

#[test]
fn test_unlock_with_master_keys() {
    let master_keys =
        crate::locked::Keys::from_bytes(&[0x11_u8; crate::locked::KEYS_LEN])
            .unwrap();
    let wrong_master_keys =
        crate::locked::Keys::from_bytes(&[0x22_u8; crate::locked::KEYS_LEN])
            .unwrap();
    let user_keys =
        crate::locked::Keys::from_bytes(&[0x33_u8; crate::locked::KEYS_LEN])
            .unwrap();

    let protected_key = crate::cipherstring::CipherString::encrypt_symmetric(
        &master_keys,
        user_keys.as_bytes(),
    )
    .unwrap()
    .to_string();
    let protected_private_key =
        crate::cipherstring::CipherString::encrypt_symmetric(
            &user_keys,
            b"dummy-private-key",
        )
        .unwrap()
        .to_string();
    let org_keys = std::collections::HashMap::new();

    let (unlocked_key, unlocked_orgs) = unlock_with_master_keys(
        &master_keys,
        &protected_key,
        &protected_private_key,
        &org_keys,
    )
    .unwrap();
    assert_eq!(unlocked_key.as_bytes(), user_keys.as_bytes());
    assert!(unlocked_orgs.is_empty());

    let err = unlock_with_master_keys(
        &wrong_master_keys,
        &protected_key,
        &protected_private_key,
        &org_keys,
    );
    assert!(matches!(err, Err(Error::IncorrectPassword { .. })));
}

#[test]
fn test_decrypt_user_key_with_prf() {
    use pkcs8::EncodePrivateKey as _;

    // All-zero PRF output must be rejected
    assert!(derive_prf_keys(&[0_u8; 32]).is_err());

    let prf_output = [0x42_u8; 32];
    let prf_keys = derive_prf_keys(&prf_output).unwrap();

    let rsa_priv = rsa::PrivateKey::new(&mut rand::rng(), 2048).unwrap();
    let rsa_pub = rsa_priv.to_public_key();
    let der = rsa_priv.to_pkcs8_der().unwrap();
    let encrypted_private_key =
        crate::cipherstring::CipherString::encrypt_symmetric(
            &prf_keys,
            der.as_bytes(),
        )
        .unwrap()
        .to_string();

    let expected_user_key = [0x5b_u8; crate::locked::KEYS_LEN];

    // Type 4 (RSA-OAEP-SHA1)
    let ct_sha1 = rsa_pub
        .encrypt(
            &mut rand::rng(),
            rsa::Oaep::<sha1::Sha1>::new(),
            &expected_user_key,
        )
        .unwrap();
    let enc_user_key_sha1 =
        format!("4.{}", crate::base64::encode(&ct_sha1));
    let unwrapped_sha1 = decrypt_user_key_with_prf(
        &prf_output,
        &encrypted_private_key,
        &enc_user_key_sha1,
    )
    .unwrap();
    assert_eq!(unwrapped_sha1.as_bytes(), &expected_user_key);

    // Type 3 (RSA-OAEP-SHA256)
    let ct_sha256 = rsa_pub
        .encrypt(
            &mut rand::rng(),
            rsa::Oaep::<sha2::Sha256>::new(),
            &expected_user_key,
        )
        .unwrap();
    let enc_user_key_sha256 =
        format!("3.{}", crate::base64::encode(&ct_sha256));
    let unwrapped_sha256 = decrypt_user_key_with_prf(
        &prf_output,
        &encrypted_private_key,
        &enc_user_key_sha256,
    )
    .unwrap();
    assert_eq!(unwrapped_sha256.as_bytes(), &expected_user_key);
}
