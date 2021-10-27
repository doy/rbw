use crate::prelude::*;

pub async fn login(
    email: &str,
    password: &crate::locked::Password,
    client_id: &str,
    client_secret: &str,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<crate::api::TwoFactorProviderType>,
) -> Result<(String, u32, String, crate::locked::Keys)> {
    let config = crate::config::Config::load_async().await?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());

    let (access_token, protected_key, iterations) = client
        .login_async(
            client_id,
            client_secret,
            two_factor_token,
            two_factor_provider,
        ).await?;

    let identity =
        crate::identity::Identity::new(email, password, iterations)?;

    let master_keys = crate::cipherstring::CipherString::new(&protected_key)?
        .decrypt_locked_symmetric(&identity.keys)?;

    Ok((
        access_token,
        iterations,
        protected_key.to_string(),
        crate::locked::Keys::new(master_keys),
    ))
}

pub async fn unlock(
    email: &str,
    password: &crate::locked::Password,
    iterations: u32,
    protected_key: &str,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let identity =
        crate::identity::Identity::new(email, password, iterations)?;

    let protected_key =
        crate::cipherstring::CipherString::new(protected_key)?;
    let key = match protected_key.decrypt_locked_symmetric(&identity.keys) {
        Ok(master_keys) => crate::locked::Keys::new(master_keys),
        Err(Error::InvalidMac) => {
            return Err(Error::IncorrectPassword {
                message: "Password is incorrect. Try again.".to_string(),
            })
        }
        Err(e) => return Err(e),
    };

    let protected_private_key =
        crate::cipherstring::CipherString::new(protected_private_key)?;
    let private_key =
        match protected_private_key.decrypt_locked_symmetric(&key) {
            Ok(private_key) => crate::locked::PrivateKey::new(private_key),
            Err(e) => return Err(e),
        };

    let mut org_keys = std::collections::HashMap::new();
    for (org_id, protected_org_key) in protected_org_keys {
        let protected_org_key =
            crate::cipherstring::CipherString::new(protected_org_key)?;
        let org_key =
            match protected_org_key.decrypt_locked_asymmetric(&private_key) {
                Ok(org_key) => crate::locked::Keys::new(org_key),
                Err(e) => return Err(e),
            };
        org_keys.insert(org_id.to_string(), org_key);
    }

    Ok((key, org_keys))
}

pub async fn sync(
    access_token: &str,
) -> Result<(
    Option<String>,
    (
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
    ),
)> {
    with_exchange_token_async(
        access_token,
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
    let config = crate::config::Config::load_async().await?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.sync(access_token).await
}

pub fn add(
    access_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<(Option<String>, ())> {
    with_exchange_token(access_token, |access_token| {
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
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.add(access_token, name, data, notes, folder_id.as_deref())?;
    Ok(())
}

pub fn edit(
    access_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<(Option<String>, ())> {
    with_exchange_token(access_token, |access_token| {
        edit_once(
            access_token,
            id,
            org_id,
            name,
            data,
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
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<()> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.edit(
        access_token,
        id,
        org_id,
        name,
        data,
        notes,
        folder_uuid,
        history,
    )?;
    Ok(())
}

pub fn remove(
    access_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_token(access_token, |access_token| {
        remove_once(access_token, id)
    })
}

fn remove_once(access_token: &str, id: &str) -> Result<()> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.remove(access_token, id)?;
    Ok(())
}

pub fn list_folders(
    access_token: &str,
) -> Result<(Option<String>, Vec<(String, String)>)> {
    with_exchange_token(access_token, |access_token| {
        list_folders_once(access_token)
    })
}

fn list_folders_once(access_token: &str) -> Result<Vec<(String, String)>> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.folders(access_token)
}

pub fn create_folder(
    access_token: &str,
    name: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_token(access_token, |access_token| {
        create_folder_once(access_token, name)
    })
}

fn create_folder_once(access_token: &str, name: &str) -> Result<String> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.create_folder(access_token, name)
}

fn with_exchange_token<F, T>(
    access_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(&str) -> Result<T>,
{
    match f(access_token) {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let (access_token, _protected_key, _iterations) = exchange_token()?;
            let t = f(&access_token)?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

async fn with_exchange_token_async<F, T>(
    access_token: &str,
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
            let (access_token, _protected_key, _iterations) = exchange_token_async().await?;
            let t = f(&access_token).await?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

fn exchange_token() -> Result<(String, String, u32)> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.login(&config.client_id.unwrap(), &config.client_secret.unwrap(), None, None)
}

async fn exchange_token_async() -> Result<(String, String, u32)> {
    let config = crate::config::Config::load_async().await?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.login_async(&config.client_id.unwrap(), &config.client_secret.unwrap(), None, None).await
}
