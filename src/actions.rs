use crate::prelude::*;

pub async fn login(
    email: &str,
    password: &crate::locked::Password,
) -> Result<(String, String, u32, String, crate::locked::Keys)> {
    let config = crate::config::Config::load_async().await?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());

    let iterations = client.prelogin(email).await?;
    let identity =
        crate::identity::Identity::new(email, password, iterations)?;

    let (access_token, refresh_token, protected_key) = client
        .login(&identity.email, &identity.master_password_hash)
        .await?;
    let master_keys = crate::cipherstring::CipherString::new(&protected_key)?
        .decrypt_locked(&identity.keys)?;

    Ok((
        access_token,
        refresh_token,
        iterations,
        protected_key,
        crate::locked::Keys::new(master_keys),
    ))
}

pub async fn unlock(
    email: &str,
    password: &crate::locked::Password,
    iterations: u32,
    protected_key: &str,
) -> Result<crate::locked::Keys> {
    let identity =
        crate::identity::Identity::new(email, password, iterations)?;

    let protected_key =
        crate::cipherstring::CipherString::new(protected_key)?;

    match protected_key.decrypt_locked(&identity.keys) {
        Ok(master_keys) => Ok(crate::locked::Keys::new(master_keys)),
        Err(Error::InvalidMac) => Err(Error::IncorrectPassword),
        Err(e) => Err(e),
    }
}

pub async fn sync(
    access_token: &str,
    refresh_token: &str,
) -> Result<(Option<String>, (String, Vec<crate::db::Entry>))> {
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
) -> Result<(String, Vec<crate::db::Entry>)> {
    let config = crate::config::Config::load_async().await?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.sync(access_token).await
}

pub fn add(
    access_token: &str,
    refresh_token: &str,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    notes: Option<&str>,
    uris: &[String],
    folder_id: Option<&str>,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        add_once(
            access_token,
            name,
            username,
            password,
            notes,
            uris,
            folder_id,
        )
    })
}

fn add_once(
    access_token: &str,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    notes: Option<&str>,
    uris: &[String],
    folder_id: Option<&str>,
) -> Result<()> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.add(
        access_token,
        name,
        username,
        password,
        notes,
        uris,
        folder_id.as_deref(),
    )?;
    Ok(())
}

pub fn edit(
    access_token: &str,
    refresh_token: &str,
    id: &str,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    notes: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        edit_once(access_token, id, name, username, password, notes, history)
    })
}

fn edit_once(
    access_token: &str,
    id: &str,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    notes: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<()> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.edit(
        access_token,
        id,
        name,
        username,
        password,
        notes,
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
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
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
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
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
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
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
        Err(crate::error::Error::RequestUnauthorized) => {
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
    >,
{
    match f(access_token).await {
        Ok(t) => Ok((None, t)),
        Err(crate::error::Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let t = f(&access_token).await?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

fn exchange_refresh_token(refresh_token: &str) -> Result<String> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.exchange_refresh_token(refresh_token)
}

async fn exchange_refresh_token_async(refresh_token: &str) -> Result<String> {
    let config = crate::config::Config::load_async().await?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.exchange_refresh_token_async(refresh_token).await
}
