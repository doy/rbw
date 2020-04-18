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
    let master_keys = protected_key.decrypt_locked(&identity.keys)?;

    Ok(crate::locked::Keys::new(master_keys))
}

pub async fn sync(
    access_token: &str,
    refresh_token: &str,
) -> Result<(Option<String>, String, Vec<crate::db::Entry>)> {
    let res = sync_once(access_token).await;
    match res {
        Ok((protected_key, ciphers)) => Ok((None, protected_key, ciphers)),
        Err(crate::error::Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let (protected_key, ciphers) = sync_once(&access_token).await?;
            Ok((Some(access_token), protected_key, ciphers))
        }
        Err(e) => Err(e),
    }
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
) -> Result<Option<String>> {
    match add_once(access_token, name, username, password, notes) {
        Ok(()) => Ok(None),
        Err(crate::error::Error::RequestUnauthorized) => {
            let access_token = exchange_refresh_token(refresh_token)?;
            add_once(&access_token, name, username, password, notes)?;
            Ok(Some(access_token))
        }
        Err(e) => Err(e),
    }
}

fn add_once(
    access_token: &str,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    notes: Option<&str>,
) -> Result<()> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.add(access_token, name, username, password, notes)?;
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
) -> Result<Option<String>> {
    match edit_once(access_token, id, name, username, password, notes) {
        Ok(()) => Ok(None),
        Err(crate::error::Error::RequestUnauthorized) => {
            let access_token = exchange_refresh_token(refresh_token)?;
            edit_once(&access_token, id, name, username, password, notes)?;
            Ok(Some(access_token))
        }
        Err(e) => Err(e),
    }
}

fn edit_once(
    access_token: &str,
    id: &str,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    notes: Option<&str>,
) -> Result<()> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.edit(access_token, id, name, username, password, notes)?;
    Ok(())
}

pub fn remove(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<Option<String>> {
    match remove_once(access_token, id) {
        Ok(()) => Ok(None),
        Err(crate::error::Error::RequestUnauthorized) => {
            let access_token = exchange_refresh_token(refresh_token)?;
            remove_once(&access_token, id)?;
            Ok(Some(access_token))
        }
        Err(e) => Err(e),
    }
}

fn remove_once(access_token: &str, id: &str) -> Result<()> {
    let config = crate::config::Config::load()?;
    let client =
        crate::api::Client::new(&config.base_url(), &config.identity_url());
    client.remove(access_token, id)?;
    Ok(())
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
