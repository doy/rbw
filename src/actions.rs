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
    code: Option<crate::api::LoginCode<'_>>,
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
            code,
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

    unlock_with_key(key, protected_private_key, protected_org_keys)
}

pub fn unlock_with_key<S: std::hash::BuildHasher>(
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

pub async fn sync(
    access_token: &str,
    refresh_token: &str,
) -> Result<(
    Option<RefreshedTokens>,
    (
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
        String,
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
    String,
)> {
    let (client, _) = api_client_async().await?;
    client.sync(access_token).await
}

pub fn add(
    access_token: &str,
    refresh_token: &str,
    user_id: &str,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<(Option<RefreshedTokens>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        add_once(access_token, user_id, name, data, fields, notes, folder_id)
    })
}

fn add_once(
    access_token: &str,
    user_id: &str,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.add(
        access_token,
        user_id,
        name,
        data,
        fields,
        notes,
        folder_id,
    )?;
    Ok(())
}

pub fn edit(
    access_token: &str,
    refresh_token: &str,
    user_id: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
    key: Option<&str>,
) -> Result<(Option<RefreshedTokens>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        edit_once(
            access_token,
            user_id,
            id,
            org_id,
            name,
            data,
            fields,
            notes,
            folder_uuid,
            history,
            key,
        )
    })
}

fn edit_once(
    access_token: &str,
    user_id: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
    key: Option<&str>,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.edit(
        access_token,
        user_id,
        id,
        org_id,
        name,
        data,
        fields,
        notes,
        folder_uuid,
        history,
        key,
    )?;
    Ok(())
}

pub fn remove(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<RefreshedTokens>, ())> {
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
) -> Result<(Option<RefreshedTokens>, Vec<(String, String)>)> {
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
) -> Result<(Option<RefreshedTokens>, String)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        create_folder_once(access_token, name)
    })
}

fn create_folder_once(access_token: &str, name: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.create_folder(access_token, name)
}

// Tokens from a successful refresh. The refresh token is the one to use
// from now on: a new one if the server rotated it, otherwise the one that was
// sent.
#[derive(Debug, Clone)]
pub struct RefreshedTokens {
    pub access_token: String,
    pub refresh_token: String,
}

impl RefreshedTokens {
    pub fn store_in(self, db: &mut crate::db::Db) {
        db.access_token = Some(self.access_token);
        db.refresh_token = Some(self.refresh_token);
    }
}

// What to do after the server rejected the refresh token that was sent.
#[derive(Debug, PartialEq, Eq)]
enum Rejected {
    // It is still the stored token and will never work again. Forget it, so
    // that the next command logs in again instead of every request
    // repeating the same rejection, and so that `rbw login` has something
    // to do.
    Forget,
    // Another process stored a newer token while the request was in
    // flight, for example the agent rotating it during a sync while `rbw
    // edit` waited for the editor. Try that one instead.
    Retry(String),
    // Nothing more to try.
    GiveUp,
}

fn on_rejected(db: &crate::db::Db, sent: &str, retried: bool) -> Rejected {
    match db.refresh_token.as_deref() {
        Some(stored) if stored == sent => Rejected::Forget,
        Some(stored) if !retried => Rejected::Retry(stored.to_string()),
        _ => Rejected::GiveUp,
    }
}

fn forget_tokens(db: &mut crate::db::Db) {
    db.access_token = None;
    db.refresh_token = None;
}

// A rotating server may already have used up the old refresh token, so the
// new tokens are saved before anything else can fail. A db without tokens
// was logged out in the meantime and stays that way.
fn store_refreshed(db: &mut crate::db::Db, tokens: &RefreshedTokens) -> bool {
    if db.refresh_token.is_none() {
        return false;
    }
    tokens.clone().store_in(db);
    true
}

fn db_location(config: &crate::config::Config) -> Option<(String, &str)> {
    config
        .email
        .as_deref()
        .map(|email| (config.server_name(), email))
}

fn with_exchange_refresh_token<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<RefreshedTokens>, T)>
where
    F: Fn(&str) -> Result<T>,
{
    match f(access_token) {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let tokens = exchange_refresh_token(refresh_token)?;
            let t = f(&tokens.access_token)?;
            Ok((Some(tokens), t))
        }
        Err(e) => Err(e),
    }
}

async fn with_exchange_refresh_token_async<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<RefreshedTokens>, T)>
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
            let tokens = exchange_refresh_token_async(refresh_token).await?;
            let t = f(&tokens.access_token).await?;
            Ok((Some(tokens), t))
        }
        Err(e) => Err(e),
    }
}

fn exchange_refresh_token(refresh_token: &str) -> Result<RefreshedTokens> {
    let (client, config) = api_client()?;
    let location = db_location(&config);
    let load = || {
        location
            .as_ref()
            .map(|(server, email)| crate::db::Db::load(server, email))
            .transpose()
    };
    let save = |db: &crate::db::Db| {
        location
            .as_ref()
            .map_or(Ok(()), |(server, email)| db.save(server, email))
    };

    let mut sent = refresh_token.to_string();
    let mut retried = false;
    loop {
        match client.exchange_refresh_token(&sent) {
            Ok((access_token, rotated)) => {
                let tokens = RefreshedTokens {
                    access_token,
                    refresh_token: rotated.unwrap_or(sent),
                };
                let stored = load().and_then(|db| {
                    db.map_or(Ok(()), |mut db| {
                        if store_refreshed(&mut db, &tokens) {
                            save(&db)
                        } else {
                            Ok(())
                        }
                    })
                });
                if let Err(e) = stored {
                    log::warn!("failed to save refreshed tokens: {e}");
                }
                return Ok(tokens);
            }
            Err(Error::RefreshTokenInvalid) => {
                let Some(mut db) = load().unwrap_or_else(|e| {
                    log::warn!("failed to load db: {e}");
                    None
                }) else {
                    return Err(Error::RefreshTokenInvalid);
                };
                match on_rejected(&db, &sent, retried) {
                    Rejected::Forget => {
                        forget_tokens(&mut db);
                        if let Err(e) = save(&db) {
                            log::warn!("failed to forget refresh token: {e}");
                        }
                        return Err(Error::RefreshTokenInvalid);
                    }
                    Rejected::Retry(stored) => {
                        sent = stored;
                        retried = true;
                    }
                    Rejected::GiveUp => {
                        return Err(Error::RefreshTokenInvalid)
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
}

async fn exchange_refresh_token_async(
    refresh_token: &str,
) -> Result<RefreshedTokens> {
    let (client, config) = api_client_async().await?;
    let location = db_location(&config);

    let mut sent = refresh_token.to_string();
    let mut retried = false;
    loop {
        match client.exchange_refresh_token_async(&sent).await {
            Ok((access_token, rotated)) => {
                let tokens = RefreshedTokens {
                    access_token,
                    refresh_token: rotated.unwrap_or(sent),
                };
                if let Some((server, email)) = &location {
                    let stored = async {
                        let mut db =
                            crate::db::Db::load_async(server, email).await?;
                        if store_refreshed(&mut db, &tokens) {
                            db.save_async(server, email).await?;
                        }
                        Ok::<_, Error>(())
                    }
                    .await;
                    if let Err(e) = stored {
                        log::warn!("failed to save refreshed tokens: {e}");
                    }
                }
                return Ok(tokens);
            }
            Err(Error::RefreshTokenInvalid) => {
                let Some((server, email)) = &location else {
                    return Err(Error::RefreshTokenInvalid);
                };
                let mut db =
                    match crate::db::Db::load_async(server, email).await {
                        Ok(db) => db,
                        Err(e) => {
                            log::warn!("failed to load db: {e}");
                            return Err(Error::RefreshTokenInvalid);
                        }
                    };
                match on_rejected(&db, &sent, retried) {
                    Rejected::Forget => {
                        forget_tokens(&mut db);
                        if let Err(e) = db.save_async(server, email).await {
                            log::warn!("failed to forget refresh token: {e}");
                        }
                        return Err(Error::RefreshTokenInvalid);
                    }
                    Rejected::Retry(stored) => {
                        sent = stored;
                        retried = true;
                    }
                    Rejected::GiveUp => {
                        return Err(Error::RefreshTokenInvalid)
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
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

async fn api_client_async(
) -> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load_async().await?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}

#[cfg(test)]
mod tests {
    use super::Rejected;

    fn db_with_tokens(refresh_token: &str) -> crate::db::Db {
        let mut db = crate::db::Db::new();
        db.access_token = Some("access".to_string());
        db.refresh_token = Some(refresh_token.to_string());
        db
    }

    #[test]
    fn rejected_refresh_token_is_forgotten() {
        let db = db_with_tokens("rejected");
        assert_eq!(
            super::on_rejected(&db, "rejected", false),
            Rejected::Forget
        );
        assert_eq!(
            super::on_rejected(&db, "rejected", true),
            Rejected::Forget
        );
    }

    #[test]
    fn newer_refresh_token_is_tried_once() {
        // another process rotated the token after this one was sent
        let db = db_with_tokens("rotated");
        assert_eq!(
            super::on_rejected(&db, "rejected", false),
            Rejected::Retry("rotated".to_string())
        );
        assert_eq!(
            super::on_rejected(&db, "rejected", true),
            Rejected::GiveUp
        );
    }

    #[test]
    fn logged_out_db_is_left_alone() {
        let mut db = crate::db::Db::new();
        assert_eq!(
            super::on_rejected(&db, "rejected", false),
            Rejected::GiveUp
        );
        let tokens = super::RefreshedTokens {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
        };
        assert!(!super::store_refreshed(&mut db, &tokens));
        assert!(db.refresh_token.is_none());
    }
}
