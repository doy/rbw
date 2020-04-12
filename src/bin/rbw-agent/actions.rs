use anyhow::Context as _;

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    tty: Option<&str>,
) -> anyhow::Result<()> {
    let email = config_email()
        .await
        .context("failed to read email from config")?;
    let mut db = rbw::db::Db::load_async(&email)
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url()
            .await
            .context("failed to read base url from config")?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let host = if let Some(host) = url.host_str() {
            host
        } else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {}",
                url_str
            ));
        };
        let password = rbw::pinentry::getpin(
            "Master Password",
            &format!("Log in to {}", host),
            tty,
        )
        .await
        .context("failed to read password from pinentry")?;
        let (access_token, refresh_token, iterations, protected_key, keys) =
            rbw::actions::login(&email, &password)
                .await
                .context("failed to log in to bitwarden instance")?;

        state.write().await.priv_key = Some(keys);

        db.access_token = Some(access_token);
        db.refresh_token = Some(refresh_token);
        db.iterations = Some(iterations);
        db.protected_key = Some(protected_key);
        db.save_async(&email)
            .await
            .context("failed to save local database")?;

        sync(sock).await?;
    } else {
        respond_ack(sock).await?;
    }

    Ok(())
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    tty: Option<&str>,
) -> anyhow::Result<()> {
    if state.read().await.needs_unlock() {
        let email = config_email()
            .await
            .context("failed to read email from config")?;
        let password = rbw::pinentry::getpin(
            "Master Password",
            "Unlock the local database",
            tty,
        )
        .await
        .context("failed to read password from pinentry")?;

        let db = rbw::db::Db::load_async(&email)
            .await
            .context("failed to load local database")?;

        let iterations = if let Some(iterations) = db.iterations {
            iterations
        } else {
            return Err(anyhow::anyhow!(
                "failed to find number of iterations in db"
            ));
        };
        let protected_key = if let Some(protected_key) = db.protected_key {
            protected_key
        } else {
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
        };
        let keys = rbw::actions::unlock(
            &email,
            &password,
            iterations,
            &protected_key,
        )
        .await
        .context("failed to unlock database")?;

        state.write().await.priv_key = Some(keys);
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
) -> anyhow::Result<()> {
    state.write().await.clear();

    respond_ack(sock).await?;

    Ok(())
}

pub async fn sync(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    let email = config_email()
        .await
        .context("failed to read email from config")?;
    let mut db = rbw::db::Db::load_async(&email)
        .await
        .context("failed to load local database")?;

    let access_token = if let Some(access_token) = &db.access_token {
        access_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find access token in db"));
    };
    let res = rbw::actions::sync(&access_token).await;
    let res = if let Err(e) = &res {
        if let rbw::error::Error::RequestUnauthorized = e {
            if let Some(refresh_token) = &db.refresh_token {
                let access_token =
                    rbw::actions::exchange_refresh_token(refresh_token)
                        .await?;
                db.access_token = Some(access_token.clone());
                rbw::actions::sync(&access_token).await
            } else {
                return Err(anyhow::anyhow!(
                    "failed to find refresh token in db"
                ));
            }
        } else {
            res
        }
    } else {
        res
    };
    let (protected_key, ciphers) =
        res.context("failed to sync database from server")?;
    db.protected_key = Some(protected_key);
    db.ciphers = ciphers;
    db.save_async(&email)
        .await
        .context("failed to save database")?;

    respond_ack(sock).await?;

    Ok(())
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    cipherstring: &str,
) -> anyhow::Result<()> {
    let state = state.read().await;
    let keys = if let Some(keys) = &state.priv_key {
        keys
    } else {
        return Err(anyhow::anyhow!(
            "failed to find decryption keys in in-memory state"
        ));
    };
    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    let plaintext = String::from_utf8(
        cipherstring
            .decrypt(&keys)
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")?;

    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack)
        .await
        .context("failed to send response")?;

    Ok(())
}

async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt { plaintext })
        .await
        .context("failed to send response")?;

    Ok(())
}

async fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async()
        .await
        .context("failed to load config")?;
    if let Some(email) = config.email {
        Ok(email)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn config_base_url() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async()
        .await
        .context("failed to load config")?;
    Ok(config.base_url())
}
