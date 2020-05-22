use anyhow::Context as _;

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    tty: Option<&str>,
) -> anyhow::Result<()> {
    let mut db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

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

        let email = config_email().await?;

        for i in 1_u8..=3 {
            let err = if i > 1 {
                Some(format!("Incorrect password (attempt {}/3)", i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                "Master Password",
                &format!("Log in to {}", host),
                err.as_deref(),
                tty,
            )
            .await
            .context("failed to read password from pinentry")?;
            let res = rbw::actions::login(&email, &password).await;
            match res {
                Ok((
                    access_token,
                    refresh_token,
                    iterations,
                    protected_key,
                    _,
                )) => {
                    db.access_token = Some(access_token);
                    db.refresh_token = Some(refresh_token);
                    db.iterations = Some(iterations);
                    db.protected_key = Some(protected_key.clone());
                    save_db(&db).await?;

                    sync(sock, false).await?;
                    db = load_db().await?;

                    let protected_private_key =
                        if let Some(protected_private_key) =
                            db.protected_private_key
                        {
                            protected_private_key
                        } else {
                            return Err(anyhow::anyhow!(
                                "failed to find protected private key in db"
                            ));
                        };

                    let res = rbw::actions::unlock(
                        &email,
                        &password,
                        iterations,
                        &protected_key,
                        &protected_private_key,
                        &db.protected_org_keys,
                    )
                    .await;

                    match res {
                        Ok((keys, org_keys)) => {
                            let mut state = state.write().await;
                            state.priv_key = Some(keys);
                            state.org_keys = Some(org_keys);
                        }
                        Err(e) => {
                            return Err(e)
                                .context("failed to unlock database")
                        }
                    }

                    break;
                }
                Err(rbw::error::Error::IncorrectPassword) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword)
                            .context(
                                "failed to log in to bitwarden instance",
                            );
                    } else {
                        continue;
                    }
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    tty: Option<&str>,
) -> anyhow::Result<()> {
    if state.read().await.needs_unlock() {
        let db = load_db().await?;

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
        let protected_private_key =
            if let Some(protected_private_key) = db.protected_private_key {
                protected_private_key
            } else {
                return Err(anyhow::anyhow!(
                    "failed to find protected private key in db"
                ));
            };

        let email = config_email().await?;

        for i in 1u8..=3 {
            let err = if i > 1 {
                Some(format!("Incorrect password (attempt {}/3)", i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                "Master Password",
                "Unlock the local database",
                err.as_deref(),
                tty,
            )
            .await
            .context("failed to read password from pinentry")?;
            let res = rbw::actions::unlock(
                &email,
                &password,
                iterations,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            )
            .await;
            match res {
                Ok((keys, org_keys)) => {
                    let mut state = state.write().await;
                    state.priv_key = Some(keys);
                    state.org_keys = Some(org_keys);
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword)
                            .context("failed to unlock database");
                    } else {
                        continue;
                    }
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
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

pub async fn sync(
    sock: &mut crate::sock::Sock,
    ack: bool,
) -> anyhow::Result<()> {
    let mut db = load_db().await?;

    let access_token = if let Some(access_token) = &db.access_token {
        access_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find access token in db"));
    };
    let refresh_token = if let Some(refresh_token) = &db.refresh_token {
        refresh_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find refresh token in db"));
    };
    let (
        access_token,
        (protected_key, protected_private_key, protected_org_keys, entries),
    ) = rbw::actions::sync(&access_token, &refresh_token)
        .await
        .context("failed to sync database from server")?;
    if let Some(access_token) = access_token {
        db.access_token = Some(access_token);
    }
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;
    save_db(&db).await?;

    if ack {
        respond_ack(sock).await?;
    }

    Ok(())
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    cipherstring: &str,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.read().await;
    let keys = if let Some(keys) = state.key(org_id) {
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
            .decrypt_symmetric(&keys)
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")?;

    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.read().await;
    let keys = if let Some(keys) = state.key(org_id) {
        keys
    } else {
        return Err(anyhow::anyhow!(
            "failed to find encryption keys in in-memory state"
        ));
    };
    let cipherstring = rbw::cipherstring::CipherString::encrypt_symmetric(
        keys,
        plaintext.as_bytes(),
    )
    .context("failed to encrypt plaintext secret")?;

    respond_encrypt(sock, cipherstring.to_string()).await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::version(),
    })
    .await
    .context("failed to send response")?;

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

async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
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

async fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        rbw::db::Db::load_async(&config.server_name(), &email)
            .await
            .context("failed to load password database")
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), &email)
            .await
            .context("failed to save password database")
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
