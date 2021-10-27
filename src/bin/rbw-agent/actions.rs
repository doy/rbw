use anyhow::Context as _;

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    tty: Option<&str>,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
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
        let client_id = config_client_id().await?;
        let client_secret = config_client_secret().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                &format!("Log in to {}", host),
                err.as_deref(),
                tty,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::login(&email, &password, &client_id, &client_secret, None, None).await {
                Ok((
                    access_token,
                    iterations,
                    protected_key,
                    _,
                )) => {
                    login_success(
                        sock,
                        state,
                        access_token,
                        iterations,
                        protected_key,
                        password,
                        db,
                        email,
                    )
                    .await?;
                    break;
                }
                Err(rbw::error::Error::TwoFactorRequired { providers }) => {
                    if providers.contains(
                        &rbw::api::TwoFactorProviderType::Authenticator,
                    ) {
                        let (
                            access_token,
                            iterations,
                            protected_key,
                        ) = two_factor(
                            tty,
                            &email,
                            &password,
                            &client_id,
                            &client_secret,
                            rbw::api::TwoFactorProviderType::Authenticator,
                        )
                        .await?;
                        login_success(
                            sock,
                            state,
                            access_token,
                            iterations,
                            protected_key,
                            password,
                            db,
                            email,
                        )
                        .await?;
                        break;
                    } else {
                        return Err(anyhow::anyhow!("TODO"));
                    }
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    } else {
                        err_msg = Some(message);
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

async fn two_factor(
    tty: Option<&str>,
    email: &str,
    password: &rbw::locked::Password,
    client_id: &str,
    client_secret: &str,
    provider: rbw::api::TwoFactorProviderType,
) -> anyhow::Result<(String, u32, String)> {
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop if
            // we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let code = rbw::pinentry::getpin(
            &config_pinentry().await?,
            "Authenticator App",
            "Enter the 6 digit verification code from your authenticator app.",
            err.as_deref(),
            tty,
        )
        .await
        .context("failed to read code from pinentry")?;
        let code = std::str::from_utf8(code.password())
            .context("code was not valid utf8")?;
        match rbw::actions::login(
            email,
            password,
            client_id,
            client_secret,
            Some(code),
            Some(provider),
        )
        .await
        {
            Ok((
                access_token,
                iterations,
                protected_key,
                _,
            )) => {
                return Ok((
                    access_token,
                    iterations,
                    protected_key,
                ))
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                } else {
                    err_msg = Some(message);
                    continue;
                }
            }
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                } else {
                    err_msg = Some(message);
                    continue;
                }
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }

    unreachable!()
}

async fn login_success(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    access_token: String,
    iterations: u32,
    protected_key: String,
    password: rbw::locked::Password,
    mut db: rbw::db::Db,
    email: String,
) -> anyhow::Result<()> {
    db.access_token = Some(access_token.to_string());
    db.iterations = Some(iterations);
    db.protected_key = Some(protected_key.to_string());
    save_db(&db).await?;

    sync(sock, false).await?;
    let db = load_db().await?;

    let protected_private_key =
        if let Some(protected_private_key) = db.protected_private_key {
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
        Err(e) => return Err(e).context("failed to unlock database"),
    }

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

        let mut err_msg = None;
        for i in 1u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                "Unlock the local database",
                err.as_deref(),
                tty,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::unlock(
                &email,
                &password,
                iterations,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            )
            .await
            {
                Ok((keys, org_keys)) => {
                    unlock_success(state, keys, org_keys).await?;
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    } else {
                        err_msg = Some(message);
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

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
) -> anyhow::Result<()> {
    let mut state = state.write().await;
    state.priv_key = Some(keys);
    state.org_keys = Some(org_keys);
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

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    _tty: Option<&str>,
) -> anyhow::Result<()> {
    if state.read().await.needs_unlock() {
        return Err(anyhow::anyhow!("agent is locked"));
    }

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
    let (
        access_token,
        (protected_key, protected_private_key, protected_org_keys, entries),
    ) = rbw::actions::sync(&access_token)
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
    .await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}

async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt { plaintext })
        .await?;

    Ok(())
}

async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

async fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = config.email {
        Ok(email)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn config_client_id() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(client_id) = config.client_id {
        Ok(client_id)
    } else {
        Err(anyhow::anyhow!("failed to find client_id in config"))
    }
}

async fn config_client_secret() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(client_secret) = config.client_secret {
        Ok(client_secret)
    } else {
        Err(anyhow::anyhow!("failed to find client_secret in config"))
    }
}

async fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        rbw::db::Db::load_async(&config.server_name(), &email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), &email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn config_base_url() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.base_url())
}

async fn config_pinentry() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry)
}
