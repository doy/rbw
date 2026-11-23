use anyhow::Context as _;
use sha2::Digest as _;

pub async fn register(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let client_id = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__id",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_id from pinentry")?;
            let client_secret = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__secret",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_secret from pinentry")?;
            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);
            match rbw::actions::register(&email, apikey.clone()).await {
                Ok(()) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
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

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        'attempts: for i in 1_u8..=3 {
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
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::login(&email, password.clone(), None).await {
                Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                )) => {
                    login_success(
                        state.clone(),
                        access_token,
                        refresh_token,
                        kdf,
                        iterations,
                        memory,
                        parallelism,
                        protected_key,
                        password,
                        db,
                        email,
                    )
                    .await?;
                    break 'attempts;
                }
                Err(rbw::error::Error::NewDeviceVerificationRequired) => {
                    let (
                        access_token,
                        refresh_token,
                        kdf,
                        iterations,
                        memory,
                        parallelism,
                        protected_key,
                    ) = login_with_code(
                        environment,
                        &email,
                        password.clone(),
                        CodePrompt::NewDevice,
                    )
                    .await?;
                    login_success(
                        state.clone(),
                        access_token,
                        refresh_token,
                        kdf,
                        iterations,
                        memory,
                        parallelism,
                        protected_key,
                        password,
                        db,
                        email,
                    )
                    .await?;
                    break 'attempts;
                }
                Err(rbw::error::Error::TwoFactorRequired {
                    providers,
                    sso_email_2fa_session_token,
                }) => {
                    let supported_types = vec![
                        rbw::api::TwoFactorProviderType::Authenticator,
                        rbw::api::TwoFactorProviderType::Yubikey,
                        rbw::api::TwoFactorProviderType::Email,
                    ];

                    for provider in supported_types {
                        if providers.contains(&provider) {
                            if provider
                                == rbw::api::TwoFactorProviderType::Email
                            {
                                if let Some(sso_email_2fa_session_token) =
                                    sso_email_2fa_session_token
                                {
                                    rbw::actions::send_two_factor_email(
                                        &email,
                                        &sso_email_2fa_session_token,
                                    )
                                    .await?;
                                }
                            }
                            let (
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                            ) = login_with_code(
                                environment,
                                &email,
                                password.clone(),
                                CodePrompt::TwoFactor(provider),
                            )
                            .await?;
                            login_success(
                                state.clone(),
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                                password,
                                db,
                                email,
                            )
                            .await?;
                            break 'attempts;
                        }
                    }
                    return Err(anyhow::anyhow!(
                        "unsupported two factor methods: {providers:?}"
                    ));
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
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

// Minimum time to wait for a code the server sent by email.
const EMAILED_CODE_TIMEOUT_SECS: u64 = 600;

// The code the second step of a login asks for.
#[derive(Clone, Copy)]
enum CodePrompt {
    TwoFactor(rbw::api::TwoFactorProviderType),
    // Bitwarden emails this code when an account without two-step login
    // signs in from a device it has not seen before.
    NewDevice,
}

async fn login_with_code(
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    prompt: CodePrompt,
) -> anyhow::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let (header, description, grab) = match prompt {
        CodePrompt::TwoFactor(provider) => (
            provider.header(),
            provider.message().to_string(),
            provider.grab(),
        ),
        CodePrompt::NewDevice => (
            "New Device Verification",
            format!(
                "Enter the verification code Bitwarden emailed to {email} \
                 to approve this device."
            ),
            // the person needs to switch to their mail client
            false,
        ),
    };

    let mut pinentry = config_pinentry().await?;
    // a code sent by email can take a while to arrive, and timing out means
    // starting over with a new code
    let emailed = matches!(
        prompt,
        CodePrompt::NewDevice
            | CodePrompt::TwoFactor(rbw::api::TwoFactorProviderType::Email)
    );
    if emailed && pinentry.timeout != 0 {
        pinentry.timeout = pinentry.timeout.max(EMAILED_CODE_TIMEOUT_SECS);
    }

    let mut err_msg: Option<String> = None;
    for i in 1_u8..=3 {
        let err = err_msg
            .as_deref()
            .map(|message| format!("{message} (attempt {i}/3)"));
        let input = rbw::pinentry::getpin(
            &pinentry,
            header,
            &description,
            err.as_deref(),
            environment,
            grab,
        )
        .await
        .context("failed to read code from pinentry")?;
        let code = std::str::from_utf8(input.password())
            .context("code was not valid utf8")?
            .trim();

        let message = match prompt {
            // sending no code would make Bitwarden email a new one
            CodePrompt::NewDevice if code.is_empty() => {
                "Enter the code from the email".to_string()
            }
            _ => {
                let login_code = match prompt {
                    CodePrompt::TwoFactor(provider) => {
                        rbw::api::LoginCode::TwoFactor {
                            provider,
                            token: code,
                        }
                    }
                    CodePrompt::NewDevice => {
                        rbw::api::LoginCode::NewDevice(code)
                    }
                };
                match rbw::actions::login(
                    email,
                    password.clone(),
                    Some(login_code),
                )
                .await
                {
                    Ok(tokens) => return Ok(tokens),
                    Err(rbw::error::Error::IncorrectPassword { message }) => {
                        message
                    }
                    // can get this if the user passes an empty string
                    Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                        "TOTP code is not a number".to_string()
                    }
                    Err(rbw::error::Error::NewDeviceVerificationRequired) => {
                        "Bitwarden emailed a new verification code"
                            .to_string()
                    }
                    Err(e) => {
                        return Err(e).context(
                            "failed to log in to bitwarden instance",
                        )
                    }
                }
            }
        };
        if i == 3 {
            return Err(rbw::error::Error::IncorrectPassword { message })
                .context("failed to log in to bitwarden instance");
        }
        err_msg = Some(message);
    }

    unreachable!()
}

async fn login_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    access_token: String,
    refresh_token: String,
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: String,
    password: rbw::locked::Password,
    mut db: rbw::db::Db,
    email: String,
) -> anyhow::Result<()> {
    db.access_token = Some(access_token.clone());
    db.refresh_token = Some(refresh_token.clone());
    db.kdf = Some(kdf);
    db.iterations = Some(iterations);
    db.memory = memory;
    db.parallelism = parallelism;
    db.protected_key = Some(protected_key.clone());
    save_db(&db).await?;

    sync(None, state.clone()).await?;
    let db = load_db().await?;

    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let res = rbw::actions::unlock(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
        &protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys)) => {
            unlock_success(state, keys, org_keys, &protected_key).await?;
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    Ok(())
}

async fn unlock_state(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let unlock_lock = state.lock().await.unlock_lock.clone();
    let _unlock_guard = unlock_lock.lock().await;

    if state.lock().await.needs_unlock() {
        let db = load_db().await?;

        let Some(kdf) = db.kdf else {
            return Err(anyhow::anyhow!("failed to find kdf type in db"));
        };

        let Some(iterations) = db.iterations else {
            return Err(anyhow::anyhow!(
                "failed to find number of iterations in db"
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key.as_deref() else {
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
        };
        let Some(protected_private_key) = db.protected_private_key.as_deref()
        else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let config = rbw::config::Config::load_async().await?;
        let email = config.email.ok_or_else(|| {
            anyhow::anyhow!("failed to find email address in config")
        })?;

        #[cfg(target_os = "macos")]
        {
            let biometric_unlock = {
                let state = state.lock().await;
                if state.touch_id_unlock {
                    state.biometric_unlock.clone()
                } else {
                    None
                }
            };
            if let Some(biometric_unlock) = biometric_unlock {
                if biometric_unlock.matches(protected_key) {
                    let biometric_unlock_for_task = biometric_unlock.clone();
                    let biometric_key =
                        tokio::task::spawn_blocking(move || {
                            biometric_unlock_for_task.unlock()
                        })
                        .await
                        .context("failed to join Touch ID task")?;
                    match biometric_key {
                        Ok(key) => match rbw::actions::unlock_with_key(
                            key,
                            protected_private_key,
                            &db.protected_org_keys,
                        ) {
                            Ok((keys, org_keys)) => {
                                if set_biometric_unlocked(
                                    state,
                                    &biometric_unlock,
                                    keys,
                                    org_keys,
                                )
                                .await
                                {
                                    return Ok(());
                                }
                                return Err(anyhow::anyhow!(
                                    "Touch ID session was revoked"
                                ));
                            }
                            Err(error) => {
                                log::warn!(
                                    "failed to unlock with cached vault key: \
                                    {error}"
                                );
                                state.lock().await.biometric_unlock = None;
                            }
                        },
                        Err(crate::biometric::UnlockError::Canceled) => {
                            return Err(anyhow::anyhow!(
                                "Touch ID was canceled"
                            ));
                        }
                        Err(
                            crate::biometric::UnlockError::PasswordRequested,
                        ) => {}
                        Err(crate::biometric::UnlockError::Unavailable(
                            error,
                        )) => {
                            log::warn!("Touch ID is unavailable: {error}");
                        }
                    }
                } else {
                    state.lock().await.biometric_unlock = None;
                }
            }
        }

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
                &format!(
                    "Unlock the local database for '{}'",
                    rbw::dirs::profile()
                ),
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
                protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok((keys, org_keys)) => {
                    unlock_success(state, keys, org_keys, protected_key)
                        .await?;
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    Ok(())
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    unlock_state(state, environment).await?;

    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
    protected_key: &str,
) -> anyhow::Result<()> {
    #[cfg(not(target_os = "macos"))]
    let _ = protected_key;

    #[cfg(target_os = "macos")]
    let biometric_unlock = {
        let enabled = state.lock().await.touch_id_unlock;
        if enabled {
            let keys = keys.clone();
            let protected_key = protected_key.to_string();
            match tokio::task::spawn_blocking(move || {
                crate::biometric::Session::new(&keys, &protected_key)
            })
            .await
            {
                Ok(Ok(session)) => Some(std::sync::Arc::new(session)),
                Ok(Err(error)) => {
                    log::warn!(
                        "failed to initialize Touch ID unlock: {error}"
                    );
                    None
                }
                Err(error) => {
                    log::warn!(
                        "failed to join Touch ID initialization task: {error}"
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    let mut state = state.lock().await;
    state.priv_key = Some(keys);
    state.org_keys = Some(org_keys);
    #[cfg(target_os = "macos")]
    {
        state.biometric_unlock = biometric_unlock;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn set_biometric_unlocked(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    biometric_unlock: &std::sync::Arc<crate::biometric::Session>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
) -> bool {
    let mut state = state.lock().await;
    let is_current_session =
        state.biometric_unlock.as_ref().is_some_and(|session| {
            std::sync::Arc::ptr_eq(session, biometric_unlock)
        });
    if !is_current_session {
        return false;
    }
    state.priv_key = Some(keys);
    state.org_keys = Some(org_keys);
    true
}

pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    state.lock().await.clear();

    respond_ack(sock).await?;

    Ok(())
}

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        return Err(anyhow::anyhow!("agent is locked"));
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let db = load_db().await?;

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
        tokens,
        (
            protected_key,
            protected_private_key,
            protected_org_keys,
            entries,
            user_id,
        ),
    ) = rbw::actions::sync(&access_token, &refresh_token)
        .await
        .context("failed to sync database from server")?;
    // the rbw command line can write the db while the sync is in flight, for
    // example to store tokens it refreshed, so apply the results to what is
    // on disk now rather than to the copy read before the request
    let mut db = load_db().await?;
    #[cfg(target_os = "macos")]
    let protected_key_changed = db
        .protected_key
        .as_deref()
        .is_some_and(|old_protected_key| old_protected_key != protected_key);
    state.lock().await.set_master_password_reprompt(&entries);
    if let Some(tokens) = tokens {
        tokens.store_in(&mut db);
    }
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.user_id = Some(user_id);
    db.entries = entries;
    save_db(&db).await?;
    #[cfg(target_os = "macos")]
    if protected_key_changed {
        // Changing the password wrapper does not necessarily rotate the live
        // vault key. Revoke only the cached alternative unlock route; changing
        // the cross-platform lock state here would be an unrelated behavior
        // change. A later unlock also checks the digest before using a session.
        state.lock().await.biometric_unlock = None;
    }

    if let Err(e) = subscribe_to_notifications(state.clone()).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

async fn decrypt_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    decrypt_cipher_in_request(
        state,
        environment,
        cipherstring,
        entry_key,
        org_id,
        &mut false,
    )
    .await
}

// Decrypts one cipherstring as part of a request that may decrypt several.
// If the user cancels or fails a master password reprompt, the request sets
// reprompt_declined, and the remaining reprompt-protected values in the same
// request fail without asking again. Values are never decrypted without a
// successful prompt of their own.
async fn decrypt_cipher_in_request(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    reprompt_declined: &mut bool,
) -> anyhow::Result<String> {
    let mut state = state.lock().await;
    if !state.master_password_reprompt_initialized() {
        let db = load_db().await?;
        state.set_master_password_reprompt(&db.entries);
    }
    let Some(keys) = state.key(org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find decryption keys in in-memory state"
        ));
    };
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };

    let mut sha256 = sha2::Sha256::new();
    sha256.update(cipherstring);
    let master_password_reprompt: [u8; 32] = sha256.finalize().into();
    if state
        .master_password_reprompt
        .contains(&master_password_reprompt)
    {
        if *reprompt_declined {
            return Err(anyhow::anyhow!(
                "master password reprompt was declined earlier in this request"
            ));
        }
        if let Err(e) = confirm_master_password(environment).await {
            *reprompt_declined = true;
            return Err(e);
        }
    }

    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    let plaintext = String::from_utf8(
        cipherstring
            .decrypt_symmetric(keys, entry_key.as_ref())
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")?;

    Ok(plaintext)
}

// Asks for the master password before revealing a value from an entry with
// master password reprompt enabled. The caller holds the state lock for the
// whole prompt, so other requests wait until it is answered.
async fn confirm_master_password(
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await?;

    let Some(kdf) = db.kdf else {
        return Err(anyhow::anyhow!("failed to find kdf type in db"));
    };

    let Some(iterations) = db.iterations else {
        return Err(anyhow::anyhow!(
            "failed to find number of iterations in db"
        ));
    };

    let memory = db.memory;
    let parallelism = db.parallelism;

    let Some(protected_key) = db.protected_key else {
        return Err(anyhow::anyhow!("failed to find protected key in db"));
    };
    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let email = config_email().await?;

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
            "Accessing this entry requires the master password",
            err.as_deref(),
            environment,
            true,
        )
        .await
        .context("failed to read password from pinentry")?;
        match rbw::actions::unlock(
            &email,
            &password,
            kdf,
            iterations,
            memory,
            parallelism,
            &protected_key,
            &protected_private_key,
            &db.protected_org_keys,
        ) {
            Ok(_) => {
                break;
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to unlock database");
                }
                err_msg = Some(message);
            }
            Err(e) => return Err(e).context("failed to unlock database"),
        }
    }
    Ok(())
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let plaintext =
        decrypt_cipher(state, environment, cipherstring, entry_key, org_id)
            .await?;
    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn decrypt_many(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    items: &[rbw::protocol::DecryptItem],
) -> anyhow::Result<()> {
    let mut plaintexts = Vec::with_capacity(items.len());
    let mut reprompt_declined = false;
    for item in items {
        // handle_request checked the lock deadline before the batch, but a
        // reprompt can keep it running for minutes (or across a sleep), so
        // check again before each value, as separate requests would
        state.lock().await.lock_if_expired();
        plaintexts.push(
            decrypt_cipher_in_request(
                state.clone(),
                environment,
                &item.cipherstring,
                item.entry_key.as_deref(),
                item.org_id.as_deref(),
                &mut reprompt_declined,
            )
            .await
            .map_err(|e| format!("{e:#}")),
        );
    }
    sock.send(&rbw::protocol::Response::DecryptMany { plaintexts })
        .await?;

    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    plaintext: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let Some(keys) = state.key(org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find encryption keys in in-memory state"
        ));
    };
    let entry_keys = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };
    let cipherstring = rbw::cipherstring::CipherString::encrypt_symmetric(
        entry_keys.as_ref().unwrap_or(keys),
        plaintext.as_bytes(),
    )
    .context("failed to encrypt plaintext secret")?;

    respond_encrypt(sock, cipherstring.to_string()).await?;

    Ok(())
}

#[cfg(feature = "clipboard")]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    text: &str,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    if let Some(clipboard) = &mut state.clipboard {
        clipboard.set_text(text).map_err(|e| {
            anyhow::anyhow!("couldn't store value to clipboard: {e}")
        })?;
    }

    respond_ack(sock).await?;

    Ok(())
}

#[cfg(not(feature = "clipboard"))]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    _text: &str,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::VERSION,
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
    config.email.map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        Ok,
    )
}

async fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        rbw::db::Db::load_async(&config.server_name(), email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), email)
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

pub async fn config_pinentry() -> anyhow::Result<rbw::pinentry::Pinentry> {
    let config = rbw::config::Config::load_async().await?;
    Ok(rbw::pinentry::Pinentry {
        program: config.pinentry,
        timeout: config.pinentry_timeout,
    })
}

pub async fn subscribe_to_notifications(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.notifications_handler.is_connected() {
        return Ok(());
    }

    let config = rbw::config::Config::load_async()
        .await
        .context("Config is missing")?;
    let email = config.email.clone().context("Config is missing email")?;
    let db = rbw::db::Db::load_async(config.server_name().as_str(), &email)
        .await?;
    let access_token =
        db.access_token.context("Error getting access token")?;

    let websocket_url = format!(
        "{}/hub?access_token={}",
        config.notifications_url(),
        access_token
    )
    .replace("https://", "wss://");

    let extra_headers = config.extra_headers()?;

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url, extra_headers)
        .await
        .err()
        .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
}

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<Vec<ssh_agent_lib::proto::Identity>> {
    let environment = {
        let mut state = state.lock().await;
        state.lock_if_expired();
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let db = load_db().await?;
    let mut identities = Vec::new();

    for entry in db.entries {
        let rbw::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        else {
            continue;
        };
        // one broken entry should not hide every other key
        let plaintext = match decrypt_cipher(
            state.clone(),
            &environment,
            encrypted,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )
        .await
        {
            Ok(plaintext) => plaintext,
            Err(e) => {
                log::warn!(
                    "skipping entry {} whose SSH public key can't be \
                     decrypted: {e:#}",
                    entry.id
                );
                continue;
            }
        };
        let public_key =
            match ssh_agent_lib::ssh_key::PublicKey::from_openssh(&plaintext)
            {
                Ok(public_key) => public_key,
                Err(e) => {
                    log::warn!(
                        "skipping entry {} with an unreadable SSH public \
                         key: {e}",
                        entry.id
                    );
                    continue;
                }
            };
        // keys generated by Bitwarden carry no comment, so name them after
        // their entry to tell them apart in `ssh-add -l`
        let comment = if public_key.comment().is_empty() {
            decrypt_cipher(
                state.clone(),
                &environment,
                &entry.name,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await
            .unwrap_or_default()
        } else {
            public_key.comment().to_string()
        };
        identities.push(ssh_agent_lib::proto::Identity {
            pubkey: public_key.key_data().clone(),
            comment,
        });
    }

    Ok(identities)
}

pub async fn find_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> anyhow::Result<(String, ssh_agent_lib::ssh_key::PrivateKey)> {
    let environment = {
        let mut state = state.lock().await;
        state.lock_if_expired();
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let request_bytes = request_public_key.to_bytes();

    let db = load_db().await?;

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        {
            let Some(public_key_enc) = public_key else {
                continue;
            };
            let public_key_plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                public_key_enc,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;
            // a malformed entry cannot be the requested key, and should not
            // stop the search for it
            let Ok(public_key) =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    &public_key_plaintext,
                )
            else {
                continue;
            };

            if public_key.to_bytes() == request_bytes {
                let private_key_enc =
                    private_key.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Matching entry has no private key")
                    })?;

                let private_key_plaintext = decrypt_cipher(
                    state.clone(),
                    &environment,
                    private_key_enc,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await?;

                let private_key =
                    ssh_agent_lib::ssh_key::PrivateKey::from_openssh(
                        private_key_plaintext,
                    )
                    .map_err(anyhow::Error::new)?;
                let name = decrypt_cipher(
                    state.clone(),
                    &environment,
                    &entry.name,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await?;
                return Ok((name, private_key));
            }
        }
    }

    Err(anyhow::anyhow!("No matching private key found"))
}
