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
                        .context("failed to log in to bitwarden instance");
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
            match rbw::actions::login(&email, password.clone(), None, None)
                .await
            {
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
                        Some(sock),
                        environment,
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
                    providers_data,
                    sso_email_2fa_session_token,
                }) => {
                    let supported_types = vec![
                        rbw::api::TwoFactorProviderType::Authenticator,
                        rbw::api::TwoFactorProviderType::Yubikey,
                        rbw::api::TwoFactorProviderType::Email,
                    ];
                    let has_other_supported = supported_types
                        .iter()
                        .any(|p| providers.contains(p));

                    if rbw::fido2::is_supported()
                        && providers.contains(
                            &rbw::api::TwoFactorProviderType::WebAuthn,
                        )
                        && let Some(webauthn_opts) =
                            rbw::api::parse_webauthn_2fa_options(
                                &providers_data,
                            )
                    {
                        let device_connected = tokio::task::spawn_blocking(
                            rbw::fido2::has_connected_device,
                        )
                        .await
                        .unwrap_or(false);
                        let use_webauthn = device_connected
                            || (!has_other_supported
                                && wait_for_fido2_device(Some(sock)).await);
                        if use_webauthn {
                            let (
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                            ) = two_factor_webauthn(
                                sock,
                                environment,
                                &email,
                                password.clone(),
                                &webauthn_opts,
                            )
                            .await?;
                            login_success(
                                Some(sock),
                                environment,
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

                    for provider in supported_types {
                        if providers.contains(&provider) {
                            if provider
                                == rbw::api::TwoFactorProviderType::Email
                                && let Some(sso_email_2fa_session_token) =
                                    sso_email_2fa_session_token
                            {
                                rbw::actions::send_two_factor_email(
                                    &email,
                                    &sso_email_2fa_session_token,
                                )
                                .await?;
                            }
                            let (
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                            ) = two_factor(
                                environment,
                                &email,
                                password.clone(),
                                provider,
                            )
                            .await?;
                            login_success(
                                Some(sock),
                                environment,
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
                        .context("failed to log in to bitwarden instance");
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn login_passkey(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let mut db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        if !rbw::fido2::is_supported() {
            return Err(rbw::error::Error::Fido2Unsupported {
                message: "rbw was compiled without the `fido2` feature"
                    .to_string(),
            })
            .context("failed to log in with passkey");
        }

        let config = rbw::config::Config::load_async().await?;
        let email = config.email.clone().ok_or_else(|| {
            anyhow::anyhow!("failed to find email address in config")
        })?;
        let ui_url = config.ui_url();
        let origin = rbw::fido2::webauthn_origin_from_ui_url(&ui_url)
            .context("failed to derive WebAuthn origin from ui_url")?;

        let options_res = rbw::actions::webauthn_login_assertion_options()
            .await
            .context("failed to fetch passkey login options")?;
        let rp_id = match options_res.options.rp_id {
            Some(rp_id) if !rp_id.is_empty() => rp_id,
            _ => rbw::fido2::rp_id_from_ui_url(&ui_url)
                .context("failed to derive WebAuthn rpId from ui_url")?,
        };

        if !wait_for_fido2_device(Some(sock)).await {
            return Err(rbw::error::Error::Fido2NoDevice)
                .context("failed to log in with passkey");
        }

        let challenge = options_res.options.challenge.clone();
        let rp_id_for_assert = rp_id.clone();
        let assertion = run_fido2_with_pin_retry(
            Some(sock),
            &config,
            environment,
            None,
            &[],
            false,
            true,
            rbw::fido2::UvPolicy::Required,
            "Touch your security key to log in...",
            move |pin| {
                let rp_id = rp_id_for_assert.clone();
                let origin = origin.clone();
                let challenge = challenge.clone();
                let email = email.clone();
                async move {
                    tokio::task::spawn_blocking(move || {
                        let pin_str = pin_as_str(pin.as_ref())?;
                        rbw::fido2::assert_passkey_login(
                            &rp_id,
                            &origin,
                            &challenge,
                            Some(&email),
                            pin_str,
                        )
                    })
                    .await
                    .map_err(|e| rbw::error::Error::Fido2 {
                        message: format!("FIDO2 task failed: {e}"),
                    })?
                }
            },
        )
        .await
        .context("failed to authenticate with passkey")?;

        let login_res = rbw::actions::login_webauthn(
            &options_res.token,
            &assertion.payload_json,
        )
        .await
        .context("failed to log in to bitwarden instance with passkey")?;

        db.access_token = Some(login_res.access_token);
        db.refresh_token = Some(login_res.refresh_token);
        if let Some(kdf) = login_res.kdf {
            db.kdf = Some(kdf);
        }
        if let Some(iterations) = login_res.kdf_iterations {
            db.iterations = Some(iterations);
        }
        if login_res.kdf_memory.is_some() {
            db.memory = login_res.kdf_memory;
        }
        if login_res.kdf_parallelism.is_some() {
            db.parallelism = login_res.kdf_parallelism;
        }
        if let Some(key) = login_res.key {
            db.protected_key = Some(key);
        }
        if let Some(ref prf_opt) = login_res.webauthn_prf_option {
            db.webauthn_prf = Some(rbw::db::WebAuthnPrfData {
                rp_id,
                credential_id: prf_opt
                    .credential_id
                    .clone()
                    .unwrap_or_else(|| assertion.credential_id.clone()),
                encrypted_private_key: prf_opt.encrypted_private_key.clone(),
                encrypted_user_key: prf_opt.encrypted_user_key.clone(),
            });
        }
        save_db(&db).await?;

        sync(None, state.clone()).await?;
        let db = load_db().await?;

        if let (Some(prf_output), Some(prf_opt)) =
            (assertion.prf_output, login_res.webauthn_prf_option)
        {
            let Some(protected_private_key) = db.protected_private_key else {
                return Err(anyhow::anyhow!(
                    "failed to find protected private key in db"
                ));
            };
            let user_key = rbw::actions::decrypt_user_key_with_prf(
                &prf_output,
                &prf_opt.encrypted_private_key,
                &prf_opt.encrypted_user_key,
            )
            .context("failed to decrypt vault key with WebAuthn PRF")?;
            let (keys, org_keys) = rbw::actions::unlock_with_user_key(
                user_key,
                &protected_private_key,
                &db.protected_org_keys,
            )
            .context("failed to unlock database")?;
            unlock_success(state, keys, org_keys).await?;
        } else {
            send_status(
                Some(sock),
                "Passkey logged in without vault encryption PRF; unlocking vault...",
            )
            .await;
            unlock_state(Some(sock), state, environment).await?;
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

async fn two_factor_webauthn(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    options: &rbw::api::WebAuthnAssertionOptions,
) -> anyhow::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let config = rbw::config::Config::load_async().await?;
    let ui_url = config.ui_url();
    let origin = rbw::fido2::webauthn_origin_from_ui_url(&ui_url)
        .context("failed to derive WebAuthn origin from ui_url")?;
    let rp_id = match &options.rp_id {
        Some(rp_id) if !rp_id.is_empty() => rp_id.clone(),
        _ => rbw::fido2::rp_id_from_ui_url(&ui_url)
            .context("failed to derive WebAuthn rpId from ui_url")?,
    };
    let allow_credentials: Vec<Vec<u8>> = options
        .allow_credentials
        .iter()
        .filter_map(|c| rbw::base64::decode_url_safe(&c.id).ok())
        .collect();
    let uv_policy = rbw::fido2::UvPolicy::from_webauthn_str(
        options.user_verification.as_deref(),
    );
    let appid = options.extensions.as_ref().and_then(|e| e.appid.clone());
    let challenge = options.challenge.clone();

    let rp_id_for_op = rp_id.clone();
    let allow_credentials_for_op = allow_credentials.clone();
    let token_json = run_fido2_with_pin_retry(
        Some(sock),
        &config,
        environment,
        Some(&rp_id),
        &allow_credentials,
        false,
        false,
        uv_policy,
        "Touch your security key to complete 2FA...",
        move |pin| {
            let rp_id = rp_id_for_op.clone();
            let origin = origin.clone();
            let challenge = challenge.clone();
            let allow_credentials = allow_credentials_for_op.clone();
            let appid = appid.clone();
            async move {
                tokio::task::spawn_blocking(move || {
                    let pin_str = pin_as_str(pin.as_ref())?;
                    rbw::fido2::assert_webauthn_2fa(
                        &rp_id,
                        &origin,
                        &challenge,
                        &allow_credentials,
                        appid.as_deref(),
                        uv_policy,
                        pin_str,
                    )
                })
                .await
                .map_err(|e| rbw::error::Error::Fido2 {
                    message: format!("FIDO2 task failed: {e}"),
                })?
            }
        },
    )
    .await
    .context("failed to complete WebAuthn 2FA")?;

    rbw::actions::login(
        email,
        password,
        Some(&token_json),
        Some(rbw::api::TwoFactorProviderType::WebAuthn),
    )
    .await
    .context("failed to log in to bitwarden instance")
}

async fn two_factor(
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    provider: rbw::api::TwoFactorProviderType,
) -> anyhow::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
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
            provider.header(),
            provider.message(),
            err.as_deref(),
            environment,
            provider.grab(),
        )
        .await
        .context("failed to read code from pinentry")?;
        let code = std::str::from_utf8(code.password())
            .context("code was not valid utf8")?;
        match rbw::actions::login(
            email,
            password.clone(),
            Some(code),
            Some(provider),
        )
        .await
        {
            Ok((
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
            )) => {
                return Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
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
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
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
                    .context("failed to log in to bitwarden instance");
            }
        }
    }

    unreachable!()
}

async fn login_success(
    sock: Option<&mut crate::sock::Sock>,
    environment: &rbw::protocol::Environment,
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

    let identity = rbw::identity::Identity::new(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
    )
    .context("failed to unlock database")?;

    let res = rbw::actions::unlock_with_master_keys(
        &identity.keys,
        &protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys)) => {
            let mut state = state.lock().await;
            state.priv_key = Some(keys);
            state.org_keys = Some(org_keys);
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    store_touchid_key_if_enabled(&email, identity.keys.clone()).await;
    enroll_yubikey_if_enabled(sock, environment, &email, identity.keys).await;

    Ok(())
}

async fn store_touchid_key_if_enabled(
    email: &str,
    master_keys: rbw::locked::Keys,
) {
    let config = match rbw::config::Config::load_async().await {
        Ok(config) => config,
        Err(e) => {
            log::warn!("failed to load config for touch id storage: {e}");
            return;
        }
    };
    if !config.touchid {
        return;
    }

    let profile = rbw::dirs::profile();
    let server = config.server_name();
    let email = email.to_string();
    match tokio::task::spawn_blocking(move || {
        rbw::touchid::store_key(&profile, &server, &email, &master_keys)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            log::warn!("failed to store touch id key in keychain: {e}");
        }
        Err(e) => {
            log::warn!("touch id key storage task failed: {e}");
        }
    }
}

async fn enroll_yubikey_if_enabled(
    mut sock: Option<&mut crate::sock::Sock>,
    environment: &rbw::protocol::Environment,
    email: &str,
    master_keys: rbw::locked::Keys,
) {
    if !rbw::fido2::is_supported() {
        return;
    }
    let config = match rbw::config::Config::load_async().await {
        Ok(config) => config,
        Err(e) => {
            log::warn!("failed to load config for YubiKey enrollment: {e}");
            return;
        }
    };
    if !config.yubikey {
        return;
    }
    let server = config.server_name();
    if rbw::yubikey::has_keys(&server, email) {
        return;
    }
    let has_device =
        tokio::task::spawn_blocking(rbw::fido2::has_connected_device)
            .await
            .unwrap_or(false);
    if !has_device {
        return;
    }

    let profile = rbw::dirs::profile();
    let require_uv = config.yubikey_uv;
    let uv_policy = if require_uv {
        rbw::fido2::UvPolicy::Required
    } else {
        rbw::fido2::UvPolicy::Discouraged
    };
    let email_owned = email.to_string();

    let res = run_fido2_with_pin_retry(
        sock.as_deref_mut(),
        &config,
        environment,
        None,
        &[],
        true,
        false,
        uv_policy,
        "Touch your security key twice to enroll for local unlock...",
        move |pin| {
            let profile = profile.clone();
            let server = server.clone();
            let email = email_owned.clone();
            let master_keys = master_keys.clone();
            async move {
                tokio::task::spawn_blocking(move || {
                    let pin_str = pin_as_str(pin.as_ref())?;
                    rbw::yubikey::enroll(
                        &profile,
                        &server,
                        &email,
                        None,
                        require_uv,
                        pin_str,
                        &master_keys,
                    )
                })
                .await
                .map_err(|e| rbw::error::Error::Fido2 {
                    message: format!("YubiKey enrollment task failed: {e}"),
                })?
            }
        },
    )
    .await;

    match res {
        Ok(entry) => {
            let msg = format!(
                "Enrolled security key '{}' for local vault unlock.",
                entry.label
            );
            send_status(sock, &msg).await;
        }
        Err(e) => {
            log::warn!("failed to auto-enroll YubiKey for local unlock: {e}");
        }
    }
}

pub async fn yubikey_enroll(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    label: Option<&str>,
) -> anyhow::Result<()> {
    if !rbw::fido2::is_supported() {
        return Err(rbw::error::Error::Fido2Unsupported {
            message: "rbw was compiled without the `fido2` feature"
                .to_string(),
        })
        .context("failed to enroll security key");
    }

    let config = rbw::config::Config::load_async().await?;
    let db = load_db().await?;
    let Some(email) = config.email.clone() else {
        return Err(anyhow::anyhow!("failed to find email address in config"));
    };
    let Some(kdf) = db.kdf else {
        return Err(anyhow::anyhow!("failed to find kdf type in db"));
    };
    let Some(iterations) = db.iterations else {
        return Err(anyhow::anyhow!(
            "failed to find number of iterations in db"
        ));
    };
    let Some(protected_key) = db.protected_key else {
        return Err(anyhow::anyhow!(
            "cannot enroll local YubiKey unlock: account has no master-password protected key"
        ));
    };
    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let mut err_msg = None;
    let mut verified_master_keys = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let password = rbw::pinentry::getpin(
            &config.pinentry,
            "Master Password",
            &format!(
                "Confirm master password to enroll a security key for '{}'",
                rbw::dirs::profile()
            ),
            err.as_deref(),
            environment,
            true,
        )
        .await
        .context("failed to read password from pinentry")?;
        let identity = rbw::identity::Identity::new(
            &email,
            &password,
            kdf,
            iterations,
            db.memory,
            db.parallelism,
        )
        .context("failed to derive master key")?;
        match rbw::actions::unlock_with_master_keys(
            &identity.keys,
            &protected_key,
            &protected_private_key,
            &db.protected_org_keys,
        ) {
            Ok((keys, org_keys)) => {
                unlock_success(state.clone(), keys, org_keys).await?;
                verified_master_keys = Some(identity.keys);
                break;
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to verify master password");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e).context("failed to verify master password");
            }
        }
    }

    let Some(master_keys) = verified_master_keys else {
        return Err(anyhow::anyhow!("failed to verify master password"));
    };

    if !wait_for_fido2_device(Some(sock)).await {
        return Err(rbw::error::Error::Fido2NoDevice)
            .context("failed to enroll security key");
    }

    let profile = rbw::dirs::profile();
    let server = config.server_name();
    let require_uv = config.yubikey_uv;
    let uv_policy = if require_uv {
        rbw::fido2::UvPolicy::Required
    } else {
        rbw::fido2::UvPolicy::Discouraged
    };
    let label_owned = label.map(std::string::ToString::to_string);

    let entry = run_fido2_with_pin_retry(
        Some(sock),
        &config,
        environment,
        None,
        &[],
        true,
        false,
        uv_policy,
        "Touch your security key twice to enroll (1: create credential, 2: verify hmac-secret)...",
        move |pin| {
            let profile = profile.clone();
            let server = server.clone();
            let email = email.clone();
            let label_owned = label_owned.clone();
            let master_keys = master_keys.clone();
            async move {
                tokio::task::spawn_blocking(move || {
                    let pin_str = pin_as_str(pin.as_ref())?;
                    rbw::yubikey::enroll(
                        &profile,
                        &server,
                        &email,
                        label_owned.as_deref(),
                        require_uv,
                        pin_str,
                        &master_keys,
                    )
                })
                .await
                .map_err(|e| rbw::error::Error::Fido2 {
                    message: format!("YubiKey enrollment task failed: {e}"),
                })?
            }
        },
    )
    .await
    .context("failed to enroll security key")?;

    let id_prefix: String = entry.credential_id.chars().take(12).collect();
    let msg = format!(
        "Enrolled security key '{}' ({id_prefix}..., uv={}).",
        entry.label, entry.uv
    );
    send_status(Some(sock), &msg).await;
    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_state(
    mut sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        let config = rbw::config::Config::load_async().await?;
        let db = load_db().await?;

        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let Some(email) = config.email.clone() else {
            return Err(anyhow::anyhow!(
                "failed to find email address in config"
            ));
        };

        // 1. Bitwarden Passkey PRF unlock (if logged in via passkey with PRF
        //    and a matching FIDO2 key is plugged in)
        if rbw::fido2::is_supported()
            && let Some(prf) = db.webauthn_prf.clone()
            && let Ok(cred_id) =
                rbw::base64::decode_url_safe(&prf.credential_id)
        {
            let rp_id_probe = prf.rp_id.clone();
            let cred_probe = cred_id.clone();
            let matched = tokio::task::spawn_blocking(move || {
                rbw::fido2::has_matching_credential(
                    &rp_id_probe,
                    &[cred_probe],
                )
            })
            .await
            .unwrap_or(false);

            if matched {
                let rp_id_eval = prf.rp_id.clone();
                let cred_eval = cred_id.clone();
                let prf_res = run_fido2_with_pin_retry(
                    sock.as_deref_mut(),
                    &config,
                    environment,
                    Some(&prf.rp_id),
                    std::slice::from_ref(&cred_id),
                    true,
                    false,
                    rbw::fido2::UvPolicy::Required,
                    "Touch your security key to unlock with passkey PRF...",
                    move |pin| {
                        let rp_id = rp_id_eval.clone();
                        let cred = cred_eval.clone();
                        async move {
                            tokio::task::spawn_blocking(move || {
                                let pin_str = pin_as_str(pin.as_ref())?;
                                rbw::fido2::eval_bitwarden_prf(
                                    &rp_id, &cred, pin_str,
                                )
                            })
                            .await
                            .map_err(|e| rbw::error::Error::Fido2 {
                                message: format!("FIDO2 PRF task failed: {e}"),
                            })?
                        }
                    },
                )
                .await;

                match prf_res {
                    Ok(mut prf_output) => {
                        let dec_res = rbw::actions::decrypt_user_key_with_prf(
                            &prf_output,
                            &prf.encrypted_private_key,
                            &prf.encrypted_user_key,
                        );
                        zeroize::Zeroize::zeroize(&mut prf_output);
                        match dec_res {
                            Ok(user_key) => {
                                let (keys, org_keys) =
                                    rbw::actions::unlock_with_user_key(
                                        user_key,
                                        &protected_private_key,
                                        &db.protected_org_keys,
                                    )
                                    .context("failed to unlock database")?;
                                unlock_success(state, keys, org_keys).await?;
                                return Ok(());
                            }
                            Err(e) => {
                                log::warn!(
                                    "passkey PRF unlock failed ({e}); falling back"
                                );
                            }
                        }
                    }
                    Err(rbw::error::Error::Fido2Cancelled) => {
                        return Err(rbw::error::Error::Fido2Cancelled)
                            .context("failed to unlock database");
                    }
                    Err(e) => {
                        log::warn!(
                            "passkey PRF authentication failed ({e}); falling back"
                        );
                    }
                }
            }
        }

        // 2. Local YubiKey hmac-secret unlock (when enabled and a matching
        //    enrolled key is connected)
        if rbw::fido2::is_supported()
            && config.yubikey
            && let Some(ref protected_key) = db.protected_key
        {
            let server = config.server_name();
            if let Ok(Some(store)) = rbw::yubikey::load_store(&server, &email)
                && !store.keys.is_empty()
            {
                let rp_id = store.rp_id.clone();
                let keys_for_probe = store.keys.clone();
                let matched_entry =
                    tokio::task::spawn_blocking(move || {
                        for entry in keys_for_probe {
                            if let Ok(cred_id) = rbw::base64::decode_url_safe(
                                &entry.credential_id,
                            ) && rbw::fido2::has_matching_credential(
                                &rp_id,
                                &[cred_id],
                            ) {
                                return Some(entry);
                            }
                        }
                        None
                    })
                    .await
                    .unwrap_or(None);

                if let Some(entry) = matched_entry {
                    let cred_id = rbw::base64::decode_url_safe(
                        &entry.credential_id,
                    )
                    .unwrap_or_default();
                    let uv_policy = if entry.uv {
                        rbw::fido2::UvPolicy::Required
                    } else {
                        rbw::fido2::UvPolicy::Discouraged
                    };
                    let rp_id_unlock = store.rp_id.clone();
                    let entry_for_unlock = entry.clone();
                    let status_msg = format!(
                        "Touch your security key '{}' to unlock...",
                        entry.label
                    );
                    let yk_res = run_fido2_with_pin_retry(
                        sock.as_deref_mut(),
                        &config,
                        environment,
                        Some(&store.rp_id),
                        std::slice::from_ref(&cred_id),
                        true,
                        false,
                        uv_policy,
                        &status_msg,
                        move |pin| {
                            let rp_id = rp_id_unlock.clone();
                            let entry = entry_for_unlock.clone();
                            async move {
                                tokio::task::spawn_blocking(move || {
                                    let pin_str = pin_as_str(pin.as_ref())?;
                                    rbw::yubikey::unlock_entry(
                                        &rp_id, &entry, pin_str,
                                    )
                                })
                                .await
                                .map_err(|e| rbw::error::Error::Fido2 {
                                    message: format!(
                                        "YubiKey unlock task failed: {e}"
                                    ),
                                })?
                            }
                        },
                    )
                    .await;

                    match yk_res {
                        Ok(master_keys) => {
                            match rbw::actions::unlock_with_master_keys(
                                &master_keys,
                                protected_key,
                                &protected_private_key,
                                &db.protected_org_keys,
                            ) {
                                Ok((keys, org_keys)) => {
                                    unlock_success(state, keys, org_keys)
                                        .await?;
                                    return Ok(());
                                }
                                Err(rbw::error::Error::IncorrectPassword {
                                    ..
                                }) => {
                                    log::warn!(
                                        "stored YubiKey key '{}' is no longer valid; \
                                        removing stale entry and falling back",
                                        entry.label
                                    );
                                    let _ = rbw::yubikey::remove_key(
                                        &server,
                                        &email,
                                        &entry.credential_id,
                                    );
                                }
                                Err(e) => {
                                    return Err(e)
                                        .context("failed to unlock database");
                                }
                            }
                        }
                        Err(rbw::error::Error::Fido2Cancelled) => {
                            return Err(rbw::error::Error::Fido2Cancelled)
                                .context("failed to unlock database");
                        }
                        Err(e) => {
                            log::warn!(
                                "YubiKey unlock failed ({e}); falling back"
                            );
                        }
                    }
                }
            }
        }

        // 3. macOS Touch ID unlock
        if config.touchid
            && let Some(ref protected_key) = db.protected_key
        {
            let profile = rbw::dirs::profile();
            let server = config.server_name();
            let email_for_touchid = email.clone();
            let reason = format!("unlock the local database for '{profile}'");
            let outcome = tokio::task::spawn_blocking(move || {
                rbw::touchid::unlock(
                    &profile,
                    &server,
                    &email_for_touchid,
                    &reason,
                )
            })
            .await
            .context("touch id authentication task failed")?;

            match outcome {
                rbw::touchid::AuthOutcome::Authenticated(master_keys) => {
                    match rbw::actions::unlock_with_master_keys(
                        &master_keys,
                        protected_key,
                        &protected_private_key,
                        &db.protected_org_keys,
                    ) {
                        Ok((keys, org_keys)) => {
                            unlock_success(state, keys, org_keys).await?;
                            return Ok(());
                        }
                        Err(rbw::error::Error::IncorrectPassword {
                            ..
                        }) => {
                            log::warn!(
                                "stored touch id key is no longer valid; \
                                falling back to master password"
                            );
                            let profile = rbw::dirs::profile();
                            let server = config.server_name();
                            let email_for_delete = email.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                rbw::touchid::delete_key(
                                    &profile,
                                    &server,
                                    &email_for_delete,
                                )
                            })
                            .await;
                        }
                        Err(e) => {
                            return Err(e)
                                .context("failed to unlock database");
                        }
                    }
                }
                rbw::touchid::AuthOutcome::Cancelled => {
                    return Err(rbw::error::Error::TouchIdCancelled)
                        .context("failed to unlock database");
                }
                rbw::touchid::AuthOutcome::Fallback => {}
            }
        }

        // 4. Master Password fallback via pinentry
        let (Some(kdf), Some(iterations), Some(protected_key)) =
            (db.kdf, db.iterations, db.protected_key)
        else {
            return Err(anyhow::anyhow!(
                "this account has no master password configured locally; \
                insert your FIDO2 security key and run `rbw unlock` again"
            ));
        };
        let memory = db.memory;
        let parallelism = db.parallelism;

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
                &config.pinentry,
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
            let identity = rbw::identity::Identity::new(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
            )
            .context("failed to unlock database")?;
            match rbw::actions::unlock_with_master_keys(
                &identity.keys,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok((keys, org_keys)) => {
                    unlock_success(state, keys, org_keys).await?;
                    store_touchid_key_if_enabled(
                        &email,
                        identity.keys.clone(),
                    )
                    .await;
                    enroll_yubikey_if_enabled(
                        sock.as_deref_mut(),
                        environment,
                        &email,
                        identity.keys,
                    )
                    .await;
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
    unlock_state(Some(sock), state, environment).await?;

    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    state.priv_key = Some(keys);
    state.org_keys = Some(org_keys);
    Ok(())
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
    state.lock().await.set_master_password_reprompt(&entries);
    if let Some(access_token) = access_token {
        db.access_token = Some(access_token);
    }
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;
    save_db(&db).await?;

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
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
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

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let Some(keys) = state.key(org_id) else {
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

async fn send_status(
    sock: Option<&mut crate::sock::Sock>,
    message: &str,
) {
    if let Some(sock) = sock {
        let _ = sock
            .send(&rbw::protocol::Response::Status {
                message: message.to_string(),
            })
            .await;
    }
}

fn pin_as_str(
    pin: Option<&rbw::locked::Password>,
) -> rbw::error::Result<Option<&str>> {
    pin.map(|p| {
        std::str::from_utf8(p.password()).map_err(|_| {
            rbw::error::Error::Fido2 {
                message: "FIDO2 PIN was not valid UTF-8".to_string(),
            }
        })
    })
    .transpose()
}

async fn wait_for_fido2_device(sock: Option<&mut crate::sock::Sock>) -> bool {
    if tokio::task::spawn_blocking(rbw::fido2::has_connected_device)
        .await
        .unwrap_or(false)
    {
        return true;
    }

    send_status(sock, "Insert your FIDO2 security key...").await;
    for _ in 0..60_u8 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if tokio::task::spawn_blocking(rbw::fido2::has_connected_device)
            .await
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

async fn run_fido2_with_pin_retry<T, F, Fut>(
    mut sock: Option<&mut crate::sock::Sock>,
    config: &rbw::config::Config,
    environment: &rbw::protocol::Environment,
    rp_id: Option<&str>,
    allow_credentials: &[Vec<u8>],
    require_hmac_secret: bool,
    require_rk: bool,
    uv_policy: rbw::fido2::UvPolicy,
    touch_message: &str,
    op: F,
) -> rbw::error::Result<T>
where
    F: Fn(Option<rbw::locked::Password>) -> Fut,
    Fut: std::future::Future<Output = rbw::error::Result<T>>,
{
    let rp_id_owned = rp_id.map(std::string::ToString::to_string);
    let allow_owned = allow_credentials.to_vec();
    let info = tokio::task::spawn_blocking(move || {
        rbw::fido2::inspect_device(
            rp_id_owned.as_deref(),
            &allow_owned,
            require_hmac_secret,
            require_rk,
        )
    })
    .await
    .map_err(|e| rbw::error::Error::Fido2 {
        message: format!("failed to inspect FIDO2 device: {e}"),
    })??;

    let decision = rbw::fido2::decide_uv_for_device(&info, uv_policy);
    let mut need_pin_product: Option<String> = match decision {
        rbw::fido2::PinDecision::PinNotSet => {
            return Err(rbw::error::Error::Fido2 {
                message: format!(
                    "{} requires a FIDO2 PIN or biometric UV; set a PIN first (e.g. `ykman fido access change-pin`)",
                    info.product_string
                ),
            });
        }
        rbw::fido2::PinDecision::PromptPin { product_string } => {
            Some(product_string)
        }
        rbw::fido2::PinDecision::NoPinNeeded
        | rbw::fido2::PinDecision::UseBuiltinUv => {
            send_status(sock.as_deref_mut(), touch_message).await;
            match op(None).await {
                Ok(val) => return Ok(val),
                Err(rbw::error::Error::Fido2PinRequired)
                    if info.has_client_pin =>
                {
                    Some(info.product_string.clone())
                }
                Err(e) => return Err(e),
            }
        }
    };

    let product = need_pin_product
        .take()
        .unwrap_or_else(|| info.product_string.clone());
    let mut err_msg: Option<String> = None;
    for attempt in 1_u8..=3 {
        let err = if attempt > 1 {
            err_msg
                .as_ref()
                .map(|m| format!("{m} (attempt {attempt}/3)"))
        } else {
            None
        };
        let pin = match rbw::pinentry::getpin(
            &config.pinentry,
            "FIDO2 PIN",
            &format!("Enter the FIDO2 PIN for {product}"),
            err.as_deref(),
            environment,
            true,
        )
        .await
        {
            Ok(pin) => pin,
            Err(rbw::error::Error::PinentryCancelled) => {
                return Err(rbw::error::Error::Fido2Cancelled);
            }
            Err(e) => return Err(e),
        };

        send_status(sock.as_deref_mut(), touch_message).await;
        match op(Some(pin)).await {
            Ok(val) => return Ok(val),
            Err(rbw::error::Error::Fido2PinInvalid { retries }) => {
                if attempt == 3 || retries == Some(0) {
                    return Err(rbw::error::Error::Fido2PinInvalid { retries });
                }
                err_msg = Some(retries.map_or_else(
                    || "Invalid FIDO2 PIN".to_string(),
                    |r| format!("Invalid FIDO2 PIN ({r} attempts remaining)"),
                ));
            }
            Err(e) => return Err(e),
        }
    }

    Err(rbw::error::Error::Fido2PinInvalid { retries: None })
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

async fn config_pinentry() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry)
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

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url)
        .await
        .err()
        .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
}

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<Vec<String>> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(None, state.clone(), &environment).await?;

    let db = load_db().await?;
    let mut pubkeys = Vec::new();

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        {
            let plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                encrypted,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;

            pubkeys.push(plaintext);
        }
    }

    Ok(pubkeys)
}

pub async fn find_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(None, state.clone(), &environment).await?;

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
            let public_key_bytes =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    &public_key_plaintext,
                )
                .map_err(anyhow::Error::new)?
                .to_bytes();

            if public_key_bytes == request_bytes {
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

                return ssh_agent_lib::ssh_key::PrivateKey::from_openssh(
                    private_key_plaintext,
                )
                .map_err(anyhow::Error::new);
            }
        }
    }

    Err(anyhow::anyhow!("No matching private key found"))
}
