use anyhow::Context as _;

pub fn config_show() -> anyhow::Result<()> {
    let config =
        rbw::config::Config::load().context("failed to load config")?;
    serde_json::to_writer_pretty(std::io::stdout(), &config)
        .context("failed to write config to stdout")?;
    println!();

    Ok(())
}

pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "lock_timeout" => {
            config.lock_timeout = value
                .parse()
                .context("failed to parse value for lock_timeout")?
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {}", key)),
    }
    config.save().context("failed to save config file")?;

    Ok(())
}

pub fn login() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;

    Ok(())
}

pub fn unlock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::unlock()?;

    Ok(())
}

pub fn sync() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::sync()?;

    Ok(())
}

pub fn list() -> anyhow::Result<()> {
    unlock()?;

    let email = config_email()?;
    let db = rbw::db::Db::load(&email)
        .context("failed to load password database")?;
    for cipher in db.ciphers {
        println!(
            "{}",
            crate::actions::decrypt(&cipher.name)
                .context("failed to decrypt entry name")?
        );
    }

    Ok(())
}

pub fn get(name: &str, user: Option<&str>) -> anyhow::Result<()> {
    unlock()?;

    let email = config_email()?;
    let db = rbw::db::Db::load(&email)
        .context("failed to load password database")?;
    let desc = format!(
        "{}{}",
        user.map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );
    for cipher in db.ciphers {
        let cipher_name = crate::actions::decrypt(&cipher.name)
            .context("failed to decrypt entry name")?;
        if name == cipher_name {
            if let Some(user) = user {
                if let Some(encrypted_user) = &cipher.login.username {
                    let cipher_user = crate::actions::decrypt(encrypted_user)
                        .context("failed to decrypt entry username")?;
                    if user == cipher_user {
                        if let Some(encrypted_pass) = &cipher.login.password {
                            let pass =
                                crate::actions::decrypt(encrypted_pass)
                                    .context(
                                        "failed to decrypt entry password",
                                    )?;
                            println!("{}", pass);
                        } else {
                            eprintln!("no password found for entry {}", desc);
                        }
                        return Ok(());
                    }
                }
            } else {
                if let Some(encrypted_pass) = &cipher.login.password {
                    let pass = crate::actions::decrypt(encrypted_pass)
                        .context("failed to decrypt entry password")?;
                    println!("{}", pass);
                } else {
                    eprintln!("no password found for entry {}", desc);
                }
                return Ok(());
            }
        }
    }

    eprintln!("no entry found for {}", desc);
    Ok(())
}

pub fn add() -> anyhow::Result<()> {
    unlock()?;

    todo!()
}

pub fn generate(
    name: Option<&str>,
    user: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let pw = rbw::pwgen::pwgen(ty, len);
    // unwrap is safe because pwgen is guaranteed to always return valid utf8
    println!("{}", std::str::from_utf8(pw.data()).unwrap());

    if name.is_some() && user.is_some() {
        unlock()?;

        todo!();
    }

    Ok(())
}

pub fn edit() -> anyhow::Result<()> {
    unlock()?;

    todo!()
}

pub fn remove() -> anyhow::Result<()> {
    unlock()?;

    todo!()
}

pub fn lock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::lock()?;

    Ok(())
}

pub fn purge() -> anyhow::Result<()> {
    stop_agent()?;

    let email = config_email()?;
    rbw::db::Db::remove(&email).context("failed to remove database")?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

fn ensure_agent() -> anyhow::Result<()> {
    let agent_path = std::env::var("RBW_AGENT");
    let agent_path = agent_path
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("rbw-agent");
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!(
                    "failed to run rbw-agent: {}",
                    status
                ));
            }
        }
    }

    Ok(())
}

fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = config.email {
        Ok(email)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}
