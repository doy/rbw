use anyhow::Context as _;

#[derive(Debug, Clone)]
struct DecryptedCipher {
    id: String,
    name: String,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
}

const HELP: &str = r#"
# The first line of this file will be the password, and the remainder of the
# file (after any blank lines after the password) will be stored as a note.
# Lines with leading # will be ignored.
"#;

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
    for entry in db.entries {
        println!(
            "{}",
            crate::actions::decrypt(&entry.name)
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

    let entry = find_entry(&db, name, user)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;
    if let Some(password) = entry.password {
        println!("{}", password);
    } else {
        eprintln!("entry for '{}' had no password", desc);
    }

    Ok(())
}

pub fn add(name: &str, username: Option<&str>) -> anyhow::Result<()> {
    unlock()?;

    let email = config_email()?;
    let mut db = rbw::db::Db::load(&email)?;
    // unwrap is safe here because the call to unlock above is guaranteed to
    // populate these or error
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let name = crate::actions::encrypt(name)?;

    let username = username
        .map(|username| crate::actions::encrypt(username))
        .transpose()?;

    let contents = rbw::edit::edit("", HELP)?;
    let mut lines = contents.lines();

    // XXX unwrap
    let password = lines.next().unwrap();
    let password = crate::actions::encrypt(password)?;

    let mut notes: String = lines
        .skip_while(|line| *line == "")
        .filter(|line| !line.starts_with('#'))
        .map(|line| format!("{}\n", line))
        .collect();
    while notes.ends_with('\n') {
        notes.pop();
    }
    let notes = if notes == "" {
        None
    } else {
        Some(crate::actions::encrypt(&notes)?)
    };

    if let Some(access_token) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &name,
        username.as_deref(),
        Some(&password),
        notes.as_deref(),
    )? {
        db.access_token = Some(access_token);
        db.save(&email).context("failed to save database")?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{}", password);

    if let Some(name) = name {
        unlock()?;

        let email = config_email()?;
        let mut db = rbw::db::Db::load(&email)?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let access_token = db.access_token.as_ref().unwrap();
        let refresh_token = db.refresh_token.as_ref().unwrap();

        let name = crate::actions::encrypt(name)?;
        let username = username
            .map(|username| crate::actions::encrypt(username))
            .transpose()?;
        let password = crate::actions::encrypt(&password)?;

        if let Some(access_token) = rbw::actions::add(
            &access_token,
            &refresh_token,
            &name,
            username.as_deref(),
            Some(&password),
            None,
        )? {
            db.access_token = Some(access_token);
            db.save(&email).context("failed to save database")?;
        }

        crate::actions::sync()?;
    }

    Ok(())
}

pub fn edit() -> anyhow::Result<()> {
    unlock()?;

    todo!()
}

pub fn remove(name: &str, username: Option<&str>) -> anyhow::Result<()> {
    unlock()?;

    let email = config_email()?;
    let mut db = rbw::db::Db::load(&email)
        .context("failed to load password database")?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username
            .map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );

    let entry = find_entry(&db, name, username)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;

    if let Some(access_token) =
        rbw::actions::remove(&access_token, &refresh_token, &entry.id)?
    {
        db.access_token = Some(access_token);
        db.save(&email).context("failed to save database")?;
    }

    crate::actions::sync()?;

    Ok(())
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

fn find_entry(
    db: &rbw::db::Db,
    name: &str,
    username: Option<&str>,
) -> anyhow::Result<DecryptedCipher> {
    let ciphers: anyhow::Result<Vec<DecryptedCipher>> = db
        .entries
        .iter()
        .cloned()
        .map(decrypt_cipher)
        .filter(|res| {
            if let Ok(decrypted_cipher) = res {
                name == decrypted_cipher.name
                    && if let Some(username) = username {
                        decrypted_cipher.username.as_deref() == Some(username)
                    } else {
                        true
                    }
            } else {
                true
            }
        })
        .collect();
    let ciphers = ciphers?;

    if ciphers.is_empty() {
        Err(anyhow::anyhow!("no entry found"))
    } else if ciphers.len() > 1 {
        let users: Vec<String> = ciphers
            .iter()
            .map(|cipher| {
                cipher
                    .username
                    .clone()
                    .unwrap_or_else(|| "(no login)".to_string())
            })
            .collect();
        let users = users.join(", ");
        Err(anyhow::anyhow!("multiple entries found: {}", users))
    } else {
        Ok(ciphers[0].clone())
    }
}

fn decrypt_cipher(entry: rbw::db::Entry) -> anyhow::Result<DecryptedCipher> {
    Ok(DecryptedCipher {
        id: entry.id.clone(),
        name: crate::actions::decrypt(&entry.name)?,
        username: entry
            .username
            .as_ref()
            .map(|username| crate::actions::decrypt(username))
            .transpose()?,
        password: entry
            .password
            .as_ref()
            .map(|password| crate::actions::decrypt(password))
            .transpose()?,
        notes: entry
            .notes
            .as_ref()
            .map(|notes| crate::actions::decrypt(notes))
            .transpose()?,
    })
}

fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = config.email {
        Ok(email)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}
