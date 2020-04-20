use anyhow::Context as _;

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedCipher {
    id: String,
    name: String,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
    history: Vec<DecryptedHistoryEntry>,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedHistoryEntry {
    last_used_date: String,
    password: String,
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

    let mut ciphers: Vec<DecryptedCipher> = db
        .entries
        .iter()
        .cloned()
        .map(|entry| decrypt_cipher(&entry))
        .collect::<anyhow::Result<_>>()?;
    ciphers.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    for cipher in ciphers {
        println!("{}", cipher.name);
    }

    Ok(())
}

pub fn get(name: &str, user: Option<&str>, full: bool) -> anyhow::Result<()> {
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

    let (_, decrypted) = find_entry(&db, name, user)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;
    if let Some(password) = decrypted.password {
        println!("{}", password);
    } else {
        eprintln!("entry for '{}' had no password", desc);
    }

    if full {
        if let Some(notes) = decrypted.notes {
            println!("\n{}", notes);
        }
    }

    Ok(())
}

pub fn add(
    name: &str,
    username: Option<&str>,
    uris: Vec<&str>,
) -> anyhow::Result<()> {
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

    let (password, notes) = parse_editor(&contents);
    let password = password
        .map(|password| crate::actions::encrypt(&password))
        .transpose()?;
    let notes = notes
        .map(|notes| crate::actions::encrypt(&notes))
        .transpose()?;
    let uris: Vec<String> = uris
        .iter()
        .map(|uri| crate::actions::encrypt(&uri))
        .collect::<anyhow::Result<_>>()?;

    if let (Some(access_token), ()) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &name,
        username.as_deref(),
        password.as_deref(),
        notes.as_deref(),
        &uris,
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
    uris: Vec<&str>,
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
        let uris: Vec<String> = uris
            .iter()
            .map(|uri| crate::actions::encrypt(&uri))
            .collect::<anyhow::Result<_>>()?;

        if let (Some(access_token), ()) = rbw::actions::add(
            &access_token,
            &refresh_token,
            &name,
            username.as_deref(),
            Some(&password),
            None,
            &uris,
        )? {
            db.access_token = Some(access_token);
            db.save(&email).context("failed to save database")?;
        }

        crate::actions::sync()?;
    }

    Ok(())
}

pub fn edit(name: &str, username: Option<&str>) -> anyhow::Result<()> {
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

    let (entry, decrypted) = find_entry(&db, name, username)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;

    let mut contents =
        format!("{}\n", decrypted.password.unwrap_or_else(String::new));
    if let Some(notes) = decrypted.notes {
        contents.push_str(&format!("\n{}\n", notes));
    }

    let contents = rbw::edit::edit(&contents, HELP)?;

    let (password, notes) = parse_editor(&contents);
    let password = password
        .map(|password| crate::actions::encrypt(&password))
        .transpose()?;
    let notes = notes
        .map(|notes| crate::actions::encrypt(&notes))
        .transpose()?;
    let mut history = entry.history.clone();
    let new_history_entry = rbw::db::HistoryEntry {
        last_used_date: format!(
            "{}",
            humantime::format_rfc3339(std::time::SystemTime::now())
        ),
        password: entry.password.unwrap_or_else(String::new),
    };
    history.insert(0, new_history_entry);

    if let (Some(access_token), ()) = rbw::actions::edit(
        &access_token,
        &refresh_token,
        &entry.id,
        &entry.name,
        entry.username.as_deref(),
        password.as_deref(),
        notes.as_deref(),
        &history,
    )? {
        db.access_token = Some(access_token);
        db.save(&email).context("failed to save database")?;
    }

    crate::actions::sync()?;
    Ok(())
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

    let (entry, _) = find_entry(&db, name, username)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;

    if let (Some(access_token), ()) =
        rbw::actions::remove(&access_token, &refresh_token, &entry.id)?
    {
        db.access_token = Some(access_token);
        db.save(&email).context("failed to save database")?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn history(name: &str, username: Option<&str>) -> anyhow::Result<()> {
    unlock()?;

    let email = config_email()?;
    let db = rbw::db::Db::load(&email)
        .context("failed to load password database")?;

    let desc = format!(
        "{}{}",
        username
            .map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );

    let (_, decrypted) = find_entry(&db, name, username)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;
    for history in decrypted.history {
        println!("{}: {}", history.last_used_date, history.password);
    }

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
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    let ciphers: Vec<(rbw::db::Entry, DecryptedCipher)> = db
        .entries
        .iter()
        .cloned()
        .map(|entry| {
            decrypt_cipher(&entry).map(|decrypted| (entry, decrypted))
        })
        .collect::<anyhow::Result<_>>()?;
    find_entry_raw(&ciphers, name, username)
}

fn find_entry_raw(
    entries: &[(rbw::db::Entry, DecryptedCipher)],
    name: &str,
    username: Option<&str>,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    let exact_matches: Vec<(rbw::db::Entry, DecryptedCipher)> = entries
        .iter()
        .cloned()
        .filter(|(_, decrypted_cipher)| {
            name == decrypted_cipher.name
                && if let Some(username) = username {
                    decrypted_cipher.username.as_deref() == Some(username)
                } else {
                    true
                }
        })
        .collect();

    if exact_matches.is_empty() {
        let partial_matches: Vec<(rbw::db::Entry, DecryptedCipher)> = entries
            .iter()
            .cloned()
            .filter(|(_, decrypted_cipher)| {
                decrypted_cipher.name.contains(name)
                    && if let Some(username) = username {
                        if let Some(decrypted_username) =
                            &decrypted_cipher.username
                        {
                            decrypted_username.contains(username)
                        } else {
                            false
                        }
                    } else {
                        true
                    }
            })
            .collect();

        if partial_matches.is_empty() {
            Err(anyhow::anyhow!("no entry found"))
        } else if partial_matches.len() > 1 {
            let entries: Vec<String> = partial_matches
                .iter()
                .map(|(_, decrypted)| {
                    if let Some(username) = &decrypted.username {
                        format!("{}@{}", username, decrypted.name)
                    } else {
                        decrypted.name.clone()
                    }
                })
                .collect();
            let entries = entries.join(", ");
            Err(anyhow::anyhow!("multiple entries found: {}", entries))
        } else {
            Ok(partial_matches[0].clone())
        }
    } else if exact_matches.len() > 1 {
        let entries: Vec<String> = exact_matches
            .iter()
            .map(|(_, decrypted)| {
                if let Some(username) = &decrypted.username {
                    format!("{}@{}", username, decrypted.name)
                } else {
                    decrypted.name.clone()
                }
            })
            .collect();
        let entries = entries.join(", ");
        Err(anyhow::anyhow!("multiple entries found: {}", entries))
    } else {
        Ok(exact_matches[0].clone())
    }
}

fn decrypt_cipher(entry: &rbw::db::Entry) -> anyhow::Result<DecryptedCipher> {
    let username = entry
        .username
        .as_ref()
        .map(|username| crate::actions::decrypt(username))
        .transpose();
    let username = match username {
        Ok(username) => username,
        Err(e) => {
            log::warn!("failed to decrypt username: {}", e);
            None
        }
    };
    let password = entry
        .password
        .as_ref()
        .map(|password| crate::actions::decrypt(password))
        .transpose();
    let password = match password {
        Ok(password) => password,
        Err(e) => {
            log::warn!("failed to decrypt password: {}", e);
            None
        }
    };
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| crate::actions::decrypt(notes))
        .transpose();
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {}", e);
            None
        }
    };
    let history = entry
        .history
        .iter()
        .map(|entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: entry.last_used_date.clone(),
                password: crate::actions::decrypt(&entry.password)?,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(DecryptedCipher {
        id: entry.id.clone(),
        name: crate::actions::decrypt(&entry.name)?,
        username,
        password,
        notes,
        history,
    })
}

fn parse_editor(contents: &str) -> (Option<String>, Option<String>) {
    let mut lines = contents.lines();

    let password = lines.next().map(std::string::ToString::to_string);

    let mut notes: String = lines
        .skip_while(|line| *line == "")
        .filter(|line| !line.starts_with('#'))
        .map(|line| format!("{}\n", line))
        .collect();
    while notes.ends_with('\n') {
        notes.pop();
    }
    let notes = if notes == "" { None } else { Some(notes) };

    (password, notes)
}

fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = config.email {
        Ok(email)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_find_entry() {
        let entries = &[
            make_entry("github", Some("foo")),
            make_entry("gitlab", Some("foo")),
            make_entry("gitlab", Some("bar")),
            make_entry("gitter", Some("baz")),
            make_entry("git", Some("foo")),
            make_entry("bitwarden", None),
        ];

        assert!(one_match(entries, "github", Some("foo"), 0), "foo@github");
        assert!(one_match(entries, "github", None, 0), "github");
        assert!(one_match(entries, "gitlab", Some("foo"), 1), "foo@gitlab");
        assert!(one_match(entries, "git", Some("bar"), 2), "bar@git");
        assert!(one_match(entries, "gitter", Some("ba"), 3), "ba@gitter");
        assert!(one_match(entries, "git", Some("foo"), 4), "foo@git");
        assert!(one_match(entries, "git", None, 4), "git");
        assert!(one_match(entries, "bitwarden", None, 5), "bitwarden");

        assert!(no_matches(entries, "gitlab", Some("baz")), "baz@gitlab");
        assert!(
            no_matches(entries, "bitbucket", Some("foo")),
            "foo@bitbucket"
        );

        assert!(many_matches(entries, "gitlab", None), "gitlab");
        assert!(many_matches(entries, "gi", Some("foo")), "foo@gi");
        assert!(many_matches(entries, "git", Some("ba")), "ba@git");
    }

    fn one_match(
        entries: &[(rbw::db::Entry, DecryptedCipher)],
        name: &str,
        username: Option<&str>,
        idx: usize,
    ) -> bool {
        entries_eq(
            &find_entry_raw(entries, name, username).unwrap(),
            &entries[idx],
        )
    }

    fn no_matches(
        entries: &[(rbw::db::Entry, DecryptedCipher)],
        name: &str,
        username: Option<&str>,
    ) -> bool {
        let res = find_entry_raw(entries, name, username);
        if let Err(e) = res {
            format!("{}", e).contains("no entry found")
        } else {
            false
        }
    }

    fn many_matches(
        entries: &[(rbw::db::Entry, DecryptedCipher)],
        name: &str,
        username: Option<&str>,
    ) -> bool {
        let res = find_entry_raw(entries, name, username);
        if let Err(e) = res {
            format!("{}", e).contains("multiple entries found")
        } else {
            false
        }
    }

    fn entries_eq(
        a: &(rbw::db::Entry, DecryptedCipher),
        b: &(rbw::db::Entry, DecryptedCipher),
    ) -> bool {
        a.0 == b.0 && a.1 == b.1
    }

    fn make_entry(
        name: &str,
        username: Option<&str>,
    ) -> (rbw::db::Entry, DecryptedCipher) {
        (
            rbw::db::Entry {
                id: "irrelevant".to_string(),
                name: "this is the encrypted name".to_string(),
                username: username
                    .map(|_| "this is the encrypted username".to_string()),
                password: None,
                notes: None,
                history: vec![],
            },
            DecryptedCipher {
                id: "irrelevant".to_string(),
                name: name.to_string(),
                username: username.map(std::string::ToString::to_string),
                password: None,
                notes: None,
                history: vec![],
            },
        )
    }
}
