use anyhow::Context as _;

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedCipher {
    id: String,
    folder: Option<String>,
    name: String,
    data: DecryptedData,
    notes: Option<String>,
    history: Vec<DecryptedHistoryEntry>,
}

impl DecryptedCipher {
    fn display_short(&self, desc: &str) -> bool {
        match &self.data {
            DecryptedData::Login { password, .. } => {
                if let Some(password) = password {
                    println!("{}", password);
                    true
                } else {
                    eprintln!("entry for '{}' had no password", desc);
                    false
                }
            }
            DecryptedData::Card { number, .. } => {
                if let Some(number) = number {
                    println!("{}", number);
                    true
                } else {
                    eprintln!("entry for '{}' had no card number", desc);
                    false
                }
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<_> =
                    [title, first_name, middle_name, last_name]
                        .iter()
                        .copied()
                        .cloned()
                        .filter_map(|x| x)
                        .collect();
                if names.is_empty() {
                    eprintln!("entry for '{}' had no name", desc);
                    false
                } else {
                    println!("{}", names.join(" "));
                    true
                }
            }
            DecryptedData::SecureNote {} => {
                if let Some(notes) = &self.notes {
                    println!("{}", notes);
                    true
                } else {
                    eprintln!("entry for '{}' had no notes", desc);
                    false
                }
            }
        }
    }

    fn display_long(&self, desc: &str) {
        match &self.data {
            DecryptedData::Login { .. } => {
                let displayed = self.display_short(desc);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{}", notes);
                }
            }
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                let mut displayed = self.display_short(desc);

                if let (Some(exp_month), Some(exp_year)) =
                    (exp_month, exp_year)
                {
                    println!("Expiration: {}/{}", exp_month, exp_year);
                    displayed = true;
                }
                displayed |= self.display_field("CVV", code.as_deref());
                displayed |=
                    self.display_field("Name", cardholder_name.as_deref());
                displayed |= self.display_field("Brand", brand.as_deref());

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{}", notes);
                }
            }
            DecryptedData::Identity {
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
                ..
            } => {
                let mut displayed = self.display_short(desc);

                displayed |=
                    self.display_field("Address", address1.as_deref());
                displayed |=
                    self.display_field("Address", address2.as_deref());
                displayed |=
                    self.display_field("Address", address3.as_deref());
                displayed |= self.display_field("City", city.as_deref());
                displayed |= self.display_field("State", state.as_deref());
                displayed |=
                    self.display_field("Postcode", postal_code.as_deref());
                displayed |=
                    self.display_field("Country", country.as_deref());
                displayed |= self.display_field("Phone", phone.as_deref());
                displayed |= self.display_field("Email", email.as_deref());
                displayed |= self.display_field("SSN", ssn.as_deref());
                displayed |=
                    self.display_field("License", license_number.as_deref());
                displayed |= self
                    .display_field("Passport", passport_number.as_deref());
                displayed |=
                    self.display_field("Username", username.as_deref());

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{}", notes);
                }
            }
            DecryptedData::SecureNote {} => {
                self.display_short(desc);
            }
        }
    }

    fn display_field(&self, name: &str, field: Option<&str>) -> bool {
        if let Some(field) = field {
            println!("{}: {}", name, field);
            true
        } else {
            false
        }
    }

    fn display_name(&self) -> String {
        match &self.data {
            DecryptedData::Login { username, .. } => {
                if let Some(username) = username {
                    format!("{}@{}", username, self.name)
                } else {
                    self.name.clone()
                }
            }
            _ => self.name.clone(),
        }
    }

    fn exact_match(&self, name: &str, username: Option<&str>) -> bool {
        if name != self.name {
            return false;
        }

        if let Some(given_username) = username {
            match &self.data {
                DecryptedData::Login { username, .. } => {
                    if let Some(found_username) = username {
                        return given_username == found_username;
                    }
                    return false;
                }
                _ => {
                    // not sure what else to do here, but open to suggestions
                    return false;
                }
            }
        }

        true
    }

    fn partial_match(&self, name: &str, username: Option<&str>) -> bool {
        if !self.name.contains(name) {
            return false;
        }

        if let Some(given_username) = username {
            match &self.data {
                DecryptedData::Login { username, .. } => {
                    if let Some(found_username) = username {
                        return found_username.contains(given_username);
                    }
                    return false;
                }
                _ => {
                    // not sure what else to do here, but open to suggestions
                    return false;
                }
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedHistoryEntry {
    last_used_date: String,
    password: String,
}

enum ListField {
    Name,
    Id,
    User,
    Folder,
}

impl std::convert::TryFrom<&str> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "name" => Self::Name,
            "id" => Self::Id,
            "user" => Self::User,
            "folder" => Self::Folder,
            _ => return Err(anyhow::anyhow!("unknown field {}", s)),
        })
    }
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

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = None,
        "base_url" => config.base_url = None,
        "identity_url" => config.identity_url = None,
        "lock_timeout" => {
            config.lock_timeout = rbw::config::default_lock_timeout()
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

pub fn list(fields: &[&str]) -> anyhow::Result<()> {
    let fields: Vec<ListField> = fields
        .iter()
        .copied()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;

    unlock()?;

    let db = load_db()?;
    let mut ciphers: Vec<DecryptedCipher> = db
        .entries
        .iter()
        .cloned()
        .map(|entry| decrypt_cipher(&entry))
        .collect::<anyhow::Result<_>>()?;
    ciphers.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    for cipher in ciphers {
        let values: Vec<String> = fields
            .iter()
            .map(|field| match field {
                ListField::Name => cipher.name.clone(),
                ListField::Id => cipher.id.clone(),
                ListField::User => match &cipher.data {
                    DecryptedData::Login { username, .. } => username
                        .as_ref()
                        .map(std::string::ToString::to_string)
                        .unwrap_or_else(|| "".to_string()),
                    _ => "".to_string(),
                },
                ListField::Folder => cipher
                    .folder
                    .as_ref()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_else(|| "".to_string()),
            })
            .collect();
        println!("{}", values.join("\t"));
    }

    Ok(())
}

pub fn get(name: &str, user: Option<&str>, full: bool) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );

    let (_, decrypted) = find_entry(&db, name, user)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;
    if full {
        decrypted.display_long(&desc);
    } else {
        decrypted.display_short(&desc);
    }

    Ok(())
}

pub fn add(
    name: &str,
    username: Option<&str>,
    uris: Vec<&str>,
    folder: Option<&str>,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    // unwrap is safe here because the call to unlock above is guaranteed to
    // populate these or error
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let name = crate::actions::encrypt(name, None)?;

    let username = username
        .map(|username| crate::actions::encrypt(username, None))
        .transpose()?;

    let contents = rbw::edit::edit("", HELP)?;

    let (password, notes) = parse_editor(&contents);
    let password = password
        .map(|password| crate::actions::encrypt(&password, None))
        .transpose()?;
    let notes = notes
        .map(|notes| crate::actions::encrypt(&notes, None))
        .transpose()?;
    let uris: Vec<String> = uris
        .iter()
        .map(|uri| crate::actions::encrypt(&uri, None))
        .collect::<anyhow::Result<_>>()?;

    let mut folder_id = None;
    if let Some(folder_name) = folder {
        let (new_access_token, folders) =
            rbw::actions::list_folders(&access_token, &refresh_token)?;
        if let Some(new_access_token) = new_access_token {
            access_token = new_access_token.clone();
            db.access_token = Some(new_access_token);
            save_db(&db)?;
        }

        let folders: Vec<(String, String)> = folders
            .iter()
            .cloned()
            .map(|(id, name)| Ok((id, crate::actions::decrypt(&name, None)?)))
            .collect::<anyhow::Result<_>>()?;

        for (id, name) in folders {
            if name == folder_name {
                folder_id = Some(id);
            }
        }
        if folder_id.is_none() {
            let (new_access_token, id) = rbw::actions::create_folder(
                &access_token,
                &refresh_token,
                &crate::actions::encrypt(folder_name, None)?,
            )?;
            if let Some(new_access_token) = new_access_token {
                access_token = new_access_token.clone();
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }
            folder_id = Some(id);
        }
    }

    if let (Some(access_token), ()) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &name,
        &rbw::db::EntryData::Login {
            username,
            password,
            uris,
        },
        notes.as_deref(),
        folder_id.as_deref(),
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: Vec<&str>,
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{}", password);

    if let Some(name) = name {
        unlock()?;

        let mut db = load_db()?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap();

        let name = crate::actions::encrypt(name, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None))
            .transpose()?;
        let password = crate::actions::encrypt(&password, None)?;
        let uris: Vec<String> = uris
            .iter()
            .map(|uri| crate::actions::encrypt(&uri, None))
            .collect::<anyhow::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (new_access_token, folders) =
                rbw::actions::list_folders(&access_token, &refresh_token)?;
            if let Some(new_access_token) = new_access_token {
                access_token = new_access_token.clone();
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }

            let folders: Vec<(String, String)> = folders
                .iter()
                .cloned()
                .map(|(id, name)| {
                    Ok((id, crate::actions::decrypt(&name, None)?))
                })
                .collect::<anyhow::Result<_>>()?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (new_access_token, id) = rbw::actions::create_folder(
                    &access_token,
                    &refresh_token,
                    &crate::actions::encrypt(folder_name, None)?,
                )?;
                if let Some(new_access_token) = new_access_token {
                    access_token = new_access_token.clone();
                    db.access_token = Some(new_access_token);
                    save_db(&db)?;
                }
                folder_id = Some(id);
            }
        }

        if let (Some(access_token), ()) = rbw::actions::add(
            &access_token,
            &refresh_token,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
            },
            None,
            folder_id.as_deref(),
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }

        crate::actions::sync()?;
    }

    Ok(())
}

pub fn edit(name: &str, username: Option<&str>) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
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

    let (data, notes, history) = match &decrypted.data {
        DecryptedData::Login { password, .. } => {
            let mut contents =
                format!("{}\n", password.as_deref().unwrap_or(""));
            if let Some(notes) = decrypted.notes {
                contents.push_str(&format!("\n{}\n", notes));
            }

            let contents = rbw::edit::edit(&contents, HELP)?;

            let (password, notes) = parse_editor(&contents);
            let password = password
                .map(|password| {
                    crate::actions::encrypt(
                        &password,
                        entry.org_id.as_deref(),
                    )
                })
                .transpose()?;
            let notes = notes
                .map(|notes| {
                    crate::actions::encrypt(&notes, entry.org_id.as_deref())
                })
                .transpose()?;
            let mut history = entry.history.clone();
            let (entry_username, entry_password, entry_uris) =
                match &entry.data {
                    rbw::db::EntryData::Login {
                        username,
                        password,
                        uris,
                    } => (username, password, uris),
                    _ => unreachable!(),
                };
            let new_history_entry = rbw::db::HistoryEntry {
                last_used_date: format!(
                    "{}",
                    humantime::format_rfc3339(std::time::SystemTime::now())
                ),
                password: entry_password.clone().unwrap_or_else(String::new),
            };
            history.insert(0, new_history_entry);
            let data = rbw::db::EntryData::Login {
                username: entry_username.clone(),
                password,
                uris: entry_uris.to_vec(),
            };
            (data, notes, history)
        }
        _ => {
            return Err(anyhow::anyhow!(
                "modifications are only supported for login entries"
            ));
        }
    };

    if let (Some(access_token), ()) = rbw::actions::edit(
        &access_token,
        &refresh_token,
        &entry.id,
        entry.org_id.as_deref(),
        &entry.name,
        &data,
        notes.as_deref(),
        entry.folder_id.as_deref(),
        &history,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

pub fn remove(name: &str, username: Option<&str>) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
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
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn history(name: &str, username: Option<&str>) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

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

    remove_db()?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

fn ensure_agent() -> anyhow::Result<()> {
    ensure_agent_once()?;
    let client_version = rbw::protocol::version();
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        log::debug!(
            "client protocol version is {} but agent protocol version is {}",
            client_version,
            agent_version
        );
        crate::actions::quit()?;
        ensure_agent_once()?;
        let agent_version = version_or_quit()?;
        if agent_version != client_version {
            crate::actions::quit()?;
            return Err(anyhow::anyhow!(
                "incompatible protocol versions: client ({}), agent ({})",
                client_version,
                agent_version
            ));
        }
    }
    Ok(())
}

fn ensure_agent_once() -> anyhow::Result<()> {
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

fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().or_else(|e| {
        let _ = crate::actions::quit();
        Err(e)
    })
}

fn find_entry(
    db: &rbw::db::Db,
    name: &str,
    username: Option<&str>,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    match uuid::Uuid::parse_str(name) {
        Ok(_) => {
            for cipher in &db.entries {
                if name == cipher.id {
                    return Ok((cipher.clone(), decrypt_cipher(&cipher)?));
                }
            }
            Err(anyhow::anyhow!("no entry found"))
        }
        Err(_) => {
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
    }
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
            decrypted_cipher.exact_match(name, username)
        })
        .collect();

    if exact_matches.is_empty() {
        let partial_matches: Vec<(rbw::db::Entry, DecryptedCipher)> = entries
            .iter()
            .cloned()
            .filter(|(_, decrypted_cipher)| {
                decrypted_cipher.partial_match(name, username)
            })
            .collect();

        if partial_matches.is_empty() {
            Err(anyhow::anyhow!("no entry found"))
        } else if partial_matches.len() > 1 {
            let entries: Vec<String> = partial_matches
                .iter()
                .map(|(_, decrypted)| decrypted.display_name())
                .collect();
            let entries = entries.join(", ");
            Err(anyhow::anyhow!("multiple entries found: {}", entries))
        } else {
            Ok(partial_matches[0].clone())
        }
    } else if exact_matches.len() > 1 {
        let entries: Vec<String> = exact_matches
            .iter()
            .map(|(_, decrypted)| decrypted.display_name())
            .collect();
        let entries = entries.join(", ");
        Err(anyhow::anyhow!("multiple entries found: {}", entries))
    } else {
        Ok(exact_matches[0].clone())
    }
}

fn decrypt_field(
    name: &str,
    field: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| crate::actions::decrypt(field, org_id))
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {}: {}", name, e);
            None
        }
    }
}

fn decrypt_cipher(entry: &rbw::db::Entry) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None))
        .transpose();
    let folder = match folder {
        Ok(folder) => folder,
        Err(e) => {
            log::warn!("failed to decrypt folder name: {}", e);
            None
        }
    };
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| crate::actions::decrypt(notes, entry.org_id.as_deref()))
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
        .map(|history_entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: crate::actions::decrypt(
                    &history_entry.password,
                    entry.org_id.as_deref(),
                )?,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username, password, ..
        } => DecryptedData::Login {
            username: decrypt_field(
                "username",
                username.as_deref(),
                entry.org_id.as_deref(),
            ),
            password: decrypt_field(
                "password",
                password.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: decrypt_field(
                "cardholder_name",
                cardholder_name.as_deref(),
                entry.org_id.as_deref(),
            ),
            number: decrypt_field(
                "number",
                number.as_deref(),
                entry.org_id.as_deref(),
            ),
            brand: decrypt_field(
                "brand",
                brand.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_month: decrypt_field(
                "exp_month",
                exp_month.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_year: decrypt_field(
                "exp_year",
                exp_year.as_deref(),
                entry.org_id.as_deref(),
            ),
            code: decrypt_field(
                "code",
                code.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: decrypt_field(
                "title",
                title.as_deref(),
                entry.org_id.as_deref(),
            ),
            first_name: decrypt_field(
                "first_name",
                first_name.as_deref(),
                entry.org_id.as_deref(),
            ),
            middle_name: decrypt_field(
                "middle_name",
                middle_name.as_deref(),
                entry.org_id.as_deref(),
            ),
            last_name: decrypt_field(
                "last_name",
                last_name.as_deref(),
                entry.org_id.as_deref(),
            ),
            address1: decrypt_field(
                "address1",
                address1.as_deref(),
                entry.org_id.as_deref(),
            ),
            address2: decrypt_field(
                "address2",
                address2.as_deref(),
                entry.org_id.as_deref(),
            ),
            address3: decrypt_field(
                "address3",
                address3.as_deref(),
                entry.org_id.as_deref(),
            ),
            city: decrypt_field(
                "city",
                city.as_deref(),
                entry.org_id.as_deref(),
            ),
            state: decrypt_field(
                "state",
                state.as_deref(),
                entry.org_id.as_deref(),
            ),
            postal_code: decrypt_field(
                "postal_code",
                postal_code.as_deref(),
                entry.org_id.as_deref(),
            ),
            country: decrypt_field(
                "country",
                country.as_deref(),
                entry.org_id.as_deref(),
            ),
            phone: decrypt_field(
                "phone",
                phone.as_deref(),
                entry.org_id.as_deref(),
            ),
            email: decrypt_field(
                "email",
                email.as_deref(),
                entry.org_id.as_deref(),
            ),
            ssn: decrypt_field(
                "ssn",
                ssn.as_deref(),
                entry.org_id.as_deref(),
            ),
            license_number: decrypt_field(
                "license_number",
                license_number.as_deref(),
                entry.org_id.as_deref(),
            ),
            passport_number: decrypt_field(
                "passport_number",
                passport_number.as_deref(),
                entry.org_id.as_deref(),
            ),
            username: decrypt_field(
                "username",
                username.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::SecureNote {} => DecryptedData::SecureNote {},
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: crate::actions::decrypt(&entry.name, entry.org_id.as_deref())?,
        data,
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

fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = &config.email {
        rbw::db::Db::load(&config.server_name(), &email)
            .context("failed to load password database")
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = &config.email {
        db.save(&config.server_name(), &email)
            .context("failed to save password database")
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

fn remove_db() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = &config.email {
        rbw::db::Db::remove(&config.server_name(), &email)
            .context("failed to remove password database")
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
                org_id: None,
                folder: None,
                folder_id: None,
                name: "this is the encrypted name".to_string(),
                data: rbw::db::EntryData::Login {
                    username: username.map(|_| {
                        "this is the encrypted username".to_string()
                    }),
                    password: None,
                    uris: vec![],
                },
                notes: None,
                history: vec![],
            },
            DecryptedCipher {
                id: "irrelevant".to_string(),
                folder: None,
                name: name.to_string(),
                data: DecryptedData::Login {
                    username: username.map(std::string::ToString::to_string),
                    password: None,
                },
                notes: None,
                history: vec![],
            },
        )
    }
}
