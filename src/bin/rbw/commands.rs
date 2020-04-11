pub fn config_show() {
    let config = rbw::config::Config::load().unwrap();
    serde_json::to_writer_pretty(std::io::stdout(), &config).unwrap();
    println!();
}

pub fn config_set(key: &str, value: &str) {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "lock_timeout" => config.lock_timeout = value.parse().unwrap(),
        _ => unimplemented!(),
    }
    config.save().unwrap();
}

pub fn login() {
    ensure_agent();
    crate::actions::login();
}

pub fn unlock() {
    ensure_agent();
    crate::actions::login();
    crate::actions::unlock();
}

pub fn sync() {
    ensure_agent();
    crate::actions::login();
    crate::actions::sync();
}

pub fn list() {
    unlock();

    let email = config_email();
    let db = rbw::db::Db::load(&email).unwrap_or_else(|_| rbw::db::Db::new());
    for cipher in db.ciphers {
        println!("{}", crate::actions::decrypt(&cipher.name));
    }
}

pub fn get(name: &str, user: Option<&str>) {
    unlock();

    let email = config_email();
    let db = rbw::db::Db::load(&email).unwrap_or_else(|_| rbw::db::Db::new());
    for cipher in db.ciphers {
        let cipher_name = crate::actions::decrypt(&cipher.name);
        if name == cipher_name {
            let cipher_user = crate::actions::decrypt(&cipher.login.username);
            if let Some(user) = user {
                if user == cipher_user {
                    let pass =
                        crate::actions::decrypt(&cipher.login.password);
                    println!("{}", pass);
                    return;
                }
            } else {
                let pass = crate::actions::decrypt(&cipher.login.password);
                println!("{}", pass);
                return;
            }
        }
    }
}

pub fn add() {
    unlock();

    todo!()
}

pub fn generate(
    name: Option<&str>,
    user: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) {
    let pw = rbw::pwgen::pwgen(ty, len);
    println!("{}", std::str::from_utf8(pw.data()).unwrap());

    if name.is_some() && user.is_some() {
        unlock();

        todo!();
    }
}

pub fn edit() {
    unlock();

    todo!()
}

pub fn remove() {
    unlock();

    todo!()
}

pub fn lock() {
    ensure_agent();
    crate::actions::lock();
}

pub fn purge() {
    stop_agent();

    let email = config_email();
    rbw::db::Db::remove(&email).unwrap();
}

pub fn stop_agent() {
    crate::actions::quit();
}

fn ensure_agent() {
    let agent_path = std::env::var("RBW_AGENT");
    let agent_path = agent_path
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("rbw-agent");
    let status = std::process::Command::new(agent_path).status().unwrap();
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                panic!("failed to run agent: {}", status);
            }
        }
    }
}

fn config_email() -> String {
    let config = rbw::config::Config::load().unwrap();
    config.email.unwrap()
}
