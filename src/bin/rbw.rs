use std::io::{BufRead as _, Write as _};

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

fn connect() -> std::os::unix::net::UnixStream {
    std::os::unix::net::UnixStream::connect(
        rbw::dirs::runtime_dir().join("socket"),
    )
    .unwrap()
}

fn send(
    sock: &mut std::os::unix::net::UnixStream,
    msg: &rbw::agent::Request,
) {
    sock.write_all(serde_json::to_string(msg).unwrap().as_bytes())
        .unwrap();
    sock.write_all(b"\n").unwrap();
}

fn recv(sock: &mut std::os::unix::net::UnixStream) -> rbw::agent::Response {
    let mut buf = std::io::BufReader::new(sock);
    let mut line = String::new();
    buf.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn decrypt(cipherstring: &str) -> String {
    let mut sock = connect();
    send(
        &mut sock,
        &rbw::agent::Request {
            tty: std::env::var("TTY").ok(),
            action: rbw::agent::Action::Decrypt {
                cipherstring: cipherstring.to_string(),
            },
        },
    );

    let res = recv(&mut sock);
    match res {
        rbw::agent::Response::Decrypt { plaintext } => plaintext,
        rbw::agent::Response::Error { error } => {
            panic!("failed to decrypt: {}", error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}

fn config_show() {
    let config = rbw::config::Config::load().unwrap();
    serde_json::to_writer_pretty(std::io::stdout(), &config).unwrap();
    println!();
}

fn config_set(key: &str, value: &str) {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        _ => unimplemented!(),
    }
    config.save().unwrap();
}

fn login() {
    ensure_agent();

    let mut sock = connect();
    send(
        &mut sock,
        &rbw::agent::Request {
            tty: std::env::var("TTY").ok(),
            action: rbw::agent::Action::Login,
        },
    );

    let res = recv(&mut sock);
    match res {
        rbw::agent::Response::Ack => (),
        rbw::agent::Response::Error { error } => {
            panic!("failed to login: {}", error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}

fn unlock() {
    ensure_agent();

    let mut sock = connect();
    send(
        &mut sock,
        &rbw::agent::Request {
            tty: std::env::var("TTY").ok(),
            action: rbw::agent::Action::Unlock,
        },
    );

    let res = recv(&mut sock);
    match res {
        rbw::agent::Response::Ack => (),
        rbw::agent::Response::Error { error } => {
            panic!("failed to unlock: {}", error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}

fn sync() {
    ensure_agent();

    let mut sock = connect();
    send(
        &mut sock,
        &rbw::agent::Request {
            tty: std::env::var("TTY").ok(),
            action: rbw::agent::Action::Sync,
        },
    );

    let res = recv(&mut sock);
    match res {
        rbw::agent::Response::Ack => (),
        rbw::agent::Response::Error { error } => {
            panic!("failed to sync: {}", error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}

fn list() {
    ensure_agent();

    let email = config_email();
    let db = rbw::db::Db::load(&email).unwrap_or_else(|_| rbw::db::Db::new());
    for cipher in db.ciphers {
        println!("{}", decrypt(&cipher.name));
    }
}

fn get(name: &str, user: Option<&str>) {
    ensure_agent();

    let email = config_email();
    let db = rbw::db::Db::load(&email).unwrap_or_else(|_| rbw::db::Db::new());
    for cipher in db.ciphers {
        let cipher_name = decrypt(&cipher.name);
        if name == cipher_name {
            let cipher_user = decrypt(&cipher.login.username);
            if let Some(user) = user {
                if user == cipher_user {
                    let pass = decrypt(&cipher.login.password);
                    println!("{}", pass);
                    return;
                }
            } else {
                let pass = decrypt(&cipher.login.password);
                println!("{}", pass);
                return;
            }
        }
    }
}

fn add() {
    ensure_agent();

    todo!()
}

fn generate() {
    ensure_agent();

    todo!()
}

fn edit() {
    ensure_agent();

    todo!()
}

fn remove() {
    ensure_agent();

    todo!()
}

fn lock() {
    ensure_agent();

    let mut sock = connect();
    send(
        &mut sock,
        &rbw::agent::Request {
            tty: std::env::var("TTY").ok(),
            action: rbw::agent::Action::Lock,
        },
    );

    let res = recv(&mut sock);
    match res {
        rbw::agent::Response::Ack => (),
        rbw::agent::Response::Error { error } => {
            panic!("failed to lock: {}", error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}

fn purge() {
    todo!()
}

fn stop_agent() {
    let mut sock = connect();
    send(
        &mut sock,
        &rbw::agent::Request {
            tty: std::env::var("TTY").ok(),
            action: rbw::agent::Action::Quit,
        },
    );
}

fn config_email() -> String {
    let config = rbw::config::Config::load().unwrap();
    config.email.unwrap()
}

fn main() {
    let matches = clap::App::new("rbw")
        .about("unofficial bitwarden cli")
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .subcommand(
            clap::SubCommand::with_name("config")
                .subcommand(clap::SubCommand::with_name("show"))
                .subcommand(
                    clap::SubCommand::with_name("set")
                        .arg(clap::Arg::with_name("key").required(true))
                        .arg(clap::Arg::with_name("value").required(true)),
                ),
        )
        .subcommand(clap::SubCommand::with_name("login"))
        .subcommand(clap::SubCommand::with_name("unlock"))
        .subcommand(clap::SubCommand::with_name("sync"))
        .subcommand(clap::SubCommand::with_name("list"))
        .subcommand(
            clap::SubCommand::with_name("get")
                .arg(clap::Arg::with_name("name").required(true))
                .arg(clap::Arg::with_name("user")),
        )
        .subcommand(clap::SubCommand::with_name("add"))
        .subcommand(clap::SubCommand::with_name("generate"))
        .subcommand(clap::SubCommand::with_name("edit"))
        .subcommand(clap::SubCommand::with_name("remove"))
        .subcommand(clap::SubCommand::with_name("lock"))
        .subcommand(clap::SubCommand::with_name("purge"))
        .subcommand(clap::SubCommand::with_name("stop-agent"))
        .get_matches();

    match matches.subcommand() {
        ("config", Some(smatches)) => match smatches.subcommand() {
            ("show", Some(_)) => config_show(),
            ("set", Some(ssmatches)) => config_set(
                ssmatches.value_of("key").unwrap(),
                ssmatches.value_of("value").unwrap(),
            ),
            _ => {
                eprintln!("{}", smatches.usage());
                std::process::exit(1);
            }
        },
        ("login", Some(_)) => login(),
        ("unlock", Some(_)) => unlock(),
        ("sync", Some(_)) => sync(),
        ("list", Some(_)) => list(),
        ("get", Some(smatches)) => get(
            smatches.value_of("name").unwrap(),
            smatches.value_of("user"),
        ),
        ("add", Some(_)) => add(),
        ("generate", Some(_)) => generate(),
        ("edit", Some(_)) => edit(),
        ("remove", Some(_)) => remove(),
        ("lock", Some(_)) => lock(),
        ("purge", Some(_)) => purge(),
        ("stop-agent", Some(_)) => stop_agent(),
        _ => {
            eprintln!("{}", matches.usage());
            std::process::exit(1);
        }
    }
}
