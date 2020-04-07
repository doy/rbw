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

fn login() {
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
            panic!("failed to login: {}", error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}

fn sync() {
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
            panic!("failed to login: {}", error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}

fn list() {
    todo!()
}

fn get() {
    todo!()
}

fn add() {
    todo!()
}

fn generate() {
    todo!()
}

fn edit() {
    todo!()
}

fn remove() {
    todo!()
}

fn lock() {
    todo!()
}

fn purge() {
    todo!()
}

fn main() {
    let matches = clap::App::new("rbw")
        .about("unofficial bitwarden cli")
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .subcommand(clap::SubCommand::with_name("login"))
        .subcommand(clap::SubCommand::with_name("unlock"))
        .subcommand(clap::SubCommand::with_name("sync"))
        .subcommand(clap::SubCommand::with_name("list"))
        .subcommand(clap::SubCommand::with_name("get"))
        .subcommand(clap::SubCommand::with_name("add"))
        .subcommand(clap::SubCommand::with_name("generate"))
        .subcommand(clap::SubCommand::with_name("edit"))
        .subcommand(clap::SubCommand::with_name("remove"))
        .subcommand(clap::SubCommand::with_name("lock"))
        .subcommand(clap::SubCommand::with_name("purge"))
        .get_matches();

    ensure_agent();

    match matches.subcommand() {
        ("login", Some(_)) => login(),
        ("unlock", Some(_)) => unlock(),
        ("sync", Some(_)) => sync(),
        ("list", Some(_)) => list(),
        ("get", Some(_)) => get(),
        ("add", Some(_)) => add(),
        ("generate", Some(_)) => generate(),
        ("edit", Some(_)) => edit(),
        ("remove", Some(_)) => remove(),
        ("lock", Some(_)) => lock(),
        ("purge", Some(_)) => purge(),
        _ => unimplemented!(),
    }
}
