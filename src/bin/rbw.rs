use std::io::Write as _;

fn send(msg: &rbw::agent::Message) {
    let mut sock = std::os::unix::net::UnixStream::connect(
        rbw::dirs::runtime_dir().join("socket"),
    )
    .unwrap();
    sock.write_all(serde_json::to_string(msg).unwrap().as_bytes())
        .unwrap();
}

fn login() {
    send(&rbw::agent::Message {
        tty: std::env::var("TTY").ok(),
        action: rbw::agent::Action::Login,
    })
}

fn unlock() {
    send(&rbw::agent::Message {
        tty: std::env::var("TTY").ok(),
        action: rbw::agent::Action::Unlock,
    })
}

fn sync() {
    send(&rbw::agent::Message {
        tty: std::env::var("TTY").ok(),
        action: rbw::agent::Action::Sync,
    })
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
