pub fn login() {
    simple_action(rbw::agent::Action::Login, "login");
}

pub fn unlock() {
    simple_action(rbw::agent::Action::Unlock, "unlock");
}

pub fn sync() {
    simple_action(rbw::agent::Action::Sync, "sync");
}

pub fn lock() {
    simple_action(rbw::agent::Action::Lock, "lock");
}

pub fn quit() {
    let mut sock = crate::sock::Sock::connect();
    sock.send(&rbw::agent::Request {
        tty: std::env::var("TTY").ok(),
        action: rbw::agent::Action::Quit,
    });
}

pub fn decrypt(cipherstring: &str) -> String {
    let mut sock = crate::sock::Sock::connect();
    sock.send(&rbw::agent::Request {
        tty: std::env::var("TTY").ok(),
        action: rbw::agent::Action::Decrypt {
            cipherstring: cipherstring.to_string(),
        },
    });

    let res = sock.recv();
    match res {
        rbw::agent::Response::Decrypt { plaintext } => plaintext,
        rbw::agent::Response::Error { error } => {
            panic!("failed to decrypt: {}", error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}

fn simple_action(action: rbw::agent::Action, desc: &str) {
    let mut sock = crate::sock::Sock::connect();

    sock.send(&rbw::agent::Request {
        tty: std::env::var("TTY").ok(),
        action,
    });

    let res = sock.recv();
    match res {
        rbw::agent::Response::Ack => (),
        rbw::agent::Response::Error { error } => {
            panic!("failed to {}: {}", desc, error)
        }
        _ => panic!("unexpected message: {:?}", res),
    }
}
