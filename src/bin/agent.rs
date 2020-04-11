use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::stream::StreamExt as _;

fn make_socket() -> anyhow::Result<tokio::net::UnixListener> {
    let runtime_dir = rbw::dirs::runtime_dir();
    std::fs::create_dir_all(&runtime_dir)?;

    let path = runtime_dir.join("socket");
    std::fs::remove_file(&path)?;
    let sock = tokio::net::UnixListener::bind(&path)?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}

async fn send_response(
    sock: &mut tokio::net::UnixStream,
    res: &rbw::agent::Response,
) {
    sock.write_all(serde_json::to_string(res).unwrap().as_bytes())
        .await
        .unwrap();
    sock.write_all(b"\n").await.unwrap();
}

async fn login(
    sock: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
    tty: Option<&str>,
) {
    let mut state = state.write().await;

    let email = config_email().await;
    let password =
        rbw::pinentry::getpin("prompt", "desc", tty).await.unwrap();

    let (access_token, refresh_token, iterations, protected_key, keys) =
        rbw::actions::login(&email, &password).await.unwrap();

    state.priv_key = Some(keys);

    let mut db = rbw::db::Db::load_async(&email)
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());
    db.access_token = Some(access_token);
    db.refresh_token = Some(refresh_token);
    db.iterations = Some(iterations);
    db.protected_key = Some(protected_key);
    db.save_async(&email).await.unwrap();

    send_response(sock, &rbw::agent::Response::Ack).await;
}

async fn unlock(
    sock: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
    tty: Option<&str>,
) {
    let mut state = state.write().await;

    let email = config_email().await;
    let password =
        rbw::pinentry::getpin("prompt", "desc", tty).await.unwrap();

    let db = rbw::db::Db::load_async(&email)
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());

    let keys = rbw::actions::unlock(
        &email,
        &password,
        db.iterations.unwrap(),
        db.protected_key.as_deref().unwrap(),
    )
    .await
    .unwrap();

    state.priv_key = Some(keys);

    send_response(sock, &rbw::agent::Response::Ack).await;
}

async fn lock(
    sock: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
) {
    let mut state = state.write().await;

    state.priv_key = None;

    send_response(sock, &rbw::agent::Response::Ack).await;
}

async fn sync(sock: &mut tokio::net::UnixStream) {
    let email = config_email().await;
    let mut db = rbw::db::Db::load_async(&email)
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());

    let (protected_key, ciphers) =
        rbw::actions::sync(db.access_token.as_ref().unwrap())
            .await
            .unwrap();
    db.protected_key = Some(protected_key);
    db.ciphers = ciphers;
    db.save_async(&email).await.unwrap();

    send_response(sock, &rbw::agent::Response::Ack).await;
}

async fn decrypt(
    sock: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
    cipherstring: &str,
) {
    let state = state.read().await;
    let keys = state.priv_key.as_ref().unwrap();
    let cipherstring =
        rbw::cipherstring::CipherString::new(cipherstring).unwrap();
    let plaintext =
        String::from_utf8(cipherstring.decrypt(keys).unwrap()).unwrap();

    send_response(sock, &rbw::agent::Response::Decrypt { plaintext }).await;
}

async fn handle_sock(
    sock: tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
) {
    let mut buf = tokio::io::BufStream::new(sock);
    let mut line = String::new();
    buf.read_line(&mut line).await.unwrap();
    let mut sock = buf.into_inner();
    let msg: rbw::agent::Request = serde_json::from_str(&line).unwrap();
    match msg.action {
        rbw::agent::Action::Login => {
            login(&mut sock, state.clone(), msg.tty.as_deref()).await
        }
        rbw::agent::Action::Unlock => {
            unlock(&mut sock, state.clone(), msg.tty.as_deref()).await
        }
        rbw::agent::Action::Lock => lock(&mut sock, state.clone()).await,
        rbw::agent::Action::Sync => sync(&mut sock).await,
        rbw::agent::Action::Decrypt { cipherstring } => {
            decrypt(&mut sock, state.clone(), &cipherstring).await
        }
        rbw::agent::Action::Quit => std::process::exit(0),
    }
}

async fn config_email() -> String {
    let config = rbw::config::Config::load_async().await.unwrap();
    config.email.unwrap()
}

struct Agent {
    timeout: tokio::time::Delay,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
}

struct State {
    priv_key: Option<rbw::locked::Keys>,
}

impl Agent {
    fn new() -> Self {
        Self {
            timeout: tokio::time::delay_for(
                tokio::time::Duration::from_secs(600), // read from config
            ),
            state: std::sync::Arc::new(tokio::sync::RwLock::new(State {
                priv_key: None,
            })),
        }
    }

    async fn run(&mut self, mut listener: tokio::net::UnixListener) {
        loop {
            tokio::select! {
                sock = listener.next() => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        handle_sock(sock.unwrap().unwrap(), state).await
                    });
                }
                _ = &mut self.timeout => {
                    self.state.write().await.priv_key = None
                }
            }
        }
    }
}

fn main() {
    env_logger::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let runtime_dir = rbw::dirs::runtime_dir();
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let (r, w) = nix::unistd::pipe().unwrap();
    let res = daemonize::Daemonize::new()
        .pid_file(runtime_dir.join("pidfile"))
        .exit_action(move || {
            nix::unistd::close(w).unwrap();
            let mut buf = [0; 1];
            nix::unistd::read(r, &mut buf).unwrap();
            nix::unistd::close(r).unwrap();
        })
        .start();
    nix::unistd::close(r).unwrap();

    match res {
        Ok(_) => (),
        Err(e) => {
            match e {
                daemonize::DaemonizeError::LockPidfile(_) => {
                    // this means that there is already an agent running, so
                    // return a special exit code to allow the cli to detect
                    // this case and not error out
                    std::process::exit(23);
                }
                _ => panic!("failed to daemonize: {}", e),
            }
        }
    }

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let listener = make_socket();

        nix::unistd::write(w, &[0]).unwrap();
        nix::unistd::close(w).unwrap();

        let mut agent = Agent::new();
        agent.run(listener.unwrap()).await;
    })
}
