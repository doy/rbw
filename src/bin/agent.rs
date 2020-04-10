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

async fn ensure_login(
    sock: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
) {
    let rstate = state.read().await;
    if rstate.access_token.is_none() {
        login(sock, state.clone(), None).await; // tty
    }
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
    let (access_token, iterations, protected_key, keys) =
        rbw::actions::login(&email, &password).await.unwrap();
    state.access_token = Some(access_token);
    state.iterations = Some(iterations);
    state.protected_key = Some(protected_key);
    state.priv_key = Some(keys);

    send_response(sock, &rbw::agent::Response::Ack).await;
}

async fn ensure_unlock(
    sock: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
) {
    let rstate = state.read().await;
    if rstate.priv_key.is_none() {
        unlock(sock, state.clone(), None).await; // tty
    }
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
    let keys = rbw::actions::unlock(
        &email,
        &password,
        state.iterations.unwrap(),
        state.protected_key.as_ref().unwrap(),
    )
    .await
    .unwrap();
    state.priv_key = Some(keys);

    send_response(sock, &rbw::agent::Response::Ack).await;
}

async fn sync(
    sock: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
) {
    ensure_login(sock, state.clone()).await;
    let mut state = state.write().await;
    let (protected_key, ciphers) =
        rbw::actions::sync(state.access_token.as_ref().unwrap())
            .await
            .unwrap();
    state.protected_key =
        Some(rbw::cipherstring::CipherString::new(&protected_key).unwrap());
    println!("{}", serde_json::to_string(&ciphers).unwrap());
    state.ciphers = ciphers;

    send_response(sock, &rbw::agent::Response::Ack).await;
}

async fn decrypt(
    sock: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
    cipherstring: &str,
) {
    ensure_unlock(sock, state.clone()).await;
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
        rbw::agent::Action::Sync => sync(&mut sock, state.clone()).await,
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
    access_token: Option<String>,
    priv_key: Option<rbw::locked::Keys>,

    // these should be in a state file
    iterations: Option<u32>,
    protected_key: Option<rbw::cipherstring::CipherString>,
    ciphers: Vec<rbw::api::Cipher>,
}

impl Agent {
    fn new() -> Self {
        Self {
            timeout: tokio::time::delay_for(
                tokio::time::Duration::from_secs(600), // read from config
            ),
            state: std::sync::Arc::new(tokio::sync::RwLock::new(State {
                access_token: None,
                iterations: None,
                protected_key: None,
                priv_key: None,
                ciphers: vec![],
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
                    break;
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
