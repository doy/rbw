use tokio::io::AsyncBufReadExt as _;
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

async fn ensure_login(state: std::sync::Arc<tokio::sync::RwLock<State>>) {
    let rstate = state.read().await;
    if rstate.access_token.is_none() {
        login(state.clone(), None).await; // tty
    }
}

async fn login(
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
    tty: Option<&str>,
) {
    let mut state = state.write().await;
    let email = "bitwarden@tozt.net"; // XXX read from config
    let password =
        rbw::pinentry::getpin("prompt", "desc", tty).await.unwrap();
    let (access_token, iterations, protected_key) =
        rbw::actions::login(email, &password).await.unwrap();
    state.access_token = Some(access_token);
    state.iterations = Some(iterations);
    let (enc_key, mac_key) =
        rbw::actions::unlock(email, &password, iterations, protected_key)
            .await
            .unwrap();
    state.priv_key = Some((enc_key, mac_key));
}

async fn ensure_unlock(state: std::sync::Arc<tokio::sync::RwLock<State>>) {
    let rstate = state.read().await;
    if rstate.priv_key.is_none() {
        unlock(state.clone(), None).await; // tty
    }
}

async fn unlock(
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
    tty: Option<&str>,
) {
    let mut state = state.write().await;
    let email = "bitwarden@tozt.net"; // XXX read from config
    let password =
        rbw::pinentry::getpin("prompt", "desc", tty).await.unwrap();
    let (enc_key, mac_key) = rbw::actions::unlock(
        email,
        &password,
        state.iterations.unwrap(),
        state.protected_key.as_ref().unwrap().to_string(),
    )
    .await
    .unwrap();
    state.priv_key = Some((enc_key, mac_key));
}

async fn sync(state: std::sync::Arc<tokio::sync::RwLock<State>>) {
    ensure_login(state.clone()).await;
    let mut state = state.write().await;
    let (protected_key, ciphers) =
        rbw::actions::sync(state.access_token.as_ref().unwrap())
            .await
            .unwrap();
    state.protected_key = Some(protected_key);
    println!("{}", serde_json::to_string(&ciphers).unwrap());
    state.ciphers = ciphers;
}

async fn decrypt(
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
    cipherstring: &str,
) {
    ensure_unlock(state.clone()).await;
    let state = state.read().await;
    let (enc_key, mac_key) = state.priv_key.as_ref().unwrap();
    let cipherstring =
        rbw::cipherstring::CipherString::new(cipherstring).unwrap();
    let plain = cipherstring.decrypt(&enc_key, &mac_key).unwrap();
    println!("{}", String::from_utf8(plain).unwrap());
}

async fn handle_sock(
    sock: tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
) {
    let buf = tokio::io::BufStream::new(sock);
    let mut lines = buf.lines();
    while let Some(line) = lines.next().await {
        let line = line.unwrap();
        let msg: rbw::agent::Message = serde_json::from_str(&line).unwrap();
        match msg.action {
            rbw::agent::Action::Login => {
                login(state.clone(), msg.tty.as_deref()).await
            }
            rbw::agent::Action::Unlock => {
                unlock(state.clone(), msg.tty.as_deref()).await
            }
            rbw::agent::Action::Sync => sync(state.clone()).await,
            rbw::agent::Action::Decrypt { cipherstring } => {
                decrypt(state.clone(), &cipherstring).await
            }
        }
    }
}

struct Agent {
    timeout: tokio::time::Delay,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
}

struct State {
    access_token: Option<String>,
    priv_key: Option<(Vec<u8>, Vec<u8>)>,

    // these should be in a state file
    iterations: Option<u32>,
    protected_key: Option<String>,
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
