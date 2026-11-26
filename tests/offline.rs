//! All state lives in temporary directories; only the loopback fake identity
//! server is reachable. No test reads the user's rbw configuration or cache.
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use serde_json::{json, Value};

const EMAIL: &str = "offline@example.invalid";
const PASSWORD: &str = "synthetic-test-password";

#[derive(Clone, Copy)]
enum Mode { Rotate, RetryFails, RecoveryRetryFails, Reject, BadPassword, TwoFactor, ServerFailure }

struct Server {
    url: String,
    state: Arc<Mutex<(Mode, usize, usize)>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn new(mode: Mode, key: String, private_key: String) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new((mode, 0, 0)));
        let shared = state.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = stop.clone();
        let thread = std::thread::spawn(move || {
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("fake server: {e}"),
                };
                socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                let mut reader = std::io::BufReader::new(&socket);
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                let mut headers = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() { break; }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                    headers.push_str(&line.to_ascii_lowercase());
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let body = String::from_utf8(body).unwrap();
                let mut state = shared.lock().unwrap();
                let mode = state.0;
                let (status, response) = if request.contains("/accounts/prelogin ") {
                    (200, json!({"kdf":0,"kdfIterations":1}))
                } else if request.contains("/connect/token ") {
                    if body.contains("grant_type=refresh_token") {
                        state.1 += 1;
                        match mode {
                            Mode::Rotate | Mode::RetryFails => (200, json!({"access_token":"rotated-access","refresh_token":"rotated-refresh"})),
                            Mode::ServerFailure => (503, json!({"error":"invalid_grant"})),
                            _ => (400, json!({"error":"invalid_grant"})),
                        }
                    } else {
                        state.2 += 1;
                        match mode {
                            Mode::BadPassword => (400, json!({"error":"invalid_grant","error_description":"invalid_username_or_password","errorModel":{"message":"DO_NOT_REPORT_SERVER_TEXT"}})),
                            Mode::TwoFactor => (400, json!({"error":"invalid_grant","error_description":"Two factor required.","twoFactorProviders":[0]})),
                            _ => (200, json!({"access_token":"relogged-access","refresh_token":"relogged-refresh","key":key})),
                        }
                    }
                } else if request.contains("/api/sync ") {
                    let authorized = headers.contains("bearer rotated-access") || headers.contains("bearer relogged-access");
                    if authorized && matches!(mode, Mode::RetryFails | Mode::RecoveryRetryFails) {
                        (503, json!({"error":"DO_NOT_REPORT_SERVER_TEXT"}))
                    } else if authorized {
                        (200, json!({"ciphers":[],"folders":[],"profile":{"key":key,"privateKey":private_key,"organizations":[]}}))
                    } else { (401, json!({})) }
                } else if request.contains("/api/folders ") || request.contains("/api/ciphers") {
                    let authorized = headers.contains("bearer rotated-access") || headers.contains("bearer relogged-access");
                    if !authorized {
                        (401, json!({}))
                    } else if matches!(mode, Mode::RetryFails) {
                        (503, json!({}))
                    } else if request.starts_with("GET /api/folders ") {
                        (200, json!({"data":[]}))
                    } else {
                        (200, json!({"id":"synthetic-folder","name":"synthetic-ciphertext"}))
                    }
                } else { (404, json!({})) };
                let response = response.to_string();
                if let Err(error) = write!(socket, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()) {
                    // A client may abandon its notification/websocket request.
                    assert!(matches!(error.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset), "{error}");
                }
            }
        });
        Self { url, state, stop, thread: Some(thread) }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

struct Fixture {
    root: tempfile::TempDir,
    db: PathBuf,
    config: PathBuf,
    socket: PathBuf,
    agent: Option<Child>,
    server: Server,
}

impl Fixture {
    fn new(mode: Mode, pinentry: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut password = rbw::locked::Vec::new();
        password.extend(PASSWORD.bytes());
        let identity = rbw::identity::Identity::new(EMAIL, &rbw::locked::Password::new(password), rbw::api::KdfType::Pbkdf2, 1, None, None).unwrap();
        let mut raw = rbw::locked::Vec::new();
        raw.extend(std::iter::repeat_n(42, 64));
        let key = rbw::cipherstring::CipherString::encrypt_symmetric(&identity.keys, raw.data()).unwrap().to_string();
        let keys = rbw::locked::Keys::new(raw);
        let private_key = rbw::cipherstring::CipherString::encrypt_symmetric(&keys, b"synthetic-unused-private-key").unwrap().to_string();
        let server = Server::new(mode, key.clone(), private_key.clone());
        #[cfg(target_os = "macos")]
        let (config_dir, cache_dir, data_dir, runtime_dir) = (
            root.path().join("Library/Application Support/rbw"),
            root.path().join("Library/Caches/rbw"),
            root.path().join("Library/Application Support/rbw"),
            root.path().join(format!("run/rbw-{}", rustix::process::getuid().as_raw())),
        );
        #[cfg(not(target_os = "macos"))]
        let (config_dir, cache_dir, data_dir, runtime_dir) = (
            root.path().join("config/rbw"), root.path().join("cache/rbw"),
            root.path().join("data/rbw"), root.path().join("run/rbw"),
        );
        for dir in [&config_dir, &cache_dir, &data_dir, &runtime_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let config = rbw::config::Config { email: Some(EMAIL.into()), base_url: Some(server.url.clone()), sync_interval: 0, pinentry: root.path().join("pinentry").to_str().unwrap().into(), ..Default::default() };
        let config_path = config_dir.join("config.json");
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let encoded = server.url.replace('%', "%25").replace('/', "%2F").replace(':', "%3A");
        let db = cache_dir.join(format!("{encoded}:{EMAIL}.json"));
        let mut cache = rbw::db::Db::new();
        cache.access_token = Some("expired-access".into());
        cache.refresh_token = Some("expired-refresh".into());
        cache.kdf = Some(rbw::api::KdfType::Pbkdf2);
        cache.iterations = Some(1);
        cache.protected_key = Some(key);
        cache.protected_private_key = Some(private_key);
        cache.last_sync = Some(123);
        std::fs::write(&db, serde_json::to_vec(&cache).unwrap()).unwrap();
        let mut fixture = Self {
            root, db, config: config_path, socket: runtime_dir.join("socket"),
            server, agent: None,
        };
        fixture.set_pinentry(pinentry);
        fixture
    }

    fn command(&self, binary: &str) -> Command {
        let mut command = Command::new(binary);
        command.env_clear().env("PATH", "/usr/bin:/bin")
            .env("HOME", self.root.path())
            .env("TMPDIR", self.root.path().join("run"))
            .env("TOKIO_WORKER_THREADS", "2")
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_CACHE_HOME", self.root.path().join("cache"))
            .env("XDG_DATA_HOME", self.root.path().join("data"))
            .env("XDG_RUNTIME_DIR", self.root.path().join("run"));
        command
    }

    fn set_pinentry(&mut self, result: &str) {
        let script = format!("#!/bin/sh\nprintf 'attempt\\n' >> '{}'\ncat >/dev/null\nprintf '%s\\n' '{}'\n", self.root.path().join("attempts").display(), result);
        let file = self.root.path().join("pinentry");
        std::fs::write(&file, script).unwrap();
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn start(&mut self) {
        assert!(self.agent.is_none());
        self.agent = Some(self.command(env!("CARGO_BIN_EXE_rbw-agent")).arg("--no-daemonize").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        for _ in 0..500 {
            if std::os::unix::net::UnixStream::connect(&self.socket).is_ok() { return; }
            if let Some(status) = self.agent.as_mut().unwrap().try_wait().unwrap() { panic!("test agent exited: {status}"); }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("test agent did not listen");
    }

    fn stop(&mut self) {
        if let Some(mut agent) = self.agent.take() {
            agent.kill().unwrap();
            agent.wait().unwrap();
        }
    }

    fn sync(&self) -> Value {
        let mut socket = std::os::unix::net::UnixStream::connect(&self.socket).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(15))).unwrap();
        socket.write_all(b"{\"action\":{\"type\":\"Sync\"}}\n").unwrap();
        let mut response = String::new();
        std::io::BufReader::new(socket).read_line(&mut response).unwrap();
        serde_json::from_str(&response).unwrap()
    }

    fn cache(&self) -> rbw::db::Db {
        serde_json::from_slice(&std::fs::read(&self.db).unwrap()).unwrap()
    }

    fn attempts(&self) -> usize {
        std::fs::read_to_string(self.root.path().join("attempts")).unwrap_or_default().lines().count()
    }

    fn status(&self) -> Value {
        let result = self.command(env!("CARGO_BIN_EXE_rbw")).arg("status").output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        serde_json::from_slice(&result.stdout).unwrap()
    }
}

impl Drop for Fixture { fn drop(&mut self) { self.stop(); } }

#[test]
fn status_does_not_start_or_unlock_the_agent() {
    let mut fixture = Fixture::new(Mode::Reject, "ERR 83886179 cancel");
    assert_eq!(fixture.status()["locked"], true);
    assert!(!fixture.socket.exists());
    fixture.start();
    assert_eq!(fixture.status()["locked"], true);
    assert_eq!(fixture.attempts(), 0);
    assert_eq!(fixture.server.state.lock().unwrap().1, 0);
}

#[test]
fn rotation_survives_success_and_failed_sync_retry() {
    for mode in [Mode::Rotate, Mode::RetryFails] {
        let mut fixture = Fixture::new(mode, "ERR 83886179 must-not-run");
        let original_key = fixture.cache().protected_key;
        fixture.start();
        let result = fixture.sync();
        let cache = fixture.cache();
        assert_eq!(cache.refresh_token.as_deref(), Some("rotated-refresh"));
        assert_eq!(cache.access_token.as_deref(), Some("rotated-access"));
        assert_eq!(cache.protected_key, original_key);
        assert_eq!(std::fs::metadata(&fixture.db).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fixture.attempts(), 0);
        if matches!(mode, Mode::Rotate) {
            assert_eq!(result["type"], "Ack", "{result}");
            assert!(cache.last_sync.unwrap() > 123);
        } else {
            assert_eq!(result["type"], "Error");
            assert_eq!(cache.last_sync, Some(123));
            assert_eq!(fixture.status()["last_error"], "sync_failed");
        }
    }
}

#[test]
fn recovery_stops_and_throttles_survive_restarts_without_losing_cache() {
    for (pinentry, stopped, code) in [
        ("ERR 83886179 cancel", true, "pinentry_cancelled"),
        ("ERR 42 transport-unavailable", false, "pinentry_unavailable"),
    ] {
        let mut fixture = Fixture::new(Mode::Reject, pinentry);
        let old = fixture.cache();
        fixture.start();
        assert_eq!(fixture.sync()["type"], "Error");
        assert_eq!(fixture.attempts(), 1);
        let cache = fixture.cache();
        assert_eq!(cache.recovery.stopped, stopped);
        assert!(cache.recovery.pending);
        assert!(cache.recovery.last_attempt.is_some());
        assert_eq!(cache.protected_key, old.protected_key);
        assert_eq!(cache.refresh_token, old.refresh_token);
        assert_eq!(cache.last_sync, old.last_sync);
        fixture.stop();
        fixture.start();
        assert_eq!(fixture.sync()["type"], "Error");
        assert_eq!(fixture.attempts(), 1);
        assert_eq!(fixture.status()["last_error"], code);
        assert_eq!(fixture.server.state.lock().unwrap().1, 1);
    }
}

#[test]
fn rejected_token_relogs_once_without_unlocking_and_auth_failures_stop() {
    for (mode, expected) in [(Mode::Reject, None), (Mode::BadPassword, Some("invalid_password")), (Mode::TwoFactor, Some("two_factor_required"))] {
        let mut fixture = Fixture::new(mode, &format!("D {PASSWORD}"));
        fixture.start();
        let result = fixture.sync();
        assert_eq!(fixture.attempts(), 1);
        assert_eq!(fixture.server.state.lock().unwrap().2, 1);
        if let Some(code) = expected {
            assert_eq!(result["type"], "Error");
            assert_eq!(fixture.status()["last_error"], code);
            assert!(fixture.cache().recovery.stopped);
            assert_eq!(fixture.sync()["type"], "Error");
            assert_eq!(fixture.attempts(), 1);
        } else {
            assert_eq!(result["type"], "Ack", "{result}");
            let cache = fixture.cache();
            assert!(!cache.recovery.pending);
            assert!(cache.recovery.last_attempt.is_some());
            assert_eq!(cache.refresh_token.as_deref(), Some("relogged-refresh"));
            assert_eq!(fixture.status()["locked"], true);
        }
        assert!(!fixture.status().to_string().contains("DO_NOT_REPORT"));
    }
}

#[test]
fn server_failure_is_not_misclassified_as_rejection() {
    let mut fixture = Fixture::new(Mode::ServerFailure, "ERR 83886179 must-not-run");
    fixture.start();
    assert_eq!(fixture.sync()["type"], "Error");
    assert_eq!(fixture.attempts(), 0);
    assert!(!fixture.cache().recovery.pending);
}

#[test]
fn only_complete_explicit_login_clears_a_permanent_stop() {
    let mut fixture = Fixture::new(Mode::Reject, "ERR 83886179 cancel");
    fixture.start();
    assert_eq!(fixture.sync()["type"], "Error");
    assert!(fixture.cache().recovery.stopped);
    fixture.set_pinentry(&format!("D {PASSWORD}"));
    let old = fixture.cache();
    fixture.server.state.lock().unwrap().0 = Mode::RecoveryRetryFails;
    let failed = fixture.command(env!("CARGO_BIN_EXE_rbw")).arg("login").output().unwrap();
    assert!(!failed.status.success());
    assert!(fixture.cache().recovery.stopped);
    assert_eq!(fixture.cache().protected_key, old.protected_key);
    assert_eq!(fixture.cache().iterations, old.iterations);
    fixture.server.state.lock().unwrap().0 = Mode::Reject;
    let result = fixture.command(env!("CARGO_BIN_EXE_rbw")).arg("login").output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let cache = fixture.cache();
    assert!(!cache.recovery.stopped);
    assert!(!cache.recovery.pending);
    assert!(cache.recovery.last_attempt.is_none());
    assert_eq!(fixture.status()["locked"], false);
}

#[test]
fn browser_sso_challenge_stops_without_invoking_pinentry() {
    let mut fixture = Fixture::new(Mode::Reject, "ERR 83886179 must-not-run");
    let config_path = &fixture.config;
    let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    config["sso_id"] = json!("synthetic-organization");
    std::fs::write(config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    fixture.start();
    assert_eq!(fixture.sync()["type"], "Error");
    assert_eq!(fixture.attempts(), 0);
    assert!(fixture.cache().recovery.stopped);
    assert_eq!(fixture.status()["last_error"], "challenge_required");
}

// Run library mutation calls in a fresh subprocess so even their configuration
// lookup is isolated, without modifying the test runner's shared environment.
#[test]
#[ignore = "subprocess driver; invoked only with a temporary fixture environment"]
fn mutation_driver() {
    let operation = std::env::var("RBW_OFFLINE_OPERATION").unwrap();
    let access = "expired-access";
    let refresh = "expired-refresh";
    let (tokens, succeeded) = match operation.as_str() {
        "folders" => {
            let (tokens, result) = rbw::actions::list_folders(access, refresh).unwrap();
            if let Err(error) = &result { eprintln!("folders response: {error:?}"); }
            (tokens, result.is_ok())
        }
        "create" => {
            let (tokens, result) = rbw::actions::create_folder(access, refresh, "synthetic-ciphertext").unwrap();
            (tokens, result.is_ok())
        }
        "add" => {
            let (tokens, result) = rbw::actions::add(access, refresh, "name", &rbw::db::EntryData::SecureNote, None, None).unwrap();
            (tokens, result.is_ok())
        }
        "edit" => {
            let (tokens, result) = rbw::actions::edit(access, refresh, "id", None, "name", &rbw::db::EntryData::SecureNote, &[], None, None, &[]).unwrap();
            (tokens, result.is_ok())
        }
        "remove" => {
            let (tokens, result) = rbw::actions::remove(access, refresh, "id").unwrap();
            (tokens, result.is_ok())
        }
        _ => panic!("unknown operation"),
    };
    let tokens = tokens.expect("refresh must be returned, including when retry fails");
    assert_eq!(succeeded, std::env::var("RBW_OFFLINE_EXPECT_OK").unwrap() == "yes");
    assert_eq!(tokens.recovered, std::env::var("RBW_OFFLINE_EXPECT_RECOVERY").unwrap() == "yes");
    assert_eq!(tokens.refresh_token.as_deref(), Some(if tokens.recovered { "relogged-refresh" } else { "rotated-refresh" }));
}

#[test]
fn all_mutation_operations_return_rotation_on_failed_retry_and_delegate_recovery() {
    for mode in [Mode::Rotate, Mode::RetryFails, Mode::Reject] {
        for operation in ["folders", "create", "add", "edit", "remove"] {
            let mut fixture = Fixture::new(mode, &format!("D {PASSWORD}"));
            fixture.start();
            let result = fixture.command(std::env::current_exe().unwrap().to_str().unwrap())
                .args(["--ignored", "--exact", "mutation_driver", "--nocapture"])
                .env("RBW_OFFLINE_OPERATION", operation)
                .env("RBW_OFFLINE_EXPECT_OK", if matches!(mode, Mode::RetryFails) { "no" } else { "yes" })
                .env("RBW_OFFLINE_EXPECT_RECOVERY", if matches!(mode, Mode::Reject) { "yes" } else { "no" })
                .output().unwrap();
            assert!(result.status.success(), "{operation}: {} {}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
            assert_eq!(fixture.server.state.lock().unwrap().1, 1);
            assert_eq!(fixture.attempts(), usize::from(matches!(mode, Mode::Reject)));
        }
    }
}

#[test]
fn failed_post_login_sync_preserves_offline_crypto_and_stages_kdf_across_restart() {
    let mut fixture = Fixture::new(Mode::RecoveryRetryFails, &format!("D {PASSWORD}"));
    let mut old = fixture.cache();
    old.protected_key = Some("old-offline-ciphertext".into());
    old.iterations = Some(777);
    std::fs::write(&fixture.db, serde_json::to_vec(&old).unwrap()).unwrap();
    fixture.start();
    assert_eq!(fixture.sync()["type"], "Error");
    let cache = fixture.cache();
    assert_eq!(cache.protected_key, old.protected_key);
    assert_eq!(cache.protected_private_key, old.protected_private_key);
    assert_eq!(cache.iterations, Some(777));
    assert_eq!(cache.last_sync, Some(123));
    assert_eq!(cache.recovery.pending_kdf.as_ref().unwrap().iterations, 1);
    assert_eq!(fixture.attempts(), 1);
    fixture.stop();
    fixture.server.state.lock().unwrap().0 = Mode::Reject;
    fixture.start();
    assert_eq!(fixture.sync()["type"], "Ack");
    let cache = fixture.cache();
    assert_ne!(cache.protected_key, old.protected_key);
    assert_eq!(cache.iterations, Some(1));
    assert!(cache.recovery.pending_kdf.is_none());
    assert_eq!(fixture.attempts(), 1);
}
