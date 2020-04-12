pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    tty: Option<&str>,
) {
    let mut state = state.write().await;
    let email = config_email().await;
    let mut db = rbw::db::Db::load_async(&email)
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url = config_base_url().await;
        let url = reqwest::Url::parse(&url).unwrap();
        let password = rbw::pinentry::getpin(
            "Master Password",
            &format!("Log in to {}", url.host_str().unwrap()),
            tty,
        )
        .await
        .unwrap();
        let (access_token, refresh_token, iterations, protected_key, keys) =
            rbw::actions::login(&email, &password).await.unwrap();

        state.priv_key = Some(keys);

        db.access_token = Some(access_token);
        db.refresh_token = Some(refresh_token);
        db.iterations = Some(iterations);
        db.protected_key = Some(protected_key);
        db.save_async(&email).await.unwrap();
    }

    respond_ack(sock).await;
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    tty: Option<&str>,
) {
    let mut state = state.write().await;

    if state.needs_unlock() {
        let email = config_email().await;
        let password = rbw::pinentry::getpin(
            "Master Password",
            "Unlock the local database",
            tty,
        )
        .await
        .unwrap();

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
    }

    respond_ack(sock).await;
}

pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
) {
    let mut state = state.write().await;

    state.priv_key = None;

    respond_ack(sock).await;
}

pub async fn sync(sock: &mut crate::sock::Sock) {
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

    respond_ack(sock).await;
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<crate::agent::State>>,
    cipherstring: &str,
) {
    let state = state.read().await;
    let keys = state.priv_key.as_ref().unwrap();
    let cipherstring =
        rbw::cipherstring::CipherString::new(cipherstring).unwrap();
    let plaintext =
        String::from_utf8(cipherstring.decrypt(keys).unwrap()).unwrap();

    respond_decrypt(sock, plaintext).await;
}

async fn respond_ack(sock: &mut crate::sock::Sock) {
    sock.send(&rbw::agent::Response::Ack).await;
}

async fn respond_decrypt(sock: &mut crate::sock::Sock, plaintext: String) {
    sock.send(&rbw::agent::Response::Decrypt { plaintext })
        .await;
}

async fn config_email() -> String {
    let config = rbw::config::Config::load_async().await.unwrap();
    config.email.unwrap()
}

async fn config_base_url() -> String {
    let config = rbw::config::Config::load_async().await.unwrap();
    config.base_url()
}
