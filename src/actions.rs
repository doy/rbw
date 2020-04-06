// TODO api needs to be async

pub async fn login(email: &str, password: &str) -> (String, u32, String) {
    let client =
        crate::api::Client::new_self_hosted("https://bitwarden.tozt.net");

    let iterations = client.prelogin(&email).await.unwrap();
    let identity =
        crate::identity::Identity::new(&email, &password, iterations)
            .unwrap();

    let (access_token, _refresh_token, protected_key) = client
        .login(&identity.email, &identity.master_password_hash)
        .await
        .unwrap();

    (access_token, iterations, protected_key)
}

pub async fn unlock(
    email: &str,
    password: &str,
    iterations: u32,
    protected_key: String,
) -> (Vec<u8>, Vec<u8>) {
    let identity =
        crate::identity::Identity::new(&email, &password, iterations)
            .unwrap();

    let protected_key =
        crate::cipherstring::CipherString::new(&protected_key).unwrap();
    let master_key = protected_key
        .decrypt(&identity.enc_key, &identity.mac_key)
        .unwrap();

    let enc_key = &master_key[0..32];
    let mac_key = &master_key[32..64];

    (enc_key.to_vec(), mac_key.to_vec())
}

pub async fn sync(access_token: &str) -> (String, Vec<crate::api::Cipher>) {
    let client =
        crate::api::Client::new_self_hosted("https://bitwarden.tozt.net");
    client.sync(access_token).await.unwrap()
}
