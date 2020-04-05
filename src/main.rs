mod api;
mod error;
mod identity;
mod prelude;
mod secret;

fn main() {
    let client = api::Client::new_self_hosted("https://bitwarden.tozt.net");

    let email = rprompt::prompt_reply_stderr("Email: ").unwrap();
    let password = rpassword::prompt_password_stderr("Password: ").unwrap();

    let iterations = client.prelogin(&email).unwrap();
    let identity =
        identity::Identity::new(&email, &password, iterations).unwrap();

    let (access_token, _refresh_token, protected_key) = client
        .login(&identity.email, &identity.master_password_hash)
        .unwrap();

    let protected_key = secret::Secret::new(&protected_key).unwrap();
    let master_key = protected_key
        .decrypt(&identity.enc_key, &identity.mac_key)
        .unwrap();

    let enc_key = &master_key[0..32];
    let mac_key = &master_key[32..64];

    let ciphers = client.sync(&access_token).unwrap();
    for cipher in ciphers {
        let secret_name = secret::Secret::new(&cipher.name).unwrap();
        let name = secret_name.decrypt(enc_key, mac_key).unwrap();
        let secret_username =
            secret::Secret::new(&cipher.login.username).unwrap();
        let username = secret_username.decrypt(enc_key, mac_key).unwrap();
        let secret_password =
            secret::Secret::new(&cipher.login.password).unwrap();
        let password = secret_password.decrypt(enc_key, mac_key).unwrap();
        println!("{}:", String::from_utf8(name).unwrap());
        println!("  Username: {}", String::from_utf8(username).unwrap());
        println!("  Password: {}", String::from_utf8(password).unwrap());
    }
}
