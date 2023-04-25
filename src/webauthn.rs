use reqwest::Url;
use webauthn_authenticator_rs::{transport::{AnyTransport, Transport}, AuthenticatorBackend};
use webauthn_authenticator_rs::ui::Cli;
use webauthn_rs_proto::PublicKeyCredentialRequestOptions;

pub async fn webauthn(challenge: PublicKeyCredentialRequestOptions) -> String {
    let mut trans = AnyTransport::new().await.unwrap();
    //Todo replace ui
    let ui = Cli {};
    let tokens = trans.connect_all(&ui);
    let mut tokens = tokens.ok().unwrap();
    let authenticator = tokens.get_mut(0).unwrap();

    let origin = String::from("https://") + challenge.rp_id.as_str();
    let origin = Url::parse(origin.as_str()).unwrap();

    let result = authenticator.perform_auth(origin, challenge, 60000);
    let out = serde_json::to_string(&result.unwrap()).unwrap();
    let out = out.replace("\"appid\":null,\"hmac_get_secret\":null", "\"appid\":false");
    let out = out.replace("clientDataJSON", "clientDataJson");
    out
}