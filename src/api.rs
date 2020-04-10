use crate::prelude::*;

#[derive(serde::Serialize, Debug)]
struct PreloginReq {
    email: String,
}

#[derive(serde::Deserialize, Debug)]
struct PreloginRes {
    #[serde(rename = "Kdf")]
    kdf: u32,
    #[serde(rename = "KdfIterations")]
    kdf_iterations: u32,
}

#[derive(serde::Serialize, Debug)]
struct ConnectReq {
    grant_type: String,
    username: String,
    password: String,
    scope: String,
    client_id: String,
    #[serde(rename = "deviceType")]
    device_type: u32,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "deviceName")]
    device_name: String,
    #[serde(rename = "devicePushToken")]
    device_push_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectRes {
    access_token: String,
    expires_in: u32,
    token_type: String,
    refresh_token: String,
    #[serde(rename = "Key")]
    key: String,
}

#[derive(serde::Deserialize, Debug)]
struct SyncRes {
    #[serde(rename = "Ciphers")]
    ciphers: Vec<Cipher>,
    #[serde(rename = "Profile")]
    profile: Profile,
}

#[derive(serde::Deserialize, Debug)]
struct Profile {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Cipher {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Login")]
    pub login: Login,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Login {
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Password")]
    pub password: String,
}

#[derive(Debug)]
pub struct Client {
    base_url: String,
    identity_url: String,
}

impl Client {
    pub fn new(base_url: &str, identity_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            identity_url: identity_url.to_string(),
        }
    }

    pub async fn prelogin(&self, email: &str) -> Result<u32> {
        let prelogin = PreloginReq {
            email: email.to_string(),
        };
        let client = reqwest::Client::new();
        let res = client
            .post(&self.api_url("/accounts/prelogin"))
            .json(&prelogin)
            .send()
            .await
            .context(crate::error::Reqwest)?;
        let prelogin_res: PreloginRes =
            res.json().await.context(crate::error::Reqwest)?;
        Ok(prelogin_res.kdf_iterations)
    }

    pub async fn login(
        &self,
        email: &str,
        master_password_hash: &crate::locked::PasswordHash,
    ) -> Result<(String, String, String)> {
        let connect_req = ConnectReq {
            grant_type: "password".to_string(),
            username: email.to_string(),
            password: base64::encode(master_password_hash.hash()),
            scope: "api offline_access".to_string(),
            client_id: "desktop".to_string(),
            device_type: 8,
            device_identifier: uuid::Uuid::new_v4()
                .to_hyphenated()
                .to_string(),
            device_name: "test cli".to_string(),
            device_push_token: "".to_string(),
        };
        let client = reqwest::Client::new();
        let res = client
            .post(&self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .context(crate::error::Reqwest)?;
        let connect_res: ConnectRes =
            res.json().await.context(crate::error::Reqwest)?;
        Ok((
            connect_res.access_token,
            connect_res.refresh_token,
            connect_res.key,
        ))
    }

    pub async fn sync(
        &self,
        access_token: &str,
    ) -> Result<(String, Vec<Cipher>)> {
        let client = reqwest::Client::new();
        let res = client
            .get(&self.api_url("/sync"))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .context(crate::error::Reqwest)?;
        let sync_res: SyncRes =
            res.json().await.context(crate::error::Reqwest)?;
        Ok((sync_res.profile.key, sync_res.ciphers))
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}
