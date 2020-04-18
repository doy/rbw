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
struct ConnectPasswordReq {
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

#[derive(serde::Serialize, Debug)]
struct ConnectRefreshTokenReq {
    grant_type: String,
    client_id: String,
    refresh_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectPasswordRes {
    access_token: String,
    expires_in: u32,
    token_type: String,
    refresh_token: String,
    #[serde(rename = "Key")]
    key: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectRefreshTokenRes {
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
    ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile")]
    profile: Profile,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPostReq {
    #[serde(rename = "type")]
    ty: u32, // XXX what are the valid types?
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    name: String,
    notes: Option<String>,
    favorite: bool,
    login: CiphersPostReqLogin,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPostReqLogin {
    uri: Option<String>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct CiphersRes {
    #[serde(rename = "FolderId")]
    folder_id: Option<String>,
    #[serde(rename = "Favorite")]
    favorite: bool,
    #[serde(rename = "Edit")]
    edit: bool,
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "OrganizationId")]
    organization_id: String,
    #[serde(rename = "Type")]
    ty: u32,
    #[serde(rename = "Login")]
    login: CiphersResLogin,
    #[serde(rename = "Username")]
    username: Option<String>,
    #[serde(rename = "Password")]
    password: Option<String>,
    #[serde(rename = "Totp")]
    totp: Option<String>,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Notes")]
    notes: Option<String>,
    #[serde(rename = "Fields")]
    fields: Option<()>, // XXX what type is this?
    #[serde(rename = "Attachments")]
    attachments: Option<()>, // XXX what type is this?
    #[serde(rename = "OrganizationUseTotp")]
    organization_use_totp: bool,
    #[serde(rename = "RevisionDate")]
    revision_date: String,
    #[serde(rename = "Object")]
    object: String,
}

#[derive(serde::Deserialize, Debug)]
struct CiphersResLogin {
    uris: Vec<CiphersResLoginUri>,
}

#[derive(serde::Deserialize, Debug)]
struct CiphersResLoginUri {
    #[serde(rename = "Uri")]
    uri: String,
    #[serde(rename = "Match")]
    mtch: Option<()>, // XXX what type is this?
}

#[derive(serde::Deserialize, Debug)]
struct Profile {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResCipher {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Login")]
    pub login: SyncResLogin,
    #[serde(rename = "Notes")]
    pub notes: Option<String>,
}

impl SyncResCipher {
    fn to_entry(&self) -> crate::db::Entry {
        crate::db::Entry {
            name: self.name.clone(),
            username: self.login.username.clone(),
            password: self.login.password.clone(),
            notes: self.notes.clone(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResLogin {
    #[serde(rename = "Username")]
    pub username: Option<String>,
    #[serde(rename = "Password")]
    pub password: Option<String>,
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
        let connect_req = ConnectPasswordReq {
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
        let connect_res: ConnectPasswordRes =
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
    ) -> Result<(String, Vec<crate::db::Entry>)> {
        let client = reqwest::Client::new();
        let res = client
            .get(&self.api_url("/sync"))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .context(crate::error::Reqwest)?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let sync_res: SyncRes =
                    res.json().await.context(crate::error::Reqwest)?;
                let ciphers = sync_res
                    .ciphers
                    .iter()
                    .map(SyncResCipher::to_entry)
                    .collect();
                Ok((sync_res.profile.key, ciphers))
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn add(
        &self,
        access_token: &str,
        name: &str,
        username: Option<&str>,
        password: Option<&str>,
        notes: Option<&str>,
    ) -> Result<()> {
        let req = CiphersPostReq {
            ty: 1,
            folder_id: None,
            organization_id: None,
            name: name.to_string(),
            notes: notes.map(std::string::ToString::to_string),
            favorite: false,
            login: CiphersPostReqLogin {
                uri: None,
                username: username.map(std::string::ToString::to_string),
                password: password.map(std::string::ToString::to_string),
                totp: None,
            },
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(&self.api_url("/ciphers"))
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&req)
            .send()
            .context(crate::error::Reqwest)?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn exchange_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "desktop".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(&self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .context(crate::error::Reqwest)?;
        let connect_res: ConnectRefreshTokenRes =
            res.json().context(crate::error::Reqwest)?;
        Ok(connect_res.access_token)
    }

    pub async fn exchange_refresh_token_async(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "desktop".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = reqwest::Client::new();
        let res = client
            .post(&self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .context(crate::error::Reqwest)?;
        let connect_res: ConnectRefreshTokenRes =
            res.json().await.context(crate::error::Reqwest)?;
        Ok(connect_res.access_token)
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}
