use crate::prelude::*;

use crate::json::{
    DeserializeJsonWithPath as _, DeserializeJsonWithPathAsync as _,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
}

impl std::convert::TryFrom<u32> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u32) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            _ => Err(Error::InvalidTwoFactorProvider { ty }),
        }
    }
}

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
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    two_factor_provider: Option<u32>,
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
struct ConnectErrorRes {
    error: String,
    error_description: String,
    #[serde(rename = "ErrorModel")]
    error_model: Option<ConnectErrorResErrorModel>,
    #[serde(rename = "TwoFactorProviders")]
    two_factor_providers: Option<Vec<u32>>,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorResErrorModel {
    #[serde(rename = "Message")]
    message: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectRefreshTokenReq {
    grant_type: String,
    client_id: String,
    refresh_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectRefreshTokenRes {
    access_token: String,
    expires_in: u32,
    token_type: String,
    refresh_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct SyncRes {
    #[serde(rename = "Ciphers")]
    ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile")]
    profile: SyncResProfile,
    #[serde(rename = "Folders")]
    folders: Vec<SyncResFolder>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResCipher {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "FolderId")]
    folder_id: Option<String>,
    #[serde(rename = "OrganizationId")]
    organization_id: Option<String>,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Login")]
    login: Option<CipherLogin>,
    #[serde(rename = "Card")]
    card: Option<CipherCard>,
    #[serde(rename = "Identity")]
    identity: Option<CipherIdentity>,
    #[serde(rename = "SecureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "Notes")]
    notes: Option<String>,
    #[serde(rename = "PasswordHistory")]
    password_history: Option<Vec<SyncResPasswordHistory>>,
}

impl SyncResCipher {
    fn to_entry(
        &self,
        folders: &[SyncResFolder],
    ) -> Option<crate::db::Entry> {
        let history = if let Some(history) = &self.password_history {
            history
                .iter()
                .map(|entry| crate::db::HistoryEntry {
                    last_used_date: entry.last_used_date.clone(),
                    password: entry.password.clone(),
                })
                .collect()
        } else {
            vec![]
        };
        let (folder, folder_id) = if let Some(folder_id) = &self.folder_id {
            let mut folder_name = None;
            for folder in folders {
                if &folder.id == folder_id {
                    folder_name = Some(folder.name.clone());
                }
            }
            (folder_name, Some(folder_id))
        } else {
            (None, None)
        };
        let data = if let Some(login) = &self.login {
            crate::db::EntryData::Login {
                username: login.username.clone(),
                password: login.password.clone(),
                uris: login.uris.as_ref().map_or_else(
                    std::vec::Vec::new,
                    |uris| {
                        uris.iter()
                            .filter_map(|uri| uri.uri.clone())
                            .collect()
                    },
                ),
            }
        } else if let Some(card) = &self.card {
            crate::db::EntryData::Card {
                cardholder_name: card.cardholder_name.clone(),
                number: card.number.clone(),
                brand: card.brand.clone(),
                exp_month: card.exp_month.clone(),
                exp_year: card.exp_year.clone(),
                code: card.code.clone(),
            }
        } else if let Some(identity) = &self.identity {
            crate::db::EntryData::Identity {
                title: identity.title.clone(),
                first_name: identity.first_name.clone(),
                middle_name: identity.middle_name.clone(),
                last_name: identity.last_name.clone(),
                address1: identity.address1.clone(),
                address2: identity.address2.clone(),
                address3: identity.address3.clone(),
                city: identity.city.clone(),
                state: identity.state.clone(),
                postal_code: identity.postal_code.clone(),
                country: identity.country.clone(),
                phone: identity.phone.clone(),
                email: identity.email.clone(),
                ssn: identity.ssn.clone(),
                license_number: identity.license_number.clone(),
                passport_number: identity.passport_number.clone(),
                username: identity.username.clone(),
            }
        } else if let Some(_secure_note) = &self.secure_note {
            crate::db::EntryData::SecureNote
        } else {
            return None;
        };
        Some(crate::db::Entry {
            id: self.id.clone(),
            org_id: self.organization_id.clone(),
            folder,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: self.name.clone(),
            data,
            notes: self.notes.clone(),
            history,
        })
    }
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfile {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "PrivateKey")]
    private_key: String,
    #[serde(rename = "Organizations")]
    organizations: Vec<SyncResProfileOrganization>,
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfileOrganization {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Key")]
    key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct SyncResFolder {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLogin {
    #[serde(rename = "Username")]
    username: Option<String>,
    #[serde(rename = "Password")]
    password: Option<String>,
    #[serde(rename = "Uris")]
    uris: Option<Vec<CipherLoginUri>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLoginUri {
    #[serde(rename = "Uri")]
    uri: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherCard {
    #[serde(rename = "CardholderName")]
    cardholder_name: Option<String>,
    #[serde(rename = "Number")]
    number: Option<String>,
    #[serde(rename = "Brand")]
    brand: Option<String>,
    #[serde(rename = "ExpMonth")]
    exp_month: Option<String>,
    #[serde(rename = "ExpYear")]
    exp_year: Option<String>,
    #[serde(rename = "Code")]
    code: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherIdentity {
    #[serde(rename = "Title")]
    title: Option<String>,
    #[serde(rename = "FirstName")]
    first_name: Option<String>,
    #[serde(rename = "MiddleName")]
    middle_name: Option<String>,
    #[serde(rename = "LastName")]
    last_name: Option<String>,
    #[serde(rename = "Address1")]
    address1: Option<String>,
    #[serde(rename = "Address2")]
    address2: Option<String>,
    #[serde(rename = "Address3")]
    address3: Option<String>,
    #[serde(rename = "City")]
    city: Option<String>,
    #[serde(rename = "State")]
    state: Option<String>,
    #[serde(rename = "PostalCode")]
    postal_code: Option<String>,
    #[serde(rename = "Country")]
    country: Option<String>,
    #[serde(rename = "Phone")]
    phone: Option<String>,
    #[serde(rename = "Email")]
    email: Option<String>,
    #[serde(rename = "SSN")]
    ssn: Option<String>,
    #[serde(rename = "LicenseNumber")]
    license_number: Option<String>,
    #[serde(rename = "PassportNumber")]
    passport_number: Option<String>,
    #[serde(rename = "Username")]
    username: Option<String>,
}

// this is just a name and some notes, both of which are already on the cipher
// object
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherSecureNote {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResPasswordHistory {
    #[serde(rename = "LastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password")]
    password: String,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPostReq {
    #[serde(rename = "type")]
    ty: u32, // XXX what are the valid types?
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    name: String,
    notes: Option<String>,
    login: Option<CipherLogin>,
    card: Option<CipherCard>,
    identity: Option<CipherIdentity>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPutReq {
    #[serde(rename = "type")]
    ty: u32, // XXX what are the valid types?
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    name: String,
    notes: Option<String>,
    login: Option<CipherLogin>,
    card: Option<CipherCard>,
    identity: Option<CipherIdentity>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "passwordHistory")]
    password_history: Vec<CiphersPutReqHistory>,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPutReqLogin {
    username: Option<String>,
    password: Option<String>,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPutReqHistory {
    #[serde(rename = "LastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password")]
    password: String,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersRes {
    #[serde(rename = "Data")]
    data: Vec<FoldersResData>,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersResData {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
}

#[derive(serde::Serialize, Debug)]
struct FoldersPostReq {
    name: String,
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
        let prelogin_res: PreloginRes = res.json_with_path().await?;
        Ok(prelogin_res.kdf_iterations)
    }

    pub async fn login(
        &self,
        email: &str,
        master_password_hash: &crate::locked::PasswordHash,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<TwoFactorProviderType>,
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
            two_factor_token: two_factor_token
                .map(std::string::ToString::to_string),
            two_factor_provider: two_factor_provider.map(|ty| ty as u32),
        };
        let client = reqwest::Client::new();
        let res = client
            .post(&self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .context(crate::error::Reqwest)?;
        if let reqwest::StatusCode::OK = res.status() {
            let connect_res: ConnectPasswordRes =
                res.json_with_path().await?;
            Ok((
                connect_res.access_token,
                connect_res.refresh_token,
                connect_res.key,
            ))
        } else {
            let code = res.status().as_u16();
            Err(classify_login_error(&res.json_with_path().await?, code))
        }
    }

    pub async fn sync(
        &self,
        access_token: &str,
    ) -> Result<(
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
    )> {
        let client = reqwest::Client::new();
        let res = client
            .get(&self.api_url("/sync"))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .context(crate::error::Reqwest)?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let sync_res: SyncRes = res.json_with_path().await?;
                let folders = sync_res.folders.clone();
                let ciphers = sync_res
                    .ciphers
                    .iter()
                    .filter_map(|cipher| cipher.to_entry(&folders))
                    .collect();
                let org_keys = sync_res
                    .profile
                    .organizations
                    .iter()
                    .map(|org| (org.id.clone(), org.key.clone()))
                    .collect();
                Ok((
                    sync_res.profile.key,
                    sync_res.profile.private_key,
                    org_keys,
                    ciphers,
                ))
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
        data: &crate::db::EntryData,
        notes: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<()> {
        let mut req = CiphersPostReq {
            ty: 1,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: name.to_string(),
            notes: notes.map(std::string::ToString::to_string),
            login: None,
            card: None,
            identity: None,
            secure_note: None,
        };
        match data {
            crate::db::EntryData::Login {
                username,
                password,
                uris,
            } => {
                let uris = if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|s| CipherLoginUri {
                                uri: Some(s.to_string()),
                            })
                            .collect(),
                    )
                };
                req.login = Some(CipherLogin {
                    username: username.clone(),
                    password: password.clone(),
                    uris,
                })
            }
            crate::db::EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                req.card = Some(CipherCard {
                    cardholder_name: cardholder_name.clone(),
                    number: number.clone(),
                    brand: brand.clone(),
                    exp_month: exp_month.clone(),
                    exp_year: exp_year.clone(),
                    code: code.clone(),
                });
            }
            crate::db::EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => {
                req.identity = Some(CipherIdentity {
                    title: title.clone(),
                    first_name: first_name.clone(),
                    middle_name: middle_name.clone(),
                    last_name: last_name.clone(),
                    address1: address1.clone(),
                    address2: address2.clone(),
                    address3: address3.clone(),
                    city: city.clone(),
                    state: state.clone(),
                    postal_code: postal_code.clone(),
                    country: country.clone(),
                    phone: phone.clone(),
                    email: email.clone(),
                    ssn: ssn.clone(),
                    license_number: license_number.clone(),
                    passport_number: passport_number.clone(),
                    username: username.clone(),
                });
            }
            crate::db::EntryData::SecureNote {} => {
                req.secure_note = Some(CipherSecureNote {});
            }
        }
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

    pub fn edit(
        &self,
        access_token: &str,
        id: &str,
        org_id: Option<&str>,
        name: &str,
        data: &crate::db::EntryData,
        notes: Option<&str>,
        folder_uuid: Option<&str>,
        history: &[crate::db::HistoryEntry],
    ) -> Result<()> {
        let mut req = CiphersPutReq {
            ty: 1,
            folder_id: folder_uuid.map(std::string::ToString::to_string),
            organization_id: org_id.map(std::string::ToString::to_string),
            name: name.to_string(),
            notes: notes.map(std::string::ToString::to_string),
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            password_history: history
                .iter()
                .map(|entry| CiphersPutReqHistory {
                    last_used_date: entry.last_used_date.clone(),
                    password: entry.password.clone(),
                })
                .collect(),
        };
        match data {
            crate::db::EntryData::Login {
                username,
                password,
                uris,
            } => {
                let uris = if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|s| CipherLoginUri {
                                uri: Some(s.to_string()),
                            })
                            .collect(),
                    )
                };
                req.login = Some(CipherLogin {
                    username: username.clone(),
                    password: password.clone(),
                    uris,
                });
            }
            crate::db::EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                req.card = Some(CipherCard {
                    cardholder_name: cardholder_name.clone(),
                    number: number.clone(),
                    brand: brand.clone(),
                    exp_month: exp_month.clone(),
                    exp_year: exp_year.clone(),
                    code: code.clone(),
                });
            }
            crate::db::EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => {
                req.identity = Some(CipherIdentity {
                    title: title.clone(),
                    first_name: first_name.clone(),
                    middle_name: middle_name.clone(),
                    last_name: last_name.clone(),
                    address1: address1.clone(),
                    address2: address2.clone(),
                    address3: address3.clone(),
                    city: city.clone(),
                    state: state.clone(),
                    postal_code: postal_code.clone(),
                    country: country.clone(),
                    phone: phone.clone(),
                    email: email.clone(),
                    ssn: ssn.clone(),
                    license_number: license_number.clone(),
                    passport_number: passport_number.clone(),
                    username: username.clone(),
                });
            }
            crate::db::EntryData::SecureNote {} => {
                req.secure_note = Some(CipherSecureNote {});
            }
        }
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(&self.api_url(&format!("/ciphers/{}", id)))
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

    pub fn remove(&self, access_token: &str, id: &str) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .delete(&self.api_url(&format!("/ciphers/{}", id)))
            .header("Authorization", format!("Bearer {}", access_token))
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

    pub fn folders(
        &self,
        access_token: &str,
    ) -> Result<Vec<(String, String)>> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(&self.api_url("/folders"))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .context(crate::error::Reqwest)?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let folders_res: FoldersRes = res.json_with_path()?;
                Ok(folders_res
                    .data
                    .iter()
                    .map(|folder| (folder.id.clone(), folder.name.clone()))
                    .collect())
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn create_folder(
        &self,
        access_token: &str,
        name: &str,
    ) -> Result<String> {
        let req = FoldersPostReq {
            name: name.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(&self.api_url("/folders"))
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&req)
            .send()
            .context(crate::error::Reqwest)?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let folders_res: FoldersResData = res.json_with_path()?;
                Ok(folders_res.id)
            }
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
        let connect_res: ConnectRefreshTokenRes = res.json_with_path()?;
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
            res.json_with_path().await?;
        Ok(connect_res.access_token)
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}

fn classify_login_error(error_res: &ConnectErrorRes, code: u16) -> Error {
    match error_res.error.as_str() {
        "invalid_grant" => match error_res.error_description.as_str() {
            "invalid_username_or_password" => {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    return Error::IncorrectPassword { message };
                }
            }
            "Two factor required." => {
                if let Some(providers) =
                    error_res.two_factor_providers.as_ref()
                {
                    let providers: Result<_> = providers
                        .iter()
                        .copied()
                        .map(std::convert::TryInto::try_into)
                        .collect();
                    return match providers {
                        Ok(providers) => {
                            Error::TwoFactorRequired { providers }
                        }
                        Err(e) => e,
                    };
                }
            }
            _ => {}
        },
        "" => {
            // bitwarden_rs returns an empty error and error_description for
            // this case, for some reason
            if error_res.error_description == "" {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    match message.as_str() {
                        "Username or password is incorrect. Try again"
                        | "TOTP code is not a number" => {
                            return Error::IncorrectPassword { message };
                        }
                        s => {
                            if s.starts_with(
                                "Invalid TOTP code! Server time: ",
                            ) {
                                return Error::IncorrectPassword { message };
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    log::warn!("unexpected error received during login: {:?}", error_res);
    Error::RequestFailed { status: code }
}
