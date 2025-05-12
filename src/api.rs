// serde_repr generates some as conversions that we can't seem to silence from
// here, unfortunately
#![allow(clippy::as_conversions)]

use crate::prelude::*;

use rand::Rng as _;
use sha2::Digest as _;
use tokio::io::AsyncReadExt as _;

use crate::json::{
    DeserializeJsonWithPath as _, DeserializeJsonWithPathAsync as _,
};

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl std::fmt::Display for UriMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::enum_glob_use)]
        use UriMatchType::*;
        let s = match self {
            Domain => "domain",
            Host => "host",
            StartsWith => "starts_with",
            Exact => "exact",
            RegularExpression => "regular_expression",
            Never => "never",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TwoFactorProviderType {
    pub fn message(&self) -> &str {
        match *self {
            Self::Authenticator => "Enter the 6 digit verification code from your authenticator app.",
            Self::Yubikey => "Insert your Yubikey and push the button.",
            Self::Email => "Enter the PIN you received via email.",
            _ => "Enter the code."
        }
    }

    pub fn header(&self) -> &str {
        match *self {
            Self::Authenticator => "Authenticator App",
            Self::Yubikey => "Yubikey",
            Self::Email => "Email Code",
            _ => "Two Factor Authentication",
        }
    }

    pub fn grab(&self) -> bool {
        !matches!(self, Self::Email)
    }
}

impl<'de> serde::Deserialize<'de> for TwoFactorProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TwoFactorProviderTypeVisitor;
        impl serde::de::Visitor<'_> for TwoFactorProviderTypeVisitor {
            type Value = TwoFactorProviderType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("two factor provider id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(TwoFactorProviderTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for TwoFactorProviderType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Authenticator),
            "1" => Ok(Self::Email),
            "2" => Ok(Self::Duo),
            "3" => Ok(Self::Yubikey),
            "4" => Ok(Self::U2f),
            "5" => Ok(Self::Remember),
            "6" => Ok(Self::OrganizationDuo),
            "7" => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider { ty: ty.to_string() }),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl<'de> serde::Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KdfTypeVisitor;
        impl serde::de::Visitor<'_> for KdfTypeVisitor {
            type Value = KdfType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("kdf id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(KdfTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for KdfType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for KdfType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Pbkdf2),
            "1" => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType { ty: ty.to_string() }),
        }
    }
}

impl serde::Serialize for KdfType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::Pbkdf2 => "0",
            Self::Argon2id => "1",
        };
        serializer.serialize_str(s)
    }
}

#[derive(serde::Serialize, Debug)]
struct PreloginReq {
    email: String,
}

#[derive(serde::Deserialize, Debug)]
struct PreloginRes {
    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: KdfType,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenReq {
    grant_type: String,
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
    #[serde(flatten)]
    auth: ConnectTokenAuth,
}

#[derive(serde::Serialize, Debug)]
#[serde(untagged)]
enum ConnectTokenAuth {
    Password(ConnectTokenPassword),
    AuthCode(ConnectTokenAuthCode),
    ClientCredentials(ConnectTokenClientCredentials),
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenPassword {
    username: String,
    password: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenAuthCode {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenClientCredentials {
    username: String,
    client_secret: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectTokenRes {
    access_token: String,
    refresh_token: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorRes {
    error: String,
    error_description: Option<String>,
    #[serde(rename = "ErrorModel", alias = "errorModel")]
    error_model: Option<ConnectErrorResErrorModel>,
    #[serde(rename = "TwoFactorProviders", alias = "twoFactorProviders")]
    two_factor_providers: Option<Vec<TwoFactorProviderType>>,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorResErrorModel {
    #[serde(rename = "Message", alias = "message")]
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
}

#[derive(serde::Deserialize, Debug)]
struct SyncRes {
    #[serde(rename = "Ciphers", alias = "ciphers")]
    ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile", alias = "profile")]
    profile: SyncResProfile,
    #[serde(rename = "Folders", alias = "folders")]
    folders: Vec<SyncResFolder>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResCipher {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "FolderId", alias = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "OrganizationId", alias = "organizationId")]
    organization_id: Option<String>,
    #[serde(rename = "Name", alias = "name")]
    name: String,
    #[serde(rename = "Login", alias = "login")]
    login: Option<CipherLogin>,
    #[serde(rename = "Card", alias = "card")]
    card: Option<CipherCard>,
    #[serde(rename = "Identity", alias = "identity")]
    identity: Option<CipherIdentity>,
    #[serde(rename = "SecureNote", alias = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "Notes", alias = "notes")]
    notes: Option<String>,
    #[serde(rename = "PasswordHistory", alias = "passwordHistory")]
    password_history: Option<Vec<SyncResPasswordHistory>>,
    #[serde(rename = "Fields", alias = "fields")]
    fields: Option<Vec<CipherField>>,
    #[serde(rename = "DeletedDate", alias = "deletedDate")]
    deleted_date: Option<String>,
    #[serde(rename = "Key", alias = "key")]
    key: Option<String>,
}

impl SyncResCipher {
    fn to_entry(
        &self,
        folders: &[SyncResFolder],
    ) -> Option<crate::db::Entry> {
        if self.deleted_date.is_some() {
            return None;
        }
        let history =
            self.password_history
                .as_ref()
                .map_or_else(Vec::new, |history| {
                    history
                        .iter()
                        .filter_map(|entry| {
                            // Gets rid of entries with a non-existent
                            // password
                            entry.password.clone().map(|p| {
                                crate::db::HistoryEntry {
                                    last_used_date: entry
                                        .last_used_date
                                        .clone(),
                                    password: p,
                                }
                            })
                        })
                        .collect()
                });

        let (folder, folder_id) =
            self.folder_id.as_ref().map_or((None, None), |folder_id| {
                let mut folder_name = None;
                for folder in folders {
                    if &folder.id == folder_id {
                        folder_name = Some(folder.name.clone());
                    }
                }
                (folder_name, Some(folder_id))
            });
        let data = if let Some(login) = &self.login {
            crate::db::EntryData::Login {
                username: login.username.clone(),
                password: login.password.clone(),
                totp: login.totp.clone(),
                uris: login.uris.as_ref().map_or_else(
                    std::vec::Vec::new,
                    |uris| {
                        uris.iter()
                            .filter_map(|uri| {
                                uri.uri.clone().map(|s| crate::db::Uri {
                                    uri: s,
                                    match_type: uri.match_type,
                                })
                            })
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
        let fields = self.fields.as_ref().map_or_else(Vec::new, |fields| {
            fields
                .iter()
                .map(|field| crate::db::Field {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect()
        });
        Some(crate::db::Entry {
            id: self.id.clone(),
            org_id: self.organization_id.clone(),
            folder,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: self.name.clone(),
            data,
            fields,
            notes: self.notes.clone(),
            history,
            key: self.key.clone(),
        })
    }
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfile {
    #[serde(rename = "Key", alias = "key")]
    key: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: String,
    #[serde(rename = "Organizations", alias = "organizations")]
    organizations: Vec<SyncResProfileOrganization>,
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfileOrganization {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct SyncResFolder {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLogin {
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
    #[serde(rename = "Totp", alias = "totp")]
    totp: Option<String>,
    #[serde(rename = "Uris", alias = "uris")]
    uris: Option<Vec<CipherLoginUri>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLoginUri {
    #[serde(rename = "Uri", alias = "uri")]
    uri: Option<String>,
    #[serde(rename = "Match", alias = "match")]
    match_type: Option<UriMatchType>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherCard {
    #[serde(rename = "CardholderName", alias = "cardholderName")]
    cardholder_name: Option<String>,
    #[serde(rename = "Number", alias = "number")]
    number: Option<String>,
    #[serde(rename = "Brand", alias = "brand")]
    brand: Option<String>,
    #[serde(rename = "ExpMonth", alias = "expMonth")]
    exp_month: Option<String>,
    #[serde(rename = "ExpYear", alias = "expYear")]
    exp_year: Option<String>,
    #[serde(rename = "Code", alias = "code")]
    code: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherIdentity {
    #[serde(rename = "Title", alias = "title")]
    title: Option<String>,
    #[serde(rename = "FirstName", alias = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "MiddleName", alias = "middleName")]
    middle_name: Option<String>,
    #[serde(rename = "LastName", alias = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "Address1", alias = "address1")]
    address1: Option<String>,
    #[serde(rename = "Address2", alias = "address2")]
    address2: Option<String>,
    #[serde(rename = "Address3", alias = "address3")]
    address3: Option<String>,
    #[serde(rename = "City", alias = "city")]
    city: Option<String>,
    #[serde(rename = "State", alias = "state")]
    state: Option<String>,
    #[serde(rename = "PostalCode", alias = "postalCode")]
    postal_code: Option<String>,
    #[serde(rename = "Country", alias = "country")]
    country: Option<String>,
    #[serde(rename = "Phone", alias = "phone")]
    phone: Option<String>,
    #[serde(rename = "Email", alias = "email")]
    email: Option<String>,
    #[serde(rename = "SSN", alias = "ssn")]
    ssn: Option<String>,
    #[serde(rename = "LicenseNumber", alias = "licenseNumber")]
    license_number: Option<String>,
    #[serde(rename = "PassportNumber", alias = "passportNumber")]
    passport_number: Option<String>,
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[repr(u16)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
    Linked = 3,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[repr(u16)]
pub enum LinkedIdType {
    LoginUsername = 100,
    LoginPassword = 101,
    CardCardholderName = 300,
    CardExpMonth = 301,
    CardExpYear = 302,
    CardCode = 303,
    CardBrand = 304,
    CardNumber = 305,
    IdentityTitle = 400,
    IdentityMiddleName = 401,
    IdentityAddress1 = 402,
    IdentityAddress2 = 403,
    IdentityAddress3 = 404,
    IdentityCity = 405,
    IdentityState = 406,
    IdentityPostalCode = 407,
    IdentityCountry = 408,
    IdentityCompany = 409,
    IdentityEmail = 410,
    IdentityPhone = 411,
    IdentitySsn = 412,
    IdentityUsername = 413,
    IdentityPassportNumber = 414,
    IdentityLicenseNumber = 415,
    IdentityFirstName = 416,
    IdentityLastName = 417,
    IdentityFullName = 418,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherField {
    #[serde(rename = "Type", alias = "type")]
    ty: Option<FieldType>,
    #[serde(rename = "Name", alias = "name")]
    name: Option<String>,
    #[serde(rename = "Value", alias = "value")]
    value: Option<String>,
    #[serde(rename = "LinkedId", alias = "linkedId")]
    linked_id: Option<LinkedIdType>,
}

// this is just a name and some notes, both of which are already on the cipher
// object
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherSecureNote {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResPasswordHistory {
    #[serde(rename = "LastUsedDate", alias = "lastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
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
    fields: Vec<CipherField>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "passwordHistory")]
    password_history: Vec<CiphersPutReqHistory>,
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
    #[serde(rename = "Data", alias = "data")]
    data: Vec<FoldersResData>,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersResData {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(serde::Serialize, Debug)]
struct FoldersPostReq {
    name: String,
}

// Used for the Bitwarden-Client-Name header. Accepted values:
// https://github.com/bitwarden/server/blob/main/src/Core/Enums/BitwardenClient.cs
const BITWARDEN_CLIENT: &str = "cli";

// DeviceType.LinuxDesktop, as per Bitwarden API device types.
const DEVICE_TYPE: u8 = 8;

#[derive(Debug)]
pub struct Client {
    base_url: String,
    identity_url: String,
    ui_url: String,
    client_cert_path: Option<std::path::PathBuf>,
}

impl Client {
    pub fn new(
        base_url: &str,
        identity_url: &str,
        ui_url: &str,
        client_cert_path: Option<&std::path::Path>,
    ) -> Self {
        Self {
            base_url: base_url.to_string(),
            identity_url: identity_url.to_string(),
            ui_url: ui_url.to_string(),
            client_cert_path: client_cert_path
                .map(std::path::Path::to_path_buf),
        }
    }

    async fn reqwest_client(&self) -> Result<reqwest::Client> {
        let mut default_headers = axum::http::HeaderMap::new();
        default_headers.insert(
            "Bitwarden-Client-Name",
            axum::http::HeaderValue::from_static(BITWARDEN_CLIENT),
        );
        default_headers.insert(
            "Bitwarden-Client-Version",
            axum::http::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        default_headers.append(
            "Device-Type",
            // unwrap is safe here because DEVICE_TYPE is a number and digits
            // are valid ASCII
            axum::http::HeaderValue::from_str(&DEVICE_TYPE.to_string())
                .unwrap(),
        );
        let user_agent = format!(
            "{}/{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        if let Some(client_cert_path) = self.client_cert_path.as_ref() {
            let mut buf = Vec::new();
            let mut f = tokio::fs::File::open(client_cert_path)
                .await
                .map_err(|e| Error::LoadClientCert {
                    source: e,
                    file: client_cert_path.clone(),
                })?;
            f.read_to_end(&mut buf).await.map_err(|e| {
                Error::LoadClientCert {
                    source: e,
                    file: client_cert_path.clone(),
                }
            })?;
            let pem = reqwest::Identity::from_pem(&buf)
                .map_err(|e| Error::CreateReqwestClient { source: e })?;
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .identity(pem)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        } else {
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        }
    }

    pub async fn prelogin(
        &self,
        email: &str,
    ) -> Result<(KdfType, u32, Option<u32>, Option<u32>)> {
        let prelogin = PreloginReq {
            email: email.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/accounts/prelogin"))
            .json(&prelogin)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        let prelogin_res: PreloginRes = res.json_with_path().await?;
        Ok((
            prelogin_res.kdf,
            prelogin_res.kdf_iterations,
            prelogin_res.kdf_memory,
            prelogin_res.kdf_parallelism,
        ))
    }

    pub async fn register(
        &self,
        email: &str,
        device_id: &str,
        apikey: &crate::locked::ApiKey,
    ) -> Result<()> {
        let connect_req = ConnectTokenReq {
            auth: ConnectTokenAuth::ClientCredentials(
                ConnectTokenClientCredentials {
                    username: email.to_string(),
                    client_secret: String::from_utf8(
                        apikey.client_secret().to_vec(),
                    )
                    .unwrap(),
                },
            ),
            grant_type: "client_credentials".to_string(),
            scope: "api".to_string(),
            // XXX unwraps here are not necessarily safe
            client_id: String::from_utf8(apikey.client_id().to_vec())
                .unwrap(),
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id.to_string(),
            device_name: "rbw".to_string(),
            device_push_token: String::new(),
            two_factor_token: None,
            two_factor_provider: None,
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    pub async fn login(
        &self,
        email: &str,
        sso_id: Option<&str>,
        device_id: &str,
        password_hash: &crate::locked::PasswordHash,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<TwoFactorProviderType>,
    ) -> Result<(String, String, String)> {
        let connect_req = match sso_id {
            Some(sso_id) => {
                let (sso_code, sso_code_verifier, callback_url) =
                    self.obtain_sso_code(sso_id).await?;

                ConnectTokenReq {
                    auth: ConnectTokenAuth::AuthCode(ConnectTokenAuthCode {
                        code: sso_code,
                        code_verifier: sso_code_verifier,
                        redirect_uri: callback_url,
                    }),
                    grant_type: "authorization_code".to_string(),
                    scope: "api offline_access".to_string(),
                    client_id: "cli".to_string(),
                    device_type: u32::from(DEVICE_TYPE),
                    device_identifier: device_id.to_string(),
                    device_name: "rbw".to_string(),
                    device_push_token: String::new(),
                    two_factor_token: two_factor_token
                        .map(std::string::ToString::to_string),
                    two_factor_provider: two_factor_provider
                        .map(|ty| ty as u32),
                }
            }
            None => ConnectTokenReq {
                auth: ConnectTokenAuth::Password(ConnectTokenPassword {
                    username: email.to_string(),
                    password: crate::base64::encode(password_hash.hash()),
                }),

                grant_type: "password".to_string(),
                scope: "api offline_access".to_string(),
                client_id: "cli".to_string(),
                device_type: 8,
                device_identifier: device_id.to_string(),
                device_name: "rbw".to_string(),
                device_push_token: String::new(),
                two_factor_token: two_factor_token
                    .map(std::string::ToString::to_string),
                two_factor_provider: two_factor_provider.map(|ty| ty as u32),
            },
        };

        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .header(
                "auth-email",
                crate::base64::encode_url_safe_no_pad(email),
            )
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;

        if res.status() == reqwest::StatusCode::OK {
            let connect_res: ConnectTokenRes = res.json_with_path().await?;
            Ok((
                connect_res.access_token,
                connect_res.refresh_token,
                connect_res.key,
            ))
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    async fn obtain_sso_code(
        &self,
        sso_id: &str,
    ) -> Result<(String, String, String)> {
        let state: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let sso_code_verifier: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let mut hasher = sha2::Sha256::new();
        hasher.update(sso_code_verifier.clone());
        let code_challenge =
            crate::base64::encode_url_safe_no_pad(hasher.finalize());

        let port = find_free_port(8065, 8070).await?;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| Error::CreateSSOCallbackServer { err: e })?;

        let callback_server =
            start_sso_callback_server(listener, state.as_str());

        let callback_url =
            "http://localhost:".to_string() + port.to_string().as_str();

        open::that(
            self.ui_url.clone()
                + "/#/sso?clientId="
                + "cli"
                + "&redirectUri="
                + urlencoding::encode(callback_url.as_str())
                    .into_owned()
                    .as_str()
                + "&state="
                + state.as_str()
                + "&codeChallenge="
                + code_challenge.as_str()
                + "&identifier="
                + sso_id,
        )
        .map_err(|e| Error::FailedToOpenWebBrowser { err: e })?;
        // TODO: probably it'd be better to display the URL in the console if the automatic
        // open operation fails, instead of failing the whole process? E.g. docker container
        // case

        let sso_code = callback_server.await?;

        Ok((sso_code, sso_code_verifier, callback_url.to_string()))
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
        let client = self.reqwest_client().await?;
        let res = client
            .get(self.api_url("/sync"))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
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
                totp,
                uris,
            } => {
                let uris = if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|s| CipherLoginUri {
                                uri: Some(s.uri.to_string()),
                                match_type: s.match_type,
                            })
                            .collect(),
                    )
                };
                req.login = Some(CipherLogin {
                    username: username.clone(),
                    password: password.clone(),
                    totp: totp.clone(),
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
            crate::db::EntryData::SecureNote => {
                req.secure_note = Some(CipherSecureNote {});
            }
        }
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.api_url("/ciphers"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
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
        fields: &[crate::db::Field],
        notes: Option<&str>,
        folder_uuid: Option<&str>,
        history: &[crate::db::HistoryEntry],
    ) -> Result<()> {
        let mut req = CiphersPutReq {
            ty: match data {
                crate::db::EntryData::Login { .. } => 1,
                crate::db::EntryData::SecureNote => 2,
                crate::db::EntryData::Card { .. } => 3,
                crate::db::EntryData::Identity { .. } => 4,
            },
            folder_id: folder_uuid.map(std::string::ToString::to_string),
            organization_id: org_id.map(std::string::ToString::to_string),
            name: name.to_string(),
            notes: notes.map(std::string::ToString::to_string),
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            fields: fields
                .iter()
                .map(|field| CipherField {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect(),
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
                totp,
                uris,
            } => {
                let uris = if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|s| CipherLoginUri {
                                uri: Some(s.uri.to_string()),
                                match_type: s.match_type,
                            })
                            .collect(),
                    )
                };
                req.login = Some(CipherLogin {
                    username: username.clone(),
                    password: password.clone(),
                    totp: totp.clone(),
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
            crate::db::EntryData::SecureNote => {
                req.secure_note = Some(CipherSecureNote {});
            }
        }
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/ciphers/{id}")))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
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
            .delete(self.api_url(&format!("/ciphers/{id}")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
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
            .get(self.api_url("/folders"))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
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
            .post(self.api_url("/folders"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
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
            client_id: "cli".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        let connect_res: ConnectRefreshTokenRes = res.json_with_path()?;
        Ok(connect_res.access_token)
    }

    pub async fn exchange_refresh_token_async(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "cli".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
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

async fn find_free_port(bottom: u16, top: u16) -> Result<u16> {
    for port in bottom..top {
        if tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }

    Err(Error::FailedToFindFreePort {
        range: format!("({bottom}..{top})"),
    })
}

#[derive(Clone)]
struct SSOHandlerState {
    state: String,
    sender: tokio::sync::mpsc::Sender<Result<String>>,
}

async fn start_sso_callback_server(
    listener: tokio::net::TcpListener,
    state: &str,
) -> Result<String> {
    let (shut_sender, shut_receiver) = tokio::sync::mpsc::channel(1);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

    let sso_handler_state = std::sync::Arc::new(SSOHandlerState {
        state: state.to_string(),
        sender: shut_sender,
    });

    let app = axum::Router::new()
        .route("/", axum::routing::get(handle_sso_callback))
        .with_state(sso_handler_state);

    axum::serve(listener, app)
        .with_graceful_shutdown(sso_server_graceful_shutdown(
            sender,
            shut_receiver,
        ))
        .await
        .map_err(|e| Error::FailedToProcessSSOCallback {
            msg: e.to_string(),
        })?;

    receiver.recv().await.unwrap()
}

async fn sso_server_graceful_shutdown(
    sender: tokio::sync::mpsc::Sender<Result<String>>,
    mut receiver: tokio::sync::mpsc::Receiver<Result<String>>,
) {
    sender.send(receiver.recv().await.unwrap()).await.unwrap();
}

async fn handle_sso_callback(
    axum::extract::State(state): axum::extract::State<
        std::sync::Arc<SSOHandlerState>,
    >,
    axum::extract::Query(params): axum::extract::Query<
        std::collections::HashMap<String, String>,
    >,
) -> axum::http::Response<String> {
    match sso_query_code(&params, state.state.as_str()) {
        Ok(sso_code) => {
            state.sender.send(Ok(sso_code)).await.unwrap();

            axum::http::Response::builder().status(axum::http::StatusCode::OK).
            body(
                "<html><head><title>Success | rbw</title></head><body> \
                  <h1>Successfully authenticated with rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>".to_string()).unwrap()
        }
        Err(e) => {
            state.sender.send(Err(e)).await.unwrap();

            axum::http::Response::builder().status(axum::http::StatusCode::BAD_REQUEST).
            body(
                "<html><head><title>Failed | rbw</title></head><body> \
                  <h1>Something went wrong logging into the rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>".to_string()).unwrap()
        }
    }
}

fn sso_query_code(
    params: &std::collections::HashMap<String, String>,
    state: &str,
) -> Result<String> {
    let sso_code =
        params
            .get("code")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain code from the URL".to_string(),
            })?;

    let received_state =
        params
            .get("state")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain state from the URL".to_string(),
            })?;

    if received_state.split("_identifier=").next().unwrap() != state {
        return Err(Error::FailedToProcessSSOCallback {
            msg: format!("SSO callback states do not match, sent: {state}, received: {received_state}"),
        });
    }

    Ok(sso_code.to_string())
}

fn classify_login_error(error_res: &ConnectErrorRes, code: u16) -> Error {
    let error_desc = error_res.error_description.clone();
    let error_desc = error_desc.as_deref();
    match error_res.error.as_str() {
        "invalid_grant" => match error_desc {
            Some("invalid_username_or_password") => {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    return Error::IncorrectPassword { message };
                }
            }
            Some("Two factor required.") => {
                if let Some(providers) =
                    error_res.two_factor_providers.as_ref()
                {
                    return Error::TwoFactorRequired {
                        providers: providers.clone(),
                    };
                }
            }
            Some("Captcha required.") => {
                return Error::RegistrationRequired;
            }
            _ => {}
        },
        "invalid_client" => {
            return Error::IncorrectApiKey;
        }
        "" => {
            // bitwarden_rs returns an empty error and error_description for
            // this case, for some reason
            if error_desc.is_none() || error_desc == Some("") {
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

    log::warn!("unexpected error received during login: {error_res:?}");
    Error::RequestFailed { status: code }
}
