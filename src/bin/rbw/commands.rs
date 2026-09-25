use std::{fmt::Write as _, io::Write as _, os::unix::ffi::OsStrExt as _};

use anyhow::Context as _;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

const MISSING_CONFIG_HELP: &str =
    "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        rbw config set base_url <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
        rbw config set identity_url <url>\n";

#[derive(Debug, Clone)]
pub enum Needle {
    Name(String),
    Uri(url::Url),
    Uuid(uuid::Uuid, String),
}

impl std::fmt::Display for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self {
            Self::Name(name) => name.clone(),
            Self::Uri(uri) => uri.to_string(),
            Self::Uuid(_, s) => s.clone(),
        };
        write!(f, "{value}")
    }
}

#[allow(clippy::unnecessary_wraps)]
pub fn parse_needle(arg: &str) -> Result<Needle, std::convert::Infallible> {
    if let Ok(uuid) = uuid::Uuid::parse_str(arg) {
        return Ok(Needle::Uuid(uuid, arg.to_string()));
    }
    if let Ok(url) = url::Url::parse(arg) {
        if url.is_special() {
            return Ok(Needle::Uri(url));
        }
    }

    Ok(Needle::Name(arg.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Field {
    Notes,
    Username,
    Password,
    Totp,
    Uris,
    IdentityName,
    City,
    State,
    PostalCode,
    Country,
    Phone,
    Ssn,
    License,
    Passport,
    CardNumber,
    Expiration,
    ExpMonth,
    ExpYear,
    Cvv,
    Cardholder,
    Brand,
    Name,
    Email,
    Address,
    Address1,
    Address2,
    Address3,
    Fingerprint,
    PublicKey,
    PrivateKey,
    Title,
    FirstName,
    MiddleName,
    LastName,
}

impl std::str::FromStr for Field {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "notes" | "note" => Self::Notes,
            "username" | "user" => Self::Username,
            "password" => Self::Password,
            "totp" | "code" => Self::Totp,
            "uris" | "urls" | "sites" => Self::Uris,
            "identityname" => Self::IdentityName,
            "city" => Self::City,
            "state" => Self::State,
            "postcode" | "zipcode" | "zip" => Self::PostalCode,
            "country" => Self::Country,
            "phone" => Self::Phone,
            "ssn" => Self::Ssn,
            "license" => Self::License,
            "passport" => Self::Passport,
            "number" | "card" => Self::CardNumber,
            "exp" => Self::Expiration,
            "exp_month" | "month" => Self::ExpMonth,
            "exp_year" | "year" => Self::ExpYear,
            // the word "code" got preceeded by Totp
            "cvv" => Self::Cvv,
            "cardholder" | "cardholder_name" => Self::Cardholder,
            "brand" | "type" => Self::Brand,
            "name" => Self::Name,
            "email" => Self::Email,
            "address1" => Self::Address1,
            "address2" => Self::Address2,
            "address3" => Self::Address3,
            "address" => Self::Address,
            "fingerprint" => Self::Fingerprint,
            "public_key" => Self::PublicKey,
            "private_key" => Self::PrivateKey,
            "title" => Self::Title,
            "first_name" => Self::FirstName,
            "middle_name" => Self::MiddleName,
            "last_name" => Self::LastName,
            _ => anyhow::bail!("unknown field {s}"),
        })
    }
}

impl Field {
    fn as_str(&self) -> &str {
        match self {
            Self::Notes => "notes",
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Uris => "uris",
            Self::IdentityName => "identityname",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postcode",
            Self::Country => "country",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::License => "license",
            Self::Passport => "passport",
            Self::CardNumber => "number",
            Self::Expiration => "exp",
            Self::ExpMonth => "exp_month",
            Self::ExpYear => "exp_year",
            Self::Cvv => "cvv",
            Self::Cardholder => "cardholder",
            Self::Brand => "brand",
            Self::Name => "name",
            Self::Email => "email",
            Self::Address1 => "address1",
            Self::Address2 => "address2",
            Self::Address3 => "address3",
            Self::Address => "address",
            Self::Fingerprint => "fingerprint",
            Self::PublicKey => "public_key",
            Self::PrivateKey => "private_key",
            Self::Title => "title",
            Self::FirstName => "first_name",
            Self::MiddleName => "middle_name",
            Self::LastName => "last_name",
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, serde::Serialize)]
struct DecryptedListCipher {
    id: String,
    name: Option<String>,
    user: Option<String>,
    folder: Option<String>,
    uris: Option<Vec<String>>,
    #[serde(rename = "type")]
    entry_type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedSearchCipher {
    id: String,
    #[serde(rename = "type")]
    entry_type: String,
    folder: Option<String>,
    name: String,
    user: Option<String>,
    uris: Vec<(String, Option<rbw::api::UriMatchType>)>,
    fields: Vec<String>,
    notes: Option<String>,
}

impl DecryptedSearchCipher {
    fn display_name(&self) -> String {
        self.user.as_ref().map_or_else(
            || self.name.clone(),
            |user| format!("{user}@{}", self.name),
        )
    }

    fn matches(
        &self,
        needle: &Needle,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
        strict_username: bool,
        strict_folder: bool,
        exact: bool,
    ) -> bool {
        let match_str = match (ignore_case, exact) {
            (true, true) => |field: &str, search_term: &str| {
                field.to_lowercase() == search_term.to_lowercase()
            },
            (true, false) => |field: &str, search_term: &str| {
                field.to_lowercase().contains(&search_term.to_lowercase())
            },
            (false, true) => {
                |field: &str, search_term: &str| field == search_term
            }
            (false, false) => {
                |field: &str, search_term: &str| field.contains(search_term)
            }
        };

        match (self.folder.as_deref(), folder) {
            (Some(folder), Some(given_folder)) => {
                if !match_str(folder, given_folder) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_folder {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match (&self.user, username) {
            (Some(username), Some(given_username)) => {
                if !match_str(username, given_username) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_username {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match needle {
            Needle::Uuid(uuid, s) => {
                if uuid::Uuid::parse_str(&self.id) != Ok(*uuid)
                    && !match_str(&self.name, s)
                {
                    return false;
                }
            }
            Needle::Name(name) => {
                if !match_str(&self.name, name) {
                    return false;
                }
            }
            Needle::Uri(given_uri) => {
                if self.uris.iter().all(|(uri, match_type)| {
                    !matches_url(uri, *match_type, given_uri)
                }) {
                    return false;
                }
            }
        }

        true
    }

    fn search_match(&self, term: &str, folder: Option<&str>) -> bool {
        if let Some(folder) = folder {
            if self.folder.as_deref() != Some(folder) {
                return false;
            }
        }

        let mut fields = vec![self.name.clone()];
        if let Some(notes) = &self.notes {
            fields.push(notes.clone());
        }
        if let Some(user) = &self.user {
            fields.push(user.clone());
        }
        fields.extend(self.uris.iter().map(|(uri, _)| uri).cloned());
        fields.extend(self.fields.iter().cloned());

        for field in fields {
            if field.to_lowercase().contains(&term.to_lowercase()) {
                return true;
            }
        }

        false
    }
}

impl From<DecryptedSearchCipher> for DecryptedListCipher {
    fn from(value: DecryptedSearchCipher) -> Self {
        Self {
            id: value.id,
            entry_type: Some(value.entry_type),
            name: Some(value.name),
            user: value.user,
            folder: value.folder,
            uris: Some(value.uris.into_iter().map(|(s, _)| s).collect()),
        }
    }
}

/// Custom field type
#[derive(JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SchemaFieldType {
    /// Plain text field
    Text,
    /// Hidden/secret field (masked in UI)
    Hidden,
    /// Boolean (true/false) field
    Boolean,
    /// Linked field
    Linked,
}

/// URI match rule
#[derive(JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SchemaUriMatchType {
    /// Match the domain (and subdomains) of the URI
    Domain,
    /// Match the exact host (including port)
    Host,
    /// Match if the URI starts with this string
    StartsWith,
    /// Match the exact URI
    Exact,
    /// Match using a regular expression
    RegularExpression,
    /// Never match this URI
    Never,
}

/// A decrypted Bitwarden cipher entry
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedCipher {
    /// The unique identifier (UUID) of this entry. Leave empty when creating a new entry.
    #[serde(default)]
    #[schemars(title = "ID")]
    id: String,
    /// The unique identifier (UUID) of the organization this entry belongs to. Leave null for personal vault.
    #[serde(default)]
    #[schemars(title = "Organization ID")]
    organization_id: Option<String>,
    /// The name of the folder to put this entry in. If the folder doesn't exist, it will be created.
    #[schemars(title = "Folder")]
    folder: Option<String>,
    /// The name of this entry (e.g. the name of the website or service).
    #[schemars(title = "Name")]
    name: String,
    /// The type-specific data of this entry (`Login`, `Card`, `Identity`, `SecureNote`, or `SshKey`).
    #[schemars(title = "Entry Data")]
    data: DecryptedData,
    /// Custom fields associated with this entry.
    #[serde(default)]
    #[schemars(title = "Custom Fields")]
    fields: Vec<DecryptedField>,
    /// Notes or description for this entry.
    #[schemars(title = "Notes")]
    notes: Option<String>,
    /// Password history for this entry (only updated if the password changes).
    #[serde(default)]
    #[schemars(title = "Password History")]
    history: Vec<DecryptedHistoryEntry>,
}

impl DecryptedCipher {
    fn display_custom_field(&self, field: &str, clipboard: bool) {
        for f in &self.fields {
            if f.name.to_lowercase().as_str().contains(field) {
                val_display_or_store(clipboard, &f.value);
                break;
            }
        }
    }
    fn display_short(&self, desc: &str, clipboard: bool) -> bool {
        match &self.data {
            DecryptedData::Login { password, .. } => {
                password.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no password");
                        false
                    },
                    |password| val_display_or_store(clipboard, password),
                )
            }
            DecryptedData::Card { number, .. } => {
                number.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no card number");
                        false
                    },
                    |number| val_display_or_store(clipboard, number),
                )
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<_> =
                    [title, first_name, middle_name, last_name]
                        .iter()
                        .copied()
                        .flatten()
                        .cloned()
                        .collect();
                if names.is_empty() {
                    eprintln!("entry for '{desc}' had no name");
                    false
                } else {
                    val_display_or_store(clipboard, &names.join(" "))
                }
            }
            DecryptedData::SecureNote => self.notes.as_ref().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no notes");
                    false
                },
                |notes| val_display_or_store(clipboard, notes),
            ),
            DecryptedData::SshKey { public_key, .. } => {
                public_key.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no public key");
                        false
                    },
                    |public_key| val_display_or_store(clipboard, public_key),
                )
            }
        }
    }

    fn display_field(&self, desc: &str, field: &str, clipboard: bool) {
        let field = field.to_lowercase();
        let field = field.as_str();
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => match field.parse() {
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = &username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Totp) => {
                    if let Some(totp) = totp {
                        match generate_totp(totp) {
                            Ok(code) => {
                                val_display_or_store(clipboard, &code);
                            }
                            Err(e) => {
                                eprintln!("{e}");
                            }
                        }
                    }
                }
                Ok(Field::Uris) => {
                    if let Some(uris) = uris {
                        let uri_strs: Vec<_> =
                            uris.iter().map(|uri| uri.uri.clone()).collect();
                        val_display_or_store(clipboard, &uri_strs.join("\n"));
                    }
                }
                Ok(Field::Password) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    self.display_custom_field(field, clipboard);
                }
            },
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => match field.parse() {
                Ok(Field::CardNumber) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Expiration) => {
                    if let (Some(month), Some(year)) = (exp_month, exp_year) {
                        val_display_or_store(
                            clipboard,
                            &format!("{month}/{year}"),
                        );
                    }
                }
                Ok(Field::ExpMonth) => {
                    if let Some(exp_month) = exp_month {
                        val_display_or_store(clipboard, exp_month);
                    }
                }
                Ok(Field::ExpYear) => {
                    if let Some(exp_year) = exp_year {
                        val_display_or_store(clipboard, exp_year);
                    }
                }
                Ok(Field::Cvv) => {
                    if let Some(code) = code {
                        val_display_or_store(clipboard, code);
                    }
                }
                Ok(Field::Name | Field::Cardholder) => {
                    if let Some(cardholder_name) = cardholder_name {
                        val_display_or_store(clipboard, cardholder_name);
                    }
                }
                Ok(Field::Brand) => {
                    if let Some(brand) = brand {
                        val_display_or_store(clipboard, brand);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    self.display_custom_field(field, clipboard);
                }
            },
            DecryptedData::Identity {
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
                ..
            } => match field.parse() {
                Ok(Field::Name) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Email) => {
                    if let Some(email) = email {
                        val_display_or_store(clipboard, email);
                    }
                }
                Ok(Field::Address) => {
                    let mut strs = vec![];
                    if let Some(address1) = address1 {
                        strs.push(address1.clone());
                    }
                    if let Some(address2) = address2 {
                        strs.push(address2.clone());
                    }
                    if let Some(address3) = address3 {
                        strs.push(address3.clone());
                    }
                    if !strs.is_empty() {
                        val_display_or_store(clipboard, &strs.join("\n"));
                    }
                }
                Ok(Field::City) => {
                    if let Some(city) = city {
                        val_display_or_store(clipboard, city);
                    }
                }
                Ok(Field::State) => {
                    if let Some(state) = state {
                        val_display_or_store(clipboard, state);
                    }
                }
                Ok(Field::PostalCode) => {
                    if let Some(postal_code) = postal_code {
                        val_display_or_store(clipboard, postal_code);
                    }
                }
                Ok(Field::Country) => {
                    if let Some(country) = country {
                        val_display_or_store(clipboard, country);
                    }
                }
                Ok(Field::Phone) => {
                    if let Some(phone) = phone {
                        val_display_or_store(clipboard, phone);
                    }
                }
                Ok(Field::Ssn) => {
                    if let Some(ssn) = ssn {
                        val_display_or_store(clipboard, ssn);
                    }
                }
                Ok(Field::License) => {
                    if let Some(license_number) = license_number {
                        val_display_or_store(clipboard, license_number);
                    }
                }
                Ok(Field::Passport) => {
                    if let Some(passport_number) = passport_number {
                        val_display_or_store(clipboard, passport_number);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    self.display_custom_field(field, clipboard);
                }
            },
            DecryptedData::SecureNote => match field.parse() {
                Ok(Field::Notes) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    self.display_custom_field(field, clipboard);
                }
            },
            DecryptedData::SshKey {
                fingerprint,
                private_key,
                ..
            } => match field.parse() {
                Ok(Field::Fingerprint) => {
                    if let Some(fingerprint) = fingerprint {
                        val_display_or_store(clipboard, fingerprint);
                    }
                }
                Ok(Field::PublicKey) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::PrivateKey) => {
                    if let Some(private_key) = private_key {
                        val_display_or_store(clipboard, private_key);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    self.display_custom_field(field, clipboard);
                }
            },
        }
    }

    fn display_long(&self, desc: &str, clipboard: bool) {
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);
                displayed |=
                    display_field("TOTP Secret", totp.as_deref(), clipboard);

                if let Some(uris) = uris {
                    for uri in uris {
                        displayed |=
                            display_field("URI", Some(&uri.uri), clipboard);
                        let match_type =
                            uri.match_type.map(|ty| format!("{ty}"));
                        displayed |= display_field(
                            "Match type",
                            match_type.as_deref(),
                            clipboard,
                        );
                    }
                }

                for field in &self.fields {
                    displayed |= display_field(
                        &field.name,
                        Some(&field.value),
                        clipboard,
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                let mut displayed = false;

                displayed |= self.display_short(desc, clipboard);
                if let (Some(exp_month), Some(exp_year)) =
                    (exp_month, exp_year)
                {
                    println!("Expiration: {exp_month}/{exp_year}");
                    displayed = true;
                }
                displayed |= display_field("CVV", code.as_deref(), clipboard);
                displayed |= display_field(
                    "Name",
                    cardholder_name.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Brand", brand.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Identity {
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
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);

                displayed |=
                    display_field("Address", address1.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address2.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address3.as_deref(), clipboard);
                displayed |=
                    display_field("City", city.as_deref(), clipboard);
                displayed |=
                    display_field("State", state.as_deref(), clipboard);
                displayed |= display_field(
                    "Postcode",
                    postal_code.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Country", country.as_deref(), clipboard);
                displayed |=
                    display_field("Phone", phone.as_deref(), clipboard);
                displayed |=
                    display_field("Email", email.as_deref(), clipboard);
                displayed |= display_field("SSN", ssn.as_deref(), clipboard);
                displayed |= display_field(
                    "License",
                    license_number.as_deref(),
                    clipboard,
                );
                displayed |= display_field(
                    "Passport",
                    passport_number.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::SecureNote => {
                self.display_short(desc, clipboard);
            }
            DecryptedData::SshKey { fingerprint, .. } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |= display_field(
                    "Fingerprint",
                    fingerprint.as_deref(),
                    clipboard,
                );

                for field in &self.fields {
                    displayed |= display_field(
                        &field.name,
                        Some(&field.value),
                        clipboard,
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
        }
    }

    /// This implementation mirror the `fn display_fied` method on which field to list
    fn display_fields_list(&self) {
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                if username.is_some() {
                    println!("{}", Field::Username);
                }
                if totp.is_some() {
                    println!("{}", Field::Totp);
                }
                if uris.is_some() {
                    println!("{}", Field::Uris);
                }
                if password.is_some() {
                    println!("{}", Field::Password);
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if number.is_some() {
                    println!("{}", Field::CardNumber);
                }
                if exp_month.is_some() {
                    println!("{}", Field::ExpMonth);
                }
                if exp_year.is_some() {
                    println!("{}", Field::ExpYear);
                }
                if code.is_some() {
                    println!("{}", Field::Cvv);
                }
                if cardholder_name.is_some() {
                    println!("{}", Field::Cardholder);
                }
                if brand.is_some() {
                    println!("{}", Field::Brand);
                }
            }

            DecryptedData::Identity {
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
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                if [title, first_name, middle_name, last_name]
                    .iter()
                    .any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("name");
                }
                if email.is_some() {
                    println!("{}", Field::Email);
                }
                if [address1, address2, address3].iter().any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("address");
                }
                if city.is_some() {
                    println!("{}", Field::City);
                }
                if state.is_some() {
                    println!("{}", Field::State);
                }
                if postal_code.is_some() {
                    println!("{}", Field::PostalCode);
                }
                if country.is_some() {
                    println!("{}", Field::Country);
                }
                if phone.is_some() {
                    println!("{}", Field::Phone);
                }
                if ssn.is_some() {
                    println!("{}", Field::Ssn);
                }
                if license_number.is_some() {
                    println!("{}", Field::License);
                }
                if passport_number.is_some() {
                    println!("{}", Field::Passport);
                }
                if username.is_some() {
                    println!("{}", Field::Username);
                }
            }

            DecryptedData::SecureNote => (), // handled at the end
            DecryptedData::SshKey {
                fingerprint,
                public_key,
                ..
            } => {
                if fingerprint.is_some() {
                    println!("{}", Field::Fingerprint);
                }
                if public_key.is_some() {
                    println!("{}", Field::PublicKey);
                }
            }
        }

        if self.notes.is_some() {
            println!("{}", Field::Notes);
        }
        for f in &self.fields {
            println!("{}", f.name);
        }
    }

    fn display_json(&self, desc: &str) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(std::io::stdout(), &self)
            .context(format!("failed to write entry '{desc}' to stdout"))?;
        println!();

        Ok(())
    }

    fn display_yaml(&self, desc: &str) -> anyhow::Result<()> {
        serde_yaml::to_writer(std::io::stdout(), &self)
            .context(format!("failed to write entry '{desc}' to stdout"))?;
        println!();

        Ok(())
    }
}

fn val_display_or_store(clipboard: bool, password: &str) -> bool {
    if clipboard {
        match clipboard_store(password) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        }
    } else {
        println!("{password}");
        true
    }
}

/// Type-specific data of the entry
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged, deny_unknown_fields, remote = "Self")]
#[cfg_attr(test, derive(Eq, PartialEq))]
enum DecryptedData {
    /// Login credentials (username, password, TOTP, URIs)
    #[schemars(title = "Login")]
    Login {
        /// The login username
        #[schemars(title = "Username")]
        username: Option<String>,
        /// The login password
        #[schemars(title = "Password")]
        password: Option<String>,
        /// The TOTP (Time-based One-Time Password) secret key
        #[schemars(title = "TOTP Secret")]
        totp: Option<String>,
        /// URIs (URLs) associated with this login
        #[schemars(title = "URIs")]
        uris: Option<Vec<DecryptedUri>>,
    },
    /// Credit/debit card details
    #[schemars(title = "Card")]
    Card {
        /// The name on the card
        #[schemars(title = "Cardholder Name")]
        cardholder_name: Option<String>,
        /// The card number
        #[schemars(title = "Card Number")]
        number: Option<String>,
        /// The card brand (e.g. Visa, Mastercard)
        #[schemars(title = "Brand")]
        brand: Option<String>,
        /// The expiration month (MM)
        #[schemars(title = "Expiration Month")]
        exp_month: Option<String>,
        /// The expiration year (YYYY)
        #[schemars(title = "Expiration Year")]
        exp_year: Option<String>,
        /// The security code (CVV/CVC)
        #[schemars(title = "Security Code (CVV)")]
        code: Option<String>,
    },
    /// Identity/personal details
    #[schemars(title = "Identity")]
    Identity {
        /// Honorific title (e.g. Mr., Ms.)
        #[schemars(title = "Title")]
        title: Option<String>,
        /// First name
        #[schemars(title = "First Name")]
        first_name: Option<String>,
        /// Middle name
        #[schemars(title = "Middle Name")]
        middle_name: Option<String>,
        /// Last name
        #[schemars(title = "Last Name")]
        last_name: Option<String>,
        /// Address line 1
        #[schemars(title = "Address Line 1")]
        address1: Option<String>,
        /// Address line 2
        #[schemars(title = "Address Line 2")]
        address2: Option<String>,
        /// Address line 3
        #[schemars(title = "Address Line 3")]
        address3: Option<String>,
        /// City
        #[schemars(title = "City")]
        city: Option<String>,
        /// State/Province
        #[schemars(title = "State/Province")]
        state: Option<String>,
        /// Postal/ZIP code
        #[schemars(title = "Postal/ZIP Code")]
        postal_code: Option<String>,
        /// Country
        #[schemars(title = "Country")]
        country: Option<String>,
        /// Phone number
        #[schemars(title = "Phone")]
        phone: Option<String>,
        /// Email address
        #[schemars(title = "Email")]
        email: Option<String>,
        /// Social Security Number (SSN) or equivalent
        #[schemars(title = "SSN")]
        ssn: Option<String>,
        /// Driver's license number
        #[schemars(title = "Driver's License")]
        license_number: Option<String>,
        /// Passport number
        #[schemars(title = "Passport Number")]
        passport_number: Option<String>,
        /// Preferred username
        #[schemars(title = "Username")]
        username: Option<String>,
    },
    /// A secure text note
    #[schemars(title = "Secure Note")]
    SecureNote,
    /// SSH Key credentials
    #[schemars(title = "SSH Key")]
    SshKey {
        /// The SSH public key
        #[schemars(title = "Public Key")]
        public_key: Option<String>,
        /// The SSH key fingerprint
        #[schemars(title = "Fingerprint")]
        fingerprint: Option<String>,
        /// The SSH private key
        #[schemars(title = "Private Key")]
        private_key: Option<String>,
    },
}

impl Serialize for DecryptedData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for DecryptedData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let opt =
            Option::<serde_json::Map<String, serde_json::Value>>::deserialize(
                deserializer,
            )?;
        let Some(mut map) = opt else {
            return Ok(Self::SecureNote);
        };
        if map.is_empty() {
            return Ok(Self::SecureNote);
        }
        if let Some(type_val) = map.remove("type") {
            let type_str = type_val.as_str().ok_or_else(|| {
                serde::de::Error::custom("expected string for `type`")
            })?;
            match type_str {
                "secure_note" | "note" => {
                    if let Some(key) = map.keys().next() {
                        return Err(serde::de::Error::unknown_field(key, &[]));
                    }
                    return Ok(Self::SecureNote);
                }
                "login" => {
                    map.entry("password").or_insert(serde_json::Value::Null);
                }
                "card" => {
                    map.entry("cardholder_name")
                        .or_insert(serde_json::Value::Null);
                }
                "identity" => {
                    map.entry("title").or_insert(serde_json::Value::Null);
                }
                "ssh_key" => {
                    map.entry("public_key").or_insert(serde_json::Value::Null);
                }
                other => {
                    return Err(serde::de::Error::unknown_variant(
                        other,
                        &[
                            "login",
                            "card",
                            "identity",
                            "secure_note",
                            "note",
                            "ssh_key",
                        ],
                    ));
                }
            }
        }
        Self::deserialize(serde_json::Value::Object(map))
            .map_err(serde::de::Error::custom)
    }
}

/// A custom field associated with the entry
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedField {
    /// The name of the custom field
    #[schemars(title = "Field Name")]
    name: String,
    /// The value of the custom field
    #[schemars(title = "Field Value")]
    value: String,
    /// The type of the custom field
    #[serde(
        serialize_with = "serialize_field_type",
        deserialize_with = "deserialize_field_type",
        rename = "type"
    )]
    #[schemars(with = "SchemaFieldType", title = "Field Type")]
    ty: rbw::api::FieldType,
    /// The linked field ID (for linked fields)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<u16>", title = "Linked Field ID")]
    linked_id: Option<rbw::api::LinkedIdType>,
}

#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
fn serialize_field_type<S>(
    ty: &rbw::api::FieldType,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let s = match ty {
        rbw::api::FieldType::Text => "text",
        rbw::api::FieldType::Hidden => "hidden",
        rbw::api::FieldType::Boolean => "boolean",
        rbw::api::FieldType::Linked => "linked",
    };
    serializer.serialize_str(s)
}

fn deserialize_field_type<'de, D>(
    deserializer: D,
) -> Result<rbw::api::FieldType, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match s.as_str() {
        "text" => Ok(rbw::api::FieldType::Text),
        "hidden" => Ok(rbw::api::FieldType::Hidden),
        "boolean" => Ok(rbw::api::FieldType::Boolean),
        "linked" => Ok(rbw::api::FieldType::Linked),
        other => Err(serde::de::Error::unknown_variant(
            other,
            &["text", "hidden", "boolean", "linked"],
        )),
    }
}

/// A historic password entry
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DecryptedHistoryEntry {
    /// The date when this password was last used (RFC3339 format)
    #[schemars(title = "Last Used Date")]
    last_used_date: String,
    /// The historic password
    #[schemars(title = "Password")]
    password: String,
}

/// A URI associated with a login entry
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedUri {
    /// The URI (URL)
    #[schemars(title = "URI")]
    uri: String,
    /// The match type rule for this URI
    #[serde(
        serialize_with = "serialize_uri_match_type",
        deserialize_with = "deserialize_uri_match_type"
    )]
    #[schemars(with = "Option<SchemaUriMatchType>", title = "Match Type")]
    match_type: Option<rbw::api::UriMatchType>,
}

// We need custom serialization/deserialization for UriMatchType in user-facing DecryptedUri
// because by default, UriMatchType derives Serialize_repr/Deserialize_repr (integers)
// for Bitwarden API compatibility and local database cache (db.json) backwards compatibility.
// Using custom serialize/deserialize allows us to present friendly strings (like "domain", "host")
// to the user while keeping the internal integer representations intact.
#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
fn serialize_uri_match_type<S>(
    match_type: &Option<rbw::api::UriMatchType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match match_type {
        Some(mt) => {
            let s = match mt {
                rbw::api::UriMatchType::Domain => "domain",
                rbw::api::UriMatchType::Host => "host",
                rbw::api::UriMatchType::StartsWith => "starts_with",
                rbw::api::UriMatchType::Exact => "exact",
                rbw::api::UriMatchType::RegularExpression => {
                    "regular_expression"
                }
                rbw::api::UriMatchType::Never => "never",
            };
            serializer.serialize_some(s)
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_uri_match_type<'de, D>(
    deserializer: D,
) -> Result<Option<rbw::api::UriMatchType>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Option<rbw::api::UriMatchType>;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str("uri match type (string or integer)")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match s {
                "domain" => Ok(Some(rbw::api::UriMatchType::Domain)),
                "host" => Ok(Some(rbw::api::UriMatchType::Host)),
                "starts_with" => Ok(Some(rbw::api::UriMatchType::StartsWith)),
                "exact" => Ok(Some(rbw::api::UriMatchType::Exact)),
                "regular_expression" => {
                    Ok(Some(rbw::api::UriMatchType::RegularExpression))
                }
                "never" => Ok(Some(rbw::api::UriMatchType::Never)),
                _ => Err(serde::de::Error::unknown_variant(
                    s,
                    &[
                        "domain",
                        "host",
                        "starts_with",
                        "exact",
                        "regular_expression",
                        "never",
                    ],
                )),
            }
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match v {
                0 => Ok(Some(rbw::api::UriMatchType::Domain)),
                1 => Ok(Some(rbw::api::UriMatchType::Host)),
                2 => Ok(Some(rbw::api::UriMatchType::StartsWith)),
                3 => Ok(Some(rbw::api::UriMatchType::Exact)),
                4 => Ok(Some(rbw::api::UriMatchType::RegularExpression)),
                5 => Ok(Some(rbw::api::UriMatchType::Never)),
                _ => Err(serde::de::Error::invalid_value(
                    serde::de::Unexpected::Unsigned(v),
                    &"integer between 0 and 5",
                )),
            }
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }
    }
    deserializer.deserialize_any(Visitor)
}

fn matches_url(
    url: &str,
    match_type: Option<rbw::api::UriMatchType>,
    given_url: &url::Url,
) -> bool {
    match match_type.unwrap_or(rbw::api::UriMatchType::Domain) {
        rbw::api::UriMatchType::Domain => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && (self_host_port == given_host_port
                            || given_host_port
                                .ends_with(&format!(".{self_host_port}")))
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
                || given_host_port.ends_with(&format!(".{url}"))
        }
        rbw::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && self_host_port == given_host_port
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
        }
        rbw::api::UriMatchType::StartsWith => {
            given_url.to_string().starts_with(url)
        }
        rbw::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        rbw::api::UriMatchType::RegularExpression => {
            let Ok(rx) = regex::Regex::new(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        rbw::api::UriMatchType::Never => false,
    }
}

fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListField {
    Id,
    Name,
    User,
    Folder,
    Uri,
    EntryType,
}

impl ListField {
    fn all() -> Vec<Self> {
        vec![
            Self::Id,
            Self::Name,
            Self::User,
            Self::Folder,
            Self::Uri,
            Self::EntryType,
        ]
    }
}

impl std::convert::TryFrom<&String> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> anyhow::Result<Self> {
        Ok(match s.as_str() {
            "name" => Self::Name,
            "id" => Self::Id,
            "user" => Self::User,
            "folder" => Self::Folder,
            "type" => Self::EntryType,
            _ => return Err(anyhow::anyhow!("unknown field {s}")),
        })
    }
}

const HELP_PW: &str = r"
# The first line of this file will be the password, and the remainder of the
# file (after any blank lines after the password) will be stored as a note.
# Lines with leading # will be ignored.
";

const HELP_NOTES: &str = r"
# The content of this file will be stored as a note.
# Lines with leading # will be ignored.
";

pub fn config_show() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    serde_json::to_writer_pretty(std::io::stdout(), &config)
        .context("failed to write config to stdout")?;
    println!();

    Ok(())
}

pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "sso_id" => config.sso_id = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "ui_url" => config.ui_url = Some(value.to_string()),
        "notifications_url" => {
            config.notifications_url = Some(value.to_string());
        }
        "client_cert_path" => {
            config.client_cert_path =
                Some(std::path::PathBuf::from(value.to_string()));
        }
        "lock_timeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for lock_timeout")?;
            if timeout == 0 {
                log::error!("lock_timeout must be greater than 0");
            } else {
                config.lock_timeout = timeout;
            }
        }
        "sync_interval" => {
            let interval = value
                .parse()
                .context("failed to parse value for sync_interval")?;
            config.sync_interval = interval;
        }
        "pinentry" => config.pinentry = value.to_string(),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = None,
        "sso_id" => config.sso_id = None,
        "base_url" => config.base_url = None,
        "identity_url" => config.identity_url = None,
        "ui_url" => config.ui_url = None,
        "notifications_url" => config.notifications_url = None,
        "client_cert_path" => config.client_cert_path = None,
        "lock_timeout" => {
            config.lock_timeout = rbw::config::default_lock_timeout();
        }
        "pinentry" => config.pinentry = rbw::config::default_pinentry(),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

fn clipboard_store(val: &str) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::clipboard_store(val)?;

    Ok(())
}

pub fn register() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::register()?;

    Ok(())
}

pub fn login() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;

    Ok(())
}

pub fn unlock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::unlock()?;

    Ok(())
}

pub fn unlocked() -> anyhow::Result<()> {
    // not ensure_agent, because we don't want `rbw unlocked` to start the
    // agent if it's not running
    let _ = check_agent_version();
    crate::actions::unlocked()?;

    Ok(())
}

pub fn sync() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::sync()?;

    Ok(())
}

pub fn list(fields: &[String], raw: bool) -> anyhow::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all()
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };

    unlock()?;

    let db = load_db()?;
    let mut entries: Vec<DecryptedListCipher> = db
        .entries
        .iter()
        .map(|entry| decrypt_list_cipher(entry, &fields))
        .collect::<anyhow::Result<_>>()?;
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn get(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    field: Option<&str>,
    full: bool,
    raw: bool,
    yaml: bool,
    clipboard: bool,
    ignore_case: bool,
    list_fields: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (_, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    if list_fields {
        decrypted.display_fields_list();
    } else if raw {
        decrypted.display_json(&desc)?;
    } else if yaml {
        decrypted.display_yaml(&desc)?;
    } else if full {
        decrypted.display_long(&desc, clipboard);
    } else if let Some(field) = field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

fn print_entry_list(
    entries: &[DecryptedListCipher],
    fields: &[ListField],
    raw: bool,
) -> anyhow::Result<()> {
    if raw {
        serde_json::to_writer_pretty(std::io::stdout(), &entries)
            .context("failed to write entries to stdout".to_string())?;
        println!();
    } else {
        for entry in entries {
            let values: Vec<String> = fields
                .iter()
                .map(|field| match field {
                    ListField::Id => entry.id.clone(),
                    ListField::Name => entry.name.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::User => entry.user.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::Folder => entry.folder.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::Uri => {
                        // "uri" is not listed in the TryFrom
                        // implementation, so there's no way to try to
                        // print it (and it's not clear what that would
                        // look like, since it's a list and not a single
                        // string)
                        unreachable!()
                    }
                    ListField::EntryType => {
                        entry.entry_type.as_ref().map_or_else(
                            String::new,
                            std::string::ToString::to_string,
                        )
                    }
                })
                .collect();

            // write to stdout but don't panic when pipe get's closed
            // this happens when piping stdout in a shell
            match writeln!(&mut std::io::stdout(), "{}", values.join("\t")) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    Ok(())
                }
                res => res,
            }?;
        }
    }

    Ok(())
}

pub fn search(
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    raw: bool,
) -> anyhow::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all()
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };

    unlock()?;

    let db = load_db()?;

    let mut entries: Vec<DecryptedListCipher> = db
        .entries
        .iter()
        .map(decrypt_search_cipher)
        .filter(|entry| {
            entry
                .as_ref()
                .map_or(true, |entry| entry.search_match(term, folder))
        })
        .map(|entry| entry.map(std::convert::Into::into))
        .collect::<Result<_, anyhow::Error>>()?;
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

pub fn code(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (_, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

fn get_or_create_folder(
    access_token: &mut String,
    refresh_token: &str,
    db: &mut rbw::db::Db,
    folder_name: &str,
) -> anyhow::Result<Option<String>> {
    let (new_access_token, folders) =
        rbw::actions::list_folders(access_token, refresh_token)?;
    if let Some(new_access_token) = new_access_token {
        access_token.clone_from(&new_access_token);
        db.access_token = Some(new_access_token);
        save_db(db)?;
    }

    let folders: Vec<(String, String)> = folders
        .iter()
        .cloned()
        .map(|(id, name)| {
            Ok((id, crate::actions::decrypt(&name, None, None)?))
        })
        .collect::<anyhow::Result<_>>()?;

    for (id, name) in folders {
        if name == folder_name {
            return Ok(Some(id));
        }
    }

    let (new_access_token, id) = rbw::actions::create_folder(
        access_token,
        refresh_token,
        &crate::actions::encrypt(folder_name, None, None)?,
    )?;
    if let Some(new_access_token) = new_access_token {
        access_token.clone_from(&new_access_token);
        db.access_token = Some(new_access_token);
        save_db(db)?;
    }
    Ok(Some(id))
}

#[derive(Debug)]
struct ParsedSshKey {
    default_name: Option<String>,
    private_key: zeroize::Zeroizing<String>,
    public_key: String,
    fingerprint: String,
}

fn parse_ssh_private_key_str<F>(
    raw: &str,
    path_hint: Option<&std::path::Path>,
    mut get_passphrase: F,
) -> anyhow::Result<ParsedSshKey>
where
    F: FnMut(Option<&str>) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>>,
{
    let mut priv_key = match ssh_agent_lib::ssh_key::PrivateKey::from_openssh(
        raw,
    ) {
        Ok(k) => k,
        Err(e) => {
            if ssh_agent_lib::ssh_key::PublicKey::from_openssh(raw).is_ok() {
                anyhow::bail!(
                    "expected an OpenSSH private key, but found a public key (pass the private key file, not the .pub file)"
                );
            }
            return Err(
                anyhow::Error::new(e).context("failed to parse OpenSSH private key")
            );
        }
    };

    if priv_key.is_encrypted() {
        for i in 1_u8..=3 {
            let err = if i > 1 {
                Some(format!("Incorrect passphrase (attempt {i}/3)"))
            } else {
                None
            };
            let passphrase = get_passphrase(err.as_deref())?;
            match priv_key.decrypt(passphrase.as_slice()) {
                Ok(decrypted) => {
                    priv_key = decrypted;
                    break;
                }
                Err(e) => {
                    if i == 3 {
                        return Err(anyhow::Error::new(e)
                            .context("failed to decrypt SSH private key"));
                    }
                }
            }
        }
    }

    if !matches!(
        priv_key.algorithm(),
        ssh_agent_lib::ssh_key::Algorithm::Ed25519
            | ssh_agent_lib::ssh_key::Algorithm::Rsa { .. }
    ) {
        log::warn!(
            "SSH key algorithm '{}' is not currently supported by rbw-agent's SSH agent for signing, but will still be stored in Bitwarden.",
            priv_key.algorithm()
        );
    }

    let comment = priv_key.comment().trim();
    let default_name = if comment.is_empty() {
        path_hint
            .filter(|p| *p != std::path::Path::new("-"))
            .and_then(std::path::Path::file_name)
            .and_then(std::ffi::OsStr::to_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
    } else {
        Some(comment.to_string())
    };

    let public_key = priv_key
        .public_key()
        .to_openssh()
        .context("failed to format SSH public key")?;
    let fingerprint = priv_key
        .fingerprint(ssh_agent_lib::ssh_key::HashAlg::Sha256)
        .to_string();
    let openssh_priv = priv_key
        .to_openssh(ssh_agent_lib::ssh_key::LineEnding::LF)
        .context("failed to format unencrypted OpenSSH private key")?;

    Ok(ParsedSshKey {
        default_name,
        private_key: zeroize::Zeroizing::new((*openssh_priv).clone()),
        public_key,
        fingerprint,
    })
}

fn load_ssh_key(path: &std::path::Path) -> anyhow::Result<ParsedSshKey> {
    let raw = if path == std::path::Path::new("-") {
        zeroize::Zeroizing::new(
            std::io::read_to_string(std::io::stdin())
                .context("failed to read SSH key from stdin")?,
        )
    } else {
        zeroize::Zeroizing::new(std::fs::read_to_string(path).with_context(
            || format!("failed to read SSH key file '{}'", path.display()),
        )?)
    };

    parse_ssh_private_key_str(&raw, Some(path), |err| {
        let pinentry = rbw::config::Config::load()
            .map_or_else(|_| rbw::config::default_pinentry(), |c| c.pinentry);
        let environment = crate::actions::get_environment();
        let desc = format!(
            "Enter passphrase to decrypt SSH key '{}'",
            path.display()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to initialize async runtime for pinentry")?;
        let pw = rt
            .block_on(rbw::pinentry::getpin(
                &pinentry,
                "SSH Key Passphrase",
                &desc,
                err,
                &environment,
                true,
            ))
            .context("failed to read SSH key passphrase from pinentry")?;
        Ok(zeroize::Zeroizing::new(pw.password().to_vec()))
    })
}

#[allow(clippy::too_many_lines)]
pub fn add(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    ssh_key: Option<&std::path::Path>,
    raw: bool,
    yaml: bool,
) -> anyhow::Result<()> {
    use is_terminal::IsTerminal as _;

    if !raw && !yaml && ssh_key.is_none() && name.is_none() {
        anyhow::bail!(
            "Name is required unless using --raw, --yaml, or --ssh-key"
        );
    }

    if (raw || yaml)
        && ssh_key == Some(std::path::Path::new("-"))
        && !std::io::stdin().is_terminal()
    {
        anyhow::bail!(
            "Cannot read both --ssh-key and --raw/--yaml input from stdin"
        );
    }

    let parsed_ssh = ssh_key.map(load_ssh_key).transpose()?;
    let resolved_name = name.map(String::from).or_else(|| {
        parsed_ssh
            .as_ref()
            .and_then(|s| s.default_name.clone())
    });

    if !raw && !yaml && resolved_name.is_none() {
        anyhow::bail!(
            "Name is required when SSH key has no comment and is read from stdin"
        );
    }

    unlock()?;

    let mut db = load_db()?;
    // unwrap is safe here because the call to unlock above is guaranteed to
    // populate these or error
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    if raw || yaml {
        let data = parsed_ssh.as_ref().map_or_else(
            || DecryptedData::Login {
                username: username.map(String::from),
                password: None,
                totp: None,
                uris: if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|(u, mt)| DecryptedUri {
                                uri: u.clone(),
                                match_type: *mt,
                            })
                            .collect(),
                    )
                },
            },
            |ssh| DecryptedData::SshKey {
                public_key: Some(ssh.public_key.clone()),
                fingerprint: Some(ssh.fingerprint.clone()),
                private_key: Some((*ssh.private_key).clone()),
            },
        );

        let template = DecryptedCipher {
            id: String::new(),
            organization_id: None,
            folder: folder.map(String::from),
            name: resolved_name.as_deref().unwrap_or("").to_string(),
            data,
            fields: Vec::new(),
            notes: None,
            history: Vec::new(),
        };

        let edited = if yaml {
            let schema = schemars::schema_for!(DecryptedCipher);
            let schema_json = serde_json::to_string_pretty(&schema)?;
            let mut contents = String::new();
            contents
                .push_str("# yaml-language-server: $schema=./schema.json\n");
            contents.push_str(&serde_yaml::to_string(&template)?);
            rbw::edit::edit(
                &contents,
                "",
                "rbw.yaml",
                &[("schema.json", &schema_json)],
            )?
        } else {
            let contents = serde_json::to_string_pretty(&template)?;
            rbw::edit::edit(&contents, "", "rbw.json", &[])?
        };

        let mut decrypted: DecryptedCipher = if yaml {
            serde_yaml::from_str(&edited)?
        } else {
            serde_json::from_str(&edited)?
        };

        if !std::io::stdin().is_terminal() {
            if let Some(name) = resolved_name.as_deref() {
                decrypted.name = name.to_string();
            }
            if let Some(folder) = folder {
                decrypted.folder = Some(folder.to_string());
            }
            if let DecryptedData::Login {
                username: dec_username,
                uris: dec_uris,
                ..
            } = &mut decrypted.data
            {
                if let Some(username) = username {
                    *dec_username = Some(username.to_string());
                }
                if !uris.is_empty() {
                    *dec_uris = Some(
                        uris.iter()
                            .map(|(u, mt)| DecryptedUri {
                                uri: u.clone(),
                                match_type: *mt,
                            })
                            .collect(),
                    );
                }
            }
        }

        let (enc_name, enc_data, enc_fields, enc_notes, enc_history) =
            encrypt_cipher(
                &decrypted,
                None,
                decrypted.organization_id.as_deref(),
            )?;

        let folder_id = if let Some(folder_name) = &decrypted.folder {
            get_or_create_folder(
                &mut access_token,
                &refresh_token,
                &mut db,
                folder_name,
            )?
        } else {
            None
        };

        if let (Some(access_token), ()) = rbw::actions::add(
            &access_token,
            &refresh_token,
            decrypted.organization_id.as_deref(),
            &enc_name,
            &enc_data,
            &enc_fields,
            enc_notes.as_deref(),
            folder_id.as_deref(),
            &enc_history,
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }
    } else if let Some(ssh) = parsed_ssh {
        let name = resolved_name.unwrap();
        let enc_name = crate::actions::encrypt(&name, None, None)?;
        let enc_private_key =
            crate::actions::encrypt(&ssh.private_key, None, None)?;
        let enc_public_key =
            crate::actions::encrypt(&ssh.public_key, None, None)?;
        let enc_fingerprint =
            crate::actions::encrypt(&ssh.fingerprint, None, None)?;

        let folder_id = if let Some(folder_name) = folder {
            get_or_create_folder(
                &mut access_token,
                &refresh_token,
                &mut db,
                folder_name,
            )?
        } else {
            None
        };

        if let (Some(access_token), ()) = rbw::actions::add(
            &access_token,
            &refresh_token,
            None,
            &enc_name,
            &rbw::db::EntryData::SshKey {
                private_key: Some(enc_private_key),
                public_key: Some(enc_public_key),
                fingerprint: Some(enc_fingerprint),
            },
            &[],
            None,
            folder_id.as_deref(),
            &[],
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }
    } else {
        let name = name.unwrap();
        let name = crate::actions::encrypt(name, None, None)?;

        let username = username
            .map(|username| crate::actions::encrypt(username, None, None))
            .transpose()?;

        let contents = rbw::edit::edit("", HELP_PW, "rbw", &[])?;

        let (password, notes) = parse_editor(&contents);
        let password = password
            .map(|password| crate::actions::encrypt(&password, None, None))
            .transpose()?;
        let notes = notes
            .map(|notes| crate::actions::encrypt(&notes, None, None))
            .transpose()?;
        let uris: Vec<_> = uris
            .iter()
            .map(|uri| {
                Ok(rbw::db::Uri {
                    uri: crate::actions::encrypt(&uri.0, None, None)?,
                    match_type: uri.1,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let folder_id = if let Some(folder_name) = folder {
            get_or_create_folder(
                &mut access_token,
                &refresh_token,
                &mut db,
                folder_name,
            )?
        } else {
            None
        };

        if let (Some(access_token), ()) = rbw::actions::add(
            &access_token,
            &refresh_token,
            None,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password,
                uris,
                totp: None,
            },
            &[],
            notes.as_deref(),
            folder_id.as_deref(),
            &[],
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }
    }

    crate::actions::sync()?;
    Ok(())
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{password}");

    if let Some(name) = name {
        unlock()?;

        let mut db = load_db()?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap().clone();

        let name = crate::actions::encrypt(name, None, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None, None))
            .transpose()?;
        let enc_password = crate::actions::encrypt(&password, None, None)?;
        let uris: Vec<_> = uris
            .iter()
            .map(|uri| {
                Ok(rbw::db::Uri {
                    uri: crate::actions::encrypt(&uri.0, None, None)?,
                    match_type: uri.1,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let folder_id = if let Some(folder_name) = folder {
            get_or_create_folder(
                &mut access_token,
                &refresh_token,
                &mut db,
                folder_name,
            )?
        } else {
            None
        };

        if let (Some(access_token), ()) = rbw::actions::add(
            &access_token,
            &refresh_token,
            None,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(enc_password),
                uris,
                totp: None,
            },
            &[],
            None,
            folder_id.as_deref(),
            &[],
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }

        crate::actions::sync()?;
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn edit(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    raw: bool,
    yaml: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (entry, decrypted_original) =
        find_entry(&db, name, username, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if raw || yaml {
        let edited = if yaml {
            let schema = schemars::schema_for!(DecryptedCipher);
            let schema_json = serde_json::to_string_pretty(&schema)?;
            let mut contents = String::new();
            contents
                .push_str("# yaml-language-server: $schema=./schema.json\n");
            contents.push_str(&serde_yaml::to_string(&decrypted_original)?);
            rbw::edit::edit(
                &contents,
                "",
                "rbw.yaml",
                &[("schema.json", &schema_json)],
            )?
        } else {
            let contents = serde_json::to_string_pretty(&decrypted_original)?;
            rbw::edit::edit(&contents, "", "rbw.json", &[])?
        };

        let mut decrypted_new: DecryptedCipher = if yaml {
            serde_yaml::from_str(&edited)?
        } else {
            serde_json::from_str(&edited)?
        };

        if decrypted_new.id != decrypted_original.id {
            log::warn!("Changing the ID in raw content is not supported and will be ignored.");
        }
        if decrypted_new.organization_id != decrypted_original.organization_id {
            log::warn!("Changing the organization_id in raw content is not supported and will be ignored.");
        }

        if matches!(decrypted_original.data, DecryptedData::Identity { .. }) {
            if let DecryptedData::Login {
                username,
                password: None,
                totp: None,
                uris: None,
            } = &decrypted_new.data
            {
                decrypted_new.data = DecryptedData::Identity {
                    title: None,
                    first_name: None,
                    middle_name: None,
                    last_name: None,
                    address1: None,
                    address2: None,
                    address3: None,
                    city: None,
                    state: None,
                    postal_code: None,
                    country: None,
                    phone: None,
                    email: None,
                    ssn: None,
                    license_number: None,
                    passport_number: None,
                    username: username.clone(),
                };
            }
        }

        if let (
            DecryptedData::Login {
                password: Some(prev_pw),
                ..
            },
            DecryptedData::Login {
                password: new_password,
                ..
            },
        ) = (&decrypted_original.data, &decrypted_new.data)
        {
            if new_password.as_ref() != Some(prev_pw)
                && decrypted_new.history == decrypted_original.history
            {
                decrypted_new.history.insert(
                    0,
                    DecryptedHistoryEntry {
                        last_used_date: format!(
                            "{}",
                            humantime::format_rfc3339(
                                std::time::SystemTime::now()
                            )
                        ),
                        password: prev_pw.clone(),
                    },
                );
            }
        }

        let (enc_name, enc_data, enc_fields, enc_notes, enc_history) =
            encrypt_cipher(
                &decrypted_new,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )?;

        let mut folder_id = entry.folder_id.clone();
        if decrypted_new.folder != decrypted_original.folder {
            if let Some(folder_name) = &decrypted_new.folder {
                folder_id = get_or_create_folder(
                    &mut access_token,
                    &refresh_token,
                    &mut db,
                    folder_name,
                )?;
            } else {
                folder_id = None;
            }
        }

        if let (Some(new_access_token), ()) = rbw::actions::edit(
            &access_token,
            &refresh_token,
            &entry.id,
            entry.org_id.as_deref(),
            &enc_name,
            &enc_data,
            &enc_fields,
            enc_notes.as_deref(),
            folder_id.as_deref(),
            &enc_history,
            entry.key.as_deref(),
        )? {
            db.access_token = Some(new_access_token);
            save_db(&db)?;
        }
    } else {
        let (data, fields, notes, history) = match &decrypted_original.data {
            DecryptedData::Login { password, .. } => {
                let mut contents =
                    format!("{}\n", password.as_deref().unwrap_or(""));
                if let Some(notes) = decrypted_original.notes.as_ref() {
                    write!(contents, "\n{notes}\n").unwrap();
                }

                let contents =
                    rbw::edit::edit(&contents, HELP_PW, "rbw", &[])?;

                let (password, notes) = parse_editor(&contents);
                let password = password
                    .map(|password| {
                        crate::actions::encrypt(
                            &password,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?;
                let notes = notes
                    .map(|notes| {
                        crate::actions::encrypt(
                            &notes,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?;
                let mut history = entry.history.clone();
                let rbw::db::EntryData::Login {
                    username: entry_username,
                    password: entry_password,
                    uris: entry_uris,
                    totp: entry_totp,
                } = &entry.data
                else {
                    unreachable!();
                };

                if let Some(prev_password) = entry_password.clone() {
                    let new_history_entry = rbw::db::HistoryEntry {
                        last_used_date: format!(
                            "{}",
                            humantime::format_rfc3339(
                                std::time::SystemTime::now()
                            )
                        ),
                        password: prev_password,
                    };
                    history.insert(0, new_history_entry);
                }

                let data = rbw::db::EntryData::Login {
                    username: entry_username.clone(),
                    password,
                    uris: entry_uris.clone(),
                    totp: entry_totp.clone(),
                };
                (data, entry.fields.clone(), notes, history)
            }
            DecryptedData::SecureNote => {
                let data = rbw::db::EntryData::SecureNote {};

                let editor_content =
                    decrypted_original.notes.as_ref().map_or_else(
                        || "\n".to_string(),
                        |notes| format!("{notes}\n"),
                    );
                let contents =
                    rbw::edit::edit(&editor_content, HELP_NOTES, "rbw", &[])?;

                // prepend blank line to be parsed as pw by `parse_editor`
                let (_, notes) = parse_editor(&format!("\n{contents}\n"));

                let notes = notes
                    .map(|notes| {
                        crate::actions::encrypt(
                            &notes,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?;

                (data, entry.fields.clone(), notes, entry.history.clone())
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "modifications are only supported for login and note entries"
                ));
            }
        };

        if let (Some(new_access_token), ()) = rbw::actions::edit(
            &access_token,
            &refresh_token,
            &entry.id,
            entry.org_id.as_deref(),
            &entry.name,
            &data,
            &fields,
            notes.as_deref(),
            entry.folder_id.as_deref(),
            &history,
            entry.key.as_deref(),
        )? {
            db.access_token = Some(new_access_token);
            save_db(&db)?;
        }
    }

    crate::actions::sync()?;
    Ok(())
}

pub fn remove(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (entry, _) = find_entry(&db, name, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let (Some(access_token), ()) =
        rbw::actions::remove(access_token, refresh_token, &entry.id)?
    {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn history(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (_, decrypted) = find_entry(&db, name, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    for history in decrypted.history {
        println!("{}: {}", history.last_used_date, history.password);
    }

    Ok(())
}

pub fn lock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::lock()?;

    Ok(())
}

pub fn purge() -> anyhow::Result<()> {
    stop_agent()?;

    remove_db()?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

fn ensure_agent() -> anyhow::Result<()> {
    check_config()?;
    if matches!(check_agent_version(), Ok(())) {
        return Ok(());
    }
    run_agent()?;
    check_agent_version()?;
    Ok(())
}

fn run_agent() -> anyhow::Result<()> {
    let agent_path = std::env::var_os("RBW_AGENT");
    let agent_path = agent_path
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::from_bytes(b"rbw-agent"));
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!(
                    "failed to run rbw-agent: {status}"
                ));
            }
        }
    }

    Ok(())
}

fn check_config() -> anyhow::Result<()> {
    rbw::config::Config::validate().map_err(|e| {
        log::error!("{MISSING_CONFIG_HELP}");
        anyhow::Error::new(e)
    })
}

fn check_agent_version() -> anyhow::Result<()> {
    let client_version = rbw::protocol::VERSION;
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        crate::actions::quit()?;
        return Err(anyhow::anyhow!(
            "client protocol version is {client_version} but agent protocol version is {agent_version}"
        ));
    }
    Ok(())
}

fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().inspect_err(|_| {
        let _ = crate::actions::quit();
    })
}

fn find_entry(
    db: &rbw::db::Db,
    mut needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    if let Needle::Uuid(uuid, s) = needle {
        for cipher in &db.entries {
            if uuid::Uuid::parse_str(&cipher.id) == Ok(uuid) {
                return Ok((cipher.clone(), decrypt_cipher(cipher)?));
            }
        }
        needle = Needle::Name(s);
    }

    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .map(|entry| {
            decrypt_search_cipher(entry)
                .map(|decrypted| (entry.clone(), decrypted))
        })
        .collect::<anyhow::Result<_>>()?;
    let (entry, _) =
        find_entry_raw(&ciphers, &needle, username, folder, ignore_case)?;
    let decrypted_entry = decrypt_cipher(&entry)?;
    Ok((entry, decrypted_entry))
}

fn find_entry_raw(
    entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
    let mut matches: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = vec![];

    let find_matches = |strict_username, strict_folder, exact| {
        entries
            .iter()
            .filter(|&(_, decrypted_cipher)| {
                decrypted_cipher.matches(
                    needle,
                    username,
                    folder,
                    ignore_case,
                    strict_username,
                    strict_folder,
                    exact,
                )
            })
            .cloned()
            .collect()
    };

    for exact in [true, false] {
        matches = find_matches(true, true, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }

        let strict_folder_matches = find_matches(false, true, exact);
        let strict_username_matches = find_matches(true, false, exact);
        if strict_folder_matches.len() == 1
            && strict_username_matches.len() != 1
        {
            return Ok(strict_folder_matches[0].clone());
        } else if strict_folder_matches.len() != 1
            && strict_username_matches.len() == 1
        {
            return Ok(strict_username_matches[0].clone());
        }

        matches = find_matches(false, false, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }
    }

    if matches.is_empty() {
        Err(anyhow::anyhow!("no entry found"))
    } else {
        let entries: Vec<String> = matches
            .iter()
            .map(|(_, decrypted)| decrypted.display_name())
            .collect();
        let entries = entries.join(", ");
        Err(anyhow::anyhow!("multiple entries found: {entries}"))
    }
}

fn decrypt_field(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| crate::actions::decrypt(field, entry_key, org_id))
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {name}: {e}");
            None
        }
    }
}

fn decrypt_list_cipher(
    entry: &rbw::db::Entry,
    fields: &[ListField],
) -> anyhow::Result<DecryptedListCipher> {
    let id = entry.id.clone();
    let name = if fields.contains(&ListField::Name) {
        Some(crate::actions::decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?)
    } else {
        None
    };
    let user = if fields.contains(&ListField::User) {
        match &entry.data {
            rbw::db::EntryData::Login { username, .. } => decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            _ => None,
        }
    } else {
        None
    };
    let folder = if fields.contains(&ListField::Folder) {
        // folder name should always be decrypted with the local key because
        // folders are local to a specific user's vault, not the organization
        entry
            .folder
            .as_ref()
            .map(|folder| crate::actions::decrypt(folder, None, None))
            .transpose()?
    } else {
        None
    };
    let uris = if fields.contains(&ListField::Uri) {
        match &entry.data {
            rbw::db::EntryData::Login { uris, .. } => Some(
                uris.iter()
                    .filter_map(|s| {
                        decrypt_field(
                            Field::Uris,
                            Some(&s.uri),
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .collect(),
            ),
            _ => None,
        }
    } else {
        None
    };
    let entry_type = fields
        .contains(&ListField::EntryType)
        .then_some(match &entry.data {
            rbw::db::EntryData::Login { .. } => "Login",
            rbw::db::EntryData::Identity { .. } => "Identity",
            rbw::db::EntryData::SshKey { .. } => "SSH Key",
            rbw::db::EntryData::SecureNote => "Note",
            rbw::db::EntryData::Card { .. } => "Card",
        })
        .map(str::to_string);

    Ok(DecryptedListCipher {
        id,
        name,
        user,
        folder,
        uris,
        entry_type,
    })
}

fn decrypt_search_cipher(
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedSearchCipher> {
    let id = entry.id.clone();
    let name = crate::actions::decrypt(
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let user = match &entry.data {
        rbw::db::EntryData::Login { username, .. } => decrypt_field(
            Field::Username,
            username.as_deref(),
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        ),
        _ => None,
    };
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None, None))
        .transpose()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let uris = if let rbw::db::EntryData::Login { uris, .. } = &entry.data {
        uris.iter()
            .filter_map(|s| {
                decrypt_field(
                    Field::Uris,
                    Some(&s.uri),
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .map(|uri| (uri, s.match_type))
            })
            .collect()
    } else {
        vec![]
    };
    let fields = entry
        .fields
        .iter()
        .filter_map(|field| {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                None
            } else {
                field.value.as_ref()
            }
        })
        .map(|value| {
            crate::actions::decrypt(
                value,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    let entry_type = (match &entry.data {
        rbw::db::EntryData::Login { .. } => "Login",
        rbw::db::EntryData::Identity { .. } => "Identity",
        rbw::db::EntryData::SshKey { .. } => "SSH Key",
        rbw::db::EntryData::SecureNote => "Note",
        rbw::db::EntryData::Card { .. } => "Card",
    })
    .to_string();

    Ok(DecryptedSearchCipher {
        id,
        entry_type,
        folder,
        name,
        user,
        uris,
        fields,
        notes,
    })
}

#[allow(clippy::ref_option)]
fn encrypt_field(
    field: &Option<String>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<Option<String>> {
    field
        .as_deref()
        .map(|v| crate::actions::encrypt(v, entry_key, org_id))
        .transpose()
}

#[allow(clippy::too_many_lines)]
fn encrypt_cipher(
    decrypted: &DecryptedCipher,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<(
    String,                     // encrypted name
    rbw::db::EntryData,         // encrypted data
    Vec<rbw::db::Field>,        // encrypted fields
    Option<String>,             // encrypted notes
    Vec<rbw::db::HistoryEntry>, // encrypted history
)> {
    let name = crate::actions::encrypt(&decrypted.name, entry_key, org_id)?;
    let notes = decrypted
        .notes
        .as_deref()
        .map(|notes| crate::actions::encrypt(notes, entry_key, org_id))
        .transpose()?;

    let fields = decrypted
        .fields
        .iter()
        .map(|field| {
            Ok(rbw::db::Field {
                ty: Some(field.ty),
                name: Some(crate::actions::encrypt(
                    &field.name,
                    entry_key,
                    org_id,
                )?),
                value: Some(crate::actions::encrypt(
                    &field.value,
                    entry_key,
                    org_id,
                )?),
                linked_id: field.linked_id,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let history = decrypted
        .history
        .iter()
        .map(|history_entry| {
            Ok(rbw::db::HistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: crate::actions::encrypt(
                    &history_entry.password,
                    entry_key,
                    org_id,
                )?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let data = match &decrypted.data {
        DecryptedData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            let username = encrypt_field(username, entry_key, org_id)?;
            let password = encrypt_field(password, entry_key, org_id)?;
            let totp = encrypt_field(totp, entry_key, org_id)?;
            let uris = uris
                .as_ref()
                .map(|uris| {
                    uris.iter()
                        .map(|uri| {
                            Ok(rbw::db::Uri {
                                uri: crate::actions::encrypt(
                                    &uri.uri, entry_key, org_id,
                                )?,
                                match_type: uri.match_type,
                            })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();

            rbw::db::EntryData::Login {
                username,
                password,
                totp,
                uris,
            }
        }
        DecryptedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => rbw::db::EntryData::Card {
            cardholder_name: encrypt_field(cardholder_name, entry_key, org_id)?,
            number: encrypt_field(number, entry_key, org_id)?,
            brand: encrypt_field(brand, entry_key, org_id)?,
            exp_month: encrypt_field(exp_month, entry_key, org_id)?,
            exp_year: encrypt_field(exp_year, entry_key, org_id)?,
            code: encrypt_field(code, entry_key, org_id)?,
        },
        DecryptedData::Identity {
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
        } => rbw::db::EntryData::Identity {
            title: encrypt_field(title, entry_key, org_id)?,
            first_name: encrypt_field(first_name, entry_key, org_id)?,
            middle_name: encrypt_field(middle_name, entry_key, org_id)?,
            last_name: encrypt_field(last_name, entry_key, org_id)?,
            address1: encrypt_field(address1, entry_key, org_id)?,
            address2: encrypt_field(address2, entry_key, org_id)?,
            address3: encrypt_field(address3, entry_key, org_id)?,
            city: encrypt_field(city, entry_key, org_id)?,
            state: encrypt_field(state, entry_key, org_id)?,
            postal_code: encrypt_field(postal_code, entry_key, org_id)?,
            country: encrypt_field(country, entry_key, org_id)?,
            phone: encrypt_field(phone, entry_key, org_id)?,
            email: encrypt_field(email, entry_key, org_id)?,
            ssn: encrypt_field(ssn, entry_key, org_id)?,
            license_number: encrypt_field(license_number, entry_key, org_id)?,
            passport_number: encrypt_field(passport_number, entry_key, org_id)?,
            username: encrypt_field(username, entry_key, org_id)?,
        },
        DecryptedData::SecureNote => rbw::db::EntryData::SecureNote,
        DecryptedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => rbw::db::EntryData::SshKey {
            public_key: encrypt_field(public_key, entry_key, org_id)?,
            fingerprint: encrypt_field(fingerprint, entry_key, org_id)?,
            private_key: encrypt_field(private_key, entry_key, org_id)?,
        },
    };

    Ok((name, data, fields, notes, history))
}

fn decrypt_cipher(entry: &rbw::db::Entry) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None, None))
        .transpose();
    let folder = match folder {
        Ok(folder) => folder,
        Err(e) => {
            log::warn!("failed to decrypt folder name: {e}");
            None
        }
    };
    let fields = entry
        .fields
        .iter()
        .map(|field| {
            Ok(DecryptedField {
                name: field
                    .name
                    .as_ref()
                    .map(|name| {
                        crate::actions::decrypt(
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?
                    .unwrap_or_default(),
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        crate::actions::decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?
                    .unwrap_or_default(),
                ty: field.ty.unwrap_or(rbw::api::FieldType::Text),
                linked_id: field.linked_id,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    let history = entry
        .history
        .iter()
        .map(|history_entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: crate::actions::decrypt(
                    &history_entry.password,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )?,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => DecryptedData::Login {
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            password: decrypt_field(
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            totp: decrypt_field(
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        Field::Uris,
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                    )
                    .map(|uri| DecryptedUri {
                        uri,
                        match_type: s.match_type,
                    })
                })
                .collect(),
        },
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: decrypt_field(
                Field::Cardholder,
                cardholder_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            number: decrypt_field(
                Field::CardNumber,
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            brand: decrypt_field(
                Field::Brand,
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_month: decrypt_field(
                Field::ExpMonth,
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_year: decrypt_field(
                Field::ExpYear,
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            code: decrypt_field(
                Field::Cvv,
                code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::Identity {
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
        } => DecryptedData::Identity {
            title: decrypt_field(
                Field::Title,
                title.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            first_name: decrypt_field(
                Field::FirstName,
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            middle_name: decrypt_field(
                Field::MiddleName,
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            last_name: decrypt_field(
                Field::LastName,
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address1: decrypt_field(
                Field::Address1,
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address2: decrypt_field(
                Field::Address2,
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address3: decrypt_field(
                Field::Address3,
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            city: decrypt_field(
                Field::City,
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            state: decrypt_field(
                Field::State,
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            postal_code: decrypt_field(
                Field::PostalCode,
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            country: decrypt_field(
                Field::Country,
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            phone: decrypt_field(
                Field::Phone,
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            email: decrypt_field(
                Field::Email,
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            ssn: decrypt_field(
                Field::Ssn,
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            license_number: decrypt_field(
                Field::License,
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            passport_number: decrypt_field(
                Field::Passport,
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::SecureNote => DecryptedData::SecureNote {},
        rbw::db::EntryData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: decrypt_field(
                Field::PublicKey,
                public_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            fingerprint: decrypt_field(
                Field::Fingerprint,
                fingerprint.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            private_key: decrypt_field(
                Field::PrivateKey,
                private_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        organization_id: entry.org_id.clone(),
        folder,
        name: crate::actions::decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?,
        data,
        fields,
        notes,
        history,
    })
}

fn parse_editor(contents: &str) -> (Option<String>, Option<String>) {
    let mut lines = contents.lines();

    let password = lines.next().map(std::string::ToString::to_string);

    let mut notes: String = lines
        .skip_while(|line| line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .fold(String::new(), |mut notes, line| {
            notes.push_str(line);
            notes.push('\n');
            notes
        });
    while notes.ends_with('\n') {
        notes.pop();
    }
    let notes = if notes.is_empty() { None } else { Some(notes) };

    (password, notes)
}

fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::load(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            db.save(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn remove_db() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::remove(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

struct TotpParams {
    secret: Vec<u8>,
    algorithm: String,
    digits: usize,
    period: u64,
}

fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let secret = secret.trim().replace(' ', "");
    let alphabets = [
        base32::Alphabet::Rfc4648 { padding: false },
        base32::Alphabet::Rfc4648 { padding: true },
        base32::Alphabet::Rfc4648Lower { padding: false },
        base32::Alphabet::Rfc4648Lower { padding: true },
    ];
    for alphabet in alphabets {
        if let Some(secret) = base32::decode(alphabet, &secret) {
            return Ok(secret);
        }
    }
    Err(anyhow::anyhow!("totp secret was not valid base32"))
}

fn parse_totp_secret(secret: &str) -> anyhow::Result<TotpParams> {
    if let Ok(u) = url::Url::parse(secret) {
        match u.scheme() {
            "otpauth" => {
                if u.host_str() != Some("totp") {
                    return Err(anyhow::anyhow!(
                        "totp secret url must have totp host"
                    ));
                }

                let query: std::collections::HashMap<_, _> =
                    u.query_pairs().collect();

                let secret = decode_totp_secret(
                    query.get("secret").ok_or_else(|| {
                        anyhow::anyhow!("totp secret url must have secret")
                    })?,
                )?;
                let algorithm = query.get("algorithm").map_or_else(
                    || String::from("SHA1"),
                    std::string::ToString::to_string,
                );
                let digits = match query.get("digits") {
                    Some(dig) => dig
                        .parse::<usize>()
                        .map_err(|_| anyhow::anyhow!("digits parameter in totp url must be a valid integer."))?,
                    None => 6,
                };
                let period = match query.get("period") {
                    Some(dig) => {
                        dig.parse::<u64>().map_err(|_| anyhow::anyhow!("period parameter in totp url must be a valid integer."))?
                    }
                    None => TOTP_DEFAULT_STEP,
                };

                Ok(TotpParams {
                    secret,
                    algorithm,
                    digits,
                    period,
                })
            }
            "steam" => {
                let steam_secret = u.host_str().unwrap();

                Ok(TotpParams {
                    secret: decode_totp_secret(steam_secret)?,
                    algorithm: String::from("STEAM"),
                    digits: 5,
                    period: TOTP_DEFAULT_STEP,
                })
            }
            _ => Err(anyhow::anyhow!(
                "totp secret url must have 'otpauth' or 'steam' scheme"
            )),
        }
    } else {
        Ok(TotpParams {
            secret: decode_totp_secret(secret)?,
            algorithm: String::from("SHA1"),
            digits: 6,
            period: TOTP_DEFAULT_STEP,
        })
    }
}

// This function exists for the sake of making the generate_totp function less
// densely packed and more readable
fn generate_totp_algorithm_type(
    alg: &str,
) -> anyhow::Result<totp_rs::Algorithm> {
    match alg {
        "SHA1" => Ok(totp_rs::Algorithm::SHA1),
        "SHA256" => Ok(totp_rs::Algorithm::SHA256),
        "SHA512" => Ok(totp_rs::Algorithm::SHA512),
        "STEAM" => Ok(totp_rs::Algorithm::Steam),
        _ => Err(anyhow::anyhow!(format!("{alg} is not a valid algorithm"))),
    }
}

fn generate_totp(secret: &str) -> anyhow::Result<String> {
    let totp_params = parse_totp_secret(secret)?;
    let alg = totp_params.algorithm.as_str();

    match alg {
        "SHA1" | "SHA256" | "SHA512" => Ok(totp_rs::TOTP::new_unchecked(
            generate_totp_algorithm_type(alg)?,
            totp_params.digits,
            1, // the library docs say this should be a 1
            totp_params.period,
            totp_params.secret,
        )
        .generate_current()?),
        "STEAM" => Ok(totp_rs::TOTP::new_steam(totp_params.secret)
            .generate_current()?),
        _ => Err(anyhow::anyhow!(format!(
            "{alg} is not a valid totp algorithm"
        ))),
    }
}

fn display_field(name: &str, field: Option<&str>, clipboard: bool) -> bool {
    field.map_or_else(
        || false,
        |field| val_display_or_store(clipboard, &format!("{name}: {field}")),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_raw_yaml_serde() {
        let original = DecryptedCipher {
            id: "some-id".to_string(),
            organization_id: Some("some-org".to_string()),
            folder: Some("some-folder".to_string()),
            name: "some-name".to_string(),
            data: DecryptedData::Login {
                username: Some("some-user".to_string()),
                password: Some("some-password".to_string()),
                totp: Some("some-totp".to_string()),
                uris: Some(vec![
                    DecryptedUri {
                        uri: "http://example.com".to_string(),
                        match_type: Some(rbw::api::UriMatchType::Domain),
                    },
                    DecryptedUri {
                        uri: "http://example.org".to_string(),
                        match_type: None,
                    },
                ]),
            },
            fields: vec![
                DecryptedField {
                    name: "field1".to_string(),
                    value: "value1\nline2\nline3".to_string(),
                    ty: rbw::api::FieldType::Text,
                    linked_id: None,
                },
                DecryptedField {
                    name: "field2".to_string(),
                    value: "value2".to_string(),
                    ty: rbw::api::FieldType::Hidden,
                    linked_id: Some(rbw::api::LinkedIdType::LoginUsername),
                },
            ],
            notes: Some("some-notes\nline2\nline3".to_string()),
            history: vec![DecryptedHistoryEntry {
                last_used_date: "2026-05-29T14:55:19-07:00".to_string(),
                password: "old-password".to_string(),
            }],
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&original).unwrap();
        // Deserialize from JSON
        let deserialized_json: DecryptedCipher =
            serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized_json);

        // Serialize to YAML
        let yaml = serde_yaml::to_string(&original).unwrap();
        // All multi-line strings should be block literals.
        // In YAML, block literal starts with `|`
        assert!(yaml.contains("notes: |"));
        assert!(yaml.contains("value: |"));
        assert!(yaml.contains("some-notes"));
        assert!(yaml.contains("value1"));
        assert!(yaml.contains("line2"));
        assert!(yaml.contains("line3"));

        // Deserialize from YAML
        let deserialized_yaml: DecryptedCipher =
            serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original, deserialized_yaml);

        // Test Schema Generation
        let schema = schemars::schema_for!(DecryptedCipher);
        let schema_json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(schema_json.contains("DecryptedCipher"));
        assert!(schema_json.contains("organization_id"));
        assert!(schema_json.contains("SchemaUriMatchType"));
        assert!(schema_json.contains("Field Type"));
    }

    #[test]
    fn test_decrypted_data_disambiguation() {
        // 1. Empty map `data: {}` deserializes as SecureNote
        let empty_map_json = r#"{
            "name": "my-note",
            "data": {},
            "notes": "secret note"
        }"#;
        let cipher: DecryptedCipher =
            serde_json::from_str(empty_map_json).unwrap();
        assert_eq!(cipher.data, DecryptedData::SecureNote);

        // 2. Explicit `"type": "identity"` with only `username` deserializes as Identity
        let identity_json = r#"{
            "name": "my-identity",
            "data": {
                "type": "identity",
                "username": "alice"
            }
        }"#;
        let cipher: DecryptedCipher =
            serde_json::from_str(identity_json).unwrap();
        assert!(matches!(
            cipher.data,
            DecryptedData::Identity {
                username: Some(ref u),
                ..
            } if u == "alice"
        ));

        // 3. Explicit `"type": "card"` with no other fields deserializes as Card
        let card_json = r#"{
            "name": "my-card",
            "data": {
                "type": "card"
            }
        }"#;
        let cipher: DecryptedCipher = serde_json::from_str(card_json).unwrap();
        assert!(matches!(cipher.data, DecryptedData::Card { .. }));
    }

    #[test]
    fn test_parse_ssh_private_key() {
        use ssh_agent_lib::ssh_key::{LineEnding, PrivateKey};

        let mut rng = rand_8::rngs::OsRng;
        let keypair =
            ssh_agent_lib::ssh_key::private::Ed25519Keypair::random(&mut rng);
        let priv_with_comment = PrivateKey::new(
            ssh_agent_lib::ssh_key::private::KeypairData::Ed25519(
                keypair.clone(),
            ),
            "alice@example.com",
        )
        .unwrap();
        let openssh_str =
            priv_with_comment.to_openssh(LineEnding::LF).unwrap();

        // 1. Key comment takes priority over filename for default_name
        let parsed = parse_ssh_private_key_str(
            &openssh_str,
            Some(std::path::Path::new("/home/alice/.ssh/id_ed25519")),
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(parsed.default_name.as_deref(), Some("alice@example.com"));
        assert!(parsed.public_key.starts_with("ssh-ed25519 "));
        assert!(parsed.fingerprint.starts_with("SHA256:"));

        // 2. Empty comment falls back to filename
        let priv_no_comment = PrivateKey::new(
            ssh_agent_lib::ssh_key::private::KeypairData::Ed25519(keypair),
            "",
        )
        .unwrap();
        let openssh_no_comment =
            priv_no_comment.to_openssh(LineEnding::LF).unwrap();
        let parsed_no_comment = parse_ssh_private_key_str(
            &openssh_no_comment,
            Some(std::path::Path::new("/home/alice/.ssh/id_ed25519")),
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(
            parsed_no_comment.default_name.as_deref(),
            Some("id_ed25519")
        );

        // 3. Passphrase-encrypted key decrypts (with retry on wrong passphrase) and outputs unencrypted OpenSSH key
        let encrypted_priv =
            priv_with_comment.encrypt(&mut rng, b"correct-horse").unwrap();
        let encrypted_openssh =
            encrypted_priv.to_openssh(LineEnding::LF).unwrap();
        let mut attempts = 0;
        let parsed_enc = parse_ssh_private_key_str(
            &encrypted_openssh,
            None,
            |err| {
                attempts += 1;
                if attempts == 1 {
                    assert!(err.is_none());
                    Ok(zeroize::Zeroizing::new(b"wrong-pass".to_vec()))
                } else {
                    assert!(err.unwrap().contains("attempt 2/3"));
                    Ok(zeroize::Zeroizing::new(b"correct-horse".to_vec()))
                }
            },
        )
        .unwrap();
        assert_eq!(attempts, 2);
        let reparsed =
            PrivateKey::from_openssh(&*parsed_enc.private_key).unwrap();
        assert!(!reparsed.is_encrypted());
        assert_eq!(parsed_enc.public_key, parsed.public_key);
        assert_eq!(parsed_enc.fingerprint, parsed.fingerprint);

        // 4. Passing a public key file produces a clear error
        let pub_err = parse_ssh_private_key_str(
            &parsed.public_key,
            Some(std::path::Path::new("id_ed25519.pub")),
            |_| unreachable!(),
        )
        .unwrap_err();
        assert!(pub_err
            .to_string()
            .contains("expected an OpenSSH private key, but found a public key"));
    }

    #[test]
    fn test_strict_validation() {
        // 1. Test unknown field in DecryptedCipher fails
        let bad_cipher_json = r#"{
            "id": "some-id",
            "name": "some-name",
            "data": {
                "username": "some-user"
            },
            "unknown_field": "invalid"
        }"#;
        let res: Result<DecryptedCipher, _> =
            serde_json::from_str(bad_cipher_json);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("unknown field `unknown_field`"));

        // 2. Test unknown field in DecryptedData (Login variant) fails
        let bad_login_json = r#"{
            "id": "some-id",
            "name": "some-name",
            "data": {
                "username": "some-user",
                "bad_field": "invalid"
            }
        }"#;
        let res: Result<DecryptedCipher, _> =
            serde_json::from_str(bad_login_json);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("data did not match any variant")
                || err_msg.contains("unknown field")
        );

        // 3. Test missing required field in DecryptedField fails
        let missing_name_field_json = r#"{
            "id": "some-id",
            "name": "some-name",
            "data": {
                "username": "some-user"
            },
            "fields": [
                {
                    "value": "some-value",
                    "type": "text"
                }
            ]
        }"#;
        let res: Result<DecryptedCipher, _> =
            serde_json::from_str(missing_name_field_json);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("missing field `name`"));

        let missing_type_field_json = r#"{
            "id": "some-id",
            "name": "some-name",
            "data": {
                "username": "some-user"
            },
            "fields": [
                {
                    "name": "some-name",
                    "value": "some-value"
                }
            ]
        }"#;
        let res: Result<DecryptedCipher, _> =
            serde_json::from_str(missing_type_field_json);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("missing field `type`"));
    }

    #[test]
    fn test_find_entry() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry("gitter", Some("baz"), None, &[]),
            make_entry("git", Some("foo"), None, &[]),
            make_entry("bitwarden", None, None, &[]),
            make_entry("github", Some("foo"), Some("websites"), &[]),
            make_entry("github", Some("foo"), Some("ssh"), &[]),
            make_entry("github", Some("root"), Some("ssh"), &[]),
            make_entry("codeberg", Some("foo"), None, &[]),
            make_entry("codeberg", None, None, &[]),
            make_entry("1password", Some("foo"), None, &[]),
            make_entry("1password", None, Some("foo"), &[]),
        ];

        assert!(
            one_match(entries, "github", Some("foo"), None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), None, 0, true),
            "foo@GITHUB"
        );
        assert!(one_match(entries, "github", None, None, 0, false), "github");
        assert!(one_match(entries, "GITHUB", None, None, 0, true), "GITHUB");
        assert!(
            one_match(entries, "gitlab", Some("foo"), None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, "GITLAB", Some("foo"), None, 1, true),
            "foo@GITLAB"
        );
        assert!(
            one_match(entries, "git", Some("bar"), None, 2, false),
            "bar@git"
        );
        assert!(
            one_match(entries, "GIT", Some("bar"), None, 2, true),
            "bar@GIT"
        );
        assert!(
            one_match(entries, "gitter", Some("ba"), None, 3, false),
            "ba@gitter"
        );
        assert!(
            one_match(entries, "GITTER", Some("ba"), None, 3, true),
            "ba@GITTER"
        );
        assert!(
            one_match(entries, "git", Some("foo"), None, 4, false),
            "foo@git"
        );
        assert!(
            one_match(entries, "GIT", Some("foo"), None, 4, true),
            "foo@GIT"
        );
        assert!(one_match(entries, "git", None, None, 4, false), "git");
        assert!(one_match(entries, "GIT", None, None, 4, true), "GIT");
        assert!(
            one_match(entries, "bitwarden", None, None, 5, false),
            "bitwarden"
        );
        assert!(
            one_match(entries, "BITWARDEN", None, None, 5, true),
            "BITWARDEN"
        );
        assert!(
            one_match(
                entries,
                "github",
                Some("foo"),
                Some("websites"),
                6,
                false
            ),
            "websites/foo@github"
        );
        assert!(
            one_match(
                entries,
                "GITHUB",
                Some("foo"),
                Some("websites"),
                6,
                true
            ),
            "websites/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("foo"), Some("ssh"), 7, false),
            "ssh/foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), Some("ssh"), 7, true),
            "ssh/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("root"), None, 8, false),
            "ssh/root@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("root"), None, 8, true),
            "ssh/root@GITHUB"
        );

        assert!(
            no_matches(entries, "gitlab", Some("baz"), None, false),
            "baz@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("baz"), None, true),
            "baz@"
        );
        assert!(
            no_matches(entries, "bitbucket", Some("foo"), None, false),
            "foo@bitbucket"
        );
        assert!(
            no_matches(entries, "BITBUCKET", Some("foo"), None, true),
            "foo@BITBUCKET"
        );
        assert!(
            no_matches(entries, "github", Some("foo"), Some("bar"), false),
            "bar/foo@github"
        );
        assert!(
            no_matches(entries, "GITHUB", Some("foo"), Some("bar"), true),
            "bar/foo@"
        );
        assert!(
            no_matches(entries, "gitlab", Some("foo"), Some("bar"), false),
            "bar/foo@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("foo"), Some("bar"), true),
            "bar/foo@GITLAB"
        );

        assert!(many_matches(entries, "gitlab", None, None, false), "gitlab");
        assert!(many_matches(entries, "gitlab", None, None, true), "GITLAB");
        assert!(
            many_matches(entries, "gi", Some("foo"), None, false),
            "foo@gi"
        );
        assert!(
            many_matches(entries, "GI", Some("foo"), None, true),
            "foo@GI"
        );
        assert!(
            many_matches(entries, "git", Some("ba"), None, false),
            "ba@git"
        );
        assert!(
            many_matches(entries, "GIT", Some("ba"), None, true),
            "ba@GIT"
        );
        assert!(
            many_matches(entries, "github", Some("foo"), Some("s"), false),
            "s/foo@github"
        );
        assert!(
            many_matches(entries, "GITHUB", Some("foo"), Some("s"), true),
            "s/foo@GITHUB"
        );

        assert!(
            one_match(entries, "codeberg", Some("foo"), None, 9, false),
            "foo@codeberg"
        );
        assert!(
            one_match(entries, "codeberg", None, None, 10, false),
            "codeberg"
        );
        assert!(
            no_matches(entries, "codeberg", Some("bar"), None, false),
            "bar@codeberg"
        );

        assert!(
            many_matches(entries, "1password", None, None, false),
            "1password"
        );
    }

    #[test]
    fn test_find_by_uuid() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry(
                "12345678-1234-1234-1234-1234567890ab",
                None,
                None,
                &[],
            ),
            make_entry(
                "12345678-1234-1234-1234-1234567890AC",
                None,
                None,
                &[],
            ),
            make_entry("123456781234123412341234567890AD", None, None, &[]),
        ];

        assert!(
            one_match(entries, &entries[0].0.id, None, None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, &entries[1].0.id, None, None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, &entries[2].0.id, None, None, 2, false),
            "bar@gitlab"
        );

        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_uppercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );
        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_lowercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );

        assert!(one_match(entries, &entries[3].0.id, None, None, 3, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890ab",
            None,
            None,
            3,
            false
        ));
        assert!(no_matches(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            false
        ));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            3,
            true
        ));
        assert!(one_match(entries, &entries[4].0.id, None, None, 4, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AC",
            None,
            None,
            4,
            false
        ));
        assert!(one_match(entries, &entries[5].0.id, None, None, 5, false));
        assert!(one_match(
            entries,
            "123456781234123412341234567890AD",
            None,
            None,
            5,
            false
        ));
    }

    #[test]
    fn test_find_by_url_default() {
        let entries = &[
            make_entry("one", None, None, &[("https://one.com/", None)]),
            make_entry("two", None, None, &[("https://two.com/login", None)]),
            make_entry(
                "three",
                None,
                None,
                &[("https://login.three.com/", None)],
            ),
            make_entry("four", None, None, &[("four.com", None)]),
            make_entry(
                "five",
                None,
                None,
                &[("https://five.com:8080/", None)],
            ),
            make_entry("six", None, None, &[("six.com:8080", None)]),
            make_entry("seven", None, None, &[("192.168.0.128:8080", None)]),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_domain() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[(
                    "192.168.0.128:8080",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_host() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[("192.168.0.128:8080", Some(rbw::api::UriMatchType::Host))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_starts_with() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    "https://one.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_exact() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Exact))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("https://four.com", Some(rbw::api::UriMatchType::Exact))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com/foo", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );
        assert!(
            one_match(entries, "https://four.com", None, None, 3, false),
            "four"
        );
        assert!(
            no_matches(entries, "https://four.com/foo", None, None, false),
            "four"
        );
    }

    #[test]
    fn test_find_by_url_regex() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    r"^https://one\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    r"^https://two\.com/(login|start)",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    r"^https://(login\.)?three\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/start", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            one_match(entries, "https://three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://www.three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_never() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Never))],
            ),
        ];

        assert!(
            no_matches(entries, "https://one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com:443/", None, None, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            no_matches(
                entries,
                "https://login.three.com/",
                None,
                None,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            no_matches(entries, "https://four.com/", None, None, false),
            "four"
        );

        assert!(
            no_matches(entries, "https://five.com:8080/", None, None, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            no_matches(entries, "https://six.com:8080/", None, None, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
    }

    #[test]
    fn test_find_with_multiple_urls() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[
                    (
                        "https://one.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                    (
                        "https://two.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                ],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            no_matches(entries, "https://zero.com/", None, None, false),
            "zero"
        );
        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            many_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
    }

    #[test]
    fn test_decode_totp_secret() {
        let decoded = decode_totp_secret("NBSW Y3DP EB3W 64TM MQQQ").unwrap();
        let want = b"hello world!".to_vec();
        assert!(decoded == want, "strips spaces");
    }

    #[track_caller]
    fn one_match(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        idx: usize,
        ignore_case: bool,
    ) -> bool {
        entries_eq(
            &find_entry_raw(
                entries,
                &parse_needle(needle).unwrap(),
                username,
                folder,
                ignore_case,
            )
            .unwrap(),
            &entries[idx],
        )
    }

    #[track_caller]
    fn no_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &parse_needle(needle).unwrap(),
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("no entry found")
        } else {
            false
        }
    }

    #[track_caller]
    fn many_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &parse_needle(needle).unwrap(),
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("multiple entries found")
        } else {
            false
        }
    }

    #[track_caller]
    fn entries_eq(
        a: &(rbw::db::Entry, DecryptedSearchCipher),
        b: &(rbw::db::Entry, DecryptedSearchCipher),
    ) -> bool {
        a.0 == b.0 && a.1 == b.1
    }

    fn make_entry(
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        uris: &[(&str, Option<rbw::api::UriMatchType>)],
    ) -> (rbw::db::Entry, DecryptedSearchCipher) {
        let id = uuid::Uuid::new_v4();
        (
            rbw::db::Entry {
                id: id.to_string(),
                org_id: None,
                folder: folder.map(|_| "encrypted folder name".to_string()),
                folder_id: None,
                name: "this is the encrypted name".to_string(),
                data: rbw::db::EntryData::Login {
                    username: username.map(|_| {
                        "this is the encrypted username".to_string()
                    }),
                    password: None,
                    uris: uris
                        .iter()
                        .map(|(_, match_type)| rbw::db::Uri {
                            uri: "this is the encrypted uri".to_string(),
                            match_type: *match_type,
                        })
                        .collect(),
                    totp: None,
                },
                fields: vec![],
                notes: None,
                history: vec![],
                key: None,
                master_password_reprompt: rbw::api::CipherRepromptType::None,
            },
            DecryptedSearchCipher {
                id: id.to_string(),
                entry_type: "Login".to_string(),
                folder: folder.map(std::string::ToString::to_string),
                name: name.to_string(),
                user: username.map(std::string::ToString::to_string),
                uris: uris
                    .iter()
                    .map(|(uri, match_type)| {
                        ((*uri).to_string(), *match_type)
                    })
                    .collect(),
                fields: vec![],
                notes: None,
            },
        )
    }
}
