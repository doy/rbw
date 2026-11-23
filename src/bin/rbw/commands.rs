use std::{
    fmt::Write as _,
    io::{IsTerminal as _, Write as _},
    os::unix::ffi::OsStrExt as _,
};

use anyhow::Context as _;

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

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedCipher {
    id: String,
    folder: Option<String>,
    name: String,
    data: DecryptedData,
    fields: Vec<DecryptedField>,
    notes: Option<String>,
    history: Vec<DecryptedHistoryEntry>,
}

impl DecryptedCipher {
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
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
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
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
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
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SecureNote => match field.parse() {
                Ok(Field::Notes) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
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
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
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
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
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
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
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
            if let Some(name) = &f.name {
                println!("{name}");
            }
        }
    }

    fn display_json(&self, desc: &str) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(std::io::stdout(), &self)
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

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
#[cfg_attr(test, derive(Eq, PartialEq))]
enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<DecryptedUri>>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        public_key: Option<String>,
        fingerprint: Option<String>,
        private_key: Option<String>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedField {
    name: Option<String>,
    value: Option<String>,
    #[serde(serialize_with = "serialize_field_type", rename = "type")]
    ty: Option<rbw::api::FieldType>,
}

#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
fn serialize_field_type<S>(
    ty: &Option<rbw::api::FieldType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ty {
        Some(ty) => {
            let s = match ty {
                rbw::api::FieldType::Text => "text",
                rbw::api::FieldType::Hidden => "hidden",
                rbw::api::FieldType::Boolean => "boolean",
                rbw::api::FieldType::Linked => "linked",
            };
            serializer.serialize_some(&Some(s))
        }
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedHistoryEntry {
    last_used_date: String,
    password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedUri {
    uri: String,
    match_type: Option<rbw::api::UriMatchType>,
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
        "pinentry_timeout" => {
            config.pinentry_timeout = value
                .parse()
                .context("failed to parse value for pinentry_timeout")?;
        }
        "touch_id_unlock" => {
            let enabled = value
                .parse()
                .context("failed to parse value for touch_id_unlock")?;
            #[cfg(not(target_os = "macos"))]
            if enabled {
                return Err(anyhow::anyhow!(
                    "touch_id_unlock is only supported on macOS"
                ));
            }
            config.touch_id_unlock = enabled;
        }
        "touch_id_ssh" => {
            let enabled = value
                .parse()
                .context("failed to parse value for touch_id_ssh")?;
            #[cfg(not(target_os = "macos"))]
            if enabled {
                return Err(anyhow::anyhow!(
                    "touch_id_ssh is only supported on macOS"
                ));
            }
            config.touch_id_ssh = enabled;
        }
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
        "pinentry_timeout" => {
            config.pinentry_timeout = rbw::config::default_pinentry_timeout();
        }
        "touch_id_unlock" => config.touch_id_unlock = false,
        "touch_id_ssh" => config.touch_id_ssh = false,
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
    let mut entries: Vec<DecryptedListCipher> =
        batch_decrypt(&db.entries, |entry, decryptor| {
            decrypt_list_cipher(entry, &fields, decryptor)
        })?;
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

    let mut entries: Vec<DecryptedListCipher> =
        batch_decrypt(&db.entries, |entry, decryptor| {
            decrypt_search_cipher(entry, decryptor)
        })?
        .into_iter()
        .filter(|entry| entry.search_match(term, folder))
        .map(std::convert::Into::into)
        .collect();
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

pub fn add(
    name: &str,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    secure_note: bool,
    fields: &[(String, String, rbw::api::FieldType)],
) -> anyhow::Result<()> {
    check_new_field_names(fields.iter().map(|(name, _, _)| name.as_str()))?;

    unlock()?;

    let mut db = load_db()?;
    if db.user_id.is_none() {
        crate::actions::sync()
            .context("failed to sync user id before adding entry")?;
        db = load_db()?;
    }
    let user_id = user_id(&db)?.to_string();
    // unwrap is safe here because the call to unlock above is guaranteed to
    // populate these or error
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let name = crate::actions::encrypt(name, None, None)?;

    let username = username
        .map(|username| crate::actions::encrypt(username, None, None))
        .transpose()?;

    let (password, notes) = if secure_note {
        let contents = rbw::edit::edit("", HELP_NOTES)?;
        // prepend blank line to be parsed as pw by `parse_editor`
        let (_, notes) = parse_editor(&format!("\n{contents}\n"));
        (None, notes)
    } else {
        parse_editor(&rbw::edit::edit("", HELP_PW)?)
    };
    let password = password
        .map(|password| crate::actions::encrypt(&password, None, None))
        .transpose()?;
    let notes = notes
        .map(|notes| crate::actions::encrypt(&notes, None, None))
        .transpose()?;
    let uris: Vec<_> = uris
        .iter()
        .map(|(uri, match_type)| encrypt_uri(uri, *match_type, None, None))
        .collect::<anyhow::Result<_>>()?;

    let fields: Vec<_> = fields
        .iter()
        .map(|(field_name, value, ty)| {
            Ok(rbw::db::Field {
                ty: Some(*ty),
                name: Some(crate::actions::encrypt(field_name, None, None)?),
                // the official clients store an empty value as null
                value: if value.is_empty() {
                    None
                } else {
                    Some(crate::actions::encrypt(value, None, None)?)
                },
                linked_id: None,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let mut folder_id = None;
    if let Some(folder_name) = folder {
        let (tokens, folders) =
            rbw::actions::list_folders(&access_token, &refresh_token)?;
        update_tokens(tokens, &mut access_token, &mut refresh_token);

        let folders = decrypt_folder_names(folders)?;

        for (id, name) in folders {
            if name == folder_name {
                folder_id = Some(id);
            }
        }
        if folder_id.is_none() {
            let (tokens, id) = rbw::actions::create_folder(
                &access_token,
                &refresh_token,
                &crate::actions::encrypt(folder_name, None, None)?,
            )?;
            update_tokens(tokens, &mut access_token, &mut refresh_token);
            folder_id = Some(id);
        }
    }

    let data = if secure_note {
        rbw::db::EntryData::SecureNote
    } else {
        rbw::db::EntryData::Login {
            username,
            password,
            uris,
            totp: None,
        }
    };

    rbw::actions::add(
        &access_token,
        &refresh_token,
        &user_id,
        &name,
        &data,
        &fields,
        notes.as_deref(),
        folder_id.as_deref(),
    )?;

    crate::actions::sync()?;

    Ok(())
}

// `rbw get --field` and `rbw edit --field` can't tell two custom fields with
// the same name apart, so don't create them
fn check_new_field_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for name in names {
        if !seen.insert(name) {
            anyhow::bail!("custom field '{name}' is given more than once");
        }
    }
    Ok(())
}

fn uri_checksum(uri: &str) -> String {
    use sha2::Digest as _;

    rbw::base64::encode(sha2::Sha256::digest(uri.as_bytes()))
}

// encrypts a uri together with its checksum (the base64 sha256 of the uri),
// which the official clients check before showing the uris of an entry
// that has its own key
fn encrypt_uri(
    uri: &str,
    match_type: Option<rbw::api::UriMatchType>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<rbw::db::Uri> {
    Ok(rbw::db::Uri {
        uri: crate::actions::encrypt(uri, entry_key, org_id)?,
        match_type,
        uri_checksum: Some(crate::actions::encrypt(
            &uri_checksum(uri),
            entry_key,
            org_id,
        )?),
    })
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
        if db.user_id.is_none() {
            crate::actions::sync().context(
                "failed to sync user id before generating a passphrase",
            )?;
            db = load_db()?;
        }
        let user_id = user_id(&db)?.to_string();
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

        let name = crate::actions::encrypt(name, None, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None, None))
            .transpose()?;
        let password = crate::actions::encrypt(&password, None, None)?;
        let uris: Vec<_> = uris
            .iter()
            .map(|(uri, match_type)| {
                encrypt_uri(uri, *match_type, None, None)
            })
            .collect::<anyhow::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (tokens, folders) =
                rbw::actions::list_folders(&access_token, &refresh_token)?;
            update_tokens(tokens, &mut access_token, &mut refresh_token);

            let folders = decrypt_folder_names(folders)?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (tokens, id) = rbw::actions::create_folder(
                    &access_token,
                    &refresh_token,
                    &crate::actions::encrypt(folder_name, None, None)?,
                )?;
                update_tokens(tokens, &mut access_token, &mut refresh_token);
                folder_id = Some(id);
            }
        }

        rbw::actions::add(
            &access_token,
            &refresh_token,
            &user_id,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
                totp: None,
            },
            &[],
            None,
            folder_id.as_deref(),
        )?;

        crate::actions::sync()?;
    }

    Ok(())
}

pub fn edit(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    field: Option<&str>,
    create: bool,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    if db.user_id.is_none() {
        crate::actions::sync()
            .context("failed to sync user id before editing entry")?;
        db = load_db()?;
    }
    let user_id = user_id(&db)?.to_string();
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (entry, decrypted) =
        find_entry(&db, name, username, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let edited = if let Some(field) = field {
        edit_field(&entry, &decrypted, field, create)?
    } else {
        Some(edit_default(&entry, &decrypted)?)
    };
    let Some((name, data, fields, notes, history)) = edited else {
        eprintln!("'{}' is unchanged, nothing to save", field.unwrap_or(""));
        return Ok(());
    };

    rbw::actions::edit(
        access_token,
        refresh_token,
        &user_id,
        &entry.id,
        entry.org_id.as_deref(),
        &name,
        &data,
        &fields,
        notes.as_deref(),
        entry.folder_id.as_deref(),
        &history,
        entry.key.as_deref(),
    )?;

    crate::actions::sync()?;
    Ok(())
}

// what an edit sends: the encrypted name, data, custom fields, notes and
// password history
type EditedEntry = (
    String,
    rbw::db::EntryData,
    Vec<rbw::db::Field>,
    Option<String>,
    Vec<rbw::db::HistoryEntry>,
);

fn edit_default(
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
) -> anyhow::Result<EditedEntry> {
    let (data, fields, notes, history) = match &decrypted.data {
        DecryptedData::Login { password, .. } => {
            let mut contents =
                format!("{}\n", password.as_deref().unwrap_or(""));
            if let Some(notes) = decrypted.notes.clone() {
                write!(contents, "\n{notes}\n").unwrap();
            }

            let contents = rbw::edit::edit(&contents, HELP_PW)?;

            let (new_password, notes) = parse_editor(&contents);
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

            let password = edit_password(
                entry,
                entry_password.as_deref(),
                password.as_deref(),
                new_password.as_deref(),
                &mut history,
            )?;

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

            let editor_content = decrypted.notes.clone().map_or_else(
                || "\n".to_string(),
                |notes| format!("{notes}\n"),
            );
            let contents = rbw::edit::edit(&editor_content, HELP_NOTES)?;

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
    Ok((entry.name.clone(), data, fields, notes, history))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldTarget {
    Builtin(Field),
    Custom,
}

fn field_target(field: &str, data: &DecryptedData) -> FieldTarget {
    match (field.parse::<Field>().ok(), data) {
        (Some(f @ (Field::Name | Field::Notes)), _)
        | (
            Some(
                f @ (Field::Username
                | Field::Password
                | Field::Totp
                | Field::Uris),
            ),
            DecryptedData::Login { .. },
        ) => FieldTarget::Builtin(f),
        _ => FieldTarget::Custom,
    }
}

fn find_custom_field(
    names: &[Option<&str>],
    field: &str,
) -> anyhow::Result<Option<usize>> {
    let named = || {
        names
            .iter()
            .enumerate()
            .filter_map(|(i, name)| name.map(|name| (i, name)))
    };
    // unlike `rbw get --field`, don't match part of a name: that would
    // edit the wrong field when the one asked for doesn't exist, or update
    // an existing field instead of creating one with --create
    let lower = field.to_lowercase();
    let levels: [Vec<(usize, &str)>; 2] = [
        named().filter(|(_, name)| *name == field).collect(),
        named()
            .filter(|(_, name)| name.to_lowercase() == lower)
            .collect(),
    ];
    for matches in levels {
        match matches.as_slice() {
            [] => {}
            [(i, _)] => return Ok(Some(*i)),
            _ => {
                let candidates = matches
                    .iter()
                    .map(|(_, name)| format!("'{name}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "field '{field}' is ambiguous, it matches {candidates}; \
                     use the exact field name"
                );
            }
        }
    }
    Ok(None)
}

fn read_field_value(
    current: Option<&str>,
    help: &str,
) -> anyhow::Result<Option<String>> {
    if std::io::stdin().is_terminal() {
        let contents =
            rbw::edit::edit(&format!("{}\n", current.unwrap_or("")), help)?;
        Ok(parse_field_value(&contents))
    } else {
        // taken verbatim on purpose, not run through the editor parser
        let input = std::io::read_to_string(std::io::stdin())
            .context("failed to read field value from stdin")?;
        Ok(parse_piped_field_value(&input))
    }
}

fn parse_piped_field_value(input: &str) -> Option<String> {
    let value = input
        .strip_suffix('\n')
        .map_or(input, |v| v.strip_suffix('\r').unwrap_or(v));
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

// what an edit does to the login password
#[derive(Debug, PartialEq, Eq)]
enum PasswordChange<'a> {
    // keep the current ciphertext
    Unchanged,
    // the new password, or none to remove it
    Changed(Option<&'a str>),
}

fn password_change<'a>(
    encrypted: Option<&str>,
    current: Option<&str>,
    new: Option<&'a str>,
) -> PasswordChange<'a> {
    // like the official clients, store an empty password as none
    let new = new.filter(|password| !password.is_empty());
    if encrypted.is_none() && new.is_none() {
        return PasswordChange::Unchanged;
    }
    // current is none with a ciphertext when it couldn't be decrypted, and
    // then it can't be compared
    if current.is_some() && current == new {
        return PasswordChange::Unchanged;
    }
    PasswordChange::Changed(new)
}

// returns the encrypted password to send. an unchanged password keeps its
// ciphertext, so that saving without changes adds nothing to the history and
// leaves the server's password revision date alone. a changed one moves the
// old one into the history, as the official clients do.
fn edit_password(
    entry: &rbw::db::Entry,
    encrypted: Option<&str>,
    current: Option<&str>,
    new: Option<&str>,
    history: &mut Vec<rbw::db::HistoryEntry>,
) -> anyhow::Result<Option<String>> {
    match password_change(encrypted, current, new) {
        PasswordChange::Unchanged => Ok(encrypted.map(str::to_string)),
        PasswordChange::Changed(new) => {
            if let Some(old) = encrypted {
                history.insert(
                    0,
                    rbw::db::HistoryEntry {
                        last_used_date: rbw::api::format_rfc3339(
                            std::time::SystemTime::now(),
                        ),
                        password: old.to_string(),
                    },
                );
            }
            new.map(|new| {
                crate::actions::encrypt(
                    new,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
            })
            .transpose()
        }
    }
}

// one uri per line, ignoring blank lines and surrounding whitespace
fn parse_uri_lines(value: Option<&str>) -> Vec<&str> {
    value
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

// checks a new value for a custom field of the given type
fn check_custom_field_value(
    field: &str,
    ty: Option<rbw::api::FieldType>,
    value: Option<&str>,
) -> anyhow::Result<()> {
    if ty == Some(rbw::api::FieldType::Boolean)
        && !matches!(value, Some("true" | "false"))
    {
        anyhow::bail!(
            "'{field}' is a boolean field, its value must be true or false"
        );
    }
    Ok(())
}

// edits one field of the entry. returns none when the value didn't change,
// so there is nothing to send.
fn edit_field(
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
    field: &str,
    create: bool,
) -> anyhow::Result<Option<EditedEntry>> {
    if field.is_empty() {
        anyhow::bail!("the field name can't be empty");
    }
    if matches!(entry.data, rbw::db::EntryData::SshKey { .. }) {
        anyhow::bail!("editing SSH key entries is not supported");
    }

    let encrypt = |plain: &str| {
        crate::actions::encrypt(
            plain,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )
    };

    let parsed = match field_target(field, &decrypted.data) {
        FieldTarget::Builtin(parsed) => parsed,
        FieldTarget::Custom => {
            // match decrypted names; indices line up with entry.fields
            let names: Vec<Option<&str>> =
                decrypted.fields.iter().map(|f| f.name.as_deref()).collect();
            let idx = find_custom_field(&names, field)?;
            let ty = match idx {
                Some(i) => entry.fields[i].ty,
                None if create => Some(rbw::api::FieldType::Hidden),
                None if field.parse::<Field>().is_ok() => anyhow::bail!(
                    "field '{field}' can't be edited on this entry type \
                     and no custom field with that name exists \
                     (use --create to add one)"
                ),
                None => anyhow::bail!(
                    "no field named '{field}' found on this entry \
                     (use --create to add it)"
                ),
            };
            if ty == Some(rbw::api::FieldType::Linked) {
                anyhow::bail!(
                    "'{field}' is a linked field, which shows another \
                     field of the entry and has no value of its own"
                );
            }

            let current =
                idx.and_then(|i| decrypted.fields[i].value.as_deref());
            let new_value = read_field_value(current, HELP_FIELD)?;
            check_custom_field_value(field, ty, new_value.as_deref())?;
            if idx.is_some() && new_value.as_deref() == current {
                return Ok(None);
            }
            let value = new_value.as_deref().map(encrypt).transpose()?;

            let mut fields = entry.fields.clone();
            if let Some(i) = idx {
                fields[i].value = value;
            } else {
                if value.is_none() {
                    anyhow::bail!(
                        "refusing to create field '{field}' with an empty \
                         value"
                    );
                }
                fields.push(rbw::db::Field {
                    ty,
                    name: Some(encrypt(field)?),
                    value,
                    linked_id: None,
                });
            }
            return Ok(Some((
                entry.name.clone(),
                entry.data.clone(),
                fields,
                entry.notes.clone(),
                entry.history.clone(),
            )));
        }
    };

    let current = match (parsed, &decrypted.data) {
        (Field::Name, _) => Some(decrypted.name.clone()),
        (Field::Notes, _) => decrypted.notes.clone(),
        (Field::Username, DecryptedData::Login { username, .. }) => {
            username.clone()
        }
        (Field::Password, DecryptedData::Login { password, .. }) => {
            password.clone()
        }
        (Field::Totp, DecryptedData::Login { totp, .. }) => totp.clone(),
        (Field::Uris, DecryptedData::Login { uris, .. }) => {
            // a uri that can't be decrypted would be dropped from the
            // edited list
            let uris = uris.as_ref().context(
                "some of the entry's uris couldn't be decrypted, so they \
                 can't be edited",
            )?;
            if uris.is_empty() {
                None
            } else {
                Some(
                    uris.iter()
                        .map(|u| u.uri.clone())
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            }
        }
        _ => unreachable!("field_target only returns editable built-ins"),
    };

    let help = if parsed == Field::Uris {
        HELP_URIS
    } else {
        HELP_FIELD
    };
    let new_value = read_field_value(current.as_deref(), help)?;
    if parsed == Field::Name && new_value.is_none() {
        anyhow::bail!("the entry name can't be empty");
    }
    let unchanged = if parsed == Field::Uris {
        parse_uri_lines(new_value.as_deref())
            == parse_uri_lines(current.as_deref())
    } else {
        new_value == current
    };
    if unchanged {
        return Ok(None);
    }

    let mut name = entry.name.clone();
    let mut notes = entry.notes.clone();
    let mut history = entry.history.clone();
    let mut data = entry.data.clone();

    match (parsed, &mut data) {
        (Field::Name, _) => {
            // checked above that there is a new name
            name = encrypt(new_value.as_deref().unwrap_or_default())?;
        }
        (Field::Notes, _) => {
            notes = new_value.as_deref().map(encrypt).transpose()?;
        }
        (
            Field::Password,
            rbw::db::EntryData::Login {
                password: entry_password,
                ..
            },
        ) => {
            *entry_password = edit_password(
                entry,
                entry_password.as_deref(),
                current.as_deref(),
                new_value.as_deref(),
                &mut history,
            )?;
        }
        (Field::Username, rbw::db::EntryData::Login { username, .. }) => {
            *username = new_value.as_deref().map(encrypt).transpose()?;
        }
        (Field::Totp, rbw::db::EntryData::Login { totp, .. }) => {
            *totp = new_value.as_deref().map(encrypt).transpose()?;
        }
        (Field::Uris, rbw::db::EntryData::Login { uris, .. }) => {
            let DecryptedData::Login {
                uris: Some(decrypted_uris),
                ..
            } = &decrypted.data
            else {
                unreachable!("checked above");
            };
            // the decrypted uris line up with the entry's. a uri that is
            // still in the list keeps its ciphertext and match type, so
            // the server's checksum for it stays valid.
            let old: Vec<(&str, &rbw::db::Uri)> = decrypted_uris
                .iter()
                .map(|u| u.uri.as_str())
                .zip(uris.iter())
                .collect();
            *uris = parse_uri_lines(new_value.as_deref())
                .into_iter()
                .map(|uri| {
                    old.iter().find(|(plain, _)| *plain == uri).map_or_else(
                        || {
                            encrypt_uri(
                                uri,
                                None,
                                entry.key.as_deref(),
                                entry.org_id.as_deref(),
                            )
                        },
                        |(_, old)| Ok((*old).clone()),
                    )
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
        }
        _ => unreachable!("field_target only returns editable built-ins"),
    }

    Ok(Some((name, data, entry.fields.clone(), notes, history)))
}

fn parse_field_value(contents: &str) -> Option<String> {
    let mut value = contents
        .lines()
        .filter(|line| !line.starts_with('#'))
        .fold(String::new(), |mut acc, line| {
            acc.push_str(line);
            acc.push('\n');
            acc
        });
    while value.ends_with('\n') {
        value.pop();
    }
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

const HELP_FIELD: &str = r"
# The content of this file will be saved as the new field value.
# Lines with leading # will be ignored.
";

const HELP_URIS: &str = r"
# Put one URI per line. Blank lines and lines with leading # will be
# ignored.
";

pub fn remove(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (entry, _) = find_entry(&db, name, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    rbw::actions::remove(access_token, refresh_token, &entry.id)?;

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
                return Ok((cipher.clone(), decrypt_cipher_batched(cipher)?));
            }
        }
        needle = Needle::Name(s);
    }

    let decrypted = batch_decrypt(&db.entries, |entry, decryptor| {
        decrypt_search_cipher(entry, decryptor)
    })?;
    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> =
        db.entries.iter().cloned().zip(decrypted).collect();
    let (entry, _) =
        find_entry_raw(&ciphers, &needle, username, folder, ignore_case)?;
    let decrypted_entry = decrypt_cipher_batched(&entry)?;
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

// decrypting an entry takes one agent round trip per field, which adds up
// fast when looking at the whole vault (e.g. finding an entry by name). to
// batch these into a single round trip, the per-entry decryption functions
// go through an EntryDecryptor: a recording pass first collects every
// cipherstring they would want if every decryption succeeded, then the whole
// batch is decrypted with one agent request, and a replay pass runs the same
// functions again and hands each of them the result for its request. their
// control flow depends on the entry structure and on which decryptions
// failed, never on decrypted values, so the replay only asks for values the
// recording pass saw.
trait EntryDecryptor {
    fn decrypt(
        &self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String>;
}

#[derive(Default)]
struct RecordingDecryptor(
    std::cell::RefCell<Vec<rbw::protocol::DecryptItem>>,
);

impl EntryDecryptor for RecordingDecryptor {
    fn decrypt(
        &self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        self.0.borrow_mut().push(rbw::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        });
        Ok(String::new())
    }
}

// hands out the agent's results during the replay pass. results are looked
// up by the request that produced them rather than by position: a failed
// decryption can make the replay skip later requests (for example, one
// unreadable uri ends the uri list in decrypt_cipher), and a positional
// replay would then hand every following result to the wrong field.
// requesting anything that wasn't recorded is an error.
struct ReplayingDecryptor(
    std::collections::HashMap<
        rbw::protocol::DecryptItem,
        Result<String, String>,
    >,
);

impl EntryDecryptor for ReplayingDecryptor {
    fn decrypt(
        &self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        let item = rbw::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        };
        self.0
            .get(&item)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "batch decryption asked for a value it didn't record"
                )
            })?
            .clone()
            .map_err(|e| anyhow::anyhow!("failed to decrypt: {e}"))
    }
}

fn record_batch<T>(
    entries: &[rbw::db::Entry],
    each: &impl Fn(&rbw::db::Entry, &dyn EntryDecryptor) -> anyhow::Result<T>,
) -> Vec<rbw::protocol::DecryptItem> {
    let recorder = RecordingDecryptor::default();
    for entry in entries {
        // the recording decryptor never fails, and these functions have no
        // other failure modes; anything real will surface during replay
        let _ = each(entry, &recorder);
    }
    recorder.0.into_inner()
}

fn replay_batch<T>(
    entries: &[rbw::db::Entry],
    each: &impl Fn(&rbw::db::Entry, &dyn EntryDecryptor) -> anyhow::Result<T>,
    items: Vec<rbw::protocol::DecryptItem>,
    results: Vec<Result<String, String>>,
) -> anyhow::Result<Vec<T>> {
    if items.len() != results.len() {
        return Err(anyhow::anyhow!(
            "agent returned {} decryption results for {} values",
            results.len(),
            items.len()
        ));
    }
    let replayer =
        ReplayingDecryptor(items.into_iter().zip(results).collect());
    entries.iter().map(|entry| each(entry, &replayer)).collect()
}

fn batch_decrypt<T>(
    entries: &[rbw::db::Entry],
    each: impl Fn(&rbw::db::Entry, &dyn EntryDecryptor) -> anyhow::Result<T>,
) -> anyhow::Result<Vec<T>> {
    let items = record_batch(entries, &each);
    // the request takes the items, and the replay needs them to match up
    // the results, so send a copy
    let results = crate::actions::decrypt_many(items.clone())?;
    replay_batch(entries, &each, items, results)
}

// decrypts folder names from the server with one agent request. any failure
// is fatal, as it was when each name took its own request.
fn decrypt_folder_names(
    folders: Vec<(String, String)>,
) -> anyhow::Result<Vec<(String, String)>> {
    let items = folders
        .iter()
        .map(|(_, name)| rbw::protocol::DecryptItem {
            cipherstring: name.clone(),
            entry_key: None,
            org_id: None,
        })
        .collect();
    let names = crate::actions::decrypt_many(items)?;
    if names.len() != folders.len() {
        return Err(anyhow::anyhow!(
            "agent returned {} decryption results for {} folders",
            names.len(),
            folders.len()
        ));
    }
    folders
        .into_iter()
        .zip(names)
        .map(|((id, _), name)| {
            name.map(|name| (id, name))
                .map_err(|e| anyhow::anyhow!("failed to decrypt: {e}"))
        })
        .collect()
}

fn decrypt_cipher_batched(
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedCipher> {
    batch_decrypt(std::slice::from_ref(entry), |entry, decryptor| {
        decrypt_cipher(entry, decryptor)
    })?
    .pop()
    .ok_or_else(|| anyhow::anyhow!("no decryption result"))
}

fn decrypt_field(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    decryptor: &dyn EntryDecryptor,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| decryptor.decrypt(field, entry_key, org_id))
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
    decryptor: &dyn EntryDecryptor,
) -> anyhow::Result<DecryptedListCipher> {
    let id = entry.id.clone();
    let name = if fields.contains(&ListField::Name) {
        Some(decryptor.decrypt(
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
                decryptor,
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
            .map(|folder| decryptor.decrypt(folder, None, None))
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
                            decryptor,
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
    decryptor: &dyn EntryDecryptor,
) -> anyhow::Result<DecryptedSearchCipher> {
    let id = entry.id.clone();
    let name = decryptor.decrypt(
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
            decryptor,
        ),
        _ => None,
    };
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| decryptor.decrypt(folder, None, None))
        .transpose()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            decryptor.decrypt(
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
                    decryptor,
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
            decryptor.decrypt(
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

fn decrypt_cipher(
    entry: &rbw::db::Entry,
    decryptor: &dyn EntryDecryptor,
) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| decryptor.decrypt(folder, None, None))
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
                        decryptor.decrypt(
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        decryptor.decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                ty: field.ty,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            decryptor.decrypt(
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
                password: decryptor.decrypt(
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
                decryptor,
            ),
            password: decrypt_field(
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            totp: decrypt_field(
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        Field::Uris,
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                        decryptor,
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
                decryptor,
            ),
            number: decrypt_field(
                Field::CardNumber,
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            brand: decrypt_field(
                Field::Brand,
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            exp_month: decrypt_field(
                Field::ExpMonth,
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            exp_year: decrypt_field(
                Field::ExpYear,
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            code: decrypt_field(
                Field::Cvv,
                code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
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
                decryptor,
            ),
            first_name: decrypt_field(
                Field::FirstName,
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            middle_name: decrypt_field(
                Field::MiddleName,
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            last_name: decrypt_field(
                Field::LastName,
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address1: decrypt_field(
                Field::Address1,
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address2: decrypt_field(
                Field::Address2,
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address3: decrypt_field(
                Field::Address3,
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            city: decrypt_field(
                Field::City,
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            state: decrypt_field(
                Field::State,
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            postal_code: decrypt_field(
                Field::PostalCode,
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            country: decrypt_field(
                Field::Country,
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            phone: decrypt_field(
                Field::Phone,
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            email: decrypt_field(
                Field::Email,
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            ssn: decrypt_field(
                Field::Ssn,
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            license_number: decrypt_field(
                Field::License,
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            passport_number: decrypt_field(
                Field::Passport,
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
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
                decryptor,
            ),
            fingerprint: decrypt_field(
                Field::Fingerprint,
                fingerprint.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            private_key: decrypt_field(
                Field::PrivateKey,
                private_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
        },
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: decryptor.decrypt(
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

fn user_id(db: &rbw::db::Db) -> anyhow::Result<&str> {
    db.user_id.as_deref().with_context(|| {
        "user id is missing from the db, please run `rbw sync` first"
            .to_string()
    })
}

// Switches to tokens that a request had to refresh, for the requests after
// it. The library has already saved them.
fn update_tokens(
    tokens: Option<rbw::actions::RefreshedTokens>,
    access_token: &mut String,
    refresh_token: &mut String,
) {
    if let Some(tokens) = tokens {
        *access_token = tokens.access_token;
        *refresh_token = tokens.refresh_token;
    }
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
    fn test_uri_checksum() {
        // the base64 sha256, as the official clients compute it
        assert_eq!(
            uri_checksum("https://example.com"),
            "EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk="
        );
    }

    #[test]
    fn test_password_change() {
        use PasswordChange::{Changed, Unchanged};
        // no password before or after
        assert_eq!(password_change(None, None, None), Unchanged);
        assert_eq!(password_change(None, None, Some("")), Unchanged);
        // the same password
        assert_eq!(
            password_change(Some("2.a"), Some("a"), Some("a")),
            Unchanged
        );
        // a new, changed or removed password
        assert_eq!(
            password_change(None, None, Some("a")),
            Changed(Some("a"))
        );
        assert_eq!(
            password_change(Some("2.a"), Some("a"), Some("b")),
            Changed(Some("b"))
        );
        assert_eq!(
            password_change(Some("2.a"), Some("a"), None),
            Changed(None)
        );
        assert_eq!(
            password_change(Some("2.a"), Some("a"), Some("")),
            Changed(None)
        );
        // a password that couldn't be decrypted can't be compared
        assert_eq!(
            password_change(Some("2.a"), None, Some("a")),
            Changed(Some("a"))
        );
        assert_eq!(password_change(Some("2.a"), None, None), Changed(None));
    }

    #[test]
    fn test_parse_uri_lines() {
        assert_eq!(parse_uri_lines(None), Vec::<&str>::new());
        assert_eq!(
            parse_uri_lines(Some(" https://a \n\n\thttps://b\r\n")),
            ["https://a", "https://b"]
        );
    }

    #[test]
    fn test_check_custom_field_value() {
        use rbw::api::FieldType;
        for ty in [None, Some(FieldType::Text), Some(FieldType::Hidden)] {
            assert!(check_custom_field_value("f", ty, Some("yes")).is_ok());
            assert!(check_custom_field_value("f", ty, None).is_ok());
        }
        let boolean = Some(FieldType::Boolean);
        assert!(check_custom_field_value("f", boolean, Some("true")).is_ok());
        assert!(check_custom_field_value("f", boolean, Some("false")).is_ok());
        assert!(check_custom_field_value("f", boolean, Some("yes")).is_err());
        assert!(check_custom_field_value("f", boolean, None).is_err());
    }

    #[test]
    fn test_check_new_field_names() {
        assert!(check_new_field_names([]).is_ok());
        assert!(check_new_field_names(["a", "b", "A"]).is_ok());
        let err = check_new_field_names(["a", "b", "a"]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "custom field 'a' is given more than once"
        );
    }

    #[test]
    fn test_parse_piped_field_value() {
        assert_eq!(
            parse_piped_field_value("s3cr3t\n"),
            Some("s3cr3t".into())
        );
        assert_eq!(
            parse_piped_field_value("s3cr3t\r\n"),
            Some("s3cr3t".into())
        );
        assert_eq!(parse_piped_field_value("s3cr3t"), Some("s3cr3t".into()));
        assert_eq!(parse_piped_field_value("#abc\n"), Some("#abc".into()));
        assert_eq!(
            parse_piped_field_value("line1\n# line2\n"),
            Some("line1\n# line2".into())
        );
        assert_eq!(parse_piped_field_value("a\n\n"), Some("a\n".into()));
        assert_eq!(parse_piped_field_value("\n"), None);
        assert_eq!(parse_piped_field_value(""), None);
    }

    #[test]
    fn test_find_custom_field() {
        let names = [
            Some("DB_PASSWORD_RO"),
            Some("DB_PASSWORD"),
            None,
            Some("api_key"),
            Some("Token"),
            Some("token"),
        ];
        assert_eq!(
            find_custom_field(&names, "DB_PASSWORD").unwrap(),
            Some(1)
        );
        assert_eq!(
            find_custom_field(&names, "DB_PASSWORD_RO").unwrap(),
            Some(0)
        );
        assert_eq!(find_custom_field(&names, "API_KEY").unwrap(), Some(3));
        assert_eq!(find_custom_field(&names, "token").unwrap(), Some(5));
        assert!(find_custom_field(&names, "TOKEN").is_err());
        assert_eq!(find_custom_field(&names, "api").unwrap(), None);
        assert_eq!(find_custom_field(&names, "db_pass").unwrap(), None);
        assert_eq!(find_custom_field(&names, "missing").unwrap(), None);
    }

    #[test]
    fn test_field_target() {
        let login = DecryptedData::Login {
            username: None,
            password: None,
            totp: None,
            uris: None,
        };
        let note = DecryptedData::SecureNote;
        assert_eq!(
            field_target("password", &login),
            FieldTarget::Builtin(Field::Password)
        );
        assert_eq!(
            field_target("notes", &note),
            FieldTarget::Builtin(Field::Notes)
        );
        assert_eq!(
            field_target("name", &note),
            FieldTarget::Builtin(Field::Name)
        );
        assert_eq!(field_target("PASSWORD", &note), FieldTarget::Custom);
        assert_eq!(field_target("email", &login), FieldTarget::Custom);
        assert_eq!(field_target("DB_PASSWORD", &login), FieldTarget::Custom);
    }

    #[test]
    fn test_parse_field_value() {
        assert_eq!(parse_field_value("hello\n"), Some("hello".into()));
        assert_eq!(
            parse_field_value("line1\nline2\n"),
            Some("line1\nline2".into())
        );
        assert_eq!(
            parse_field_value("# comment\nvalue\n"),
            Some("value".into())
        );
        assert_eq!(parse_field_value("\n# nothing\n"), None);
        assert_eq!(parse_field_value(""), None);
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

    // an entry exercising every decryption site: login with username,
    // password, totp, uris, custom fields (text and hidden), notes,
    // history, folder, and an individual entry key. every "cipherstring"
    // starts with the given prefix, so results can be traced back to the
    // entry they came from.
    fn make_full_entry(prefix: &str) -> rbw::db::Entry {
        let s = |field: &str| format!("{prefix} {field}");
        rbw::db::Entry {
            id: uuid::Uuid::new_v4().to_string(),
            org_id: Some("org".to_string()),
            folder: Some(s("folder")),
            folder_id: None,
            name: s("name"),
            data: rbw::db::EntryData::Login {
                username: Some(s("username")),
                password: Some(s("password")),
                totp: Some(s("totp")),
                uris: vec![
                    rbw::db::Uri {
                        uri: s("uri 1"),
                        match_type: None,
                        uri_checksum: None,
                    },
                    rbw::db::Uri {
                        uri: s("uri 2"),
                        match_type: None,
                        uri_checksum: None,
                    },
                ],
            },
            fields: vec![
                rbw::db::Field {
                    ty: Some(rbw::api::FieldType::Text),
                    name: Some(s("field name")),
                    value: Some(s("field value")),
                    linked_id: None,
                },
                rbw::db::Field {
                    ty: Some(rbw::api::FieldType::Hidden),
                    name: Some(s("hidden name")),
                    value: Some(s("hidden value")),
                    linked_id: None,
                },
            ],
            notes: Some(s("notes")),
            history: vec![rbw::db::HistoryEntry {
                last_used_date: "2020-01-01".to_string(),
                password: s("old password"),
            }],
            key: Some("entry key".to_string()),
            master_password_reprompt: rbw::api::CipherRepromptType::None,
        }
    }

    // stands in for the agent: "decrypts" by adding a marker, and fails the
    // cipherstrings for which fail returns true
    fn fake_agent(
        items: &[rbw::protocol::DecryptItem],
        fail: impl Fn(&str) -> bool,
    ) -> Vec<Result<String, String>> {
        items
            .iter()
            .map(|item| {
                if fail(&item.cipherstring) {
                    Err(format!("cannot decrypt {}", item.cipherstring))
                } else {
                    Ok(format!("plain {}", item.cipherstring))
                }
            })
            .collect()
    }

    fn replay_with<T>(
        entries: &[rbw::db::Entry],
        each: impl Fn(&rbw::db::Entry, &dyn EntryDecryptor) -> anyhow::Result<T>,
        fail: impl Fn(&str) -> bool,
    ) -> anyhow::Result<Vec<T>> {
        let items = record_batch(entries, &each);
        let results = fake_agent(&items, fail);
        replay_batch(entries, &each, items, results)
    }

    #[test]
    fn test_batch_decrypt_record_replay() {
        // the replay pass must only ask for decryptions the recording pass
        // saw, and a result count that doesn't match what was recorded is
        // an error
        fn check<T>(
            entries: &[rbw::db::Entry],
            each: impl Fn(
                &rbw::db::Entry,
                &dyn EntryDecryptor,
            ) -> anyhow::Result<T>,
        ) -> Vec<rbw::protocol::DecryptItem> {
            let items = record_batch(entries, &each);
            assert_ne!(items.len(), 0);
            let results = fake_agent(&items, |_| false);
            replay_batch(entries, &each, items.clone(), results).unwrap();
            let mut results = fake_agent(&items, |_| false);
            results.push(Ok(String::new()));
            assert!(
                replay_batch(entries, &each, items.clone(), results).is_err()
            );
            let mut results = fake_agent(&items, |_| false);
            results.pop();
            assert!(
                replay_batch(entries, &each, items.clone(), results).is_err()
            );
            items
        }

        let entries = vec![make_full_entry("a"), make_full_entry("b")];

        let search_items = check(&entries, |entry, decryptor| {
            decrypt_search_cipher(entry, decryptor)
        });
        // search must never ask for hidden field values (they could
        // trigger master password reprompt)
        assert!(!search_items
            .iter()
            .any(|item| item.cipherstring.ends_with("hidden value")));

        check(&entries, |entry, decryptor| {
            decrypt_cipher(entry, decryptor)
        });
        let list_items = check(&entries, |entry, decryptor| {
            decrypt_list_cipher(entry, &ListField::all(), decryptor)
        });
        assert!(!list_items
            .iter()
            .any(|item| item.cipherstring.ends_with("password")));

        // folders are always decrypted with the user's own key
        for item in &list_items {
            if item.cipherstring.ends_with("folder") {
                assert_eq!(item.entry_key, None);
                assert_eq!(item.org_id, None);
            } else {
                assert_eq!(item.entry_key.as_deref(), Some("entry key"));
                assert_eq!(item.org_id.as_deref(), Some("org"));
            }
        }
    }

    #[test]
    fn test_batch_decrypt_results_land_in_their_fields() {
        let entries = vec![make_full_entry("a"), make_full_entry("b")];
        let decrypted = replay_with(
            &entries,
            |entry, decryptor| decrypt_cipher(entry, decryptor),
            |_| false,
        )
        .unwrap();
        for (prefix, cipher) in ["a", "b"].iter().zip(&decrypted) {
            let p = |field: &str| format!("plain {prefix} {field}");
            assert_eq!(cipher.name, p("name"));
            assert_eq!(cipher.folder, Some(p("folder")));
            assert_eq!(cipher.notes, Some(p("notes")));
            assert_eq!(cipher.history[0].password, p("old password"));
            assert_eq!(cipher.fields[1].name, Some(p("hidden name")));
            assert_eq!(cipher.fields[1].value, Some(p("hidden value")));
            let DecryptedData::Login {
                username,
                password,
                totp,
                uris,
            } = &cipher.data
            else {
                panic!("not a login");
            };
            assert_eq!(username, &Some(p("username")));
            assert_eq!(password, &Some(p("password")));
            assert_eq!(totp, &Some(p("totp")));
            let uris: Vec<_> =
                uris.iter().flatten().map(|u| u.uri.clone()).collect();
            assert_eq!(uris, vec![p("uri 1"), p("uri 2")]);
        }
    }

    #[test]
    fn test_batch_decrypt_keeps_per_field_failure_handling() {
        let entries = vec![make_full_entry("a"), make_full_entry("b")];

        // failures in optional fields only drop those fields, in this entry
        let decrypted = replay_with(
            &entries,
            |entry, decryptor| decrypt_cipher(entry, decryptor),
            |c| {
                c.starts_with("a ")
                    && ["folder", "notes", "password", "totp", "uri 1"]
                        .iter()
                        .any(|field| c.ends_with(field))
                    && !c.ends_with("old password")
            },
        )
        .unwrap();
        assert_eq!(decrypted[0].folder, None);
        assert_eq!(decrypted[0].notes, None);
        let DecryptedData::Login {
            username,
            password,
            totp,
            uris,
        } = &decrypted[0].data
        else {
            panic!("not a login");
        };
        assert_eq!(username, &Some("plain a username".to_string()));
        assert_eq!(password, &None);
        assert_eq!(totp, &None);
        // as before batching, one unreadable uri drops the whole list here
        assert!(uris.is_none());
        assert_eq!(decrypted[1].folder, Some("plain b folder".to_string()));
        assert_eq!(decrypted[1].notes, Some("plain b notes".to_string()));

        // the entry name, custom fields and history are required
        for required in ["b name", "b hidden value", "b old password"] {
            let err = replay_with(
                &entries,
                |entry, decryptor| decrypt_cipher(entry, decryptor),
                |c| c == required,
            )
            .err()
            .unwrap();
            assert!(format!("{err:#}").contains(required), "{err:#}");
        }

        // list and search tolerate the same fields as before: user and uris
        // in both, and notes in search
        let listed = replay_with(
            &entries,
            |entry, decryptor| {
                decrypt_list_cipher(entry, &ListField::all(), decryptor)
            },
            |c| c.ends_with("username") || c.ends_with("uri 1"),
        )
        .unwrap();
        assert_eq!(listed[0].user, None);
        assert_eq!(listed[0].uris, Some(vec!["plain a uri 2".to_string()]));
        assert!(replay_with(
            &entries,
            |entry, decryptor| {
                decrypt_list_cipher(entry, &ListField::all(), decryptor)
            },
            |c| c.ends_with("folder"),
        )
        .is_err());
        let found = replay_with(
            &entries,
            |entry, decryptor| decrypt_search_cipher(entry, decryptor),
            |c| c.ends_with("username") || c.ends_with("notes"),
        )
        .unwrap();
        assert_eq!(found[1].user, None);
        assert_eq!(found[1].notes, None);
        assert!(replay_with(
            &entries,
            |entry, decryptor| decrypt_search_cipher(entry, decryptor),
            |c| c.ends_with("name"),
        )
        .is_err());
    }

    #[test]
    fn test_batch_decrypt_rejects_unrecorded_requests() {
        let entries = vec![make_full_entry("a")];
        let each = |entry: &rbw::db::Entry,
                    decryptor: &dyn EntryDecryptor| {
            decrypt_cipher(entry, decryptor)
        };
        let mut items = record_batch(&entries, &each);
        let results = fake_agent(&items, |_| false);
        // the entry name is required, so this has to fail the replay
        let name = items
            .iter_mut()
            .find(|item| item.cipherstring == "a name")
            .unwrap();
        name.cipherstring.push_str(" changed");
        assert!(replay_batch(&entries, &each, items, results).is_err());
    }

    #[test]
    fn test_old_agent_rejects_decrypt_many_recognizably() {
        // decrypt_many falls back to single requests when the agent's error
        // contains this text, which is what serde says when an agent built
        // before DecryptMany existed parses the request
        #[derive(serde::Deserialize, Debug)]
        #[serde(tag = "type")]
        #[allow(dead_code)]
        enum OldAction {
            Decrypt {
                cipherstring: String,
                entry_key: Option<String>,
                org_id: Option<String>,
            },
            Version,
        }
        let request =
            serde_json::to_string(&rbw::protocol::Action::DecryptMany {
                items: vec![rbw::protocol::DecryptItem {
                    cipherstring: "2.x|y|z".to_string(),
                    entry_key: None,
                    org_id: None,
                }],
            })
            .unwrap();
        let err = serde_json::from_str::<OldAction>(&request).unwrap_err();
        assert!(
            err.to_string().contains("unknown variant `DecryptMany`"),
            "{err}"
        );
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
                            uri_checksum: None,
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
