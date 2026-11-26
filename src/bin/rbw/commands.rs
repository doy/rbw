use std::{fmt::Write as _, io::Write as _, os::unix::ffi::OsStrExt as _};

use anyhow::Context as _;

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

const MISSING_CONFIG_HELP: &str = "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw account add\n\n\
    or:\n\n    \
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
    if let Ok(url) = url::Url::parse(arg)
        && url.is_special()
    {
        return Ok(Needle::Uri(url));
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
        if let Some(folder) = folder
            && self.folder.as_deref() != Some(folder)
        {
            return false;
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
                        if let Some(name) = &f.name
                            && name.to_lowercase().as_str().contains(field)
                        {
                            val_display_or_store(
                                clipboard,
                                f.value.as_deref().unwrap_or(""),
                            );
                            break;
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
                        if let Some(name) = &f.name
                            && name.to_lowercase().as_str().contains(field)
                        {
                            val_display_or_store(
                                clipboard,
                                f.value.as_deref().unwrap_or(""),
                            );
                            break;
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
                        if let Some(name) = &f.name
                            && name.to_lowercase().as_str().contains(field)
                        {
                            val_display_or_store(
                                clipboard,
                                f.value.as_deref().unwrap_or(""),
                            );
                            break;
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
                        if let Some(name) = &f.name
                            && name.to_lowercase().as_str().contains(field)
                        {
                            val_display_or_store(
                                clipboard,
                                f.value.as_deref().unwrap_or(""),
                            );
                            break;
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
                        if let Some(name) = &f.name
                            && name.to_lowercase().as_str().contains(field)
                        {
                            val_display_or_store(
                                clipboard,
                                f.value.as_deref().unwrap_or(""),
                            );
                            break;
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
            if let Ok(self_url) = url::Url::parse(url)
                && let Some(self_host_port) = host_port(&self_url)
                && self_url.scheme() == given_url.scheme()
                && (self_host_port == given_host_port
                    || given_host_port
                        .ends_with(&format!(".{self_host_port}")))
            {
                return true;
            }
            url == given_host_port
                || given_host_port.ends_with(&format!(".{url}"))
        }
        rbw::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url)
                && let Some(self_host_port) = host_port(&self_url)
                && self_url.scheme() == given_url.scheme()
                && self_host_port == given_host_port
            {
                return true;
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

#[derive(Copy, Clone)]
pub struct AccountAddOpts<'a> {
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub server: Option<&'a str>,
    pub identity_url: Option<&'a str>,
    pub ui_url: Option<&'a str>,
    pub notifications_url: Option<&'a str>,
    pub sso_id: Option<&'a str>,
    pub client_cert_path: Option<&'a std::path::Path>,
    pub no_switch: bool,
    pub login: bool,
    pub no_login: bool,
    pub passkey: bool,
}

struct AccountContext {
    name: Option<String>,
    config: rbw::config::Config,
}

impl AccountContext {
    fn load(account: Option<&str>) -> anyhow::Result<Self> {
        let (name, config) = rbw::config::Config::resolve_account(account)
            .map_err(|e| {
                if matches!(
                    e,
                    rbw::error::Error::LoadConfig { .. }
                        | rbw::error::Error::ConfigMissingEmail
                        | rbw::error::Error::NoAccountsConfigured
                ) {
                    log::error!("{MISSING_CONFIG_HELP}");
                }
                anyhow::Error::new(e)
            })?;
        if config.email.is_none() {
            log::error!("{MISSING_CONFIG_HELP}");
            return Err(anyhow::Error::new(
                rbw::error::Error::ConfigMissingEmail,
            ));
        }
        Ok(Self { name, config })
    }

    fn account_ref(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum AccountStatus {
    Unlocked,
    Locked,
    LoggedOut,
}

impl AccountStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Locked => "locked",
            Self::LoggedOut => "logged out",
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct AccountListRow {
    name: String,
    email: Option<String>,
    server: String,
    base_url: Option<String>,
    active: bool,
    status: AccountStatus,
}

fn unlocked_account_set() -> std::collections::HashSet<rbw::config::AccountKey>
{
    crate::actions::account_states()
        .unwrap_or_default()
        .into_iter()
        .collect()
}

fn account_status(
    config: &rbw::config::Config,
    unlocked: &std::collections::HashSet<rbw::config::AccountKey>,
) -> AccountStatus {
    let Some(key) = config.account_key() else {
        return AccountStatus::LoggedOut;
    };
    if unlocked.contains(&key) {
        return AccountStatus::Unlocked;
    }
    match rbw::db::Db::load(&key.server, &key.email) {
        Ok(db) if !db.needs_login() => AccountStatus::Locked,
        _ => AccountStatus::LoggedOut,
    }
}

fn build_account_select_items(
    entries: &[rbw::config::AccountEntry],
    unlocked: &std::collections::HashSet<rbw::config::AccountKey>,
) -> Vec<crate::prompt::SelectItem> {
    let name_w = entries.iter().map(|e| e.name.len()).max().unwrap_or(0);
    let email_w = entries
        .iter()
        .map(|e| e.config.email.as_deref().unwrap_or("<no email>").len())
        .max()
        .unwrap_or(0);
    let server_w = entries
        .iter()
        .map(|e| e.config.server_display_name().len())
        .max()
        .unwrap_or(0);

    entries
        .iter()
        .map(|entry| {
            let marker = if entry.active { '*' } else { ' ' };
            let email = entry.config.email.as_deref().unwrap_or("<no email>");
            let server = entry.config.server_display_name();
            let status = account_status(&entry.config, unlocked);
            let badge = if entry.active {
                format!("active, {}", status.label())
            } else {
                status.label().to_string()
            };
            crate::prompt::SelectItem {
                label: format!(
                    "{marker} {:<name_w$}  {:<email_w$}  {:<server_w$}  [{badge}]",
                    entry.name, email, server
                ),
                highlight: entry.active || status == AccountStatus::Unlocked,
            }
        })
        .collect()
}

pub fn account_add(opts: AccountAddOpts<'_>) -> anyhow::Result<()> {
    let mut cf = rbw::config::ConfigFile::load()
        .unwrap_or_else(|_| rbw::config::ConfigFile::new());

    let interactive = opts.email.is_none();
    if interactive && !crate::prompt::is_interactive() {
        anyhow::bail!(
            "--email is required when adding an account non-interactively"
        );
    }

    let base_url = if let Some(server) = opts.server {
        rbw::config::normalize_server_input(server)
    } else if interactive {
        let server_choices = [
            crate::prompt::SelectItem {
                label: "bitwarden.com (Official US cloud)".to_string(),
                highlight: false,
            },
            crate::prompt::SelectItem {
                label: "bitwarden.eu (Official EU cloud)".to_string(),
                highlight: false,
            },
            crate::prompt::SelectItem {
                label: "Self-hosted / custom server".to_string(),
                highlight: false,
            },
        ];
        let Some(choice) =
            crate::prompt::select("Select vault server", &server_choices, 0)?
        else {
            eprintln!("Cancelled.");
            return Ok(());
        };
        match choice {
            0 => None,
            1 => Some("https://api.bitwarden.eu".to_string()),
            _ => {
                let Some(custom) = crate::prompt::input(
                    "Server URL (e.g. https://vault.example.com)",
                    None,
                )?
                else {
                    eprintln!("Cancelled.");
                    return Ok(());
                };
                if custom.trim().is_empty() {
                    anyhow::bail!("server URL cannot be empty");
                }
                rbw::config::normalize_server_input(&custom)
            }
        }
    } else {
        None
    };

    let email = if let Some(email) = opts.email {
        let trimmed = email.trim();
        if trimmed.is_empty() {
            anyhow::bail!("email address cannot be empty");
        }
        trimmed.to_string()
    } else {
        let Some(input_email) = crate::prompt::input("Email address", None)?
        else {
            eprintln!("Cancelled.");
            return Ok(());
        };
        let trimmed = input_email.trim();
        if trimmed.is_empty() {
            anyhow::bail!("email address cannot be empty");
        }
        trimmed.to_string()
    };

    let name = if let Some(name) = opts.name {
        Some(name.to_string())
    } else if interactive {
        let mut preview = cf.clone();
        preview.migrate_legacy_if_needed();
        let suggested =
            preview.suggest_account_name(&email, base_url.as_deref());
        let Some(chosen) =
            crate::prompt::input("Account name", Some(&suggested))?
        else {
            eprintln!("Cancelled.");
            return Ok(());
        };
        Some(chosen)
    } else {
        None
    };

    let should_login = if opts.login || opts.passkey {
        true
    } else if opts.no_login {
        false
    } else if interactive {
        crate::prompt::confirm("Log in now?", true)?
    } else {
        false
    };

    let account_cfg = rbw::config::AccountConfig {
        email: Some(email.clone()),
        sso_id: opts.sso_id.map(str::to_string),
        base_url: base_url.clone(),
        identity_url: opts.identity_url.map(str::to_string),
        ui_url: opts.ui_url.map(str::to_string),
        notifications_url: opts.notifications_url.map(str::to_string),
        client_cert_path: opts
            .client_cert_path
            .map(std::path::Path::to_path_buf),
        ..rbw::config::AccountConfig::default()
    };

    let final_name =
        cf.add_account(name.as_deref(), account_cfg, !opts.no_switch)?;
    cf.save()?;

    let server_display =
        rbw::config::server_display_name_from_base_url(base_url.as_deref());
    let active_suffix = if cf.effective_active_account_name().as_deref()
        == Some(&final_name)
    {
        " (active)"
    } else {
        ""
    };
    println!(
        "Added account '{final_name}' ({email} @ {server_display}){active_suffix}"
    );

    if should_login {
        login(Some(&final_name), opts.passkey, false)?;
    }

    Ok(())
}

pub fn account_switch(
    selector: Option<&str>,
    email: Option<&str>,
    server: Option<&str>,
) -> anyhow::Result<()> {
    let mut cf = rbw::config::ConfigFile::load().map_err(|e| {
        if matches!(e, rbw::error::Error::LoadConfig { .. }) {
            anyhow::anyhow!(
                "no accounts configured; run `rbw account add` first"
            )
        } else {
            anyhow::Error::new(e)
        }
    })?;

    let entries = cf.entries();
    if entries.is_empty() {
        anyhow::bail!("no accounts configured; run `rbw account add` first");
    }

    let unlocked = unlocked_account_set();
    let chosen = if selector.is_none() && email.is_none() && server.is_none()
    {
        if !crate::prompt::is_interactive() {
            anyhow::bail!(
                "specify an account to switch to, or run interactively in a terminal"
            );
        }
        let items = build_account_select_items(&entries, &unlocked);
        let initial = entries.iter().position(|e| e.active).unwrap_or(0);
        let Some(idx) = crate::prompt::select(
            "Select an account to switch to",
            &items,
            initial,
        )?
        else {
            eprintln!("Cancelled.");
            return Ok(());
        };
        entries[idx].clone()
    } else {
        let matches = cf.find_by_filters(selector, email, server);
        match matches.as_slice() {
            [] => {
                let target =
                    selector.or(email).or(server).unwrap_or("<unspecified>");
                return Err(anyhow::Error::new(
                    rbw::error::Error::AccountNotFound {
                        account: target.to_string(),
                    },
                ));
            }
            [only] => only.clone(),
            many => {
                if crate::prompt::is_interactive() {
                    let items = build_account_select_items(many, &unlocked);
                    let initial =
                        many.iter().position(|e| e.active).unwrap_or(0);
                    let Some(idx) = crate::prompt::select(
                        "Multiple accounts matched; select one",
                        &items,
                        initial,
                    )?
                    else {
                        eprintln!("Cancelled.");
                        return Ok(());
                    };
                    many[idx].clone()
                } else {
                    let label = selector
                        .or(email)
                        .or(server)
                        .unwrap_or("<unspecified>");
                    return Err(anyhow::Error::new(
                        rbw::error::Error::AccountAmbiguous {
                            selector: label.to_string(),
                            matches: rbw::config::format_account_matches(
                                many,
                            ),
                        },
                    ));
                }
            }
        }
    };

    let changed = cf.switch_account(&chosen.name)?;
    cf.save()?;

    let email_str = chosen.config.email.as_deref().unwrap_or("<no email>");
    let server_str = chosen.config.server_display_name();
    let status = account_status(&chosen.config, &unlocked).label();
    if changed {
        println!(
            "Switched active account to '{}' ({email_str} @ {server_str}) [{status}]",
            chosen.name
        );
    } else {
        println!(
            "Already using account '{}' ({email_str} @ {server_str}) [{status}]",
            chosen.name
        );
    }

    Ok(())
}

pub fn account_list(raw: bool) -> anyhow::Result<()> {
    let cf = match rbw::config::ConfigFile::load() {
        Ok(cf) => cf,
        Err(rbw::error::Error::LoadConfig { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            rbw::config::ConfigFile::new()
        }
        Err(e) => return Err(e.into()),
    };

    let entries = cf.entries();
    let unlocked = unlocked_account_set();

    if raw {
        let rows: Vec<AccountListRow> = entries
            .iter()
            .map(|entry| AccountListRow {
                name: entry.name.clone(),
                email: entry.config.email.clone(),
                server: entry.config.server_display_name(),
                base_url: entry.config.base_url.clone(),
                active: entry.active,
                status: account_status(&entry.config, &unlocked),
            })
            .collect();
        serde_json::to_writer_pretty(std::io::stdout(), &rows)
            .context("failed to write account list to stdout")?;
        println!();
        return Ok(());
    }

    if entries.is_empty() {
        println!(
            "No accounts configured. Run 'rbw account add' or 'rbw config set email <email>'."
        );
        return Ok(());
    }

    let name_w = entries.iter().map(|e| e.name.len()).max().unwrap_or(0);
    let email_w = entries
        .iter()
        .map(|e| e.config.email.as_deref().unwrap_or("<no email>").len())
        .max()
        .unwrap_or(0);
    let server_w = entries
        .iter()
        .map(|e| e.config.server_display_name().len())
        .max()
        .unwrap_or(0);

    for entry in &entries {
        let marker = if entry.active { '*' } else { ' ' };
        let email = entry.config.email.as_deref().unwrap_or("<no email>");
        let server = entry.config.server_display_name();
        let status = account_status(&entry.config, &unlocked);
        let state = if entry.active {
            format!("active, {}", status.label())
        } else {
            status.label().to_string()
        };
        println!(
            "{marker} {:<name_w$}  {:<email_w$}  {:<server_w$}  {state}",
            entry.name, email, server
        );
    }

    Ok(())
}

pub fn account_current(account: Option<&str>) -> anyhow::Result<()> {
    let cf = rbw::config::ConfigFile::load()?;
    let (resolved_name, _) = cf.resolve_config(account)?;
    let name = resolved_name
        .or_else(|| cf.effective_active_account_name())
        .ok_or(rbw::error::Error::NoAccountsConfigured)?;
    println!("{name}");
    Ok(())
}

pub fn account_remove(
    selector: Option<&str>,
    keep_data: bool,
) -> anyhow::Result<()> {
    let mut cf = rbw::config::ConfigFile::load()?;
    let entries = cf.entries();
    if entries.is_empty() {
        anyhow::bail!("no accounts configured");
    }

    let unlocked = unlocked_account_set();
    let target = if let Some(sel) = selector {
        let matches = cf.resolve_matches(sel);
        match matches.as_slice() {
            [] => {
                return Err(anyhow::Error::new(
                    rbw::error::Error::AccountNotFound {
                        account: sel.to_string(),
                    },
                ));
            }
            [only] => only.clone(),
            many => {
                return Err(anyhow::Error::new(
                    rbw::error::Error::AccountAmbiguous {
                        selector: sel.to_string(),
                        matches: rbw::config::format_account_matches(many),
                    },
                ));
            }
        }
    } else {
        if !crate::prompt::is_interactive() {
            anyhow::bail!(
                "specify an account to remove, or run interactively in a terminal"
            );
        }
        let items = build_account_select_items(&entries, &unlocked);
        let initial = entries.iter().position(|e| e.active).unwrap_or(0);
        let Some(idx) = crate::prompt::select(
            "Select an account to remove",
            &items,
            initial,
        )?
        else {
            eprintln!("Cancelled.");
            return Ok(());
        };
        entries[idx].clone()
    };

    if !keep_data {
        delete_touchid_key(&target.config, Some(&target.name));
    }
    evict_account_if_running(&target.config);
    if !keep_data {
        delete_yubikey_keys(&target.config);
        let _ = remove_db(&target.config);
    }

    let (removed_config, next_active) = cf.remove_account(&target.name)?;
    cf.save()?;

    let email = removed_config.email.as_deref().unwrap_or("<no email>");
    let server = removed_config.server_display_name();
    println!("Removed account '{}' ({email} @ {server})", target.name);
    if target.active {
        if let Some(next) = next_active {
            println!("Active account is now '{next}'");
        } else {
            println!("No active account remaining.");
        }
    }

    Ok(())
}

pub fn account_rename(old: &str, new: &str) -> anyhow::Result<()> {
    let mut cf = rbw::config::ConfigFile::load()?;
    let matches = cf.resolve_matches(old);
    let resolved_old = match matches.as_slice() {
        [] => {
            return Err(anyhow::Error::new(
                rbw::error::Error::AccountNotFound {
                    account: old.to_string(),
                },
            ));
        }
        [only] => only.name.clone(),
        many => {
            return Err(anyhow::Error::new(
                rbw::error::Error::AccountAmbiguous {
                    selector: old.to_string(),
                    matches: rbw::config::format_account_matches(many),
                },
            ));
        }
    };

    cf.rename_account(&resolved_old, new)?;
    cf.save()?;
    println!("Renamed account '{resolved_old}' to '{new}'");

    Ok(())
}

pub fn config_show(
    account: Option<&str>,
    global: bool,
) -> anyhow::Result<()> {
    if global {
        let cf = rbw::config::ConfigFile::load()?;
        serde_json::to_writer_pretty(
            std::io::stdout(),
            &cf.global_defaults(),
        )
        .context("failed to write config to stdout")?;
        println!();
        return Ok(());
    }

    let config = rbw::config::Config::load_account(account)?;
    serde_json::to_writer_pretty(std::io::stdout(), &config)
        .context("failed to write config to stdout")?;
    println!();

    Ok(())
}

pub fn config_set(
    account: Option<&str>,
    global: bool,
    key: &str,
    value: &str,
) -> anyhow::Result<()> {
    let mut cf = rbw::config::ConfigFile::load()
        .unwrap_or_else(|_| rbw::config::ConfigFile::new());

    if global {
        match key {
            "email" | "sso_id" | "base_url" | "identity_url" | "ui_url"
            | "notifications_url" | "client_cert_path" => {
                anyhow::bail!(
                    "'{key}' is an account-specific setting and cannot be set with --global"
                );
            }
            "lock_timeout" => {
                let timeout = value
                    .parse()
                    .context("failed to parse value for lock_timeout")?;
                if timeout == 0 {
                    log::error!("lock_timeout must be greater than 0");
                } else {
                    cf.lock_timeout = timeout;
                }
            }
            "sync_interval" => {
                let interval = value
                    .parse()
                    .context("failed to parse value for sync_interval")?;
                cf.sync_interval = interval;
            }
            "pinentry" => cf.pinentry = value.to_string(),
            "touchid" => {
                #[cfg(target_os = "macos")]
                {
                    let enabled: bool = value
                        .parse()
                        .context("failed to parse value for touchid")?;
                    cf.touchid = enabled;
                    if !enabled {
                        for entry in cf.entries() {
                            let overrides_true = cf
                                .accounts
                                .get(&entry.name)
                                .is_some_and(|a| a.touchid == Some(true));
                            if !overrides_true {
                                delete_touchid_key(
                                    &entry.config,
                                    Some(&entry.name),
                                );
                            }
                        }
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = value;
                    return Err(anyhow::anyhow!(
                        "touchid is only supported on macOS"
                    ));
                }
            }
            "yubikey" => {
                let enabled: bool = value
                    .parse()
                    .context("failed to parse value for yubikey")?;
                cf.yubikey = enabled;
                if !enabled {
                    for entry in cf.entries() {
                        let overrides_true = cf
                            .accounts
                            .get(&entry.name)
                            .is_some_and(|a| a.yubikey == Some(true));
                        if !overrides_true {
                            delete_yubikey_keys(&entry.config);
                        }
                    }
                }
            }
            "yubikey_uv" => {
                let enabled: bool = value
                    .parse()
                    .context("failed to parse value for yubikey_uv")?;
                cf.yubikey_uv = enabled;
            }
            "passkey_login" => {
                let enabled: bool = value
                    .parse()
                    .context("failed to parse value for passkey_login")?;
                cf.passkey_login = enabled;
            }
            _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
        }
        cf.save()?;
        return Ok(());
    }

    if cf.is_multi_account() {
        let (target_name, old_config) = cf.resolve_config(account)?;
        let target_name =
            target_name.ok_or(rbw::error::Error::NoAccountsConfigured)?;
        let mut identity_changed = false;

        let new_email_check = if key == "email" {
            Some(value.to_string())
        } else {
            old_config.email.clone()
        };
        let new_base_url_check = if key == "base_url" {
            Some(value.to_string())
        } else {
            old_config.base_url.clone()
        };
        if matches!(key, "email" | "base_url") {
            cf.check_duplicate_identity(
                Some(&target_name),
                new_base_url_check.as_deref(),
                new_email_check.as_deref(),
            )?;
        }

        let acct = cf.accounts.get_mut(&target_name).unwrap();
        match key {
            "email" => {
                acct.email = Some(value.to_string());
                identity_changed = true;
            }
            "sso_id" => {
                acct.sso_id = Some(value.to_string());
                identity_changed = true;
            }
            "base_url" => {
                acct.base_url = Some(value.to_string());
                identity_changed = true;
            }
            "identity_url" => {
                acct.identity_url = Some(value.to_string());
                identity_changed = true;
            }
            "ui_url" => {
                acct.ui_url = Some(value.to_string());
                identity_changed = true;
            }
            "notifications_url" => {
                acct.notifications_url = Some(value.to_string());
                identity_changed = true;
            }
            "client_cert_path" => {
                acct.client_cert_path =
                    Some(std::path::PathBuf::from(value.to_string()));
                identity_changed = true;
            }
            "lock_timeout" => {
                let timeout = value
                    .parse()
                    .context("failed to parse value for lock_timeout")?;
                if timeout == 0 {
                    log::error!("lock_timeout must be greater than 0");
                } else {
                    acct.lock_timeout = Some(timeout);
                }
            }
            "sync_interval" => {
                let interval = value
                    .parse()
                    .context("failed to parse value for sync_interval")?;
                acct.sync_interval = Some(interval);
            }
            "pinentry" => acct.pinentry = Some(value.to_string()),
            "touchid" => {
                #[cfg(target_os = "macos")]
                {
                    let enabled: bool = value
                        .parse()
                        .context("failed to parse value for touchid")?;
                    acct.touchid = Some(enabled);
                    if !enabled {
                        delete_touchid_key(&old_config, Some(&target_name));
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = value;
                    return Err(anyhow::anyhow!(
                        "touchid is only supported on macOS"
                    ));
                }
            }
            "yubikey" => {
                let enabled: bool = value
                    .parse()
                    .context("failed to parse value for yubikey")?;
                acct.yubikey = Some(enabled);
                if !enabled {
                    delete_yubikey_keys(&old_config);
                }
            }
            "yubikey_uv" => {
                let enabled: bool = value
                    .parse()
                    .context("failed to parse value for yubikey_uv")?;
                if old_config.yubikey_uv != enabled {
                    acct.yubikey_uv = Some(enabled);
                    if let Some(email) = &old_config.email
                        && rbw::yubikey::has_keys(
                            &old_config.server_name(),
                            email,
                        )
                    {
                        eprintln!(
                            "Note: existing enrolled security keys keep their original UV mode; run `rbw yubikey clear` and re-enroll to apply the new setting."
                        );
                    }
                }
            }
            "passkey_login" => {
                let enabled: bool = value
                    .parse()
                    .context("failed to parse value for passkey_login")?;
                acct.passkey_login = Some(enabled);
            }
            _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
        }

        cf.save()?;
        if identity_changed {
            evict_account_if_running(&old_config);
        }
        return Ok(());
    }

    // Legacy single-account mode
    if let Some(sel) = account {
        let _ = cf.resolve_config(Some(sel))?;
    }
    let (_, old_config) = cf.resolve_config(None)?;
    let mut identity_changed = false;
    match key {
        "email" => {
            cf.email = Some(value.to_string());
            identity_changed = true;
        }
        "sso_id" => {
            cf.sso_id = Some(value.to_string());
            identity_changed = true;
        }
        "base_url" => {
            cf.base_url = Some(value.to_string());
            identity_changed = true;
        }
        "identity_url" => {
            cf.identity_url = Some(value.to_string());
            identity_changed = true;
        }
        "ui_url" => {
            cf.ui_url = Some(value.to_string());
            identity_changed = true;
        }
        "notifications_url" => {
            cf.notifications_url = Some(value.to_string());
            identity_changed = true;
        }
        "client_cert_path" => {
            cf.client_cert_path =
                Some(std::path::PathBuf::from(value.to_string()));
            identity_changed = true;
        }
        "lock_timeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for lock_timeout")?;
            if timeout == 0 {
                log::error!("lock_timeout must be greater than 0");
            } else {
                cf.lock_timeout = timeout;
            }
        }
        "sync_interval" => {
            let interval = value
                .parse()
                .context("failed to parse value for sync_interval")?;
            cf.sync_interval = interval;
        }
        "pinentry" => cf.pinentry = value.to_string(),
        "touchid" => {
            #[cfg(target_os = "macos")]
            {
                let enabled: bool = value
                    .parse()
                    .context("failed to parse value for touchid")?;
                cf.touchid = enabled;
                if !enabled {
                    delete_touchid_key(&old_config, None);
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = value;
                return Err(anyhow::anyhow!(
                    "touchid is only supported on macOS"
                ));
            }
        }
        "yubikey" => {
            let enabled: bool =
                value.parse().context("failed to parse value for yubikey")?;
            cf.yubikey = enabled;
            if !enabled {
                delete_yubikey_keys(&old_config);
            }
        }
        "yubikey_uv" => {
            let enabled: bool = value
                .parse()
                .context("failed to parse value for yubikey_uv")?;
            if cf.yubikey_uv != enabled {
                cf.yubikey_uv = enabled;
                if let Some(email) = &old_config.email
                    && rbw::yubikey::has_keys(
                        &old_config.server_name(),
                        email,
                    )
                {
                    eprintln!(
                        "Note: existing enrolled security keys keep their original UV mode; run `rbw yubikey clear` and re-enroll to apply the new setting."
                    );
                }
            }
        }
        "passkey_login" => {
            let enabled: bool = value
                .parse()
                .context("failed to parse value for passkey_login")?;
            cf.passkey_login = enabled;
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    cf.save()?;

    if identity_changed {
        evict_account_if_running(&old_config);
    }

    Ok(())
}

pub fn config_unset(
    account: Option<&str>,
    global: bool,
    key: &str,
) -> anyhow::Result<()> {
    let mut cf = rbw::config::ConfigFile::load()
        .unwrap_or_else(|_| rbw::config::ConfigFile::new());

    if global {
        match key {
            "email" | "sso_id" | "base_url" | "identity_url" | "ui_url"
            | "notifications_url" | "client_cert_path" => {
                anyhow::bail!(
                    "'{key}' is an account-specific setting and cannot be unset with --global"
                );
            }
            "lock_timeout" => {
                cf.lock_timeout = rbw::config::default_lock_timeout();
            }
            "sync_interval" => {
                cf.sync_interval = rbw::config::default_sync_interval();
            }
            "pinentry" => cf.pinentry = rbw::config::default_pinentry(),
            "touchid" => {
                #[cfg(target_os = "macos")]
                {
                    cf.touchid = false;
                    for entry in cf.entries() {
                        let overrides_true = cf
                            .accounts
                            .get(&entry.name)
                            .is_some_and(|a| a.touchid == Some(true));
                        if !overrides_true {
                            delete_touchid_key(
                                &entry.config,
                                Some(&entry.name),
                            );
                        }
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    return Err(anyhow::anyhow!(
                        "touchid is only supported on macOS"
                    ));
                }
            }
            "yubikey" => {
                cf.yubikey = false;
                for entry in cf.entries() {
                    let overrides_true = cf
                        .accounts
                        .get(&entry.name)
                        .is_some_and(|a| a.yubikey == Some(true));
                    if !overrides_true {
                        delete_yubikey_keys(&entry.config);
                    }
                }
            }
            "yubikey_uv" => cf.yubikey_uv = false,
            "passkey_login" => cf.passkey_login = false,
            _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
        }
        cf.save()?;
        return Ok(());
    }

    if cf.is_multi_account() {
        let (target_name, old_config) = cf.resolve_config(account)?;
        let target_name =
            target_name.ok_or(rbw::error::Error::NoAccountsConfigured)?;
        let mut identity_changed = false;

        if key == "base_url" {
            cf.check_duplicate_identity(
                Some(&target_name),
                None,
                old_config.email.as_deref(),
            )?;
        }

        let global_touchid = cf.touchid;
        let global_yubikey = cf.yubikey;
        let acct = cf.accounts.get_mut(&target_name).unwrap();
        match key {
            "email" => {
                acct.email = None;
                identity_changed = true;
            }
            "sso_id" => {
                acct.sso_id = None;
                identity_changed = true;
            }
            "base_url" => {
                acct.base_url = None;
                identity_changed = true;
            }
            "identity_url" => {
                acct.identity_url = None;
                identity_changed = true;
            }
            "ui_url" => {
                acct.ui_url = None;
                identity_changed = true;
            }
            "notifications_url" => {
                acct.notifications_url = None;
                identity_changed = true;
            }
            "client_cert_path" => {
                acct.client_cert_path = None;
                identity_changed = true;
            }
            "lock_timeout" => acct.lock_timeout = None,
            "sync_interval" => acct.sync_interval = None,
            "pinentry" => acct.pinentry = None,
            "touchid" => {
                #[cfg(target_os = "macos")]
                {
                    acct.touchid = None;
                    if !global_touchid {
                        delete_touchid_key(&old_config, Some(&target_name));
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = global_touchid;
                    return Err(anyhow::anyhow!(
                        "touchid is only supported on macOS"
                    ));
                }
            }
            "yubikey" => {
                acct.yubikey = None;
                if !global_yubikey {
                    delete_yubikey_keys(&old_config);
                }
            }
            "yubikey_uv" => acct.yubikey_uv = None,
            "passkey_login" => acct.passkey_login = None,
            _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
        }

        cf.save()?;
        if identity_changed {
            evict_account_if_running(&old_config);
        }
        return Ok(());
    }

    // Legacy single-account mode
    if let Some(sel) = account {
        let _ = cf.resolve_config(Some(sel))?;
    }
    let (_, old_config) = cf.resolve_config(None)?;
    let mut identity_changed = false;
    match key {
        "email" => {
            cf.email = None;
            identity_changed = true;
        }
        "sso_id" => {
            cf.sso_id = None;
            identity_changed = true;
        }
        "base_url" => {
            cf.base_url = None;
            identity_changed = true;
        }
        "identity_url" => {
            cf.identity_url = None;
            identity_changed = true;
        }
        "ui_url" => {
            cf.ui_url = None;
            identity_changed = true;
        }
        "notifications_url" => {
            cf.notifications_url = None;
            identity_changed = true;
        }
        "client_cert_path" => {
            cf.client_cert_path = None;
            identity_changed = true;
        }
        "lock_timeout" => {
            cf.lock_timeout = rbw::config::default_lock_timeout();
        }
        "sync_interval" => {
            cf.sync_interval = rbw::config::default_sync_interval();
        }
        "pinentry" => cf.pinentry = rbw::config::default_pinentry(),
        "touchid" => {
            #[cfg(target_os = "macos")]
            {
                cf.touchid = false;
                delete_touchid_key(&old_config, None);
            }
            #[cfg(not(target_os = "macos"))]
            {
                return Err(anyhow::anyhow!(
                    "touchid is only supported on macOS"
                ));
            }
        }
        "yubikey" => {
            cf.yubikey = false;
            delete_yubikey_keys(&old_config);
        }
        "yubikey_uv" => {
            cf.yubikey_uv = false;
        }
        "passkey_login" => {
            cf.passkey_login = false;
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    cf.save()?;

    if identity_changed {
        evict_account_if_running(&old_config);
    }

    Ok(())
}

fn clipboard_store(val: &str) -> anyhow::Result<()> {
    ensure_agent_running()?;
    crate::actions::clipboard_store(val)?;

    Ok(())
}

pub fn register(account: Option<&str>) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    ensure_agent_running()?;
    crate::actions::register(ctx.account_ref())?;

    Ok(())
}

pub fn login(
    account: Option<&str>,
    passkey: bool,
    password: bool,
) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    ensure_agent_running()?;
    if passkey {
        crate::actions::login_passkey(ctx.account_ref())?;
    } else if password {
        crate::actions::login(ctx.account_ref())?;
    } else {
        login_default(&ctx)?;
    }

    Ok(())
}

fn login_default(ctx: &AccountContext) -> anyhow::Result<()> {
    if ctx.config.passkey_login {
        crate::actions::login_passkey(ctx.account_ref())?;
    } else {
        crate::actions::login(ctx.account_ref())?;
    }
    Ok(())
}

pub fn yubikey_enroll(
    account: Option<&str>,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    ensure_agent_running()?;
    login_default(&ctx)?;
    crate::actions::yubikey_enroll(ctx.account_ref(), label)?;
    if !ctx.config.yubikey {
        eprintln!(
            "Hint: enable local YubiKey unlock with `rbw config set yubikey true`"
        );
    }

    Ok(())
}

pub fn yubikey_list(account: Option<&str>) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    let Some(email) = &ctx.config.email else {
        anyhow::bail!("email address not set");
    };
    let Some(store) =
        rbw::yubikey::load_store(&ctx.config.server_name(), email)?
    else {
        println!("No security keys enrolled.");
        return Ok(());
    };
    if store.keys.is_empty() {
        println!("No security keys enrolled.");
        return Ok(());
    }
    for key in &store.keys {
        let id_prefix: String = key.credential_id.chars().take(12).collect();
        println!(
            "{}\t{}...\tuv={}\taaguid={}",
            key.label, id_prefix, key.uv, key.aaguid
        );
    }
    Ok(())
}

pub fn yubikey_remove(
    account: Option<&str>,
    selector: &str,
) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    let Some(email) = &ctx.config.email else {
        anyhow::bail!("email address not set");
    };
    if !rbw::yubikey::remove_key(&ctx.config.server_name(), email, selector)?
    {
        anyhow::bail!("no enrolled security key matching '{selector}'");
    }
    Ok(())
}

pub fn yubikey_clear(account: Option<&str>) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    let Some(email) = &ctx.config.email else {
        anyhow::bail!("email address not set");
    };
    rbw::yubikey::delete_keys(&ctx.config.server_name(), email)?;
    Ok(())
}

pub fn unlock(account: Option<&str>) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)
}

fn unlock_ctx(ctx: &AccountContext) -> anyhow::Result<()> {
    ensure_agent_running()?;
    login_default(ctx)?;
    crate::actions::unlock(ctx.account_ref())?;

    Ok(())
}

pub fn unlocked(account: Option<&str>) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    // not ensure_agent, because we don't want `rbw unlocked` to start the
    // agent if it's not running
    let _ = check_agent_version();
    crate::actions::unlocked(ctx.account_ref())?;

    Ok(())
}

pub fn sync(account: Option<&str>) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    ensure_agent_running()?;
    login_default(&ctx)?;
    crate::actions::sync(ctx.account_ref())?;

    Ok(())
}

pub fn list(
    account: Option<&str>,
    fields: &[String],
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

    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)?;

    let db = load_db(&ctx.config)?;
    let mut entries: Vec<DecryptedListCipher> = db
        .entries
        .iter()
        .map(|entry| decrypt_list_cipher(ctx.account_ref(), entry, &fields))
        .collect::<anyhow::Result<_>>()?;
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn get(
    account: Option<&str>,
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
    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)?;

    let db = load_db(&ctx.config)?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (_, decrypted) =
        find_entry(ctx.account_ref(), &db, needle, user, folder, ignore_case)
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
    account: Option<&str>,
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

    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)?;

    let db = load_db(&ctx.config)?;

    let mut entries: Vec<DecryptedListCipher> = db
        .entries
        .iter()
        .map(|entry| decrypt_search_cipher(ctx.account_ref(), entry))
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
    account: Option<&str>,
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)?;

    let db = load_db(&ctx.config)?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (_, decrypted) =
        find_entry(ctx.account_ref(), &db, needle, user, folder, ignore_case)
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
    account: Option<&str>,
    name: &str,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)?;

    let mut db = load_db(&ctx.config)?;
    // unwrap is safe here because the call to unlock above is guaranteed to
    // populate these or error
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let name = crate::actions::encrypt(ctx.account_ref(), name, None)?;

    let username = username
        .map(|username| {
            crate::actions::encrypt(ctx.account_ref(), username, None)
        })
        .transpose()?;

    let contents = rbw::edit::edit("", HELP_PW)?;

    let (password, notes) = parse_editor(&contents);
    let password = password
        .map(|password| {
            crate::actions::encrypt(ctx.account_ref(), &password, None)
        })
        .transpose()?;
    let notes = notes
        .map(|notes| crate::actions::encrypt(ctx.account_ref(), &notes, None))
        .transpose()?;
    let uris: Vec<_> = uris
        .iter()
        .map(|uri| {
            Ok(rbw::db::Uri {
                uri: crate::actions::encrypt(
                    ctx.account_ref(),
                    &uri.0,
                    None,
                )?,
                match_type: uri.1,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let mut folder_id = None;
    if let Some(folder_name) = folder {
        let (new_access_token, folders) = rbw::actions::list_folders(
            &ctx.config,
            &access_token,
            refresh_token,
        )?;
        if let Some(new_access_token) = new_access_token {
            access_token.clone_from(&new_access_token);
            db.access_token = Some(new_access_token);
            save_db(&ctx.config, &db)?;
        }

        let folders: Vec<(String, String)> = folders
            .iter()
            .cloned()
            .map(|(id, name)| {
                Ok((
                    id,
                    crate::actions::decrypt(
                        ctx.account_ref(),
                        &name,
                        None,
                        None,
                    )?,
                ))
            })
            .collect::<anyhow::Result<_>>()?;

        for (id, name) in folders {
            if name == folder_name {
                folder_id = Some(id);
            }
        }
        if folder_id.is_none() {
            let (new_access_token, id) = rbw::actions::create_folder(
                &ctx.config,
                &access_token,
                refresh_token,
                &crate::actions::encrypt(
                    ctx.account_ref(),
                    folder_name,
                    None,
                )?,
            )?;
            if let Some(new_access_token) = new_access_token {
                access_token.clone_from(&new_access_token);
                db.access_token = Some(new_access_token);
                save_db(&ctx.config, &db)?;
            }
            folder_id = Some(id);
        }
    }

    if let (Some(access_token), ()) = rbw::actions::add(
        &ctx.config,
        &access_token,
        refresh_token,
        &name,
        &rbw::db::EntryData::Login {
            username,
            password,
            uris,
            totp: None,
        },
        notes.as_deref(),
        folder_id.as_deref(),
    )? {
        db.access_token = Some(access_token);
        save_db(&ctx.config, &db)?;
    }

    crate::actions::sync(ctx.account_ref())?;

    Ok(())
}

pub fn generate(
    account: Option<&str>,
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
        let ctx = AccountContext::load(account)?;
        unlock_ctx(&ctx)?;

        let mut db = load_db(&ctx.config)?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap();

        let name = crate::actions::encrypt(ctx.account_ref(), name, None)?;
        let username = username
            .map(|username| {
                crate::actions::encrypt(ctx.account_ref(), username, None)
            })
            .transpose()?;
        let password =
            crate::actions::encrypt(ctx.account_ref(), &password, None)?;
        let uris: Vec<_> = uris
            .iter()
            .map(|uri| {
                Ok(rbw::db::Uri {
                    uri: crate::actions::encrypt(
                        ctx.account_ref(),
                        &uri.0,
                        None,
                    )?,
                    match_type: uri.1,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (new_access_token, folders) = rbw::actions::list_folders(
                &ctx.config,
                &access_token,
                refresh_token,
            )?;
            if let Some(new_access_token) = new_access_token {
                access_token.clone_from(&new_access_token);
                db.access_token = Some(new_access_token);
                save_db(&ctx.config, &db)?;
            }

            let folders: Vec<(String, String)> = folders
                .iter()
                .cloned()
                .map(|(id, name)| {
                    Ok((
                        id,
                        crate::actions::decrypt(
                            ctx.account_ref(),
                            &name,
                            None,
                            None,
                        )?,
                    ))
                })
                .collect::<anyhow::Result<_>>()?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (new_access_token, id) = rbw::actions::create_folder(
                    &ctx.config,
                    &access_token,
                    refresh_token,
                    &crate::actions::encrypt(
                        ctx.account_ref(),
                        folder_name,
                        None,
                    )?,
                )?;
                if let Some(new_access_token) = new_access_token {
                    access_token.clone_from(&new_access_token);
                    db.access_token = Some(new_access_token);
                    save_db(&ctx.config, &db)?;
                }
                folder_id = Some(id);
            }
        }

        if let (Some(access_token), ()) = rbw::actions::add(
            &ctx.config,
            &access_token,
            refresh_token,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
                totp: None,
            },
            None,
            folder_id.as_deref(),
        )? {
            db.access_token = Some(access_token);
            save_db(&ctx.config, &db)?;
        }

        crate::actions::sync(ctx.account_ref())?;
    }

    Ok(())
}

pub fn edit(
    account: Option<&str>,
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)?;

    let mut db = load_db(&ctx.config)?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (entry, decrypted) = find_entry(
        ctx.account_ref(),
        &db,
        name,
        username,
        folder,
        ignore_case,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let (data, fields, notes, history) = match &decrypted.data {
        DecryptedData::Login { password, .. } => {
            let mut contents =
                format!("{}\n", password.as_deref().unwrap_or(""));
            if let Some(notes) = decrypted.notes {
                write!(contents, "\n{notes}\n").unwrap();
            }

            let contents = rbw::edit::edit(&contents, HELP_PW)?;

            let (password, notes) = parse_editor(&contents);
            let password = password
                .map(|password| {
                    crate::actions::encrypt(
                        ctx.account_ref(),
                        &password,
                        entry.org_id.as_deref(),
                    )
                })
                .transpose()?;
            let notes = notes
                .map(|notes| {
                    crate::actions::encrypt(
                        ctx.account_ref(),
                        &notes,
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
            (data, entry.fields, notes, history)
        }
        DecryptedData::SecureNote => {
            let data = rbw::db::EntryData::SecureNote {};

            let editor_content = decrypted.notes.map_or_else(
                || "\n".to_string(),
                |notes| format!("{notes}\n"),
            );
            let contents = rbw::edit::edit(&editor_content, HELP_NOTES)?;

            // prepend blank line to be parsed as pw by `parse_editor`
            let (_, notes) = parse_editor(&format!("\n{contents}\n"));

            let notes = notes
                .map(|notes| {
                    crate::actions::encrypt(
                        ctx.account_ref(),
                        &notes,
                        entry.org_id.as_deref(),
                    )
                })
                .transpose()?;

            (data, entry.fields, notes, entry.history)
        }
        _ => {
            return Err(anyhow::anyhow!(
                "modifications are only supported for login and note entries"
            ));
        }
    };

    if let (Some(access_token), ()) = rbw::actions::edit(
        &ctx.config,
        access_token,
        refresh_token,
        &entry.id,
        entry.org_id.as_deref(),
        &entry.name,
        &data,
        &fields,
        notes.as_deref(),
        entry.folder_id.as_deref(),
        &history,
    )? {
        db.access_token = Some(access_token);
        save_db(&ctx.config, &db)?;
    }

    crate::actions::sync(ctx.account_ref())?;
    Ok(())
}

pub fn remove(
    account: Option<&str>,
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)?;

    let mut db = load_db(&ctx.config)?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (entry, _) = find_entry(
        ctx.account_ref(),
        &db,
        name,
        username,
        folder,
        ignore_case,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let (Some(access_token), ()) = rbw::actions::remove(
        &ctx.config,
        access_token,
        refresh_token,
        &entry.id,
    )? {
        db.access_token = Some(access_token);
        save_db(&ctx.config, &db)?;
    }

    crate::actions::sync(ctx.account_ref())?;

    Ok(())
}

pub fn history(
    account: Option<&str>,
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    let ctx = AccountContext::load(account)?;
    unlock_ctx(&ctx)?;

    let db = load_db(&ctx.config)?;

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (_, decrypted) = find_entry(
        ctx.account_ref(),
        &db,
        name,
        username,
        folder,
        ignore_case,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    for history in decrypted.history {
        println!("{}: {}", history.last_used_date, history.password);
    }

    Ok(())
}

pub fn lock(account: Option<&str>, all: bool) -> anyhow::Result<()> {
    if all {
        let _ = check_agent_version();
        crate::actions::lock_all()?;
        return Ok(());
    }

    let ctx = AccountContext::load(account)?;
    ensure_agent_running()?;
    crate::actions::lock(ctx.account_ref())?;

    Ok(())
}

pub fn purge(account: Option<&str>) -> anyhow::Result<()> {
    let resolved = rbw::config::Config::resolve_account(account);
    let (name, config) = match resolved {
        Ok((name, config)) => (name, config),
        Err(e) => {
            if account.is_some() {
                return Err(e.into());
            }
            stop_agent()?;
            return Err(e.into());
        }
    };

    delete_touchid_key(&config, name.as_deref());
    evict_account_if_running(&config);
    delete_yubikey_keys(&config);
    remove_db(&config)?;

    Ok(())
}

fn delete_touchid_key(config: &rbw::config::Config, account: Option<&str>) {
    let Some(email) = &config.email else {
        return;
    };
    let profile = rbw::dirs::profile();
    let server = config.server_name();
    if !rbw::touchid::has_key(&profile, &server, email) {
        return;
    }

    // Touch ID keychain items are created by `rbw-agent`, so ask the agent
    // (the owning binary) to delete the item first to avoid macOS Keychain
    // `errSecInvalidOwnerEdit` (-25244) ACL errors.
    if ensure_agent_running().is_ok()
        && crate::actions::delete_touchid_key(
            account,
            Some(&server),
            Some(email),
        )
        .is_ok()
    {
        return;
    }

    if let Err(e) = rbw::touchid::delete_key(&profile, &server, email) {
        log::warn!("failed to delete touch id key from keychain: {e}");
    }
}

fn delete_yubikey_keys(config: &rbw::config::Config) {
    if let Some(email) = &config.email
        && let Err(e) =
            rbw::yubikey::delete_keys(&config.server_name(), email)
    {
        log::warn!("failed to delete local YubiKey keys: {e}");
    }
}

fn evict_account_if_running(config: &rbw::config::Config) {
    let Some(email) = &config.email else {
        return;
    };
    let server = config.server_name();
    if let Err(e) = crate::actions::evict_account(&server, email) {
        log::warn!("failed to evict account from agent: {e}; stopping agent");
        let _ = stop_agent();
    }
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

fn ensure_agent_running() -> anyhow::Result<()> {
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
    if !status.success()
        && let Some(code) = status.code()
        && code != 23
    {
        return Err(anyhow::anyhow!("failed to run rbw-agent: {status}"));
    }

    Ok(())
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
    account: Option<&str>,
    db: &rbw::db::Db,
    mut needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    if let Needle::Uuid(uuid, s) = needle {
        for cipher in &db.entries {
            if uuid::Uuid::parse_str(&cipher.id) == Ok(uuid) {
                return Ok((
                    cipher.clone(),
                    decrypt_cipher(account, cipher)?,
                ));
            }
        }
        needle = Needle::Name(s);
    }

    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .map(|entry| {
            decrypt_search_cipher(account, entry)
                .map(|decrypted| (entry.clone(), decrypted))
        })
        .collect::<anyhow::Result<_>>()?;
    let (entry, _) =
        find_entry_raw(&ciphers, &needle, username, folder, ignore_case)?;
    let decrypted_entry = decrypt_cipher(account, &entry)?;
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
    account: Option<&str>,
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| {
            crate::actions::decrypt(account, field, entry_key, org_id)
        })
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
    account: Option<&str>,
    entry: &rbw::db::Entry,
    fields: &[ListField],
) -> anyhow::Result<DecryptedListCipher> {
    let id = entry.id.clone();
    let name = if fields.contains(&ListField::Name) {
        Some(crate::actions::decrypt(
            account,
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
                account,
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
            .map(|folder| {
                crate::actions::decrypt(account, folder, None, None)
            })
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
                            account,
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
    account: Option<&str>,
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedSearchCipher> {
    let id = entry.id.clone();
    let name = crate::actions::decrypt(
        account,
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let user = match &entry.data {
        rbw::db::EntryData::Login { username, .. } => decrypt_field(
            account,
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
        .map(|folder| crate::actions::decrypt(account, folder, None, None))
        .transpose()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                account,
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
                    account,
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
                account,
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
    account: Option<&str>,
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(account, folder, None, None))
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
                            account,
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
                        crate::actions::decrypt(
                            account,
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
            crate::actions::decrypt(
                account,
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
                    account,
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
                account,
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            password: decrypt_field(
                account,
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            totp: decrypt_field(
                account,
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        account,
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
                account,
                Field::Cardholder,
                cardholder_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            number: decrypt_field(
                account,
                Field::CardNumber,
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            brand: decrypt_field(
                account,
                Field::Brand,
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_month: decrypt_field(
                account,
                Field::ExpMonth,
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_year: decrypt_field(
                account,
                Field::ExpYear,
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            code: decrypt_field(
                account,
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
                account,
                Field::Title,
                title.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            first_name: decrypt_field(
                account,
                Field::FirstName,
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            middle_name: decrypt_field(
                account,
                Field::MiddleName,
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            last_name: decrypt_field(
                account,
                Field::LastName,
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address1: decrypt_field(
                account,
                Field::Address1,
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address2: decrypt_field(
                account,
                Field::Address2,
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address3: decrypt_field(
                account,
                Field::Address3,
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            city: decrypt_field(
                account,
                Field::City,
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            state: decrypt_field(
                account,
                Field::State,
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            postal_code: decrypt_field(
                account,
                Field::PostalCode,
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            country: decrypt_field(
                account,
                Field::Country,
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            phone: decrypt_field(
                account,
                Field::Phone,
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            email: decrypt_field(
                account,
                Field::Email,
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            ssn: decrypt_field(
                account,
                Field::Ssn,
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            license_number: decrypt_field(
                account,
                Field::License,
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            passport_number: decrypt_field(
                account,
                Field::Passport,
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            username: decrypt_field(
                account,
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
                account,
                Field::PublicKey,
                public_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            fingerprint: decrypt_field(
                account,
                Field::Fingerprint,
                fingerprint.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            private_key: decrypt_field(
                account,
                Field::PrivateKey,
                private_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: crate::actions::decrypt(
            account,
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

fn load_db(config: &rbw::config::Config) -> anyhow::Result<rbw::db::Db> {
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::load(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn save_db(
    config: &rbw::config::Config,
    db: &rbw::db::Db,
) -> anyhow::Result<()> {
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            db.save(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn remove_db(config: &rbw::config::Config) -> anyhow::Result<()> {
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
    digits: u8,
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
                        .parse::<u8>()
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
        "SHA1" | "SHA256" | "SHA512" => Ok(totp_rs::Builder::new()
            .with_algorithm(generate_totp_algorithm_type(alg)?)
            .with_digits(totp_params.digits)
            .with_skew(1)
            .with_step_duration(totp_params.period)
            .with_secret(totp_params.secret)
            .build_noncompliant()
            .generate_current()
            .to_string()),
        "STEAM" => Ok(totp_rs::Builder::new_steam()
            .with_secret(totp_params.secret)
            .build_noncompliant()
            .generate_current()
            .to_string()),
        _ => Err(anyhow::anyhow!("{alg} is not a valid totp algorithm")),
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

    #[test]
    fn test_generate_totp() {
        let sha1_code = generate_totp("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(sha1_code.len(), 6);
        assert!(sha1_code.chars().all(|c| c.is_ascii_digit()));

        let sha256_code = generate_totp(
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=30",
        )
        .unwrap();
        assert_eq!(sha256_code.len(), 8);
        assert!(sha256_code.chars().all(|c| c.is_ascii_digit()));

        let steam_code = generate_totp("steam://JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(steam_code.len(), 5);
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
