use std::io::Write as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
mod prompt;
mod sock;

#[derive(Debug, clap::Args)]
struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
    needle: commands::Needle,
    #[arg(help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
}

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
struct Cli {
    #[arg(
        short = 'a',
        long = "account",
        global = true,
        help = "Account name, email, or server to use for this command [env: RBW_ACCOUNT]"
    )]
    account: Option<String>,

    #[command(subcommand)]
    command: Opt,
}

#[derive(Debug, clap::Subcommand)]
enum Opt {
    #[command(about = "Manage multiple Bitwarden / Vaultwarden accounts")]
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },

    #[command(about = "Switch the active Bitwarden account")]
    Switch {
        #[arg(help = "Account name, email, server, or email@server")]
        account: Option<String>,
        #[arg(short = 'e', long, help = "Filter by account email address")]
        email: Option<String>,
        #[arg(
            short = 's',
            long,
            help = "Filter by vault server host or URL"
        )]
        server: Option<String>,
    },

    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
    },

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register,

    #[command(about = "Log in to the Bitwarden server")]
    Login {
        #[arg(
            long,
            conflicts_with = "password",
            help = "Log in using a FIDO2 passkey (WebAuthn PRF)"
        )]
        passkey: bool,
        #[arg(
            long,
            conflicts_with = "passkey",
            help = "Log in using master password (overrides passkey_login config)"
        )]
        password: bool,
    },

    #[command(about = "Manage FIDO2 / YubiKey local unlock keys")]
    Yubikey {
        #[command(subcommand)]
        action: YubikeyAction,
    },

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock,

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[command(
        about = "List all entries in the local Bitwarden database",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
        #[cfg(feature = "clipboard")]
        #[arg(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[arg(short, long, help = "List fields in this entry")]
        list_fields: bool,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(
        about = "Display the authenticator code for a given entry",
        visible_alias = "totp"
    )]
    Code {
        #[command(flatten)]
        find_args: FindArgs,
        #[cfg(feature = "clipboard")]
        #[arg(long, help = "Copy result to clipboard")]
        clipboard: bool,
    },

    #[command(
        about = "Add a new password to the database",
        long_about = "Add a new password to the database\n\n\
            This command will open a text editor to enter \
            the password and notes. The editor to use is determined \
            by the value of the $VISUAL or $EDITOR environment variables.
            The first line will be saved as the password and the \
            remainder will be saved as a note."
    )]
    Add {
        #[arg(help = "Name of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen",
        group = clap::ArgGroup::new("password-type").args(&[
            "no_symbols",
            "only_numbers",
            "nonconfusables",
            "diceware",
        ])
    )]
    Generate {
        #[arg(help = "Length of the password to generate")]
        len: usize,
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(
            long = "no-symbols",
            help = "Generate a password with no special characters"
        )]
        no_symbols: bool,
        #[arg(
            long = "only-numbers",
            help = "Generate a password consisting of only numbers"
        )]
        only_numbers: bool,
        #[arg(
            long,
            help = "Generate a password without visually similar \
                characters (useful for passwords intended to be \
                written down)"
        )]
        nonconfusables: bool,
        #[arg(
            long,
            help = "Generate a password of multiple dictionary \
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
    },

    #[command(
        about = "Modify an existing password",
        long_about = "Modify an existing password\n\n\
            This command will open a text editor with the existing \
            password and notes of the given entry for editing. \
            The editor to use is determined  by the value of the \
            $VISUAL or $EDITOR environment variables. The first line \
            will be saved as the password and the remainder will be saved \
            as a note."
    )]
    Edit {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Lock the password database")]
    Lock {
        #[arg(long, help = "Lock all configured accounts")]
        all: bool,
    },

    #[command(about = "Remove the local copy of the password database")]
    Purge,

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: CompletionShell },
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Account { action } => {
                format!("account {}", action.subcommand_name())
            }
            Self::Switch { .. } => "switch".to_string(),
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register => "register".to_string(),
            Self::Login { .. } => "login".to_string(),
            Self::Yubikey { action } => {
                format!("yubikey {}", action.subcommand_name())
            }
            Self::Unlock => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync => "sync".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
            Self::Search { .. } => "search".to_string(),
            Self::Code { .. } => "code".to_string(),
            Self::Add { .. } => "add".to_string(),
            Self::Generate { .. } => "generate".to_string(),
            Self::Edit { .. } => "edit".to_string(),
            Self::Remove { .. } => "remove".to_string(),
            Self::History { .. } => "history".to_string(),
            Self::Lock { .. } => "lock".to_string(),
            Self::Purge => "purge".to_string(),
            Self::StopAgent => "stop-agent".to_string(),
            Self::GenCompletions { .. } => "gen-completions".to_string(),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
    Nushell,
    Fig,
}

#[derive(Debug, clap::Subcommand)]
enum AccountAction {
    #[command(about = "Add a new Bitwarden / Vaultwarden account")]
    Add {
        #[arg(help = "Short name/alias for this account")]
        name: Option<String>,
        #[arg(long, help = "Account email address")]
        email: Option<String>,
        #[arg(
            long,
            visible_alias = "base-url",
            help = "Vault server (bitwarden.com, bitwarden.eu, or custom URL)"
        )]
        server: Option<String>,
        #[arg(long, help = "Custom identity server URL")]
        identity_url: Option<String>,
        #[arg(long, help = "Custom UI URL")]
        ui_url: Option<String>,
        #[arg(long, help = "Custom notifications server URL")]
        notifications_url: Option<String>,
        #[arg(long, help = "SSO organization ID")]
        sso_id: Option<String>,
        #[arg(long, help = "Path to client TLS certificate")]
        client_cert_path: Option<std::path::PathBuf>,
        #[arg(
            long,
            help = "Do not switch to the new account after adding it"
        )]
        no_switch: bool,
        #[arg(
            long,
            conflicts_with = "no_login",
            help = "Log in immediately after adding the account"
        )]
        login: bool,
        #[arg(
            long,
            conflicts_with = "login",
            help = "Do not prompt to log in after adding the account"
        )]
        no_login: bool,
        #[arg(
            long,
            conflicts_with = "no_login",
            help = "Log in using a FIDO2 passkey after adding the account"
        )]
        passkey: bool,
    },
    #[command(about = "Switch the active Bitwarden account")]
    Switch {
        #[arg(help = "Account name, email, server, or email@server")]
        account: Option<String>,
        #[arg(short = 'e', long, help = "Filter by account email address")]
        email: Option<String>,
        #[arg(
            short = 's',
            long,
            help = "Filter by vault server host or URL"
        )]
        server: Option<String>,
    },
    #[command(
        about = "List configured accounts and their lock status",
        visible_aliases = ["ls", "status"]
    )]
    List {
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },
    #[command(about = "Print the active account name")]
    Current,
    #[command(about = "Remove a configured account", visible_alias = "rm")]
    Remove {
        #[arg(help = "Account name, email, server, or email@server")]
        account: Option<String>,
        #[arg(
            long,
            help = "Keep local cached database, Touch ID, and YubiKey keys"
        )]
        keep_data: bool,
    },
    #[command(about = "Rename an account alias")]
    Rename {
        #[arg(help = "Current account name or selector")]
        old: String,
        #[arg(help = "New account name")]
        new: String,
    },
}

impl AccountAction {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Add { .. } => "add",
            Self::Switch { .. } => "switch",
            Self::List { .. } => "list",
            Self::Current => "current",
            Self::Remove { .. } => "remove",
            Self::Rename { .. } => "rename",
        }
        .to_string()
    }
}

#[derive(Debug, clap::Subcommand)]
enum Config {
    #[command(about = "Show the values of all configuration settings")]
    Show {
        #[arg(long, help = "Show global default settings")]
        global: bool,
    },
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(
            long,
            help = "Set a global default instead of an account-specific override"
        )]
        global: bool,
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(
            long,
            help = "Reset a global default instead of an account-specific override"
        )]
        global: bool,
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show { .. } => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

#[derive(Debug, clap::Subcommand)]
enum YubikeyAction {
    #[command(
        about = "Enroll a connected FIDO2 security key for local vault unlock"
    )]
    Enroll {
        #[arg(long, help = "Optional label for this security key")]
        label: Option<String>,
    },
    #[command(about = "List enrolled security keys for local vault unlock")]
    List,
    #[command(
        about = "Remove an enrolled security key by label or ID prefix"
    )]
    Remove {
        #[arg(help = "Label or credential ID prefix of the key to remove")]
        key: String,
    },
    #[command(about = "Remove all enrolled security keys for this account")]
    Clear,
}

impl YubikeyAction {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Enroll { .. } => "enroll",
            Self::List => "list",
            Self::Remove { .. } => "remove",
            Self::Clear => "clear",
        }
        .to_string()
    }
}

fn main() {
    let cli = Cli::parse();
    let env_account = std::env::var("RBW_ACCOUNT").ok();
    let account = cli
        .account
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| env_account.as_deref().filter(|s| !s.is_empty()));

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        if let Some((terminal_size::Width(w), _)) =
            terminal_size::terminal_size()
        {
            let out = format!("{}: {}", record.level(), record.args());
            writeln!(buf, "{}", textwrap::fill(&out, usize::from(w) - 1))
        } else {
            writeln!(buf, "{}: {}", record.level(), record.args())
        }
    })
    .init();

    let subcommand_name = cli.command.subcommand_name();
    let res = match cli.command {
        Opt::Account { action } => match action {
            AccountAction::Add {
                name,
                email,
                server,
                identity_url,
                ui_url,
                notifications_url,
                sso_id,
                client_cert_path,
                no_switch,
                login,
                no_login,
                passkey,
            } => commands::account_add(commands::AccountAddOpts {
                name: name.as_deref(),
                email: email.as_deref(),
                server: server.as_deref(),
                identity_url: identity_url.as_deref(),
                ui_url: ui_url.as_deref(),
                notifications_url: notifications_url.as_deref(),
                sso_id: sso_id.as_deref(),
                client_cert_path: client_cert_path.as_deref(),
                no_switch,
                login,
                no_login,
                passkey,
            }),
            AccountAction::Switch {
                account: target,
                email,
                server,
            } => commands::account_switch(
                target.as_deref(),
                email.as_deref(),
                server.as_deref(),
            ),
            AccountAction::List { raw } => commands::account_list(raw),
            AccountAction::Current => commands::account_current(account),
            AccountAction::Remove {
                account: target,
                keep_data,
            } => commands::account_remove(target.as_deref(), keep_data),
            AccountAction::Rename { old, new } => {
                commands::account_rename(&old, &new)
            }
        },
        Opt::Switch {
            account: target,
            email,
            server,
        } => commands::account_switch(
            target.as_deref(),
            email.as_deref(),
            server.as_deref(),
        ),
        Opt::Config { config } => match config {
            Config::Show { global } => commands::config_show(account, global),
            Config::Set { global, key, value } => {
                commands::config_set(account, global, &key, &value)
            }
            Config::Unset { global, key } => {
                commands::config_unset(account, global, &key)
            }
        },
        Opt::Register => commands::register(account),
        Opt::Login { passkey, password } => {
            commands::login(account, passkey, password)
        }
        Opt::Yubikey { action } => match action {
            YubikeyAction::Enroll { label } => {
                commands::yubikey_enroll(account, label.as_deref())
            }
            YubikeyAction::List => commands::yubikey_list(account),
            YubikeyAction::Remove { key } => {
                commands::yubikey_remove(account, &key)
            }
            YubikeyAction::Clear => commands::yubikey_clear(account),
        },
        Opt::Unlock => commands::unlock(account),
        Opt::Unlocked => commands::unlocked(account),
        Opt::Sync => commands::sync(account),
        Opt::List { fields, raw } => commands::list(account, &fields, raw),
        Opt::Get {
            find_args,
            field,
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            list_fields,
        } => commands::get(
            account,
            find_args.needle.clone(),
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            field.as_deref(),
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
            list_fields,
        ),
        Opt::Search {
            term,
            fields,
            folder,
            raw,
        } => {
            commands::search(account, &term, &fields, folder.as_deref(), raw)
        }
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
        } => commands::code(
            account,
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
        ),
        Opt::Add {
            name,
            user,
            uri,
            folder,
        } => commands::add(
            account,
            &name,
            user.as_deref(),
            &uri.iter()
                // XXX not sure what the ui for specifying the match type
                // should be
                .map(|uri| (uri.clone(), None))
                .collect::<Vec<_>>(),
            folder.as_deref(),
        ),
        Opt::Generate {
            len,
            name,
            user,
            uri,
            folder,
            no_symbols,
            only_numbers,
            nonconfusables,
            diceware,
        } => {
            let ty = if no_symbols {
                rbw::pwgen::Type::NoSymbols
            } else if only_numbers {
                rbw::pwgen::Type::Numbers
            } else if nonconfusables {
                rbw::pwgen::Type::NonConfusables
            } else if diceware {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
            commands::generate(
                account,
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                len,
                ty,
            )
        }
        Opt::Edit { find_args } => commands::edit(
            account,
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Remove { find_args } => commands::remove(
            account,
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::History { find_args } => commands::history(
            account,
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Lock { all } => commands::lock(account, all),
        Opt::Purge => commands::purge(account),
        Opt::StopAgent => commands::stop_agent(),
        Opt::GenCompletions { shell } => {
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.bash"));
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.fish"));
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.zsh"));
                }
                CompletionShell::Powershell => {
                    clap_complete::generate(
                        clap_complete::Shell::PowerShell,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Elvish => {
                    clap_complete::generate(
                        clap_complete::Shell::Elvish,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Nushell => {
                    clap_complete::generate(
                        clap_complete_nushell::Nushell,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Fig => {
                    clap_complete::generate(
                        clap_complete_fig::Fig,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
            }
            Ok(())
        }
    }
    .with_context(|| format!("rbw {subcommand_name}"));

    if let Err(e) = res {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_global_account_and_account_subcommands() {
        let cli = Cli::try_parse_from(["rbw", "-a", "work", "ls"]).unwrap();
        assert_eq!(cli.account.as_deref(), Some("work"));
        assert!(matches!(cli.command, Opt::List { .. }));

        let cli =
            Cli::try_parse_from(["rbw", "get", "github", "--account", "bw"])
                .unwrap();
        assert_eq!(cli.account.as_deref(), Some("bw"));
        assert!(matches!(cli.command, Opt::Get { .. }));

        let cli = Cli::try_parse_from(["rbw", "switch", "nullbyte"]).unwrap();
        assert!(matches!(
            cli.command,
            Opt::Switch {
                account: Some(ref a),
                email: None,
                server: None,
            } if a == "nullbyte"
        ));

        let cli = Cli::try_parse_from(["rbw", "account", "status", "--raw"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Opt::Account {
                action: AccountAction::List { raw: true }
            }
        ));

        let cli = Cli::try_parse_from([
            "rbw",
            "account",
            "add",
            "work",
            "--email",
            "user@example.com",
            "--server",
            "https://vault.example.com",
            "--no-switch",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Opt::Account {
                action: AccountAction::Add {
                    name: Some(ref n),
                    email: Some(ref e),
                    server: Some(ref s),
                    no_switch: true,
                    ..
                }
            } if n == "work" && e == "user@example.com" && s == "https://vault.example.com"
        ));

        let cli = Cli::try_parse_from(["rbw", "lock", "--all"]).unwrap();
        assert!(matches!(cli.command, Opt::Lock { all: true }));

        let cli = Cli::try_parse_from([
            "rbw",
            "config",
            "set",
            "--global",
            "lock_timeout",
            "1800",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Opt::Config {
                config: Config::Set {
                    global: true,
                    ref key,
                    ref value,
                }
            } if key == "lock_timeout" && value == "1800"
        ));
    }
}
