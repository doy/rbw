use std::io::Write as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
mod sock;

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
enum Opt {
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
    Login,

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
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
        needle: commands::Needle,
        #[arg(help = "Username of the entry to display")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[cfg(feature = "clipboard")]
        #[structopt(long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[structopt(short, long, help = "Ignore case")]
        ignorecase: bool,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[structopt(long, help = "Display output as JSON")]
	raw: bool,
    },

    #[command(
        about = "Display the authenticator code for a given entry",
        visible_alias = "totp"
    )]
    Code {
        #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
        needle: commands::Needle,
        #[arg(help = "Username of the entry to display")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[cfg(feature = "clipboard")]
        #[structopt(long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[arg(short, long, help = "Ignore case")]
        ignorecase: bool,
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
        #[arg(help = "Name or UUID of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(short, long, help = "Ignore case")]
        ignorecase: bool,
    },

    #[command(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[arg(help = "Name or UUID of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(short, long, help = "Ignore case")]
        ignorecase: bool,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[arg(help = "Name or UUID of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(short, long, help = "Ignore case")]
        ignorecase: bool,
    },

    #[command(about = "Lock the password database")]
    Lock,

    #[command(about = "Remove the local copy of the password database")]
    Purge,

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: clap_complete::Shell },
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register => "register".to_string(),
            Self::Login => "login".to_string(),
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
            Self::Lock => "lock".to_string(),
            Self::Purge => "purge".to_string(),
            Self::StopAgent => "stop-agent".to_string(),
            Self::GenCompletions { .. } => "gen-completions".to_string(),
        }
    }
}

#[derive(Debug, clap::Parser)]
enum Config {
    #[command(about = "Show the values of all configuration settings")]
    Show,
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

fn main() {
    let opt = Opt::parse();

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

    let res = match &opt {
        Opt::Config { config } => match config {
            Config::Show => commands::config_show(),
            Config::Set { key, value } => commands::config_set(key, value),
            Config::Unset { key } => commands::config_unset(key),
        },
        Opt::Register => commands::register(),
        Opt::Login => commands::login(),
        Opt::Unlock => commands::unlock(),
        Opt::Unlocked => commands::unlocked(),
        Opt::Sync => commands::sync(),
        Opt::List { fields } => commands::list(fields),
        Opt::Get {
            needle,
            user,
            folder,
            field,
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            ignorecase,
        } => commands::get(
            needle,
            user.as_deref(),
            folder.as_deref(),
            field.as_deref(),
            *full,
            *raw,
            #[cfg(feature = "clipboard")]
            *clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            *ignorecase,
        ),
        Opt::Search { term, folder, raw } => {
            commands::search(term, folder.as_deref(), *raw)
        }
        Opt::Code {
            needle,
            user,
            folder,
            #[cfg(feature = "clipboard")]
            clipboard,
            ignorecase,
        } => commands::code(
            needle,
            user.as_deref(),
            folder.as_deref(),
            #[cfg(feature = "clipboard")]
            *clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            *ignorecase,
        ),
        Opt::Add {
            name,
            user,
            uri,
            folder,
        } => commands::add(
            name,
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
            let ty = if *no_symbols {
                rbw::pwgen::Type::NoSymbols
            } else if *only_numbers {
                rbw::pwgen::Type::Numbers
            } else if *nonconfusables {
                rbw::pwgen::Type::NonConfusables
            } else if *diceware {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
            commands::generate(
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                *len,
                ty,
            )
        }
        Opt::Edit {
            name,
            user,
            folder,
            ignorecase,
        } => commands::edit(
            name,
            user.as_deref(),
            folder.as_deref(),
            *ignorecase,
        ),
        Opt::Remove {
            name,
            user,
            folder,
            ignorecase,
        } => commands::remove(
            name,
            user.as_deref(),
            folder.as_deref(),
            *ignorecase,
        ),
        Opt::History {
            name,
            user,
            folder,
            ignorecase,
        } => commands::history(
            name,
            user.as_deref(),
            folder.as_deref(),
            *ignorecase,
        ),
        Opt::Lock => commands::lock(),
        Opt::Purge => commands::purge(),
        Opt::StopAgent => commands::stop_agent(),
        Opt::GenCompletions { shell } => {
            clap_complete::generate(
                *shell,
                &mut Opt::command(),
                "rbw",
                &mut std::io::stdout(),
            );
            Ok(())
        }
    }
    .context(format!("rbw {}", opt.subcommand_name()));

    if let Err(e) = res {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
