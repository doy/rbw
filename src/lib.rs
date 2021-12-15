#![warn(clippy::cargo)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::as_conversions)]
#![warn(clippy::get_unwrap)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]
// we aren't really documenting apis anyway
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod actions;
pub mod api;
pub mod cipherstring;
pub mod config;
pub mod db;
pub mod dirs;
pub mod edit;
pub mod error;
pub mod identity;
pub mod json;
pub mod locked;
pub mod pinentry;
mod prelude;
pub mod protocol;
pub mod pwgen;
pub mod wordlist;
