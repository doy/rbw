#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::implicit_hasher)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]
#![allow(clippy::single_match)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]

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
