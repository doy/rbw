use crate::prelude::*;
use std::os::unix::fs::PermissionsExt as _;

pub fn make_all() -> Result<()> {
    let cache_dir = cache_dir();
    std::fs::create_dir_all(&cache_dir).map_err(|source| {
        Error::CreateDirectory {
            source,
            file: cache_dir,
        }
    })?;

    let runtime_dir = runtime_dir();
    std::fs::create_dir_all(&runtime_dir).map_err(|source| {
        Error::CreateDirectory {
            source,
            file: runtime_dir.clone(),
        }
    })?;
    std::fs::set_permissions(
        &runtime_dir,
        std::fs::Permissions::from_mode(0o700),
    )
    .map_err(|source| Error::CreateDirectory {
        source,
        file: runtime_dir,
    })?;

    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir).map_err(|source| {
        Error::CreateDirectory {
            source,
            file: data_dir,
        }
    })?;

    Ok(())
}

#[must_use]
pub fn config_file() -> std::path::PathBuf {
    config_dir().join("config.json")
}

const INVALID_PATH: &percent_encoding::AsciiSet =
    &percent_encoding::CONTROLS.add(b'/').add(b'%').add(b':');
#[must_use]
pub fn db_file(server: &str, email: &str) -> std::path::PathBuf {
    let server =
        percent_encoding::percent_encode(server.as_bytes(), INVALID_PATH)
            .to_string();
    cache_dir().join(format!("{}:{}.json", server, email))
}

#[must_use]
pub fn pid_file() -> std::path::PathBuf {
    runtime_dir().join("pidfile")
}

#[must_use]
pub fn agent_stdout_file() -> std::path::PathBuf {
    data_dir().join("agent.out")
}

#[must_use]
pub fn agent_stderr_file() -> std::path::PathBuf {
    data_dir().join("agent.err")
}

#[must_use]
pub fn device_id_file() -> std::path::PathBuf {
    data_dir().join("device_id")
}

#[must_use]
pub fn socket_file() -> std::path::PathBuf {
    runtime_dir().join("socket")
}

#[must_use]
fn config_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.config_dir().to_path_buf()
}

#[must_use]
fn cache_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.cache_dir().to_path_buf()
}

#[must_use]
fn data_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.data_dir().to_path_buf()
}

#[must_use]
fn runtime_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    match project_dirs.runtime_dir() {
        Some(dir) => dir.to_path_buf(),
        None => format!(
            "{}/rbw-{}",
            std::env::temp_dir().to_string_lossy(),
            nix::unistd::getuid().as_raw()
        )
        .into(),
    }
}
