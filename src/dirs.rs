use crate::prelude::*;

pub fn make_all() -> Result<()> {
    std::fs::create_dir_all(&cache_dir())
        .context(crate::error::CreateDirectory)?;

    std::fs::create_dir_all(&runtime_dir())
        .context(crate::error::CreateDirectory)?;

    std::fs::create_dir_all(&data_dir())
        .context(crate::error::CreateDirectory)?;

    Ok(())
}

pub fn config_file() -> std::path::PathBuf {
    config_dir().join("config.json")
}

const INVALID_PATH: &percent_encoding::AsciiSet =
    &percent_encoding::CONTROLS.add(b'/').add(b'%').add(b':');
pub fn db_file(server: &str, email: &str) -> std::path::PathBuf {
    let server =
        percent_encoding::percent_encode(server.as_bytes(), INVALID_PATH)
            .to_string();
    cache_dir().join(format!("{}:{}.json", server, email))
}

pub fn pid_file() -> std::path::PathBuf {
    runtime_dir().join("pidfile")
}

pub fn agent_stdout_file() -> std::path::PathBuf {
    data_dir().join("agent.out")
}

pub fn agent_stderr_file() -> std::path::PathBuf {
    data_dir().join("agent.err")
}

pub fn socket_file() -> std::path::PathBuf {
    runtime_dir().join("socket")
}

fn config_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.config_dir().to_path_buf()
}

fn cache_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.cache_dir().to_path_buf()
}

fn data_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.data_dir().to_path_buf()
}

fn runtime_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.runtime_dir().unwrap().to_path_buf()
}
