#[must_use]
pub fn config_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.config_dir().to_path_buf()
}

#[must_use]
pub fn cache_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.cache_dir().to_path_buf()
}

#[must_use]
pub fn data_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.data_dir().to_path_buf()
}

#[must_use]
pub fn runtime_dir() -> std::path::PathBuf {
    let project_dirs = directories::ProjectDirs::from("", "", "rbw").unwrap();
    project_dirs.runtime_dir().unwrap().to_path_buf()
}
