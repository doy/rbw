use crate::prelude::*;

use std::io::{Read as _, Write as _};

pub fn edit(contents: &str, help: &str) -> Result<String> {
    let mut var = "VISUAL";
    let editor = std::env::var_os(var).unwrap_or_else(|| {
        var = "EDITOR";
        std::env::var_os(var).unwrap_or_else(|| "/usr/bin/vim".into())
    });
    let editor = std::path::Path::new(&editor);

    let mut args = vec![];
    match editor.file_name() {
        Some(editor) => match editor.to_str() {
            Some("vim") | Some("nvim") => {
                // disable swap files and viminfo for password entry
                args.push(std::ffi::OsStr::new("-ni"));
                args.push(std::ffi::OsStr::new("NONE"));
            }
            _ => {
                // other editor support welcomed
            }
        },
        None => {
            return Err(Error::InvalidEditor {
                var: var.to_string(),
                editor: editor.as_os_str().to_os_string(),
            })
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rbw");
    let mut fh = std::fs::File::create(&file).unwrap();
    fh.write_all(contents.as_bytes()).unwrap();
    fh.write_all(help.as_bytes()).unwrap();
    drop(fh);

    args.push(file.as_os_str());
    let res = std::process::Command::new(&editor).args(&args).status();
    match res {
        Ok(res) => {
            if !res.success() {
                return Err(Error::FailedToRunEditor {
                    editor: editor.to_owned(),
                    res,
                });
            }
        }
        Err(err) => {
            return Err(Error::FailedToFindEditor {
                editor: editor.to_owned(),
                err,
            })
        }
    }

    let mut fh = std::fs::File::open(&file).unwrap();
    let mut contents = String::new();
    fh.read_to_string(&mut contents).unwrap();
    drop(fh);

    Ok(contents)
}
