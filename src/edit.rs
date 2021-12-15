use crate::prelude::*;

use std::io::{Read as _, Write as _};

pub fn edit(contents: &str, help: &str) -> Result<String> {
    let mut var = "VISUAL";
    let editor = std::env::var_os(var).unwrap_or_else(|| {
        var = "EDITOR";
        std::env::var_os(var).unwrap_or_else(|| "/usr/bin/vim".into())
    });

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rbw");
    let mut fh = std::fs::File::create(&file).unwrap();
    fh.write_all(contents.as_bytes()).unwrap();
    fh.write_all(help.as_bytes()).unwrap();
    drop(fh);

    let (cmd, args) = if contains_shell_metacharacters(&editor) {
        let mut cmdline = std::ffi::OsString::new();
        cmdline.extend([
            editor.as_ref(),
            std::ffi::OsStr::new(" "),
            file.as_os_str(),
        ]);

        let editor_args = vec![std::ffi::OsString::from("-c"), cmdline];
        (std::path::Path::new("/bin/sh"), editor_args)
    } else {
        let editor = std::path::Path::new(&editor);
        let mut editor_args = vec![];

        #[allow(clippy::single_match)] // more to come
        match editor.file_name() {
            Some(editor) => match editor.to_str() {
                Some("vim" | "nvim") => {
                    // disable swap files and viminfo for password entry
                    editor_args.push(std::ffi::OsString::from("-ni"));
                    editor_args.push(std::ffi::OsString::from("NONE"));
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
        editor_args.push(file.clone().into_os_string());
        (editor, editor_args)
    };

    let res = std::process::Command::new(&cmd).args(&args).status();
    match res {
        Ok(res) => {
            if !res.success() {
                return Err(Error::FailedToRunEditor {
                    editor: cmd.to_owned(),
                    args,
                    res,
                });
            }
        }
        Err(err) => {
            return Err(Error::FailedToFindEditor {
                editor: cmd.to_owned(),
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

fn contains_shell_metacharacters(cmd: &std::ffi::OsStr) -> bool {
    match cmd.to_str() {
        Some(s) => s.contains(&[' ', '$', '\'', '"'][..]),
        None => false,
    }
}
