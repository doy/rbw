use crate::prelude::*;

use tokio::io::AsyncWriteExt as _;

pub async fn getpin(
    prompt: &str,
    desc: &str,
    tty: Option<&str>,
) -> Result<String> {
    let mut opts = tokio::process::Command::new("pinentry");
    let opts = opts
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let opts = if let Some(tty) = tty {
        opts.args(&["-T", tty])
    } else {
        opts
    };
    let mut child = opts.spawn().context(crate::error::Spawn)?;
    {
        let stdin = child.stdin.as_mut().unwrap();

        stdin
            .write_all(b"SETTITLE rbw\n")
            .await
            .context(crate::error::WriteStdin)?;
        stdin
            .write_all(format!("SETPROMPT {}\n", prompt).as_bytes())
            .await
            .context(crate::error::WriteStdin)?;
        stdin
            .write_all(format!("SETDESC {}\n", desc).as_bytes())
            .await
            .context(crate::error::WriteStdin)?;
        stdin
            .write_all(b"GETPIN\n")
            .await
            .context(crate::error::WriteStdin)?;
    }

    let out = child
        .wait_with_output()
        .await
        .context(crate::error::ProcessWaitOutput)?
        .stdout;
    let out_str = String::from_utf8(out.clone()).context(
        crate::error::FailedToParsePinentryUtf8 { out: out.clone() },
    )?;
    for line in out_str.lines() {
        if line.starts_with("D ") {
            return Ok(line[2..line.len()].to_string());
        } else if !line.starts_with("OK") {
            break;
        }
    }

    Err(Error::FailedToParsePinentry { out })
}
