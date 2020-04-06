use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

// TODO result
pub async fn pinentry(prompt: &str, desc: &str, tty: Option<&str>) -> String {
    let mut opts = tokio::process::Command::new("pinentry");
    let opts = opts
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let opts = if let Some(tty) = tty {
        opts.args(&["-T", tty])
    } else {
        opts
    };
    let mut child = opts.spawn().unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        let mut stdout =
            tokio::io::BufReader::new(child.stdout.as_mut().unwrap());
        let mut buf = String::new();

        stdin.write_all(b"SETTITLE rbw\n").await.unwrap();
        stdout.read_line(&mut buf).await.unwrap();

        stdin
            .write_all(format!("SETPROMPT {}\n", prompt).as_bytes())
            .await
            .unwrap();
        stdout.read_line(&mut buf).await.unwrap();

        stdin
            .write_all(format!("SETDESC {}\n", desc).as_bytes())
            .await
            .unwrap();
        stdout.read_line(&mut buf).await.unwrap();

        stdin.write_all(b"GETPIN\n").await.unwrap();
    }
    let res =
        String::from_utf8(child.wait_with_output().await.unwrap().stdout)
            .unwrap();
    for line in res.lines() {
        if line.starts_with("OK") {
            continue;
        } else if line.starts_with("D ") {
            return line[2..line.len()].to_string();
        }
    }
    panic!("failed to parse pinentry output: {:?}", res)
}
