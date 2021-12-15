use crate::prelude::*;

use std::convert::TryFrom as _;
use tokio::io::AsyncWriteExt as _;

pub async fn getpin(
    pinentry: &str,
    prompt: &str,
    desc: &str,
    err: Option<&str>,
    tty: Option<&str>,
    grab: bool,
) -> Result<crate::locked::Password> {
    let mut opts = tokio::process::Command::new(pinentry);
    opts.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut args = vec!["-o", "0"];
    if let Some(tty) = tty {
        args.extend(&["-T", tty]);
    }
    if !grab {
        args.push("-g");
    }
    opts.args(args);
    let mut child = opts.spawn().map_err(|source| Error::Spawn { source })?;
    // unwrap is safe because we specified stdin as piped in the command opts
    // above
    let mut stdin = child.stdin.take().unwrap();

    let mut ncommands = 1;
    stdin
        .write_all(b"SETTITLE rbw\n")
        .await
        .map_err(|source| Error::WriteStdin { source })?;
    ncommands += 1;
    stdin
        .write_all(format!("SETPROMPT {}\n", prompt).as_bytes())
        .await
        .map_err(|source| Error::WriteStdin { source })?;
    ncommands += 1;
    stdin
        .write_all(format!("SETDESC {}\n", desc).as_bytes())
        .await
        .map_err(|source| Error::WriteStdin { source })?;
    ncommands += 1;
    if let Some(err) = err {
        stdin
            .write_all(format!("SETERROR {}\n", err).as_bytes())
            .await
            .map_err(|source| Error::WriteStdin { source })?;
        ncommands += 1;
    }
    stdin
        .write_all(b"GETPIN\n")
        .await
        .map_err(|source| Error::WriteStdin { source })?;
    ncommands += 1;
    drop(stdin);

    let mut buf = crate::locked::Vec::new();
    buf.zero();
    // unwrap is safe because we specified stdout as piped in the command opts
    // above
    let len = read_password(
        ncommands,
        buf.data_mut(),
        child.stdout.as_mut().unwrap(),
    )
    .await?;
    buf.truncate(len);

    child
        .wait()
        .await
        .map_err(|source| Error::PinentryWait { source })?;

    Ok(crate::locked::Password::new(buf))
}

async fn read_password<
    R: tokio::io::AsyncRead + tokio::io::AsyncReadExt + Unpin,
>(
    mut ncommands: u8,
    data: &mut [u8],
    mut r: R,
) -> Result<usize>
where
    R: Send,
{
    let mut len = 0;
    loop {
        let nl = data.iter().take(len).position(|c| *c == b'\n');
        if let Some(nl) = nl {
            if data.starts_with(b"OK") {
                if ncommands == 1 {
                    len = 0;
                    break;
                }
                data.copy_within((nl + 1).., 0);
                len -= nl + 1;
                ncommands -= 1;
            } else if data.starts_with(b"D ") {
                data.copy_within(2..nl, 0);
                len = nl - 2;
                break;
            } else if data.starts_with(b"ERR ") {
                let line: Vec<u8> = data.iter().take(nl).copied().collect();
                let line = String::from_utf8(line).unwrap();
                let mut split = line.splitn(3, ' ');
                let _ = split.next(); // ERR
                let code = split.next();
                match code {
                    Some("83886179") => {
                        return Err(Error::PinentryCancelled);
                    }
                    Some(code) => {
                        if let Some(error) = split.next() {
                            return Err(Error::PinentryErrorMessage {
                                error: error.to_string(),
                            });
                        }
                        return Err(Error::PinentryErrorMessage {
                            error: format!("unknown error ({})", code),
                        });
                    }
                    None => {
                        return Err(Error::PinentryErrorMessage {
                            error: "unknown error".to_string(),
                        });
                    }
                }
            } else {
                return Err(Error::FailedToParsePinentry {
                    out: String::from_utf8_lossy(data).to_string(),
                });
            }
        } else {
            let bytes = r
                .read(&mut data[len..])
                .await
                .map_err(|source| Error::PinentryReadOutput { source })?;
            len += bytes;
        }
    }

    len = percent_decode(&mut data[..len]);

    Ok(len)
}

// not using the percent-encoding crate because it doesn't provide a way to do
// this in-place, and we want the password to always live within the locked
// vec. should really move something like this into the percent-encoding crate
// at some point.
fn percent_decode(buf: &mut [u8]) -> usize {
    let mut read_idx = 0;
    let mut write_idx = 0;
    let len = buf.len();

    while read_idx < len {
        let mut c = buf[read_idx];

        if c == b'%' && read_idx + 2 < len {
            if let Some(h) = char::from(buf[read_idx + 1]).to_digit(16) {
                #[allow(clippy::cast_possible_truncation)]
                if let Some(l) = char::from(buf[read_idx + 2]).to_digit(16) {
                    // h and l were parsed from a single hex digit, so they
                    // must be in the range 0-15, so these unwraps are safe
                    c = u8::try_from(h).unwrap() * 0x10
                        + u8::try_from(l).unwrap();
                    read_idx += 2;
                }
            }
        }

        buf[write_idx] = c;
        read_idx += 1;
        write_idx += 1;
    }

    write_idx
}

#[test]
fn test_read_password() {
    let good_inputs = &[
        (0, &b"D super secret password\n"[..]),
        (4, &b"OK\nOK\nOK\nD super secret password\nOK\n"[..]),
        (12, &b"OK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nD super secret password\nOK\n"[..]),
        (24, &b"OK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nD super secret password\nOK\n"[..]),
    ];
    for (ncommands, input) in good_inputs {
        let mut buf = [0; 64];
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let len = read_password(*ncommands, &mut buf, &input[..])
                .await
                .unwrap();
            assert_eq!(&buf[0..len], b"super secret password");
        });
    }

    let match_inputs = &[
        (&b"OK\nOK\nOK\nOK\n"[..], &b""[..]),
        (&b"D foo%25bar\n"[..], &b"foo%bar"[..]),
        (&b"D foo%0abar\n"[..], &b"foo\nbar"[..]),
        (&b"D foo%0Abar\n"[..], &b"foo\nbar"[..]),
        (&b"D foo%0Gbar\n"[..], &b"foo%0Gbar"[..]),
        (&b"D foo%0\n"[..], &b"foo%0"[..]),
        (&b"D foo%\n"[..], &b"foo%"[..]),
        (&b"D %25foo\n"[..], &b"%foo"[..]),
        (&b"D %25\n"[..], &b"%"[..]),
    ];

    for (input, output) in match_inputs {
        let mut buf = [0; 64];
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let len = read_password(4, &mut buf, &input[..]).await.unwrap();
            assert_eq!(&buf[0..len], &output[..]);
        });
    }
}
