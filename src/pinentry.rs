use crate::prelude::*;

use std::convert::TryFrom as _;

use tokio::io::AsyncWriteExt as _;

// pinentry's errors are GPG_ERR_SOURCE_PINENTRY (5 << 24) plus the code
// GPG_ERR_TIMEOUT
const PINENTRY_ERR_TIMEOUT: &str = "83886142";
// GPG_ERR_CANCELED, from the cancel button or closing the dialog
const PINENTRY_ERR_CANCELED: &str = "83886179";
// GPG_ERR_NOT_CONFIRMED, from the "not OK" button of CONFIRM
const PINENTRY_ERR_NOT_CONFIRMED: &str = "83886194";

// How long past its own timeout a pinentry may take to exit before it is
// killed. Letting it exit by itself lets a terminal pinentry restore the
// terminal.
const KILL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

pub struct Pinentry {
    pub program: String,
    // Seconds an unanswered prompt stays up, or 0 to wait forever.
    pub timeout: u64,
}

pub async fn getpin(
    pinentry: &Pinentry,
    prompt: &str,
    desc: &str,
    err: Option<&str>,
    environment: &crate::protocol::Environment,
    grab: bool,
) -> Result<crate::locked::Password> {
    let mut child = spawn(pinentry, environment, grab)?;
    // unwrap is safe because we specified stdin as piped in the command opts
    // above
    let mut stdin = child.stdin.take().unwrap();

    let mut ncommands = 1;
    send(&mut stdin, "SETTITLE rbw").await?;
    ncommands += 1;
    send(&mut stdin, &format!("SETPROMPT {}", assuan_escape(prompt))).await?;
    ncommands += 1;
    send(&mut stdin, &format!("SETDESC {}", assuan_escape(desc))).await?;
    ncommands += 1;
    if let Some(err) = err {
        send(&mut stdin, &format!("SETERROR {}", assuan_escape(err))).await?;
        ncommands += 1;
    }
    send(&mut stdin, "GETPIN").await?;
    ncommands += 1;
    drop(stdin);

    let mut buf = crate::locked::Vec::new();
    buf.zero();
    let answer = async {
        // unwrap is safe because we specified stdout as piped in the command
        // opts above
        let len = read_password(
            ncommands,
            buf.data_mut(),
            child.stdout.as_mut().unwrap(),
        )
        .await?;
        child
            .wait()
            .await
            .map_err(|source| Error::PinentryWait { source })?;
        Ok(len)
    };
    let len = with_timeout(pinentry, answer).await?;
    buf.truncate(len);

    Ok(crate::locked::Password::new(buf))
}

// Asks the person to approve something, with the description as the whole
// question. Returns Ok only when they choose the approve button: cancelling,
// declining, a timeout, or a pinentry that can't show the dialog are all
// errors.
pub async fn confirm(
    pinentry: &Pinentry,
    desc: &str,
    environment: &crate::protocol::Environment,
) -> Result<()> {
    // never in a terminal: a terminal pinentry shares the screen and the
    // keyboard with whatever runs there, and focuses the approve button, so
    // an Enter typed for the shell could approve. a graphical pinentry is
    // needed, and without one the request is refused.
    let environment = environment.without_tty();
    // a request nobody answers must not hold up every later one, so this
    // prompt always times out, even with pinentry_timeout set to 0
    let pinentry = Pinentry {
        program: pinentry.program.clone(),
        timeout: if pinentry.timeout == 0 {
            CONFIRM_DEFAULT_TIMEOUT_SECS
        } else {
            pinentry.timeout
        },
    };
    // no keyboard grab: a dialog that pops up while the person is typing
    // elsewhere should not capture an Enter meant for another window
    let mut child = spawn(&pinentry, &environment, false)?;
    // unwrap is safe because we specified stdin as piped in spawn
    let mut stdin = child.stdin.take().unwrap();

    let mut ncommands = 1;
    send(&mut stdin, "SETTITLE rbw").await?;
    ncommands += 1;
    send(&mut stdin, &format!("SETDESC {}", assuan_escape(desc))).await?;
    ncommands += 1;
    send(&mut stdin, "SETOK Allow").await?;
    ncommands += 1;
    send(&mut stdin, "SETCANCEL Deny").await?;
    ncommands += 1;
    send(&mut stdin, "CONFIRM").await?;
    ncommands += 1;
    drop(stdin);

    let answer = async {
        // unwrap is safe because we specified stdout as piped in spawn
        let stdout =
            tokio::io::BufReader::new(child.stdout.as_mut().unwrap());
        read_confirmation(ncommands, stdout).await?;
        child
            .wait()
            .await
            .map_err(|source| Error::PinentryWait { source })?;
        Ok(())
    };
    with_timeout(&pinentry, answer).await
}

const CONFIRM_DEFAULT_TIMEOUT_SECS: u64 = 120;

fn spawn(
    pinentry: &Pinentry,
    environment: &crate::protocol::Environment,
    grab: bool,
) -> Result<tokio::process::Child> {
    let mut opts = tokio::process::Command::new(&pinentry.program);
    opts.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        // a prompt nobody is waiting for anymore should not outlive the
        // request that opened it
        .kill_on_drop(true);
    let mut args =
        vec!["--timeout".into(), pinentry.timeout.to_string().into()];
    // the ssh agent reuses the environment of the last rbw command, whose
    // terminal may be closed by now. a terminal pinentry pointed at a dead
    // tty can neither be seen nor answered, and spins at full cpu, so leave
    // the tty out and let pinentry find its own or fail.
    if let Some(tty) = environment.tty().filter(|tty| tty_is_usable(tty)) {
        args.extend(["--ttyname".into(), tty.into()]);
    }

    let env_vars = environment.env_vars();
    // Not all pinentry appear to respect the --display flag, so we also keep the environment
    // variable.
    if let Some(display) =
        env_vars.get(std::ffi::OsString::from("DISPLAY").as_os_str())
    {
        args.extend(["--display".into(), display.clone()]);
    }
    if !grab {
        args.push("--no-global-grab".into());
    }
    opts.args(args);

    for env_var in &*crate::protocol::ENVIRONMENT_VARIABLES_OS {
        if let Some(val) = env_vars.get(env_var) {
            opts.env(env_var, val);
        } else {
            opts.env_remove(env_var);
        }
    }
    opts.envs(env_vars);

    opts.spawn().map_err(|source| Error::Spawn { source })
}

async fn send(
    stdin: &mut tokio::process::ChildStdin,
    line: &str,
) -> Result<()> {
    stdin
        .write_all(format!("{line}\n").as_bytes())
        .await
        .map_err(|source| Error::WriteStdin { source })
}

// Enforces the timeout here too, for pinentry programs that ignore it.
async fn with_timeout<T>(
    pinentry: &Pinentry,
    answer: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if pinentry.timeout == 0 {
        answer.await
    } else {
        let limit =
            std::time::Duration::from_secs(pinentry.timeout) + KILL_GRACE;
        tokio::time::timeout(limit, answer)
            .await
            .unwrap_or(Err(Error::PinentryTimedOut))
    }
}

// Longest text, once escaped, sent as the argument of one Assuan command.
// Assuan lines are limited to 1000 bytes, including the command name and
// the newline.
const MAX_ASSUAN_ARGUMENT: usize = 900;

// Escapes text for an Assuan command line. A newline would end the command
// and let the rest of the text run as another command, and pinentry decodes
// %XX sequences, so '%', CR, LF and the other ASCII control characters are
// sent as %XX. Text that would make the line too long is cut, without
// splitting a character or a %XX sequence, and ends with "...".
pub fn assuan_escape(text: &str) -> String {
    use std::fmt::Write as _;

    const ELLIPSIS: &str = "...";

    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '%' || c.is_ascii_control() {
            // writing to a String can't fail
            let _ = write!(escaped, "%{:02X}", u32::from(c));
        } else {
            escaped.push(c);
        }
    }
    if escaped.len() <= MAX_ASSUAN_ARGUMENT {
        return escaped;
    }

    let mut cut = MAX_ASSUAN_ARGUMENT - ELLIPSIS.len();
    while !escaped.is_char_boundary(cut) {
        cut -= 1;
    }
    // every '%' left in the text starts a %XX sequence
    if let Some(start) = escaped[..cut].rfind('%') {
        if start + 3 > cut {
            cut = start;
        }
    }
    escaped.truncate(cut);
    escaped.push_str(ELLIPSIS);
    escaped
}

// Whether the path is still a terminal that can be opened. Opened without
// blocking and without becoming our controlling terminal.
fn tty_is_usable(tty: &std::ffi::OsStr) -> bool {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(tty)
        .is_ok_and(|f| rustix::termios::isatty(&f))
}

async fn read_password<R>(
    mut ncommands: u8,
    data: &mut [u8],
    mut r: R,
) -> Result<usize>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncReadExt + Unpin + Send,
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
            } else if data.starts_with(b"S ") {
                data.copy_within((nl + 1).., 0);
                len -= nl + 1;
            } else if data.starts_with(b"ERR ") {
                let line = String::from_utf8_lossy(&data[..nl]).into_owned();
                return Err(pinentry_error(&line));
            } else {
                return Err(Error::FailedToParsePinentry {
                    out: String::from_utf8_lossy(data)
                        .trim_end_matches('\0')
                        .to_string(),
                });
            }
        } else {
            let bytes = r
                .read(&mut data[len..])
                .await
                .map_err(|source| Error::PinentryReadOutput { source })?;
            if bytes == 0 {
                return Err(Error::PinentryReadOutput {
                    source: std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ),
                });
            }
            len += bytes;
        }
    }

    len = percent_decode(&mut data[..len]);

    Ok(len)
}

// Reads pinentry's answers to `ncommands` commands, counting its greeting
// as one, when the last command is CONFIRM. Only an OK to every one of them
// means the person approved.
async fn read_confirmation<R>(mut ncommands: u8, r: R) -> Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt as _;

    let mut lines = r.lines();
    loop {
        let line = lines
            .next_line()
            .await
            .map_err(|source| Error::PinentryReadOutput { source })?
            .ok_or_else(|| Error::PinentryReadOutput {
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ),
            })?;
        if line == "OK" || line.starts_with("OK ") {
            ncommands -= 1;
            if ncommands == 0 {
                return Ok(());
            }
        } else if line.starts_with("S ") || line.starts_with('#') {
            // status and comment lines carry no answer
        } else if line.starts_with("ERR ") {
            return Err(pinentry_error(&line));
        } else {
            return Err(Error::FailedToParsePinentry { out: line });
        }
    }
}

// The error for an "ERR <code> <description>" line.
fn pinentry_error(line: &str) -> Error {
    let mut split = line.splitn(3, ' ');
    let _ = split.next(); // ERR
    match split.next() {
        Some(PINENTRY_ERR_CANCELED | PINENTRY_ERR_NOT_CONFIRMED) => {
            Error::PinentryCancelled
        }
        Some(PINENTRY_ERR_TIMEOUT) => Error::PinentryTimedOut,
        Some(code) => split.next().map_or_else(
            || Error::PinentryErrorMessage {
                error: format!("unknown error ({code})"),
            },
            |error| Error::PinentryErrorMessage {
                error: error.to_string(),
            },
        ),
        None => Error::PinentryErrorMessage {
            error: "unknown error".to_string(),
        },
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Writing an executable while another test forks can make running it
    // fail with "text file busy", because the forked child briefly holds the
    // file open for writing. Tests that write and run a stand-in take turns.
    static SPAWN_LOCK: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    // Writes a pinentry stand-in that runs the given shell script.
    fn fake_pinentry(name: &str, script: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir()
            .join(format!("rbw-pinentry-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        path
    }

    async fn ask(
        program: &std::path::Path,
    ) -> Result<crate::locked::Password> {
        getpin(
            &Pinentry {
                program: program.to_string_lossy().into_owned(),
                timeout: 1,
            },
            "Prompt",
            "Description",
            None,
            &crate::protocol::Environment::default(),
            false,
        )
        .await
    }

    #[tokio::test]
    async fn pinentry_that_never_answers_is_stopped() {
        let _guard = SPAWN_LOCK.lock().await;
        let program = fake_pinentry("hang", "exec sleep 600");
        let started = std::time::Instant::now();
        assert!(matches!(ask(&program).await, Err(Error::PinentryTimedOut)));
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
    }

    #[tokio::test]
    async fn pinentry_timeout_is_reported() {
        let _guard = SPAWN_LOCK.lock().await;
        let program = fake_pinentry(
            "timeout",
            "echo OK; echo 'ERR 83886142 Timeout <Pinentry>'",
        );
        assert!(matches!(ask(&program).await, Err(Error::PinentryTimedOut)));
    }

    async fn ask_to_confirm(
        program: &std::path::Path,
        desc: &str,
    ) -> Result<()> {
        confirm(
            &Pinentry {
                program: program.to_string_lossy().into_owned(),
                timeout: 1,
            },
            desc,
            &crate::protocol::Environment::default(),
        )
        .await
    }

    // A pinentry that answers OK to everything and logs the commands it
    // got to the returned file.
    fn approving_pinentry(
        name: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let log = std::env::temp_dir()
            .join(format!("rbw-pinentry-test-{}", std::process::id()))
            .join(format!("{name}.log"));
        let _ = std::fs::remove_file(&log);
        let program = fake_pinentry(
            name,
            &format!(
                "echo 'OK Pleased to meet you'\n\
                 while IFS= read -r line; do\n\
                 printf '%s\\n' \"$line\" >> '{}'\n\
                 echo OK\n\
                 done",
                log.display()
            ),
        );
        (program, log)
    }

    #[tokio::test]
    async fn confirmation_needs_an_ok_to_confirm() {
        let _guard = SPAWN_LOCK.lock().await;
        let (program, log) = approving_pinentry("approve");
        ask_to_confirm(&program, "Sign with \"key\"?")
            .await
            .unwrap();
        let commands = std::fs::read_to_string(log).unwrap();
        assert_eq!(
            commands,
            "SETTITLE rbw\nSETDESC Sign with \"key\"?\nSETOK Allow\n\
             SETCANCEL Deny\nCONFIRM\n"
        );
    }

    #[tokio::test]
    async fn confirmation_text_cannot_add_commands() {
        let _guard = SPAWN_LOCK.lock().await;
        let (program, log) = approving_pinentry("inject");
        ask_to_confirm(&program, "evil\nGETPIN\r\nBYE 100%")
            .await
            .unwrap();
        let commands = std::fs::read_to_string(log).unwrap();
        let lines: Vec<_> = commands.lines().collect();
        assert_eq!(lines.len(), 5, "{commands:?}");
        assert_eq!(lines[1], "SETDESC evil%0AGETPIN%0D%0ABYE 100%25");
    }

    #[tokio::test]
    async fn refused_confirmations_are_errors() {
        let _guard = SPAWN_LOCK.lock().await;
        // answers OK to every command but CONFIRM
        let answer_confirm = |name, answer: &str| {
            fake_pinentry(
                name,
                &format!(
                    "echo OK\n\
                     while IFS= read -r line; do\n\
                     case \"$line\" in\n\
                     CONFIRM) {answer}; exit 0;;\n\
                     *) echo OK;;\n\
                     esac\n\
                     done"
                ),
            )
        };

        let cancelled = answer_confirm(
            "cancel",
            "echo 'ERR 83886179 Operation cancelled'",
        );
        assert!(matches!(
            ask_to_confirm(&cancelled, "?").await,
            Err(Error::PinentryCancelled)
        ));
        let declined =
            answer_confirm("decline", "echo 'ERR 83886194 Not confirmed'");
        assert!(matches!(
            ask_to_confirm(&declined, "?").await,
            Err(Error::PinentryCancelled)
        ));
        let timed_out =
            answer_confirm("confirm-timeout", "echo 'ERR 83886142 Timeout'");
        assert!(matches!(
            ask_to_confirm(&timed_out, "?").await,
            Err(Error::PinentryTimedOut)
        ));
        // a pinentry that can't show the dialog
        let no_display = answer_confirm(
            "no-display",
            "echo 'ERR 83918950 Inappropriate ioctl for device'",
        );
        assert!(matches!(
            ask_to_confirm(&no_display, "?").await,
            Err(Error::PinentryErrorMessage { .. })
        ));
        // anything but OK is not an approval
        let data = answer_confirm("data", "echo 'D 1'; echo OK");
        assert!(matches!(
            ask_to_confirm(&data, "?").await,
            Err(Error::FailedToParsePinentry { .. })
        ));
        let okay = answer_confirm("okay", "echo OKAY");
        assert!(matches!(
            ask_to_confirm(&okay, "?").await,
            Err(Error::FailedToParsePinentry { .. })
        ));
        let silent = answer_confirm("exit", "exit 1");
        assert!(matches!(
            ask_to_confirm(&silent, "?").await,
            Err(Error::PinentryReadOutput { .. })
        ));
        let missing = std::path::Path::new("/nonexistent/rbw-pinentry");
        assert!(matches!(
            ask_to_confirm(missing, "?").await,
            Err(Error::Spawn { .. })
        ));
    }

    #[tokio::test]
    async fn confirmation_nobody_answers_is_refused() {
        let _guard = SPAWN_LOCK.lock().await;
        let program = fake_pinentry("confirm-hang", "exec sleep 600");
        let started = std::time::Instant::now();
        assert!(matches!(
            ask_to_confirm(&program, "?").await,
            Err(Error::PinentryTimedOut)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
    }

    #[tokio::test]
    async fn prompt_text_cannot_add_commands() {
        let _guard = SPAWN_LOCK.lock().await;
        let log = std::env::temp_dir()
            .join(format!("rbw-pinentry-test-{}", std::process::id()))
            .join("getpin.log");
        let _ = std::fs::remove_file(&log);
        let program = fake_pinentry(
            "getpin",
            &format!(
                "echo OK\n\
                 while IFS= read -r line; do\n\
                 printf '%s\\n' \"$line\" >> '{}'\n\
                 case \"$line\" in\n\
                 GETPIN) echo 'D pass%25word'; echo OK; exit 0;;\n\
                 *) echo OK;;\n\
                 esac\n\
                 done",
                log.display()
            ),
        );
        let password = getpin(
            &Pinentry {
                program: program.to_string_lossy().into_owned(),
                timeout: 1,
            },
            "Master Password",
            "Unlock 100%\nGETPIN",
            Some("server said:\r\nBYE"),
            &crate::protocol::Environment::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(password.password(), b"pass%word");
        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            "SETTITLE rbw\nSETPROMPT Master Password\n\
             SETDESC Unlock 100%25%0AGETPIN\n\
             SETERROR server said:%0D%0ABYE\nGETPIN\n"
        );
    }

    #[test]
    fn assuan_text_is_escaped() {
        assert_eq!(assuan_escape("plain text"), "plain text");
        assert_eq!(assuan_escape("100%"), "100%25");
        assert_eq!(assuan_escape("a\nb\r\0c\x7f"), "a%0Ab%0D%00c%7F");
        assert_eq!(assuan_escape("ssh (pid 1) \u{e9}"), "ssh (pid 1) \u{e9}");
        // the escape itself is not decoded twice
        assert_eq!(assuan_escape("%0A"), "%250A");
    }

    #[test]
    fn long_assuan_text_is_cut() {
        let cut = assuan_escape(&"x".repeat(5000));
        assert_eq!(cut.len(), MAX_ASSUAN_ARGUMENT);
        assert!(cut.ends_with("xx..."));

        // never in the middle of a character
        let cut = assuan_escape(&"\u{e9}".repeat(1000));
        assert!(cut.len() <= MAX_ASSUAN_ARGUMENT);
        assert!(cut.trim_end_matches("...").chars().all(|c| c == '\u{e9}'));

        // never in the middle of a %XX sequence
        for prefix in 0..3 {
            let text = "x".repeat(prefix) + &"\n".repeat(1000);
            let cut = assuan_escape(&text);
            assert!(cut.len() <= MAX_ASSUAN_ARGUMENT);
            let body = cut.strip_suffix("...").unwrap();
            // a short last chunk would be a cut sequence
            assert!(body.as_bytes()[prefix..]
                .chunks(3)
                .all(|chunk| chunk == b"%0A"));
        }

        // short enough text is not cut
        let exact = "y".repeat(MAX_ASSUAN_ARGUMENT);
        assert_eq!(assuan_escape(&exact), exact);
    }

    #[test]
    fn only_terminals_are_usable_ttys() {
        assert!(!tty_is_usable(std::ffi::OsStr::new("/dev/null")));
        assert!(!tty_is_usable(std::ffi::OsStr::new("/dev/rbw-no-such-tty")));
    }
}
