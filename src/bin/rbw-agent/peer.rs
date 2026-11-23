// Names the program on the other end of an ssh agent connection, for the
// prompt that approves a signature.
//
// A program can give itself any name, so the description is a hint for the
// person approving, not proof of who is asking. It is cleaned up before it
// is shown: control and invisible formatting characters are replaced, and
// names are cut to a bounded length.

// Process names are at most 15 bytes on Linux and 32 on macOS. Anything
// longer did not come from the kernel.
const MAX_NAME_CHARS: usize = 64;

// For example "ssh (pid 4242), started by git".
pub fn describe(socket: &tokio::net::UnixStream) -> String {
    let Some(pid) = socket.peer_cred().ok().and_then(|cred| cred.pid())
    else {
        return "an unknown program".to_string();
    };
    describe_pid(pid)
}

fn describe_pid(pid: libc::pid_t) -> String {
    let Some((name, parent)) = process_info(pid) else {
        return format!("process {pid}");
    };
    let name = printable(&name, MAX_NAME_CHARS);
    parent.and_then(process_info).map_or_else(
        || format!("{name} (pid {pid})"),
        |(parent_name, _)| {
            let parent_name = printable(&parent_name, MAX_NAME_CHARS);
            format!("{name} (pid {pid}), started by {parent_name}")
        },
    )
}

// Text from outside rbw (a process or entry name) made safe to show in a
// prompt: control characters, and the Unicode characters that reorder or
// hide text, become '?', and text over max_chars characters is cut and ends
// with "...".
pub fn printable(text: &str, max_chars: usize) -> String {
    let mut out: String = text
        .chars()
        .take(max_chars)
        .map(|c| {
            if c.is_control() || is_invisible(c) {
                '?'
            } else {
                c
            }
        })
        .collect();
    if text.chars().nth(max_chars).is_some() {
        out.push_str("...");
    }
    out
}

// Zero width characters and bidirectional overrides, which can make a name
// read as something else.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
    )
}

// Returns the process name and its parent pid.
#[cfg(target_os = "macos")]
fn process_info(pid: libc::pid_t) -> Option<(String, Option<libc::pid_t>)> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size =
        libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .ok()?;
    // SAFETY: the buffer is exactly one proc_bsdinfo, as its size says.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo filled the whole struct.
    let info = unsafe { info.assume_init() };

    let name = c_chars_to_string(&info.pbi_name)
        .filter(|name| !name.is_empty())
        .or_else(|| c_chars_to_string(&info.pbi_comm))?;
    let parent = libc::pid_t::try_from(info.pbi_ppid)
        .ok()
        .filter(|&ppid| ppid > 1);
    Some((name, parent))
}

#[cfg(target_os = "macos")]
fn c_chars_to_string(chars: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = chars
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c.to_ne_bytes()[0])
        .collect();
    String::from_utf8(bytes).ok()
}

// Returns the process name and its parent pid.
#[cfg(target_os = "linux")]
fn process_info(pid: libc::pid_t) -> Option<(String, Option<libc::pid_t>)> {
    // the name and the parent come from one read of one file, so they
    // describe the same process even if the pid is reused meanwhile
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_stat(&String::from_utf8_lossy(&stat))
}

// Parses /proc/<pid>/stat: "<pid> (<comm>) <state> <ppid> ...". The name
// can itself hold spaces and parentheses, so it ends at the last ')'.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat(stat: &str) -> Option<(String, Option<libc::pid_t>)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat.get(open + 1..close)?.to_string();
    let mut fields = stat.get(close + 1..)?.split_ascii_whitespace();
    let _state = fields.next()?;
    // pid 1 (init) and pid 0 (the kernel) start everything, and naming them
    // would tell nothing
    let parent = fields
        .next()?
        .parse::<libc::pid_t>()
        .ok()
        .filter(|&ppid| ppid > 1);
    Some((name, parent))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_info(_pid: libc::pid_t) -> Option<(String, Option<libc::pid_t>)> {
    None
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn c_chars_stop_at_nul() {
        let chars: Vec<libc::c_char> = b"ssh\0junk"
            .iter()
            .map(|&b| libc::c_char::from_ne_bytes([b]))
            .collect();
        assert_eq!(super::c_chars_to_string(&chars).as_deref(), Some("ssh"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn own_process_is_described() {
        let pid = libc::pid_t::try_from(std::process::id()).unwrap();
        // the parent isn't checked: it is left out for pid 1, which the
        // tests can be in a container
        let (name, _) = super::process_info(pid).unwrap();
        assert_ne!(name, "");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_process_description_names_the_parent() {
        let pid = libc::pid_t::try_from(std::process::id()).unwrap();
        let (name, parent) = super::process_info(pid).unwrap();
        if parent.is_none() {
            // run directly under pid 1, so there is no parent to name
            return;
        }
        let description = super::describe_pid(pid);
        assert!(
            description.starts_with(&format!(
                "{} (pid {pid}), started by ",
                super::printable(&name, super::MAX_NAME_CHARS)
            )),
            "{description}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn socket_peer_is_described() {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let pid = std::process::id();
        assert!(super::describe(&a).contains(&format!("(pid {pid})")));
    }

    #[test]
    fn proc_stat_is_parsed() {
        assert_eq!(
            super::parse_proc_stat("4242 (ssh) S 4200 4242 4200 0 -1 0"),
            Some(("ssh".to_string(), Some(4200)))
        );
        // names with spaces and parentheses
        assert_eq!(
            super::parse_proc_stat("7 (a) b (c) R 1234 7 7"),
            Some(("a) b (c".to_string(), Some(1234)))
        );
        assert_eq!(
            super::parse_proc_stat("7 () R 1234 7 7"),
            Some((String::new(), Some(1234)))
        );
        // a name that looks like more fields
        assert_eq!(
            super::parse_proc_stat("7 (x) S 1 ) Z 666) S 99 7 7"),
            Some(("x) S 1 ) Z 666".to_string(), Some(99)))
        );
        // started by init or the kernel: no parent worth naming
        assert_eq!(
            super::parse_proc_stat("7 (sshd) S 1 7 7"),
            Some(("sshd".to_string(), None))
        );
        assert_eq!(
            super::parse_proc_stat("2 (kthreadd) S 0 0 0"),
            Some(("kthreadd".to_string(), None))
        );
        // malformed
        assert_eq!(super::parse_proc_stat(""), None);
        assert_eq!(super::parse_proc_stat("7 (ssh"), None);
        assert_eq!(super::parse_proc_stat("7 ssh) S 3"), None);
        assert_eq!(super::parse_proc_stat("7 (ssh) S"), None);
        assert_eq!(
            super::parse_proc_stat("7 (ssh) S nope"),
            Some(("ssh".to_string(), None))
        );
    }

    #[test]
    fn names_are_made_printable() {
        assert_eq!(super::printable("git", 64), "git");
        assert_eq!(super::printable("caf\u{e9}", 64), "caf\u{e9}");
        assert_eq!(
            super::printable("ssh\nGETPIN\r\0\u{1b}[2J", 64),
            "ssh?GETPIN???[2J"
        );
        // right-to-left override and zero width space
        assert_eq!(
            super::printable("\u{202e}hss\u{200b}x\u{feff}", 64),
            "?hss?x?"
        );
        assert_eq!(super::printable("abcdef", 3), "abc...");
        assert_eq!(super::printable("abc", 3), "abc");
        assert_eq!(
            super::printable(&"\u{e9}".repeat(100), 64),
            "\u{e9}".repeat(64) + "..."
        );
    }
}
