use std::io::{BufRead as _, Read as _, Write as _};

use anyhow::Context as _;
use rustix::termios::{
    LocalModes, OptionalActions, SpecialCodeIndex, Termios,
};

#[derive(Debug, Clone)]
pub struct SelectItem {
    pub label: String,
    pub highlight: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    Home,
    End,
    Enter,
    Cancel,
    Other,
}

pub fn is_interactive() -> bool {
    is_terminal::is_terminal(std::io::stdin())
        && is_terminal::is_terminal(std::io::stderr())
}

fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
}

fn terminal_width() -> usize {
    terminal_size::terminal_size()
        .map_or(80, |(terminal_size::Width(w), _)| usize::from(w))
}

fn truncate_line(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_string();
    }
    if max_chars <= 1 {
        return s.chars().take(max_chars).collect();
    }
    let mut out: String = s.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

fn decode_key(bytes: &[u8]) -> Key {
    match bytes {
        [b'\r' | b'\n'] => Key::Enter,
        [b'k' | b'K' | 0x10] | [0x1b, b'[' | b'O', b'A'] => Key::Up,
        [b'j' | b'J' | 0x0e] | [0x1b, b'[' | b'O', b'B'] => Key::Down,
        [b'q' | b'Q' | 0x03 | 0x04 | 0x1b] => Key::Cancel,
        [0x1b, b'[' | b'O', b'H'] => Key::Home,
        [0x1b, b'[' | b'O', b'F'] => Key::End,
        _ => Key::Other,
    }
}

struct RawModeGuard {
    original: Termios,
}

impl RawModeGuard {
    fn enter() -> anyhow::Result<Self> {
        let stdin = std::io::stdin();
        let original = rustix::termios::tcgetattr(&stdin)
            .context("failed to read terminal attributes")?;
        let mut raw = original.clone();
        raw.local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO | LocalModes::ISIG);
        raw.special_codes[SpecialCodeIndex::VMIN] = 1;
        raw.special_codes[SpecialCodeIndex::VTIME] = 0;
        rustix::termios::tcsetattr(&stdin, OptionalActions::Now, &raw)
            .context("failed to enable raw terminal mode")?;
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\x1b[?25l");
        let _ = stderr.flush();
        Ok(Self { original })
    }

    fn set_read_timeout(vmin: u8, vtime: u8) {
        let stdin = std::io::stdin();
        if let Ok(mut current) = rustix::termios::tcgetattr(&stdin) {
            current.special_codes[SpecialCodeIndex::VMIN] = vmin;
            current.special_codes[SpecialCodeIndex::VTIME] = vtime;
            let _ = rustix::termios::tcsetattr(
                &stdin,
                OptionalActions::Now,
                &current,
            );
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let stdin = std::io::stdin();
        let _ = rustix::termios::tcsetattr(
            &stdin,
            OptionalActions::Now,
            &self.original,
        );
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\x1b[?25h");
        let _ = stderr.flush();
    }
}

fn read_key() -> anyhow::Result<Key> {
    let mut stdin = std::io::stdin().lock();
    let mut first = [0_u8; 1];
    let n = stdin
        .read(&mut first)
        .context("failed to read from terminal")?;
    if n == 0 {
        return Ok(Key::Cancel);
    }

    if first[0] != 0x1b {
        return Ok(decode_key(&first));
    }

    // Distinguish standalone Escape from multi-byte escape sequences (arrows)
    RawModeGuard::set_read_timeout(0, 1);
    let mut seq = [0x1b, 0, 0];
    let mut len = 1;
    let mut second = [0_u8; 1];
    if stdin.read(&mut second).unwrap_or(0) == 1 {
        seq[1] = second[0];
        len = 2;
        if matches!(second[0], b'[' | b'O') {
            let mut third = [0_u8; 1];
            if stdin.read(&mut third).unwrap_or(0) == 1 {
                seq[2] = third[0];
                len = 3;
            }
        }
    }
    RawModeGuard::set_read_timeout(1, 0);

    Ok(decode_key(&seq[..len]))
}

fn render_menu(
    stderr: &mut std::io::Stderr,
    title: &str,
    items: &[SelectItem],
    selected: usize,
    color: bool,
    redraw: bool,
) -> anyhow::Result<()> {
    let total_lines = items.len() + 1;
    if redraw {
        write!(stderr, "\r\x1b[{total_lines}A")?;
    }

    let max_width = terminal_width().saturating_sub(1);
    let header = truncate_line(
        &format!("{title} (↑/↓ to move, Enter to select, Esc to cancel)"),
        max_width,
    );
    if color {
        writeln!(stderr, "\x1b[1m{header}\x1b[0m\x1b[K")?;
    } else {
        writeln!(stderr, "{header}\x1b[K")?;
    }

    let item_max = max_width.saturating_sub(2);
    for (idx, item) in items.iter().enumerate() {
        let label = truncate_line(&item.label, item_max);
        if idx == selected {
            if color {
                writeln!(stderr, "\x1b[1;36m> {label}\x1b[0m\x1b[K")?;
            } else {
                writeln!(stderr, "> {label}\x1b[K")?;
            }
        } else if item.highlight && color {
            writeln!(stderr, "  \x1b[32m{label}\x1b[0m\x1b[K")?;
        } else {
            writeln!(stderr, "  {label}\x1b[K")?;
        }
    }
    stderr.flush()?;
    Ok(())
}

fn clear_menu(
    stderr: &mut std::io::Stderr,
    item_count: usize,
) -> anyhow::Result<()> {
    let total_lines = item_count + 1;
    write!(stderr, "\r\x1b[{total_lines}A\x1b[J")?;
    stderr.flush()?;
    Ok(())
}

pub fn select(
    title: &str,
    items: &[SelectItem],
    initial_index: usize,
) -> anyhow::Result<Option<usize>> {
    if items.is_empty() {
        return Ok(None);
    }

    let _guard = RawModeGuard::enter()?;
    let color = use_color();
    let mut selected = initial_index.min(items.len() - 1);
    let mut stderr = std::io::stderr();

    render_menu(&mut stderr, title, items, selected, color, false)?;

    loop {
        match read_key()? {
            Key::Up => {
                selected = if selected == 0 {
                    items.len() - 1
                } else {
                    selected - 1
                };
                render_menu(
                    &mut stderr,
                    title,
                    items,
                    selected,
                    color,
                    true,
                )?;
            }
            Key::Down => {
                selected = (selected + 1) % items.len();
                render_menu(
                    &mut stderr,
                    title,
                    items,
                    selected,
                    color,
                    true,
                )?;
            }
            Key::Home => {
                selected = 0;
                render_menu(
                    &mut stderr,
                    title,
                    items,
                    selected,
                    color,
                    true,
                )?;
            }
            Key::End => {
                selected = items.len() - 1;
                render_menu(
                    &mut stderr,
                    title,
                    items,
                    selected,
                    color,
                    true,
                )?;
            }
            Key::Enter => {
                clear_menu(&mut stderr, items.len())?;
                return Ok(Some(selected));
            }
            Key::Cancel => {
                clear_menu(&mut stderr, items.len())?;
                return Ok(None);
            }
            Key::Other => {}
        }
    }
}

pub fn input(
    prompt: &str,
    default: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let mut stderr = std::io::stderr();
    if let Some(default) = default {
        write!(stderr, "{prompt} [{default}]: ")?;
    } else {
        write!(stderr, "{prompt}: ")?;
    }
    stderr.flush()?;

    let mut line = String::new();
    let n = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read input from terminal")?;
    if n == 0 {
        return Ok(None);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.map(str::to_string))
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

pub fn confirm(prompt: &str, default_yes: bool) -> anyhow::Result<bool> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    let mut stderr = std::io::stderr();
    write!(stderr, "{prompt} [{hint}]: ")?;
    stderr.flush()?;

    let mut line = String::new();
    let n = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read confirmation from terminal")?;
    if n == 0 {
        return Ok(false);
    }
    let trimmed = line.trim().to_ascii_lowercase();
    Ok(match trimmed.as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_key() {
        assert_eq!(decode_key(b"\x1b[A"), Key::Up);
        assert_eq!(decode_key(b"\x1bOA"), Key::Up);
        assert_eq!(decode_key(b"k"), Key::Up);
        assert_eq!(decode_key(b"\x1b[B"), Key::Down);
        assert_eq!(decode_key(b"\x1bOB"), Key::Down);
        assert_eq!(decode_key(b"j"), Key::Down);
        assert_eq!(decode_key(b"\x1b[H"), Key::Home);
        assert_eq!(decode_key(b"\x1b[F"), Key::End);
        assert_eq!(decode_key(b"\r"), Key::Enter);
        assert_eq!(decode_key(b"\n"), Key::Enter);
        assert_eq!(decode_key(b"\x1b"), Key::Cancel);
        assert_eq!(decode_key(b"q"), Key::Cancel);
        assert_eq!(decode_key(&[0x03]), Key::Cancel);
        assert_eq!(decode_key(&[0x04]), Key::Cancel);
        assert_eq!(decode_key(b"x"), Key::Other);
    }

    #[test]
    fn test_truncate_line() {
        assert_eq!(truncate_line("hello", 10), "hello");
        assert_eq!(truncate_line("hello", 5), "hello");
        assert_eq!(truncate_line("hello world", 5), "hell…");
        assert_eq!(truncate_line("hello", 1), "h");
        assert_eq!(truncate_line("hello", 0), "");
    }
}
