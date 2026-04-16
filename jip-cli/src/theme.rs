//! Terminal awareness: layout mode + color palette.
//!
//! Color suppression (`NO_COLOR`, `CLICOLOR_FORCE`, non-TTY) is handled
//! for us by [`anstream::stdout`], which strips ANSI when stdout isn't a
//! real terminal. So we don't gate style emission ourselves — we just
//! always write `anstyle` escapes and let anstream filter.
//!
//! What we *do* decide here: the layout mode. Pretty (aligned `tabled`
//! output, headers, color styles applied) vs Plain (tab-separated,
//! no headers) — the latter is friendly to `jip | awk`.
//!
//! Rule: non-TTY stdout ⇒ Plain. TTY (or `CLICOLOR_FORCE=1`) ⇒ Pretty.
//! `--json` bypasses this module entirely.

use std::io::IsTerminal;
use std::sync::OnceLock;

use anstyle::{AnsiColor, Color, Style};

static MODE: OnceLock<Mode> = OnceLock::new();

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Pretty,
    Plain,
}

pub fn init() {
    let tty = std::io::stdout().is_terminal();
    let force = std::env::var("CLICOLOR_FORCE")
        .ok()
        .is_some_and(|v| !v.is_empty() && v != "0");
    let mode = if tty || force { Mode::Pretty } else { Mode::Plain };
    let _ = MODE.set(mode);
}

pub fn mode() -> Mode {
    MODE.get().copied().unwrap_or(Mode::Plain)
}

pub fn is_plain() -> bool { mode() == Mode::Plain }

// --- palette ---------------------------------------------------------
// All render modules draw from these; swap here to change the whole CLI.

pub fn header() -> Style {
    Style::new().bold().underline()
}
pub fn dim() -> Style {
    Style::new().dimmed()
}
pub fn ok() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))).bold()
}
pub fn ok_soft() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)))
}
pub fn warn() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)))
}
pub fn bad() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red))).bold()
}
pub fn info() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan)))
}
pub fn accent() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Blue)))
}
pub fn accent2() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Magenta)))
}
pub fn strong() -> Style {
    Style::new().bold()
}

/// Wrap `text` in the given style, or return it unchanged in Plain mode so
/// pipe consumers never see escapes. Call sites stop caring about which
/// mode we're in.
pub fn paint<S: AsRef<str>>(style: Style, text: S) -> String {
    if is_plain() {
        text.as_ref().to_string()
    } else {
        format!("{style}{}{style:#}", text.as_ref())
    }
}

/// Dim a literal placeholder like "-" so empty cells don't draw the eye.
pub fn dim_placeholder(s: &str) -> String {
    paint(dim(), s)
}
