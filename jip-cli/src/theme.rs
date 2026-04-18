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

/// Output mode: styled terminal output vs plain pipe-friendly text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Colored, aligned table output for an interactive terminal.
    Pretty,
    /// Tab-separated, no ANSI escapes — friendly to `awk`/`cut`/`grep`.
    Plain,
}

/// Detect the terminal mode and store it for the lifetime of the process.
/// Must be called once at startup before any render functions are used.
pub fn init() {
    let tty = std::io::stdout().is_terminal();
    let force = std::env::var("CLICOLOR_FORCE")
        .ok()
        .is_some_and(|v| !v.is_empty() && v != "0");
    let mode = if tty || force {
        Mode::Pretty
    } else {
        Mode::Plain
    };
    let _ = MODE.set(mode);
}

/// Return the current output mode. Defaults to [`Mode::Plain`] if
/// [`init`] has not been called.
pub fn mode() -> Mode {
    MODE.get().copied().unwrap_or(Mode::Plain)
}

/// Return `true` when output is going to a non-TTY (pipe / file).
pub fn is_plain() -> bool {
    mode() == Mode::Plain
}

// --- palette ---------------------------------------------------------
// All render modules draw from these; swap here to change the whole CLI.

/// Bold + underline style for table headers.
pub fn header() -> Style {
    Style::new().bold().underline()
}
/// Dimmed style for de-emphasised text (placeholders, secondary info).
pub fn dim() -> Style {
    Style::new().dimmed()
}
/// Bold green for a healthy / successful state.
pub fn ok() -> Style {
    Style::new()
        .fg_color(Some(Color::Ansi(AnsiColor::Green)))
        .bold()
}
/// Regular green for a healthy state without strong emphasis.
pub fn ok_soft() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)))
}
/// Yellow for a warning or degraded state.
pub fn warn() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)))
}
/// Bold red for a broken or error state.
pub fn bad() -> Style {
    Style::new()
        .fg_color(Some(Color::Ansi(AnsiColor::Red)))
        .bold()
}
/// Cyan for informational annotations.
pub fn info() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan)))
}
/// Blue accent for TCP protocol labels and similar.
pub fn accent() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Blue)))
}
/// Magenta accent for UDP protocol labels and similar.
pub fn accent2() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::Magenta)))
}
/// Bold text without a color change, for process names and key values.
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
