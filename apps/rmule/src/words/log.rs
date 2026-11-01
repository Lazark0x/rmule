//! The Networks log pane's words: its title, its key hint, and what it says with
//! nothing to show. A line's own glyph and word are [`Severity`]'s.

use crate::words::severity::Severity;

/// How a line's time reads.
pub const TIME_FORMAT: &str = "%H:%M:%S";

/// How a day reads, on the log's date line and wherever a moment is named.
pub const DAY_FORMAT: &str = "%Y-%m-%d";

/// A warning's or a failure's line: the severity's word, then what it says.
#[must_use]
pub fn worded(word: &str, text: &str) -> String {
    format!("{word}: {text}")
}

/// The pane's title: how many lines, and how many of them the key narrowed to.
#[must_use]
pub fn title(shown: usize, kept: usize, floor: Severity) -> String {
    match floor {
        Severity::Info => format!(" Log ({kept}) "),
        Severity::Warning => format!(" Log ({shown} of {kept}) · warnings and failures "),
        Severity::Failure => format!(" Log ({shown} of {kept}) · failures "),
    }
}

/// The pane's key hint: `f` acts only on the focused log.
#[must_use]
pub const fn hint(focused: bool) -> &'static str {
    if focused {
        " / filter · f severity · z zoom "
    } else {
        " z zoom "
    }
}

/// What the pane says with no line to show.
#[must_use]
pub const fn nothing_shown(floor: Severity) -> &'static str {
    match floor {
        Severity::Info => "nothing has happened yet",
        Severity::Warning => "no warnings or failures",
        Severity::Failure => "no failures",
    }
}
