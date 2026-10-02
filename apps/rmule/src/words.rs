//! The TUI's words: every sentence the operator reads, written here from the
//! codes core hands the TUI. Core carries codes and data; the TUI owns
//! the language, so it can be translated and nothing on screen reads as code
//! — no `Debug`, no core type's `Display`.
//!
//! One module per domain, each wording its vocabulary with an exhaustive
//! `match`, so a code core adds cannot reach the screen without its words.
//! The log pane, the status bar's note and the flash take a [`Sentence`], and
//! only this module and its children can make one: a `String` built anywhere
//! else cannot reach those surfaces.

use std::borrow::Cow;
use std::fmt;

pub mod app;
pub mod download;
pub mod event;
pub mod front_door;
pub mod kad;
pub mod login;
pub mod os;
pub mod peer;
pub mod portmap;
pub mod reach;
pub mod scan;
pub mod search;
pub mod serve;
pub mod server;
pub mod store;
pub mod units;

/// A sentence the operator reads — a Networks log line, the status bar's
/// note, a flash. Its field is private to this module and its children, so
/// one is made only by the words modules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sentence(Cow<'static, str>);

impl Sentence {
    /// A sentence that is always the same.
    const fn fixed(text: &'static str) -> Self {
        Self(Cow::Borrowed(text))
    }

    /// A sentence written from data.
    fn owned(text: String) -> Self {
        Self(Cow::Owned(text))
    }

    /// The text, to draw.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Any text as a sentence, for a test that exercises a surface's layout
    /// rather than its words.
    #[cfg(test)]
    pub(crate) fn for_test(text: impl Into<String>) -> Self {
        Self::owned(text.into())
    }
}

impl std::ops::Deref for Sentence {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sentence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for Sentence {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Sentence {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}
