//! The operator's words: every sentence a front end shows, written here from
//! the codes core hands it. Core carries codes and data; the front ends own
//! the language, so it can be translated and nothing an operator reads shows
//! code — no `Debug`, no core type's `Display`. Both front ends speak from
//! here: the TUI on its log pane, status bar and flashes, the CLI on its
//! output lines.
//!
//! One module per domain, each wording its vocabulary with an exhaustive
//! `match`, so a code core adds cannot reach an operator without its words.
//! The TUI's log pane, status bar note and flash take a [`Sentence`]. One
//! is made only in a words module: this crate's, or the TUI's own, which
//! words the TUI's own types. `scripts/guards.sh` refuses a constructor
//! call anywhere else, so a `String` built elsewhere cannot reach those
//! surfaces.

#![warn(missing_docs)]

use std::borrow::Cow;
use std::fmt;

pub mod app;
pub mod download;
pub mod event;
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
pub mod software;
pub mod store;
pub mod units;

/// A sentence the operator reads — a Networks log line, the status bar's
/// note, a flash. Its field is private, and its constructors are called
/// only in a words module (see the crate docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sentence(Cow<'static, str>);

impl Sentence {
    /// A sentence that is always the same. Called only in a words module.
    #[must_use]
    pub const fn fixed(text: &'static str) -> Self {
        Self(Cow::Borrowed(text))
    }

    /// A sentence written from data. Called only in a words module.
    #[must_use]
    pub fn owned(text: String) -> Self {
        Self(Cow::Owned(text))
    }

    /// The text, to draw.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Any text as a sentence, for a test that exercises a surface's layout
    /// rather than its words.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn for_test(text: impl Into<String>) -> Self {
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
