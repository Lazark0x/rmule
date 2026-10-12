//! The TUI's own search words, beside the shared ones it re-exports: why a
//! search entry has no more to ask for, and why nothing can be sent — which
//! word the TUI's own types.

pub use rmule_words::search::*;

use super::Sentence;
use crate::state::{AttachFailure, MoreEnded};

/// A [`MoreEnded`] as the operator reads it in the entry's status line.
#[must_use]
pub const fn more_ended_words(ended: MoreEnded) -> &'static str {
    match ended {
        MoreEnded::Replaced => {
            "no more to ask for: a newer search replaced the rows the server kept"
        }
        MoreEnded::Answered => "the server sent all it had",
        MoreEnded::Disconnected => "no more to ask for: the server that kept them disconnected",
    }
}

/// `n` on a search whose server holds no more for it, and why.
#[must_use]
pub fn more_ended(ended: Option<MoreEnded>) -> Sentence {
    Sentence::fixed(ended.map_or(MORE_REFUSED, more_ended_words))
}

/// Why nothing can be sent now: no core attached, and why (`Some`), or the
/// core stopped (`None`).
#[must_use]
pub fn no_core_words(ui_only: Option<AttachFailure>) -> String {
    match ui_only {
        Some(failure) => format!(
            "no core is attached (UI-only run: {})",
            super::app::attach_failure_words(failure)
        ),
        None => "the core has stopped".to_string(),
    }
}

/// `n` with no core to send through.
#[must_use]
pub fn nothing_sent(ui_only: Option<AttachFailure>) -> Sentence {
    Sentence::owned(format!("nothing sent — {}", no_core_words(ui_only)))
}
