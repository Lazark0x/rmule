//! The TUI's own search words, beside the shared ones it re-exports: why a
//! search entry has no more to ask for, and why nothing can be sent — which
//! word the TUI's own types.

pub use rmule_words::search::*;

use super::Sentence;
use crate::state::MoreEnded;

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

/// What a held entry shows when the engine stopped under it while it ran.
pub const STOPPED_WITH_THE_ENGINE: &str = "stopped with the engine";

/// [`STOPPED_WITH_THE_ENGINE`] opening a pane's title.
pub const STOPPED_WITH_THE_ENGINE_TITLE: &str = "Stopped with the engine";

/// Why nothing can be sent now.
pub const ENGINE_STOPPED: &str = "the engine has stopped";

/// `n` with the engine stopped.
pub const NOTHING_SENT: Sentence = Sentence::fixed("nothing sent — the engine has stopped");
