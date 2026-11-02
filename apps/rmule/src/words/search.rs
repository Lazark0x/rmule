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

/// The empty results pane while the query holds the keyboard.
pub const TYPE_A_QUERY: &str = "type a query, Enter searches";

/// The empty results pane with the query left alone.
pub const PRESS_SLASH: &str = "press / and type a query";

/// A search closed: its one undo.
pub const CLOSED: crate::words::Sentence =
    crate::words::Sentence::fixed("search closed: u brings it back");

/// What the empty results pane says while a search waits for a connection.
pub const WAITING_FOR_A_CONNECTION: &str =
    "waiting for a connection — press c on a server in Networks (1) to connect";
/// What it says while a search runs.
pub const SEARCHING: &str = "searching…";
/// What it says of a finished search with nothing to list.
pub const NO_RESULTS: &str = "no results";
/// What it says of a stopped search.
pub const SEARCH_CANCELLED: &str = "search cancelled";
/// What it says of a failed one.
pub const SEARCH_FAILED: &str = "search failed";
/// The query pane's title.
pub const SEARCH_TITLE: &str = " Search ";
/// An empty answer. A server that grants the search and does not implement it
/// reads the same, and rmule keeps no per-server verdict (ADR-0037).
pub const NO_RELATED_FILES: &str =
    "no related files — the server found none, or the file has too few sources for it to answer";
/// The re-add confirm over a failed download.
pub const RESTART_TITLE: &str = " Restart download? ";
/// The re-add confirm over a file held before.
pub const AGAIN_TITLE: &str = " Download again? ";

/// The results pane's title with nothing asked yet.
pub const RESULTS: &str = " Results ";
/// A search never sent.
pub const RESULTS_NOT_SENT: &str = " Results · Not sent ";
/// The status clause of a search waiting on a reconnect.
pub const WAITING_RECONNECT: &str = "Waiting for the reconnect · sent when it lands";
/// The status clause of a search waiting on the operator's connect.
pub const WAITING_CONNECTION: &str = "Waiting for a connection · sent when you connect";
/// The status clause of a running search.
pub const STATUS_RUNNING: &str = "Running…";
/// The status clause of a stopped search.
pub const STATUS_CANCELLED: &str = "Cancelled";
/// The status clause of a refused search.
pub const STATUS_REFUSED: &str = "Refused";

/// The status clause of a search held back by the server's flood limit.
#[must_use]
pub fn waiting_turn(seconds: u64) -> String {
    format!("Waiting its turn on this server · sent in {seconds} s")
}

/// The status clause of a finished search.
#[must_use]
pub fn status_completed(total: usize) -> String {
    format!("Completed · {total}")
}

/// The status clause of a failed search.
#[must_use]
pub fn status_failed(why: &str) -> String {
    format!("Failed · {why}")
}

/// The results pane's title around a status clause.
#[must_use]
pub fn results_title(status: &str, skipped: usize) -> String {
    if skipped > 0 {
        format!(" Results · {status} · {skipped} skipped ")
    } else {
        format!(" Results · {status} ")
    }
}

/// How many rows the fold dropped for answering no running search.
#[must_use]
pub fn unattributed(rows: u64) -> String {
    super::plural::Plural::new(
        " {n} row answered no running search and was dropped ",
        " {n} rows answered no running search and were dropped ",
    )
    .of(rows)
}

/// What the results pane says of an entry never sent, a related one naming no
/// query to keep.
#[must_use]
pub fn not_sent(why: &str, related: bool) -> String {
    if related {
        format!("not sent — {why}")
    } else {
        format!("not sent — {why}. The query is still in the input.")
    }
}

/// The query line of a related search whose file has no name yet.
#[must_use]
pub fn related_to_hash(hash: &str) -> String {
    format!("related to: the file with hash {hash} — its name is not known yet")
}

/// The query line of a related search.
#[must_use]
pub fn related_to(name: &str) -> String {
    format!("related to: {name}")
}

/// A related search a server refused.
#[must_use]
pub fn refused_for(why: &str) -> String {
    format!("refused: {why}")
}
