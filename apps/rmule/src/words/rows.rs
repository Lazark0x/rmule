//! The words a row's actions speak: what a confirm asks by name or count, what
//! the Row Filter counts, and how a pane counts its Tags.

use super::Sentence;

/// What a sentence calls a file whose name has not landed yet.
pub const UNNAMED_FILE: &str = "a file whose name is not known yet";

/// What the cancel confirm asks of one download: by name, its size and how
/// much of it is done when they are known.
#[must_use]
pub fn cancel_one(name: &str, size: &str, done: Option<&str>) -> String {
    match done {
        Some(done) => format!("Cancel {name} ({size}, {done} done)?"),
        None => format!("Cancel {name} ({size})?"),
    }
}

/// What the cancel confirm asks of several downloads.
#[must_use]
pub fn cancel_many(count: usize) -> String {
    format!("Cancel {count} downloads?")
}

/// What a yes to the cancel confirm does.
#[must_use]
pub const fn cancel_does(count: usize) -> &'static str {
    if count == 1 {
        "This deletes the part file. It cannot be undone."
    } else {
        "This deletes their part files. It cannot be undone."
    }
}

/// What the unshare confirm asks of one file, by name.
#[must_use]
pub fn unshare_one(name: &str) -> String {
    format!("Unshare {name}?")
}

/// What the unshare confirm asks of several files.
#[must_use]
pub fn unshare_many(count: usize) -> String {
    format!("Unshare {count} files?")
}

/// What a yes to the unshare confirm does.
pub const UNSHARE_DOES: &str = "Stops serving it; peers lose the source.";

/// What the remove confirm asks of one server, by name and address.
#[must_use]
pub fn remove_one(name: &str, address: &str) -> String {
    format!("Remove {name} ({address})?")
}

/// What the remove confirm asks of several servers.
#[must_use]
pub fn remove_many(count: usize) -> String {
    format!("Remove {count} servers?")
}

/// What a yes to the remove confirm does: the list entry goes, a session does
/// not (ADR-0080).
pub const REMOVE_DOES: &str = "The list entry goes; a session connected to it stays up.";

/// The Row Filter's count: how many rows hold what is typed.
#[must_use]
pub fn filter_count(kept: usize, total: usize) -> String {
    format!("{kept} of {total}")
}

/// A list the Row Filter left empty.
pub const NO_MATCH: &str = "nothing here holds what is typed";

/// A pane's count of its tagged rows.
#[must_use]
pub fn tagged(count: usize) -> String {
    format!("{count} tagged")
}

/// Why a row menu's item waits while rows are tagged.
pub const ONE_ROW_ONLY: &str = "one row at a time";

/// Tagged results the operator has a history with, left for a row of their own.
#[must_use]
pub fn tagged_marked_left(count: usize) -> Sentence {
    Sentence::owned(format!(
        "{count} tagged left: they ask first, one at a time"
    ))
}
