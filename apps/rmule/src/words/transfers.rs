//! The Transfers tab's own words: its panes, the details modal's rows, and
//! why a row's item waits.

use crate::words::units;

/// The details modal's title.
pub const DETAILS_TITLE: &str = " File details ";
/// A details row: the file's name.
pub const NAME: &str = "name";
/// A details row: its hash.
pub const HASH: &str = "hash";
/// A details row: its size.
pub const SIZE: &str = "size";
/// A details row: where the record came from.
pub const ORIGIN: &str = "origin";
/// A details row: how much is done.
pub const DONE: &str = "done";
/// A details row: its rate.
pub const SPEED: &str = "speed";
/// A details row: its sources.
pub const SOURCES: &str = "sources";
/// A details row: what it takes on disk.
pub const ON_DISK: &str = "on disk";
/// A details row: why it failed.
pub const FAILED: &str = "failed";
/// A details row: what its run waits on.
pub const WAITING: &str = "waiting";
/// A details row: what stopped it.
pub const STOPPED: &str = "stopped";
/// A details row: what reads its parts back.
pub const CHECKING: &str = "checking";
/// A details row: what its completion is doing.
pub const MOVE: &str = "move";

/// Every label the details modal may show, which its label column is sized to.
pub const DETAIL_LABELS: [&str; 13] = [
    NAME, HASH, SIZE, ORIGIN, DONE, SPEED, SOURCES, ON_DISK, FAILED, WAITING, STOPPED, CHECKING,
    MOVE,
];

/// A download whose record came from a link.
pub const ORIGIN_LINK: &str = "link";
/// A download whose link was recovered.
pub const ORIGIN_RECOVERED: &str = "recovered link";

/// The empty downloads pane.
pub const NO_DOWNLOADS: &str =
    "no downloads — start one from Searches, or paste an eD2k link with L";
/// Why a completed row has no cancel.
pub const COMPLETED_IS_KEPT: &str = "completed: the file is kept and shared";
/// Why a row's search-related waits.
pub const HASH_NOT_KNOWN: &str = "file hash not known yet";
/// Why a named row's link waits.
pub const FILE_NAME_UNKNOWN: &str = "file name unknown";
/// Why a row with no record's link waits.
pub const NO_METADATA: &str = "no metadata yet";
/// The sources pane with no row selected.
pub const NO_DOWNLOAD_SELECTED: &str = "no download selected";
/// The sources pane of a row with none active.
pub const NO_ACTIVE_SOURCES: &str = "no active sources";

/// The downloads pane's title.
#[must_use]
pub fn downloads_title(count: usize, tagged: Option<&str>) -> String {
    match tagged {
        Some(tagged) => format!(" Downloads ({count}) · {tagged} "),
        None => format!(" Downloads ({count}) "),
    }
}

/// The sources pane's title, naming the row when one is selected.
#[must_use]
pub fn sources_title(name: Option<&str>) -> String {
    match name {
        Some(name) => format!(" Sources · {name} "),
        None => " Sources ".to_string(),
    }
}

/// The details modal's done row: the percent, and the parts when there are.
#[must_use]
pub fn done_of_parts(percent: &str, verified: u64, total: u64) -> String {
    format!("{percent}  ({verified}/{total} parts)")
}

/// The Size cell of a size only estimated from its parts.
#[must_use]
pub fn estimated(size: &str) -> String {
    format!("≈ {size}")
}

/// The widest percent the Done column shows.
#[must_use]
pub fn widest_percent() -> String {
    units::percent(100)
}
