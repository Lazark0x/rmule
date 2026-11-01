//! The Shared Files tab's words.

/// A shared file with nothing wrong.
pub const SHARED: &str = "shared";
/// The title's total before every size is read.
pub const SIZE_BEING_READ: &str = "size still being read";
/// Why a file's link cannot be copied yet.
pub const NOT_READ_YET: &str = "its name and size are not read yet";
/// The peers pane showing the active ones.
pub const ACTIVE_ONLY: &str = "active only";
/// The peers pane showing every peer.
pub const ALL_PEERS: &str = "all";
/// The peers pane with nobody in it.
pub const NO_UPLOAD_ACTIVITY: &str = "no upload activity";
/// The peers table with nobody active.
pub const NO_ACTIVE_UPLOADS: &str = "no active uploads";

/// A withheld file's state: why, and since when.
#[must_use]
pub fn withheld_since(why: &str, day: &str) -> String {
    format!("{why} since {day}")
}

/// The files pane's title.
#[must_use]
pub fn files_title(files: &str, total: &str, tagged: Option<&str>) -> String {
    match tagged {
        Some(tagged) => format!(" Shared Files · {files} · {total} · {tagged} "),
        None => format!(" Shared Files · {files} · {total} "),
    }
}

/// The peers pane's title.
#[must_use]
pub fn uploads_title(mode: &str) -> String {
    format!(" Uploads · {mode} ")
}
