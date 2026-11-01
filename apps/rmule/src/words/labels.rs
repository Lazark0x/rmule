//! The short words a menu row and a status cell wear. Each is a constant the
//! views name, so a label has one place to be translated; sorting never reads
//! them.

use crate::state::DownloadStatus;

/// A row menu's copy of the row's eD2k link.
pub const COPY_LINK: &str = "Copy eD2k link";
/// The download action.
pub const DOWNLOAD: &str = "Download";
/// The search for files related to a row's file.
pub const SEARCH_RELATED: &str = "Search related";
/// A download row's cancel, which asks first.
pub const CANCEL: &str = "Cancel…";
/// A download row's details.
pub const SHOW_DETAILS: &str = "Show file details";
/// A download row's preview.
pub const PREVIEW: &str = "Preview";
/// A running download's pause.
pub const PAUSE: &str = "Pause";
/// A paused download's resume.
pub const RESUME: &str = "Resume";
/// A failed download's restart.
pub const RESTART: &str = "Restart";
/// A completed download's way out of the list.
pub const CLEAR_FROM_LIST: &str = "Clear from list";
/// A shared file's unshare, which asks first.
pub const UNSHARE: &str = "Unshare…";
/// A shared file's comments, which rmule holds none of.
pub const COMMENTS: &str = "Comments";
/// The server list's update.
pub const UPDATE_LIST: &str = "Update list from URL… (U)";
/// The server list's add.
pub const ADD_SERVER: &str = "Add server… (a)";
/// A server row's connect.
pub const CONNECT: &str = "Connect (c)";
/// A server row's disconnect.
pub const DISCONNECT: &str = "Disconnect (c)";
/// A server row's end of re-making a lost session.
pub const STOP_RECONNECTING: &str = "Stop reconnecting (c)";
/// A static server row's unpin.
pub const UNPIN: &str = "Unpin (currently static)";
/// A server row's pin.
pub const PIN: &str = "Pin as static";
/// A server row's copy of its link.
pub const COPY_SERVER_LINK: &str = "Copy server link";
/// The server menu's item for what the server grants, its health and shares.
pub const DETAILS: &str = "Details";
/// A server row's removal, which asks first.
pub const REMOVE: &str = "Remove…";

/// A running download while core re-makes the operator's session.
pub const RECONNECTING: &str = "Reconnecting";
/// A download Kad alone can find sources for.
pub const ASKING_KAD: &str = "Asking Kad";
/// A download parked on its queue standings at peers.
pub const QUEUED: &str = "Queued";

/// A download that holds a slot and has moved no bytes for a while.
pub const STALLED: &str = "Stalled";

/// A download's status in its cell of eleven cells.
#[must_use]
pub const fn status(status: DownloadStatus) -> &'static str {
    match status {
        DownloadStatus::Waiting => "Waiting",
        // Waiting for a server session or Kad: the status column's eleven
        // cells hold "Downloading" and no more.
        DownloadStatus::NoConnection => "No network",
        DownloadStatus::Downloading => "Downloading",
        DownloadStatus::Paused => "Paused",
        DownloadStatus::Completing => "Completing",
        DownloadStatus::Completed => "Completed",
        DownloadStatus::Failed => "Failed",
    }
}
