//! The **Shared Directory List**'s, its scans' and the folder watch's words
//! (ADR-0100): every edge as a status-feed and log sentence, why a directory
//! was refused, each entry's state, and the two confirms — sharing a
//! directory and stopping.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rmule_core::{
    DirectoryOffer, DirectoryRefusal, DirectoryRole, DirectoryState, ScanEvent, ScanPhase,
    WatchFault,
};

use super::Sentence;
use super::os::{kind_words, refusal_words};
use crate::state::SharedUnder;
use crate::views::human_size;

/// Why a watch does not hold, as a clause: "… not watched: {this}".
#[must_use]
pub fn watch_fault_words(fault: WatchFault) -> String {
    match fault {
        WatchFault::Limit => "the system's limit on watched files is reached \
             (on Linux, raise fs.inotify.max_user_watches)"
            .to_string(),
        WatchFault::PathNotFound => "the folder is not there".to_string(),
        WatchFault::Io { kind, os_code } => refusal_words(kind, os_code),
        WatchFault::Stopped => "the system stopped sending change notices".to_string(),
        WatchFault::Backend => "the file watch failed (see the run log)".to_string(),
        WatchFault::RegistryUnreadable => "the list of shared files could not be read".to_string(),
    }
}

/// A moment rmule noticed something, to the minute, in local time.
#[must_use]
pub fn moment(at: SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(at)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

/// Why a directory was not added or removed, as a clause.
#[must_use]
pub fn refusal(reason: &DirectoryRefusal) -> String {
    match reason {
        DirectoryRefusal::NotADirectory => "there is no directory there".to_string(),
        DirectoryRefusal::Unreachable(kind) => {
            format!("it cannot be looked at: {}", kind_words(*kind))
        }
        DirectoryRefusal::NotUtf8 => "its name is not valid UTF-8".to_string(),
        DirectoryRefusal::HomeDirectory => {
            "it is your home directory — share a folder inside it".to_string()
        }
        DirectoryRefusal::FilesystemRoot => {
            "it is the root of a disk — share a folder on it".to_string()
        }
        DirectoryRefusal::DataDirectory => {
            "it is rmule's own data directory, which holds its keys and store".to_string()
        }
        DirectoryRefusal::HoldsDataDirectory => {
            "it holds rmule's own data directory, which holds its keys and store".to_string()
        }
        DirectoryRefusal::AlreadyShared => "it is already shared".to_string(),
        DirectoryRefusal::InsideShared { parent } => {
            format!("it is already shared as part of {}", parent.display())
        }
        DirectoryRefusal::DownloadDirectory => {
            "it is the download directory — change that above, under Paths".to_string()
        }
        DirectoryRefusal::NotShared => "it is not in the list".to_string(),
        DirectoryRefusal::StoreFailed => {
            "the list could not be saved (see the run log)".to_string()
        }
    }
}

/// A list of directories, joined for a sentence.
fn paths(dirs: &[PathBuf]) -> String {
    dirs.iter()
        .map(|dir| dir.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A scan or list edge, in the status feed and the log.
#[must_use]
pub fn line(event: &ScanEvent) -> Sentence {
    Sentence::owned(match event {
        ScanEvent::ConsentRequested {
            dir, offer, adding, ..
        } if *adding => format!(
            "{} would share {} ({}) — confirm in Settings or Shared Files",
            dir.display(),
            files(offer.files),
            human_size(offer.bytes)
        ),
        ScanEvent::ConsentRequested { dir, offer, .. } => format!(
            "{} files in the download dir {} wait to be shared — answer in Shared Files",
            offer.files,
            dir.display()
        ),
        ScanEvent::Finished { dir, summary } => format!(
            "{} scanned: {} kept, {} carried, {} hashed, {} dropped, {} skipped, {} unreadable",
            dir.display(),
            summary.trusted,
            summary.carried,
            summary.hashed,
            summary.dropped,
            summary.skipped,
            summary.unreadable
        ),
        ScanEvent::Declined { dir } => format!("{} not shared (declined)", dir.display()),
        ScanEvent::DirectoryAdded { dir, replaced } if replaced.is_empty() => {
            format!("{} is shared", dir.display())
        }
        ScanEvent::DirectoryAdded { dir, replaced } => format!(
            "{} is shared, in place of {}",
            dir.display(),
            paths(replaced)
        ),
        ScanEvent::DirectoryRefused { dir, reason } => match reason {
            DirectoryRefusal::DownloadDirectory | DirectoryRefusal::NotShared => {
                format!("{} not removed: {}", dir.display(), refusal(reason))
            }
            _ => format!("{} not shared: {}", dir.display(), refusal(reason)),
        },
        ScanEvent::DirectoryRemoved { dir, files } => format!(
            "{} no longer shared: {} left the offer, still on disk",
            dir.display(),
            self::files(*files)
        ),
        ScanEvent::DirectoryMissing { dir, since } => format!(
            "{} is missing (noticed {}): its files are not offered until it is back",
            dir.display(),
            moment(*since)
        ),
        ScanEvent::DirectoryReturned { dir } => format!(
            "{} is back: its files are looked at again and offered",
            dir.display()
        ),
        ScanEvent::WatchUnavailable { dir, reason } => format!(
            "{} not watched, new files wait for a restart: {}",
            dir.display(),
            watch_fault_words(*reason)
        ),
        ScanEvent::LeftoverParts { paths, .. } => format!(
            "{} part files left by ended downloads are not shared; delete them to free the space",
            paths.len()
        ),
        ScanEvent::WatchInterrupted { dir, reason } => format!(
            "{} watch lost, re-establishing: {}",
            dir.display(),
            watch_fault_words(*reason)
        ),
        ScanEvent::WatchRestored { dir } => {
            format!("{} watched again; rechecking what changed", dir.display())
        }
        ScanEvent::PathUnwatched { path, reason, .. } => format!(
            "{} not watched, the rest is: {}",
            path.display(),
            watch_fault_words(*reason)
        ),
        ScanEvent::FileNotHashed {
            path,
            kind,
            os_code,
            ..
        } => format!(
            "{} cannot be read, so it is not shared: {}",
            path.display(),
            refusal_words(*kind, *os_code)
        ),
        ScanEvent::Unlistable { dir } => format!(
            "{} cannot be listed, nothing unshared; it is scanned again at the next start",
            dir.display()
        ),
    })
}

/// A scan's phase as a short state: the strip's and Settings' words.
#[must_use]
pub fn phase_words(phase: &ScanPhase) -> String {
    match phase {
        ScanPhase::Walking => "scanning".to_string(),
        ScanPhase::AwaitingConsent { .. } => "waiting for your answer".to_string(),
        ScanPhase::Hashing { done, total, .. } => {
            let percent = done.saturating_mul(100) / (*total).max(1);
            format!("hashing {}/{total}, {percent} %", done + 1)
        }
        ScanPhase::StartingWatch => "starting the watch".to_string(),
        ScanPhase::Watching { settling: 0 } => "watched".to_string(),
        ScanPhase::Watching { settling } => format!("watched, {settling} settling"),
        ScanPhase::Rewatching { attempt, .. } => format!("watch lost, retry {attempt}"),
        ScanPhase::Unwatched { reason } => {
            format!("not watched: {}", watch_fault_words(*reason))
        }
        ScanPhase::Missing { since } => format!("missing since {}", moment(*since)),
    }
}

/// A listed directory's state, in words.
#[must_use]
pub fn state_words(state: &DirectoryState) -> String {
    match state {
        DirectoryState::Scan(phase) => phase_words(phase),
        DirectoryState::Starting => "starting".to_string(),
        DirectoryState::Covered { by } => format!("inside {}", by.display()),
        DirectoryState::Declined => "declined, not shared".to_string(),
        DirectoryState::Unlistable => "cannot be listed".to_string(),
    }
}

/// The strip's first entry: the whole share set.
#[must_use]
pub fn all_words(count: usize) -> String {
    format!("all shared files · {}", files(count))
}

/// The strip's key hint.
pub const STRIP_HINT: &str = "  [ ] filter by directory · add or remove in Settings";

/// The files table with nothing shared.
pub const NOTHING_SHARED: &str = "nothing shared — add a directory in Settings";

/// The files table filtered to a directory that holds no shared file.
#[must_use]
pub fn nothing_under(dir: &Path) -> String {
    format!(
        "nothing shared under {} — [ ] for another directory",
        dir.display()
    )
}

/// What kind of entry a listed directory is, when it is not a plain one.
#[must_use]
pub const fn role_words(role: DirectoryRole) -> Option<&'static str> {
    match role {
        DirectoryRole::DownloadDirectory => Some("download dir"),
        DirectoryRole::Added => None,
        DirectoryRole::Adding => Some("being added"),
    }
}

/// A count of files, in words.
#[must_use]
pub fn files(count: usize) -> String {
    match count {
        1 => "1 file".to_string(),
        count => format!("{count} files"),
    }
}

/// How much of the share set lies under a directory.
#[must_use]
pub fn under_words(under: SharedUnder) -> String {
    match (under.files, under.bytes) {
        (0, _) => "no files shared yet".to_string(),
        (count, Some(bytes)) => format!("{}, {}", files(count), human_size(bytes)),
        (count, None) => format!("{}, size still being read", files(count)),
    }
}

/// The share confirm: its title, its question, and what a yes discloses.
#[must_use]
pub fn share_confirm(
    dir: &Path,
    offer: DirectoryOffer,
    adding: bool,
    replaces: &[PathBuf],
) -> (&'static str, String, String) {
    let hashed = if offer.unread > 0 {
        format!(", {} of them already hashed", offer.unread)
    } else {
        String::new()
    };
    let question = format!(
        "Share {}? {}, {}{hashed}.",
        dir.display(),
        files(offer.files),
        human_size(offer.bytes)
    );
    let mut consequence = "Every file's name and hash will be offered to the servers you \
                           connect to and published on Kad, subfolders included, and new \
                           files as they appear. Hidden files and rmule's own part files \
                           are skipped. Nothing is shared until you answer."
        .to_string();
    if !replaces.is_empty() {
        consequence.push_str(&format!(
            " It takes the place of {}, which lie inside it.",
            paths(replaces)
        ));
    }
    let title = if adding {
        " Share this directory? "
    } else {
        " Share the download directory? "
    };
    (title, question, consequence)
}

/// The add row's commit with nothing typed.
pub const ADD_EMPTY: &str = "type the path of a directory to share";

/// The add row's commit with a relative path.
pub const ADD_RELATIVE: &str = "a shared directory is named by its absolute path";

/// The remove confirm's title.
pub const REMOVE_TITLE: &str = " Stop sharing? ";

/// The remove confirm: its question and what a yes does.
#[must_use]
pub fn remove_confirm(dir: &Path, under: SharedUnder) -> (String, String) {
    (
        format!("Stop sharing {}? {}.", dir.display(), under_words(under)),
        "They leave the offer at once: servers and Kad stop hearing of them, and an \
         upload in progress ends. The files stay on disk, and adding the directory \
         again reads nothing."
            .to_string(),
    )
}
