//! A run's own words: quit, a command core refused, the clipboard, and the Run
//! Log.

use std::path::Path;

use rmule_core::{
    CoreCommandRejectReason, DirectoryRefusal, KadUnavailableReason, LongTask, QuitStep,
};

use super::Sentence;
use super::kad::kad_unavailable_words;
use super::os::refusal_words;

/// The quit path's opening flash, up before the core names its
/// first step.
pub const SHUTTING_DOWN: Sentence = Sentence::fixed("Shutting down…");

/// The status bar's key to the help overlay.
pub const HELP_KEY: &str = "?";

/// Beside the status bar's [`HELP_KEY`].
pub const HELP_HINT: &str = " help";

/// The status bar's key out of a text field.
pub const LEAVE_KEY: &str = "Esc";

/// Beside the status bar's [`LEAVE_KEY`].
pub const LEAVE_HINT: &str = " leave";

/// Every confirm's key for yes.
pub const YES_KEY: &str = "y";

/// Beside [`YES_KEY`].
pub const YES_WORD: &str = " yes    ";

/// Every confirm's key for no.
pub const NO_KEY: &str = "n";

/// Beside [`NO_KEY`].
pub const NO_WORD: &str = " no";

/// A menu item wearing the key that runs it.
#[must_use]
pub fn keyed_item(label: &str, key: char) -> String {
    format!("{label} ({key})")
}

/// The quit confirm's title.
pub const QUIT_TITLE: &str = " Quit rmule? ";

/// What a quit would interrupt: the counts the quit confirm says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuitCost {
    /// Downloads moving bytes, or moving the finished file into place.
    pub running: usize,
    /// Downloads waiting for a source, a queue place or a connection.
    pub waiting: usize,
    /// Peers holding an upload slot.
    pub uploads: usize,
    /// Peers waiting in the upload queue.
    pub queued: usize,
}

impl QuitCost {
    /// Whether nothing is under way, so a quit needs no asking.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        self.running == 0 && self.waiting == 0 && self.uploads == 0 && self.queued == 0
    }
}

/// What a quit does to what is under way now. Every count that is not zero is
/// said, and a peer's place in the queue is said to be lost: the downloads come
/// back at the next start, that place does not.
#[must_use]
pub fn quit_confirm(cost: QuitCost) -> String {
    let count = |n: usize, one: &str, many: &str| super::units::count(n as u64, one, many);
    let parts: Vec<String> = [
        (
            cost.running,
            count(cost.running, "download", "downloads") + " running",
        ),
        (
            cost.waiting,
            count(cost.waiting, "download", "downloads") + " waiting",
        ),
        (
            cost.uploads,
            count(cost.uploads, "upload", "uploads") + " running",
        ),
        (cost.queued, count(cost.queued, "peer", "peers") + " queued"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(_, part)| part)
    .collect();
    let parts = parts.join(", ");
    if cost.uploads + cost.queued > 0 {
        format!("{parts}. They stop now, and peers lose their place in your queue.")
    } else {
        format!("{parts}. They stop now and carry on at the next start.")
    }
}

/// `rmule-cli add` was asked to stop by the OS (ADR-0118); it still quits.
pub const CLI_STOPPED: &str = "stopped by a signal before the download completed";

/// A running download's status once its core has stopped.
pub const ROW_STOPPED: &str = "Stopped";

/// A panic ended one task and the run goes on (ADR-0118).
pub const INTERNAL_FAULT: Sentence =
    Sentence::fixed("rmule hit an internal fault, written to its log; restart it when you can");

/// The operator could not be promised a clean Quit on a signal, since the OS
/// refused the handlers (ADR-0118).
pub const NO_STOP_SIGNALS: Sentence =
    Sentence::fixed("rmule cannot hear a stop signal this run; quit with q");

/// The OS refused job control's handlers (ADR-0118).
pub const NO_JOB_CONTROL: Sentence =
    Sentence::fixed("rmule cannot hear a job stop this run; after fg, press Ctrl-L");

/// The run was stopped as a job and is going again (ADR-0118): no transfer
/// moved while it stood. Short, so the bar's elision leaves the words that
/// matter.
pub const CONTINUED: Sentence = Sentence::fixed("transfers stood still");

/// What the normal screen says after a panic (ADR-0118): where it happened,
/// and the log that holds it.
#[must_use]
pub fn fault_at(file: &str, line: u32, log: Option<&Path>) -> String {
    match log {
        Some(log) => format!(
            "rmule hit an internal fault at {file}:{line}; the record is in {}",
            log.display()
        ),
        None => format!("rmule hit an internal fault at {file}:{line}; this run has no log"),
    }
}

/// A long task stopped on an internal fault (ADR-0118). It says what no longer
/// works for the rest of the run.
#[must_use]
pub const fn task_died(task: LongTask) -> Sentence {
    Sentence::fixed(match task {
        LongTask::Core => "rmule hit an internal fault and its engine stopped; see the log",
        LongTask::ClientUdpFront | LongTask::ClientUdpSends => {
            "rmule hit an internal fault: peer UDP stopped until the next start; see the log"
        }
        LongTask::ReaskRouter => {
            "rmule hit an internal fault: reask replies stopped until the next start; see the log"
        }
        LongTask::FirewalledFront => {
            "rmule hit an internal fault: buddy relays stopped until the next start; see the log"
        }
        LongTask::NattFront => {
            "rmule hit an internal fault: NAT traversal stopped until the next start; see the log"
        }
    })
}

/// The step of quit now running.
#[must_use]
pub const fn quit_step(step: QuitStep) -> Sentence {
    Sentence::fixed(match step {
        QuitStep::DirectoryScan => "Shutting down… directory scan",
        QuitStep::Search => "Shutting down… searches",
        QuitStep::Download => "Shutting down… downloads",
        QuitStep::Serve => "Shutting down… serving",
        QuitStep::Kad => "Shutting down… Kad",
        QuitStep::ServerSession => "Shutting down… server connection",
        QuitStep::PortMapping => "Shutting down… port mappings",
        QuitStep::CreditCheckpoint => "Shutting down… saving credits",
    })
}

/// Quit's grace ran out before core confirmed its flush.
pub const SHUTDOWN_GRACE_ELAPSED: Sentence =
    Sentence::fixed("Quit ran out of time: recent credits may be lost");

/// The core's event stream ended.
pub const CORE_STOPPED: Sentence =
    Sentence::fixed("the engine stopped; press q and start rmule again");

/// A link was written to the terminal, which may ignore the clipboard write.
pub const LINK_SENT: Sentence = Sentence::fixed("link sent to the terminal's clipboard");

/// The link itself for the log, since no terminal says whether it took it.
#[must_use]
pub fn link_sent(link: &str) -> Sentence {
    Sentence::owned(format!("link: {}", super::plain(link)))
}

/// Why a command was refused. Each names what to do about it where there is
/// something to do.
#[must_use]
pub fn command_rejected(reason: &CoreCommandRejectReason) -> Sentence {
    use CoreCommandRejectReason as R;
    let text = match reason {
        R::KadUnavailable(why) => return kad_unavailable(*why),
        R::DuplicateDownload => "download refused: this file is already in Transfers",
        R::DownloadPathConflict => {
            "download refused: a file of that name is already in the download dir"
        }
        R::PartFileMoved => {
            "restart refused: its part file is not where it was placed, and a file of that \
             name stands in the Temp dir; put it back rather than start over"
        }
        R::FileTooLargeForVolume => {
            "download refused: the file is over 4 GB, and the download dir or the Temp dir \
             lies on a FAT disk, which cannot hold it"
        }
        R::NoDownloadDir => return super::download::NO_DOWNLOAD_DIR,
        R::DownloadDirRefused(guard) => {
            return Sentence::owned(format!(
                "download refused: everything under the download dir is shared, and {}",
                super::scan::download_dir_refusal(guard)
            ));
        }
        R::DownloadStoreFailed => {
            "download refused: writing to the data directory failed (see the run log)"
        }
        R::DownloadAlreadyActive => "resume refused: that download is already running",
        R::DownloadCompleting => {
            "refused: the finished file is already in place, and the download completes on its own"
        }
        R::DownloadNotCompleted => {
            "clear refused: only a completed download is cleared; cancel drops the rest"
        }
        R::UnknownDownload => "refused: that download is no longer known",
        R::UnknownSearch => "refused: that search has already ended",
        R::SearchIdInUse => "search refused: one with the same number is running",
        R::UnknownServer => "refused: that server is not in the list",
        R::ServerAddressReserved => "add refused: no server can be at that address",
        R::ServerListStoreFailed => {
            "the server list could not be saved; it is unchanged (see the run log)"
        }
        R::ServerListFetchUnavailable => "update refused: this build cannot fetch a server list",
        R::ServerListUpdateInFlight => "update refused: a server list update is already running",
        R::ServerConnectInFlight => "connect refused: a connect is already dialing",
    };
    Sentence::fixed(text)
}

/// What the one-shot CLI adds to a refusal about the download directory: the
/// command that changes it.
const CHOOSE_ANOTHER: &str = "choose another with `rmule-cli config set-download-dir <path>`";

/// [`command_rejected`] as the one-shot CLI says it: a refusal about the
/// download directory also names the command that sets one.
#[must_use]
pub fn cli_command_rejected(reason: &CoreCommandRejectReason) -> Sentence {
    match reason {
        CoreCommandRejectReason::NoDownloadDir => Sentence::fixed(
            "no download directory configured; run `rmule-cli config set-download-dir <path>`",
        ),
        CoreCommandRejectReason::DownloadDirRefused(_) => {
            Sentence::owned(format!("{}; {CHOOSE_ANOTHER}", command_rejected(reason)))
        }
        other => command_rejected(other),
    }
}

/// The download directory the add's core refused to share, as the CLI says
/// it while the download goes on.
#[must_use]
pub fn cli_download_dir_not_shared(dir: &Path, reason: &DirectoryRefusal) -> Sentence {
    Sentence::owned(format!(
        "the download directory {} is not shared: {}; {CHOOSE_ANOTHER}",
        dir.display(),
        super::scan::download_dir_refusal(reason)
    ))
}

/// Why a one-shot download found no connection to ride.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoConnection {
    /// No server is configured and none of the link's own sources could be
    /// used.
    NoSourceUsable,
    /// The configured server did not answer.
    ServerSilent,
}

/// A one-shot download that waits for a connection no operator will make,
/// named by `download` (its id, or that it is not yet queued).
#[must_use]
pub fn cli_no_connection(download: &str, cause: NoConnection) -> Sentence {
    Sentence::owned(match cause {
        NoConnection::NoSourceUsable => format!(
            "download {download} has no connection: none of the link's sources could be used, no server is configured and Kad is off"
        ),
        NoConnection::ServerSilent => format!(
            "download {download} has no connection: the server did not answer and Kad is off"
        ),
    })
}

/// Kad could not start.
fn kad_unavailable(why: KadUnavailableReason) -> Sentence {
    Sentence::owned(format!("Kad refused: {}", kad_unavailable_words(why)))
}

/// A run with no data directory, and what would give it one on this
/// platform, as a clause.
#[cfg(not(windows))]
pub const NO_DATA_DIR: &str = "no data dir (set RMULE_DATA or HOME)";
/// A run with no data directory, and what would give it one on this
/// platform, as a clause.
#[cfg(windows)]
pub const NO_DATA_DIR: &str = "no data dir (set RMULE_DATA or LOCALAPPDATA)";

/// The app fell behind the node and `count` peer events were skipped.
#[must_use]
pub fn events_shed(count: u64) -> Sentence {
    Sentence::owned(format!(
        "fell behind the node: {count} peer events skipped, the Run Log has them"
    ))
}

/// The run has no Run Log, and why.
#[must_use]
pub fn no_run_log(failure: rmule_core::run_log::RunLogFailure) -> Sentence {
    use rmule_core::run_log::{FILE_NAME, RunLogFailure};
    Sentence::owned(match failure {
        RunLogFailure::NoDataDir => format!("no run log: {NO_DATA_DIR}"),
        RunLogFailure::Open { kind, os_code } => format!(
            "no run log: {FILE_NAME} could not be opened ({})",
            refusal_words(kind, os_code)
        ),
        RunLogFailure::AlreadyInstalled => {
            "no run log: another logger was installed first".to_string()
        }
        RunLogFailure::Write { kind, os_code } => format!(
            "the run log stopped: {FILE_NAME} could not be written ({})",
            refusal_words(kind, os_code)
        ),
        RunLogFailure::Rotate { kind, os_code } => format!(
            "the run log keeps growing: {FILE_NAME} could not be moved aside ({})",
            refusal_words(kind, os_code)
        ),
    })
}
