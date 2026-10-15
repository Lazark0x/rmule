//! A run's own words: quit, a command core refused, a run with no core, the
//! clipboard, and the Run Log.

use std::path::Path;

use rmule_core::{CoreCommandRejectReason, DirectoryRefusal, KadUnavailableReason, QuitStep};

use super::Sentence;
use super::kad::kad_unavailable_words;
use super::os::refusal_words;

/// The quit path's opening flash, up before the core names its
/// first step.
pub const SHUTTING_DOWN: Sentence = Sentence::fixed("Shutting down…");

/// The step of quit now running.
#[must_use]
pub const fn quit_step(step: QuitStep) -> Sentence {
    Sentence::fixed(match step {
        QuitStep::DirectoryScan => "Shutting down… directory scan",
        QuitStep::Search => "Shutting down… searches",
        QuitStep::Download => "Shutting down… downloads",
        QuitStep::Serve => "Shutting down… serving",
        QuitStep::Kad => "Shutting down… Kad",
        QuitStep::PortMapping => "Shutting down… port mappings",
        QuitStep::CreditCheckpoint => "Shutting down… saving credits",
    })
}

/// Quit's grace ran out before core confirmed its flush.
pub const SHUTDOWN_GRACE_ELAPSED: Sentence =
    Sentence::fixed("Shutdown grace period elapsed — flush unconfirmed");

/// The core's event stream ended.
pub const CORE_STOPPED: Sentence = Sentence::fixed("core stopped");

/// A command on a run with no core.
pub const CORE_NOT_ATTACHED: Sentence = Sentence::fixed("core not attached (UI-only run)");

/// A link went to the clipboard.
pub const LINK_COPIED: Sentence = Sentence::fixed("link copied");

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
        R::NoDownloadDir => return super::download::NO_DOWNLOAD_DIR,
        R::DownloadDirRefused(guard) => {
            return Sentence::owned(format!(
                "download refused: everything under the download dir is shared, and {}",
                super::scan::download_dir_refusal(guard)
            ));
        }
        R::DownloadStoreFailed => "download refused: the download store failed (see the run log)",
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
