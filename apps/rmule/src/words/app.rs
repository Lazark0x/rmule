//! The app's own words: quit, a run with no core, a command core refused, a
//! Settings receipt, the clipboard, and the Run Log.

use rmule_core::{CoreCommandRejectReason, KadUnavailableReason, QuitStep};

use super::Sentence;
use super::kad::kad_unavailable_words;
use super::os::refusal_words;
use crate::config::PrefEdit;
use crate::state::AttachFailure;

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

/// An action that needs the node's credentials, on a run with none.
pub const NO_CREDENTIALS: Sentence = Sentence::fixed("no credentials — UI-only run");

/// A link went to the clipboard.
pub const LINK_COPIED: Sentence = Sentence::fixed("link copied");

/// The status-bar receipt for a saved Settings edit, which names the restart
/// when there is one.
#[must_use]
pub fn receipt(edit: &PrefEdit) -> Sentence {
    let on_off = |on: bool| if on { "on" } else { "off" };
    let what = match edit {
        PrefEdit::DownloadDir(dir) => format!("download dir → {}", dir.display()),
        PrefEdit::Nickname(name) => format!("nickname → {name}"),
        PrefEdit::TcpPort(port) => format!("eD2k port → {port}"),
        PrefEdit::UdpPort(port) => format!("UDP port → {port}"),
        PrefEdit::ServerMetUrl(url) => format!("server.met URL → {url}"),
        PrefEdit::AutoFetchServerMet(on) => {
            format!("server.met fetch at start → {}", on_off(*on))
        }
        PrefEdit::NodesDatUrl(url) => format!("nodes.dat URL → {url}"),
        PrefEdit::AutoFetchNodesDat(on) => format!("nodes.dat auto-fetch → {}", on_off(*on)),
        PrefEdit::Theme(choice) => format!("theme → {}", choice.name()),
        PrefEdit::Obfuscation(choice) => format!("obfuscation → {}", choice.name()),
        PrefEdit::PortMapping(on) => format!("port mapping → {}", on_off(*on)),
        PrefEdit::ConnectAtStart(on) => format!("connect at start → {}", on_off(*on)),
        PrefEdit::RunLogFull(on) => format!("full run log → {}", on_off(*on)),
        PrefEdit::LastServer(server) => {
            format!("last server → {}", super::units::server_label(server))
        }
        PrefEdit::TableSort {
            table,
            column,
            direction,
        } => format!("{table} sort → {column} {}", direction.arrow()),
        PrefEdit::DeadServerRetries(_) | PrefEdit::WithholdShares(_) => {
            super::server::policy_receipt(edit)
        }
        PrefEdit::RememberPeers(peers) => super::download::remember_peers_receipt(*peers),
    };
    Sentence::owned(if edit.is_live() {
        format!("saved: {what}")
    } else {
        format!("saved: {what} (takes effect on restart)")
    })
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
        R::DownloadStoreFailed => "download refused: the download store failed (see the run log)",
        R::DownloadAlreadyActive => "resume refused: that download is already running",
        R::DownloadNotCompleted => {
            "clear refused: only a completed download is cleared; cancel drops the rest"
        }
        R::UnknownDownload => "refused: that download is no longer known",
        R::UnknownSearch => "refused: that search has already ended",
        R::SearchIdInUse => "search refused: one with the same number is running",
        R::UnknownServer => "refused: that server is not in the list",
        R::ServerListStoreFailed => {
            "the server list could not be saved; it is unchanged (see the run log)"
        }
        R::ServerListFetchUnavailable => "update refused: this build cannot fetch a server list",
        R::ServerListUpdateInFlight => "update refused: a server list update is already running",
        R::ServerConnectInFlight => "connect refused: a connect is already dialing",
    };
    Sentence::fixed(text)
}

/// Kad could not start.
fn kad_unavailable(why: KadUnavailableReason) -> Sentence {
    Sentence::owned(format!("Kad refused: {}", kad_unavailable_words(why)))
}

/// A run with no data directory, and what would give it one on this
/// platform, as a clause.
#[cfg(not(windows))]
const NO_DATA_DIR: &str = "no data dir (set RMULE_DATA or HOME)";
#[cfg(windows)]
const NO_DATA_DIR: &str = "no data dir (set RMULE_DATA or LOCALAPPDATA)";

/// Why the core could not be attached, as a clause; what the store or the
/// web client said is in the Run Log.
#[must_use]
pub const fn attach_failure_words(failure: AttachFailure) -> &'static str {
    match failure {
        AttachFailure::NoDataDir => NO_DATA_DIR,
        AttachFailure::OpenStore => {
            "the store would not open — is another rmule running on this data dir?"
        }
        AttachFailure::Identity => "the node's identity could not be read",
        AttachFailure::KadIdentity => "the Kad identity could not be read",
        AttachFailure::KadUdpKey => "the Kad UDP key could not be read",
        AttachFailure::PortMapSecret => "the port-mapping secret could not be read",
        AttachFailure::Servers => "the server list could not be read",
        AttachFailure::Preferences => "the preferences could not be read",
        AttachFailure::HttpClient => "the web client for server-list updates could not start",
    }
}

/// A run with no core, and why — the status bar's note.
#[must_use]
pub fn ui_only(failure: AttachFailure) -> Sentence {
    Sentence::owned(format!(
        "UI-only: {} (see the run log)",
        attach_failure_words(failure)
    ))
}

/// The run has no Run Log, and why.
#[must_use]
pub fn no_run_log(failure: crate::run_log::RunLogFailure) -> Sentence {
    use crate::run_log::{FILE_NAME, RunLogFailure};
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
