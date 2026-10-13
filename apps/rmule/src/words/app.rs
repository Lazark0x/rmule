//! The TUI's own app words, beside the shared ones it re-exports: a Settings
//! receipt and a run with no core, which word the TUI's own types.

pub use rmule_words::app::*;

use super::Sentence;
use crate::config::PrefEdit;
use crate::state::AttachFailure;

/// The status-bar receipt for a saved Settings edit, which names the restart
/// when the edit waits for one — and, for the `server.met` mirror, the update
/// that reads it next: the Networks tab's update form opens on the stored URL,
/// so the operator's next update uses it whatever core takes up.
#[must_use]
pub fn receipt(edit: &PrefEdit, effect: rmule_core::TakesEffect) -> Sentence {
    let on_off = |on: bool| if on { "on" } else { "off" };
    let what = match edit {
        PrefEdit::DownloadDir(dir) => format!("download dir → {}", dir.display()),
        PrefEdit::TempDir(dir) => format!("temp dir → {}", dir.display()),
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
        PrefEdit::PlayerCommand(command) => super::player::receipt(command.as_deref()),
    };
    let when = match (edit, effect) {
        (PrefEdit::ServerMetUrl(_), _) => Some("the next server list update uses it"),
        (PrefEdit::TempDir(_), rmule_core::TakesEffect::Now) => {
            Some("downloads started from now on; the rest stay where they are")
        }
        (_, rmule_core::TakesEffect::Now) => None,
        (_, rmule_core::TakesEffect::NextStart) => Some("takes effect on restart"),
    };
    Sentence::owned(match when {
        None => format!("saved: {what}"),
        Some(when) => format!("saved: {what} ({when})"),
    })
}

/// Why the core could not be attached, as a clause; what the store or the
/// web client said is in the Run Log.
#[must_use]
pub const fn attach_failure_words(failure: AttachFailure) -> &'static str {
    match failure {
        AttachFailure::NoDataDir => NO_DATA_DIR,
        AttachFailure::OpenStore => {
            "the store would not open — is another rmule running on this data dir?"
        }
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
