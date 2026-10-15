//! The TUI's own app words, beside the shared ones it re-exports: a Settings
//! receipt, why a form field refused its text (each refusal a code worded
//! here, so a form carries a [`Sentence`] and never a `String`) and what an
//! unset Temp Directory reads as, and a run with no core, which word the
//! TUI's own types.

pub use rmule_words::app::*;

use std::path::Path;

use super::Sentence;
use crate::config::{PrefEdit, UnfitDirectory};
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
        PrefEdit::TempDir(Some(dir)) => format!("Temp Directory → {}", dir.display()),
        PrefEdit::TempDir(None) => "Temp Directory → the default".to_string(),
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

/// The Download dir row left empty: downloads need somewhere to land.
pub const DOWNLOAD_DIR_REQUIRED: Sentence = Sentence::fixed("a download directory is required");

/// Why the Download dir row's text names no directory rmule takes.
#[must_use]
pub fn download_dir_unfit(unfit: &UnfitDirectory) -> Sentence {
    match unfit {
        UnfitDirectory::Relative => {
            Sentence::fixed("the download directory must be an absolute path")
        }
        UnfitDirectory::NotADirectory(text) => not_a_directory(text),
    }
}

/// Why the Temp dir row's text names no directory rmule takes; left empty,
/// the row goes back to the default instead.
#[must_use]
pub fn temp_dir_unfit(unfit: &UnfitDirectory) -> Sentence {
    match unfit {
        UnfitDirectory::Relative => Sentence::fixed("the Temp Directory must be an absolute path"),
        UnfitDirectory::NotADirectory(text) => not_a_directory(text),
    }
}

fn not_a_directory(text: &str) -> Sentence {
    Sentence::owned(format!("'{text}' exists and is not a directory"))
}

/// Why a typed nickname is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NicknameRefusal {
    /// Nothing but blanks was typed.
    Required,
    /// It holds a control character, which a hello packet would carry.
    ControlCharacter,
}

/// A refused nickname, as the line under the field.
#[must_use]
pub const fn nickname_refusal(refusal: NicknameRefusal) -> Sentence {
    Sentence::fixed(match refusal {
        NicknameRefusal::Required => "nickname is required",
        NicknameRefusal::ControlCharacter => "nickname must not contain control characters",
    })
}

/// Why a typed port is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortRefusal {
    /// Nothing was typed.
    Required,
    /// The text, as typed, is not a number from 1 to 65535.
    NotAPort(String),
}

/// A refused port, as the line under the field.
#[must_use]
pub fn port_refusal(refusal: &PortRefusal) -> Sentence {
    match refusal {
        PortRefusal::Required => Sentence::fixed("port is required (1–65535)"),
        PortRefusal::NotAPort(text) => {
            Sentence::owned(format!("'{text}' is not a port number (1–65535)"))
        }
    }
}

/// The two Settings ports, which may not be the same number: the row that was
/// edited, against the one it met.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortClash {
    /// The eD2k TCP port typed equal to the UDP port.
    TcpAgainstUdp,
    /// The UDP port typed equal to the eD2k TCP port.
    UdpAgainstTcp,
}

/// A port typed equal to the other one, naming both rows.
#[must_use]
pub const fn port_clash(clash: PortClash) -> Sentence {
    Sentence::fixed(match clash {
        PortClash::TcpAgainstUdp => "the eD2k port must differ from the UDP port",
        PortClash::UdpAgainstTcp => "the UDP port must differ from the eD2k port",
    })
}

/// A typed URL that is not `http` or `https`, the only two schemes fetched.
pub const URL_SCHEME: Sentence = Sentence::fixed("URL must start with http:// or https://");

/// Why a typed server address is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostRefusal {
    /// Nothing was typed.
    Required,
    /// Four dotted numbers that are not an IPv4 address; the text as typed.
    NotIpv4(String),
    /// Neither an IPv4 address nor a hostname; the text as typed.
    NotIpv4OrHostname(String),
    /// Well formed, but no server can be at it.
    NoServerThere,
}

/// A refused server address, as the line under the field.
#[must_use]
pub fn host_refusal(refusal: &HostRefusal) -> Sentence {
    match refusal {
        HostRefusal::Required => Sentence::fixed("address is required (IPv4 or hostname)"),
        HostRefusal::NotIpv4(text) => {
            Sentence::owned(format!("'{text}' is not a valid IPv4 address"))
        }
        HostRefusal::NotIpv4OrHostname(text) => {
            Sentence::owned(format!("'{text}' is not an IPv4 address or a hostname"))
        }
        HostRefusal::NoServerThere => Sentence::fixed(super::server::INVALID_ADDRESS),
    }
}

/// A typed Dead Server Limit outside 1 to 10, aMule's own spin box's range.
pub const DEAD_AFTER_REFUSED: Sentence =
    Sentence::fixed("dead after: a whole number of tries from 1 to 10");

/// A typed `Remember peers` that is not a whole number from 1 to 255.
pub const REMEMBER_PEERS_REFUSED: Sentence =
    Sentence::fixed(super::download::REMEMBER_PEERS_REFUSED);

/// The shared-directory add row's refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddDirectoryRefusal {
    /// Nothing was typed.
    Empty,
    /// The path is relative.
    Relative,
}

/// A refused shared-directory add, as the line under the field.
#[must_use]
pub const fn add_directory_refusal(refusal: AddDirectoryRefusal) -> Sentence {
    Sentence::fixed(match refusal {
        AddDirectoryRefusal::Empty => super::scan::ADD_EMPTY,
        AddDirectoryRefusal::Relative => super::scan::ADD_RELATIVE,
    })
}

/// The share guards refused a directory, as the line under the Settings
/// form.
#[must_use]
pub fn shared_directory_refusal(reason: &rmule_core::DirectoryRefusal) -> Sentence {
    Sentence::owned(super::scan::refusal(reason))
}

/// A search's typed filters that do not parse, as the line under the filter
/// form.
#[must_use]
pub fn filter_refusal(error: &super::search::FilterError) -> Sentence {
    Sentence::owned(super::search::filter_error_words(error))
}

/// The guards passed a download directory: everything under it will be
/// offered, and the next Enter confirms.
#[must_use]
pub fn share_warning(dir: &Path) -> Sentence {
    Sentence::owned(format!(
        "everything under {} will be offered to the network — Enter to confirm, Esc to cancel",
        dir.display()
    ))
}

/// The Temp dir row while none is set: the directory core reads by default,
/// `default`, or where it lies while no data directory is known.
#[must_use]
pub fn temp_dir_default(default: Option<&Path>) -> String {
    match default {
        Some(dir) => format!("{}  (the default)", dir.display()),
        None => "the default: Temp in the data dir".to_string(),
    }
}
