//! The TUI's own app words, beside the shared ones it re-exports: a Settings
//! receipt, why a form field refused its text (each refusal a code worded
//! here, so a form carries a [`Sentence`] and never a `String`) and what an
//! unset Temp Directory reads as, and why a run could not start, which word
//! the TUI's own types.

pub use rmule_words::app::*;

use std::path::Path;

use super::Sentence;
use crate::config::{PrefEdit, UnfitDirectory};
use rmule_core::Opening;
use rmule_os::terminal::NoStop;

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
        PrefEdit::AutoUpdateServerMet(on) => {
            format!("server list auto-update at start → {}", on_off(*on))
        }
        PrefEdit::ServerMetAutoUpdateUrls(urls) => match urls.len() {
            0 => "server list auto-update addresses → none".to_string(),
            1 => "server list auto-update addresses → 1".to_string(),
            n => format!("server list auto-update addresses → {n}"),
        },
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
        PrefEdit::LastTab(view) => format!("last tab → {}", view.title()),
        PrefEdit::TerminalTitle(on) => format!("terminal title → {}", on_off(*on)),
        PrefEdit::CompletionBell(on) => format!("completion bell → {}", on_off(*on)),
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
pub fn attach_failure_words(failure: AttachFailure) -> String {
    match failure {
        AttachFailure::NoDataDir => NO_DATA_DIR.to_string(),
        AttachFailure::OpenStore(refusal) => crate::words::store::open_refusal(refusal),
        AttachFailure::PortMapSecret => "the port-mapping secret could not be read".to_string(),
        AttachFailure::Servers => "the server list could not be read".to_string(),
        AttachFailure::Preferences => "the preferences could not be read".to_string(),
        AttachFailure::HttpClient => {
            "the web client for server-list updates could not start".to_string()
        }
    }
}

/// What a slow store open is doing, on the plain terminal before the screen
/// starts.
#[must_use]
pub fn store_opening(opening: Opening) -> Sentence {
    match opening {
        Opening::Repairing { .. } => Sentence::fixed(
            "the last run did not close the store; checking it, this can take a while",
        ),
        Opening::Climbing { from, to } => Sentence::owned(format!(
            "upgrading the store from version {from} to {to}; a copy stays as rmule.redb.v{from}"
        )),
    }
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
    /// Nothing is at the path, or it is not a directory.
    Missing,
}

/// A refused shared-directory add, as the line under the field.
#[must_use]
pub const fn add_directory_refusal(refusal: AddDirectoryRefusal) -> Sentence {
    Sentence::fixed(match refusal {
        AddDirectoryRefusal::Empty => super::scan::ADD_EMPTY,
        AddDirectoryRefusal::Relative => super::scan::ADD_RELATIVE,
        AddDirectoryRefusal::Missing => super::scan::ADD_MISSING,
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

/// [`share_warning`] for a directory that does not exist yet.
#[must_use]
pub fn share_warning_missing(dir: &Path) -> Sentence {
    Sentence::owned(format!(
        "{} does not exist and will be made, and everything under it will be offered to the \
         network — Enter to confirm, Esc to cancel",
        dir.display()
    ))
}

/// A Temp dir that does not exist yet, before the `Enter` that sets it.
#[must_use]
pub fn temp_dir_missing(dir: &Path) -> Sentence {
    Sentence::owned(format!(
        "{} does not exist and will be made — Enter to confirm, Esc to cancel",
        dir.display()
    ))
}

/// A directory field's `Tab` found nothing to complete to.
pub const NO_DIRECTORY_MATCHES: Sentence = Sentence::fixed("no directory there begins like that");

/// A directory field's `Tab` could not look in `dir`, as typed.
#[must_use]
pub fn path_unreadable(dir: &str) -> Sentence {
    Sentence::owned(format!("cannot look in {dir}"))
}

/// The directories a `Tab` left to choose from, the first few by name.
#[must_use]
pub fn directories_match(names: &[String]) -> Sentence {
    const SHOWN: usize = 6;
    let list = names
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("  ");
    Sentence::owned(match names.len().saturating_sub(SHOWN) {
        0 => list,
        more => format!("{list}  and {more} more"),
    })
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

/// What a terminal too small for the views says: its size, the size it
/// takes, and the way out, the one key that still answers.
#[must_use]
pub fn too_small((width, height): (u16, u16), (need_w, need_h): (u16, u16)) -> String {
    format!("Terminal {width}×{height} is too small. rmule needs {need_w}×{need_h}. q quits.")
}

/// The status bar's connection, each state a code.
pub const ED2K_HIGH_ID: Sentence = Sentence::fixed("eD2k HighID");
/// See [`ED2K_HIGH_ID`].
pub const ED2K_LOW_ID: Sentence = Sentence::fixed("eD2k LowID");
/// A dial is out and no session stands yet.
pub const ED2K_CONNECTING: Sentence = Sentence::fixed("eD2k connecting…");
/// No session, by the operator's choice.
pub const ED2K_OFF: Sentence = Sentence::fixed("eD2k off");
/// No session, and the operator wanted one.
pub const ED2K_LOST: Sentence = Sentence::fixed("eD2k lost");

/// The status bar's connection while core re-makes a lost session.
#[must_use]
pub fn ed2k_reconnecting(attempt: u32) -> String {
    format!("eD2k reconnecting {attempt}")
}

/// How old a note on the status bar is, set behind its words.
#[must_use]
pub fn note_age(age: std::time::Duration) -> Sentence {
    Sentence::owned(format!(" · {}m ago", age.as_secs() / 60))
}

/// One count of the download tally: `3 active`, or `3↓` where the row is tight.
#[must_use]
pub fn tally_part(part: crate::state::TallyPart, count: usize, short: bool) -> String {
    use crate::state::TallyPart as P;
    match (part, short) {
        (P::Active, false) => format!("{count} active"),
        (P::Failed, false) => format!("{count} failed"),
        (P::Done, false) => format!("{count} done"),
        (P::Active, true) => format!("{count}↓"),
        (P::Failed, true) => format!("{count}✗"),
        (P::Done, true) => format!("{count}✓"),
    }
}

/// What stands between two counts of the tally.
#[must_use]
pub const fn tally_gap(short: bool) -> &'static str {
    if short { " " } else { " · " }
}

/// The terminal's title: the rates and the tally, read from a tab or a tmux
/// window with the app out of sight.
#[must_use]
pub fn terminal_title(down: &str, up: &str, tally: crate::state::Tally) -> String {
    let mut title = format!("rmule ▼ {down} ▲ {up}");
    for (part, count) in tally.parts() {
        if count > 0 {
            title.push(' ');
            title.push_str(&tally_part(part, count, true));
        }
    }
    title
}

/// What the Settings row for the terminal title does.
pub const TERMINAL_TITLE_NOTE: &str = "rates and counts in the window title";

/// What the Settings row for the completion bell does.
pub const COMPLETION_BELL_NOTE: &str = "rings the terminal when a download finishes";

/// Why Ctrl-Z did not stop this run (ADR-0118).
#[must_use]
pub const fn no_suspend(why: NoStop) -> Sentence {
    Sentence::fixed(match why {
        NoStop::NoJobControl => "this system cannot stop a program; rmule keeps running",
        NoStop::NoShell => "no shell here could bring rmule back; it keeps running",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sentence the operator acts on: asking about a second process
    /// after a downgrade sends them to delete the file instead.
    #[test]
    fn a_refused_store_is_told_by_its_cause() {
        let words = |refusal| attach_failure_words(AttachFailure::OpenStore(refusal));
        use rmule_core::OpenRefusal;
        assert!(words(OpenRefusal::Busy).contains("another rmule"));
        let newer = words(OpenRefusal::Newer {
            found: 17,
            current: 16,
        });
        assert!(newer.contains("17") && newer.contains("16"), "{newer}");
        for refusal in [
            OpenRefusal::Newer {
                found: 17,
                current: 16,
            },
            OpenRefusal::TooOld { found: 1 },
            OpenRefusal::Damaged,
            OpenRefusal::Disk { os_code: Some(28) },
            OpenRefusal::NotCopied { os_code: None },
        ] {
            let sentence = words(refusal);
            assert!(!sentence.contains("another rmule"), "{sentence}");
        }
        assert!(words(OpenRefusal::Damaged).contains("keep"));
    }
}

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
