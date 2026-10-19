//! The serve surface's words: a shared file offered or withheld, the
//! listener, the upload queue and its refusals, and every serve event's line
//! in the Networks log.

use rmule_core::file_history::HistoryPart;
use rmule_core::{
    DialBackEnd, GrantRoad, PartialEnd, ServeEvent, ServeStartFailure, ServeStopReason,
    ShareRejectReason, SharesWithheld, WaiterLeaveCause, WithheldReason,
};

use super::Sentence;
use super::os::kind_words;
use super::units::{address, human_size};

/// Why a row is withheld: the Shared Files table's State cell.
#[must_use]
pub const fn withheld_words(reason: WithheldReason) -> &'static str {
    match reason {
        WithheldReason::Missing => "missing",
        WithheldReason::Changed => "changed",
        WithheldReason::FolderMissing => "folder missing",
        WithheldReason::Unreadable(_) => "unreadable",
        WithheldReason::Refused => "folder refused",
    }
}

/// A download offering the parts it verified: the Shared Files table's
/// State cell.
pub const PARTIAL: &str = "partial";

/// A peer holding an upload slot: the Shared Files peers table's State cell.
pub const UPLOADING: &str = "Uploading";

/// A waiter being dialled back to take the upload slot held for it: the
/// Shared Files peers table's State cell.
pub const DIALING_BACK: &str = "Dialling back";

/// How an upload slot reached its peer, as the tail of its log line: nothing
/// for a grant on the link the peer held.
const fn grant_road_words(road: GrantRoad) -> &'static str {
    match road {
        GrantRoad::Linked => "",
        GrantRoad::DialedBack => " on the link dialled back to it",
        GrantRoad::CameBack => ", held for it until it came back",
        GrantRoad::NextConnection => " when it came back as a Low ID",
    }
}

/// Why a slot held for a dial-back never reached its waiter.
fn dial_back_end_words(end: DialBackEnd) -> String {
    match end {
        DialBackEnd::Dial(cause) => format!(
            "the dial back ended before its hello: {}",
            super::download::dial_end_words(cause)
        ),
        DialBackEnd::AnotherClient => "another client answered at its address".to_owned(),
        DialBackEnd::Lapsed => "it did not come back within the hour".to_owned(),
    }
}

/// A peer waiting in the upload queue at `rank`: the peers table's State
/// cell.
#[must_use]
pub fn queued_words(rank: u16) -> String {
    format!("Queued #{rank}")
}

/// What the peers table says of the waiters its filter left out, so none is
/// silently dropped.
#[must_use]
pub fn hidden_queued(count: usize) -> String {
    format!("{count} hidden queued")
}

/// A withhold edge, in the status feed and the log.
#[must_use]
pub fn withheld(reason: WithheldReason) -> Sentence {
    let why = match reason {
        WithheldReason::Missing => "its file is not where it was".to_string(),
        WithheldReason::Changed => "its file changed on disk".to_string(),
        WithheldReason::FolderMissing => "its folder is missing — an unplugged disk?".to_string(),
        WithheldReason::Unreadable(kind) => {
            format!("its file cannot be read ({})", kind_words(kind))
        }
        WithheldReason::Refused => {
            "its shared folder now leads where rmule will not share".to_string()
        }
    };
    Sentence::owned(format!("a shared file is no longer offered: {why}"))
}

/// File History parts core could not read: the marks they draw may be
/// missing or out of date.
#[must_use]
pub fn history_unread(parts: &[HistoryPart]) -> Sentence {
    let names: Vec<&str> = parts
        .iter()
        .map(|part| match part {
            HistoryPart::Shared => "the shared files",
            HistoryPart::Had => "the files once shared",
            HistoryPart::Cancelled => "the cancelled downloads",
        })
        .collect();
    let list = match names.split_last() {
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => String::new(),
    };
    Sentence::owned(format!(
        "search marks may be missing or out of date: {list} could not be read (see the run log)"
    ))
}

/// Offered again.
pub const OFFERED: Sentence = Sentence::fixed("a shared file is readable again and offered again");

/// A download began to offer the parts it verified.
pub const PARTIAL_OFFERED: Sentence =
    Sentence::fixed("a download offers the parts it has verified");

/// A restarted download's Offer Check read its verified parts again before
/// it may be offered: how much it read, and how long that took.
#[must_use]
pub fn offer_checked(bytes_read: u64, took: std::time::Duration) -> Sentence {
    Sentence::owned(format!(
        "a restarted download's verified parts were read again before it is offered: {} in {} ms",
        human_size(bytes_read),
        took.as_millis()
    ))
}

/// A download stopped offering its parts, and why.
#[must_use]
pub const fn partial_withdrawn(cause: PartialEnd) -> Sentence {
    Sentence::fixed(match cause {
        PartialEnd::Completed => "a download finished and is shared whole",
        PartialEnd::Ended => "a download no longer offers its parts: it ended",
        PartialEnd::HeldBack => {
            "a download no longer offers its parts: its folder leads where rmule will not share"
        }
        PartialEnd::Changed => {
            "a download no longer offers its parts: its part file changed on disk"
        }
        PartialEnd::Unreadable => {
            "a download no longer offers its parts: its part file cannot be read"
        }
    })
}

/// The folder watch's degrade.
pub const UNWATCHED: Sentence = Sentence::fixed(
    "shared files outside the download dir are not watched: a file that goes is noticed when a peer asks for it, or at the next start",
);

/// A file joined the share set.
pub const FILE_SHARED: Sentence = Sentence::fixed("file shared");
/// A file left the share set.
pub const FILE_UNSHARED: Sentence = Sentence::fixed("file unshared");
/// A peer asked for an upload and the queue had no room.
pub const QUEUE_FULL: Sentence = Sentence::fixed("upload queue full: a peer was turned away");
/// A peer's address already holds its share of the queue.
pub const ADDRESS_CAP: Sentence =
    Sentence::fixed("upload refused: that address already waits in the queue as often as allowed");
/// The Low-ID abuse guard turned a peer away.
pub const LOW_ID_ABUSE: Sentence =
    Sentence::fixed("upload refused: the guard against Low ID abuse turned a peer away");
/// A queued peer's reask could not be read.
pub const REASK_MALFORMED: Sentence =
    Sentence::fixed("a queued peer's reask could not be read; not answered");
/// A peer asked a file's name in a form its own hello ruled out.
pub const NAME_ASK_MALFORMED: Sentence =
    Sentence::fixed("a peer asked a file's name malformed; connection closed");

/// Why an unshare was refused.
#[must_use]
pub fn share_rejected(reason: ShareRejectReason) -> Sentence {
    Sentence::fixed(match reason {
        ShareRejectReason::NotShared => "not unshared: the file was not shared",
        ShareRejectReason::RegistryError => {
            "not unshared: the list of shared files could not be saved (see the run log)"
        }
    })
}

/// The listener did not come up.
#[must_use]
pub fn serving_failed(reason: ServeStartFailure) -> Sentence {
    Sentence::owned(match reason {
        ServeStartFailure::Bind(std::io::ErrorKind::AddrInUse) => {
            "not serving: the eD2k listen port is in use by another program or a second rmule — \
             serving is off until that port is free or another is chosen"
                .to_string()
        }
        ServeStartFailure::Bind(kind) => {
            format!(
                "not serving: the listener could not open its port ({})",
                kind_words(kind)
            )
        }
        ServeStartFailure::Adapter => {
            "not serving: the serving task ended earlier; restart rmule to serve again".to_string()
        }
    })
}

/// The listener closed.
#[must_use]
pub const fn serving_stopped(reason: ServeStopReason) -> Sentence {
    Sentence::fixed(match reason {
        ServeStopReason::Requested => "serving stopped",
        ServeStopReason::ListenerClosed => "serving stopped: the listener closed on its own",
        ServeStopReason::TaskFailed => {
            "serving stopped: the serving task failed; restart rmule to serve again"
        }
    })
}

/// The listener is up.
#[must_use]
pub fn serving_started(port: u16) -> Sentence {
    Sentence::owned(format!("serving: listening for peers on TCP port {port}"))
}

/// The server was told what is shared.
#[must_use]
pub fn announced(files: usize) -> Sentence {
    Sentence::owned(format!("announced {files} files to the server"))
}

/// The server was not told what is shared, and why.
#[must_use]
pub fn shares_withheld(files: usize, reason: SharesWithheld) -> Sentence {
    let why = match reason {
        SharesWithheld::RelatedSearchGranted => {
            "it answers related searches, and the preference keeps shares from such servers"
        }
        SharesWithheld::RelatedSearchGrantedAfterAnnounce => {
            "it answers related searches; it keeps the list announced before the preference was switched on"
        }
    };
    Sentence::owned(format!(
        "did not announce {files} files to the server: {why}"
    ))
}

/// A serve event's line in the Networks log.
#[must_use]
pub fn log_line(event: &ServeEvent) -> Sentence {
    use ServeEvent as Sv;
    match event {
        Sv::FileShared { .. } => FILE_SHARED,
        Sv::FileUnshared { .. } => FILE_UNSHARED,
        Sv::FileWithheld { reason, .. } => withheld(*reason),
        Sv::FileOffered { .. } => OFFERED,
        Sv::PartialOffered { .. } => PARTIAL_OFFERED,
        Sv::PartialWithdrawn { cause, .. } => partial_withdrawn(*cause),
        Sv::OfferChecked {
            bytes_read, took, ..
        } => offer_checked(*bytes_read, *took),
        Sv::SharesUnwatched => UNWATCHED,
        Sv::ShareRejected { reason } => share_rejected(*reason),
        Sv::ServingStarted { listen_addr } => serving_started(listen_addr.port()),
        Sv::ServingFailed { reason } => serving_failed(*reason),
        Sv::ServingStopped { reason } => serving_stopped(*reason),
        Sv::FilesAnnounced { file_count } => announced(*file_count),
        Sv::FilesWithheld { file_count, reason } => shares_withheld(*file_count, *reason),
        Sv::UploadSlotGranted { peer, road, .. } => Sentence::owned(format!(
            "upload slot to {}{}",
            address(*peer),
            grant_road_words(*road)
        )),
        Sv::UploadDialBack { peer, .. } => Sentence::owned(format!(
            "dialling {} back to hand it its upload slot",
            address(*peer)
        )),
        Sv::UploadDialBackFailed { peer, cause } => Sentence::owned(format!(
            "upload slot held for {} goes to the next waiter: {}",
            address(*peer),
            dial_back_end_words(*cause)
        )),
        Sv::PeerQueued { peer, rank, .. } => Sentence::owned(format!(
            "upload peer {} waits at rank {rank}",
            address(*peer)
        )),
        Sv::UploadQueueFull { peer } => {
            Sentence::owned(format!("upload queue full: {} turned away", address(*peer)))
        }
        Sv::UploadLowIdAbuseRefused { peer } => Sentence::owned(format!(
            "upload refused by the Low ID abuse guard: {}",
            address(*peer)
        )),
        Sv::UploadAddressCapReached { peer } => Sentence::owned(format!(
            "upload refused: {} already waits as often as allowed",
            address(*peer)
        )),
        Sv::ReaskPingMalformed { peer } => Sentence::owned(format!(
            "reask from {} could not be read; not answered",
            address(*peer)
        )),
        Sv::NameAskMalformed { peer } => Sentence::owned(format!(
            "name ask from {} malformed; connection closed",
            address(*peer)
        )),
        Sv::UploadSlotReleased { peer } => {
            Sentence::owned(format!("upload slot of {} released", address(*peer)))
        }
        Sv::WaiterLeft { peer, cause } => {
            let how = match cause {
                WaiterLeaveCause::Purged => "dropped from the upload queue",
                WaiterLeaveCause::Cancelled => "left the upload queue",
                WaiterLeaveCause::UserHashClash => {
                    "dropped from the upload queue: another client asked under its user hash"
                }
            };
            Sentence::owned(format!("{} {how}", address(*peer)))
        }
        Sv::WaiterRelinked { from, to } => Sentence::owned(format!(
            "upload peer {} came back as {} and keeps its place",
            address(*from),
            address(*to)
        )),
        Sv::SourcesServed { peer, count, .. } => {
            Sentence::owned(format!("served {count} sources to {}", address(*peer)))
        }
    }
}
