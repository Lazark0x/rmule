//! The operator's words for the codes core hands the download surface: why a
//! download failed, why a part went back to the pool, why a source left, the
//! state a recovered download came back in, what a Restart did, and every
//! download event's line in the Networks log. Core carries codes and the TUI
//! owns every sentence, so the app can be translated; each match is
//! exhaustive, so a code core adds cannot reach the screen without its words.

use rmule_core::{
    DialEnd, DownloadEvent, DownloadFailure, DownloadId, DownloadLifecycle, DownloadMetadata,
    IgnoredReaskReply, PartFault, PartFileChange, PartReleaseReason, PartsLost,
    PeerRetirementReason, RestartOutcome, SourceWait, StorageIntegrityFault,
};

use super::Sentence;
use super::units::{address, count, short_hex};
use crate::views::human_size;

/// What a download waiting for a connection needs to move on (ADR-0097): no
/// server session and no Kad node exist to ask for sources on.
pub const NO_NETWORK_WAIT: &str =
    "waiting for a network to find sources on: connect to a server, or enable Kad";

/// [`NO_NETWORK_WAIT`] as the status bar's note.
pub const NO_NETWORK_WAIT_NOTE: Sentence = Sentence::fixed(NO_NETWORK_WAIT);

/// Why a failed row has no reason to give (ADR-0094): it failed before rmule
/// kept why — store version 5 or earlier, or the version-6 bare
/// storage-integrity code — and its next Restart finds the fault again.
pub const FAILURE_NOT_RECORDED: &str =
    "not recorded: it failed before rmule kept the reason; Restart finds it again";

/// A download's ETA cell when it moves too slowly to estimate: its speed
/// averaged over the last minute is under 1 KiB/s, or the estimate is past
/// 30 days (ADR-0071, "Download ETA").
pub const ETA_TOO_SLOW: &str = "slow";

/// A download's time left, compact enough for the ETA cell: seconds, then
/// minutes and seconds, hours and minutes, and whole days past one.
#[must_use]
pub fn eta_time(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else if secs < 86_400 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d+", secs / 86_400)
    }
}

/// Why a download failed, as a clause that completes "It failed because …".
#[must_use]
pub fn download_failure_words(reason: &DownloadFailure) -> String {
    let code: &str = match reason {
        DownloadFailure::NoUsableSources => {
            "no source could be reached and nothing was looking for more"
        }
        DownloadFailure::HashSetMismatch => "a source's part hashes contradicted the link's own",
        DownloadFailure::Cancelled => "it was cancelled",
        DownloadFailure::Paused => "it was paused",
        DownloadFailure::ServerDisconnected => "the server disconnected before it named any source",
        DownloadFailure::ServerFiltered => "the server's address is in your IP filter",
        DownloadFailure::SourceLookupTimedOut => "the server never answered the ask for sources",
        DownloadFailure::PeerDisconnected => {
            "the last source disconnected with parts still missing"
        }
        DownloadFailure::PartVerificationFailed => {
            "a part kept failing its check and no other source had it"
        }
        DownloadFailure::StorageIntegrityFailed(fault) => {
            return format!(
                "the file on disk no longer backs the parts already checked: {}",
                integrity_fault_words(fault)
            );
        }
        DownloadFailure::FinalPathTaken => {
            "a file already stands where the finished file goes; every checked part is kept, so move that file away and Restart"
        }
        DownloadFailure::CompletedFileNotMoved { os_code } => {
            let why = os_code.map_or_else(String::new, |code| {
                format!(
                    " ({})",
                    super::os::refusal_words(
                        std::io::Error::from_raw_os_error(code).kind(),
                        Some(code)
                    )
                )
            });
            return format!(
                "the finished file could not be moved to where it goes{why}; every checked part is kept, so Restart once the folder takes it"
            );
        }
        DownloadFailure::StoreFailed => {
            "rmule's store could not read or write this download's record"
        }
    };
    code.to_string()
}

/// Which check condemned a download's part file, and what it found.
#[must_use]
pub fn integrity_fault_words(fault: &StorageIntegrityFault) -> String {
    match fault {
        StorageIntegrityFault::PartFileMissing => "its part file is missing".to_string(),
        StorageIntegrityFault::PartFileUnreadable { os_code } => match os_code {
            Some(code) => format!(
                "its part file could not be read ({})",
                super::os::refusal_words(
                    std::io::Error::from_raw_os_error(*code).kind(),
                    Some(*code)
                )
            ),
            None => "its part file could not be read".to_string(),
        },
        StorageIntegrityFault::NoPartHolds { recorded, first } => format!(
            "none of its {recorded} checked parts still matches ({})",
            part_fault_words(first)
        ),
    }
}

/// How one checked part failed on disk.
#[must_use]
pub fn part_fault_words(fault: &PartFault) -> String {
    match fault {
        PartFault::Short {
            part_index,
            expected_end,
            found_len,
        } => format!(
            "part {part_index} should end at byte {expected_end}, the part file holds {found_len}"
        ),
        PartFault::HashMismatch {
            part_index,
            expected,
            found,
        } => format!(
            "part {part_index} hashes to {}, it was checked as {}",
            short_hex(found.as_bytes()),
            short_hex(expected.as_bytes())
        ),
    }
}

/// Why a source left a download.
#[must_use]
pub const fn retirement_words(reason: PeerRetirementReason) -> &'static str {
    match reason {
        PeerRetirementReason::PeerDisconnected => "it disconnected",
        PeerRetirementReason::SlotRejected => "it refused an upload slot",
        PeerRetirementReason::SlotTimeout => "its queue took too long",
        PeerRetirementReason::PartVerificationFailed => "a part it sent failed its check",
        PeerRetirementReason::VerificationAuthorityMismatch => {
            "its part hashes contradicted the file's"
        }
        PeerRetirementReason::CryptIncompatible => "its encryption and yours cannot meet",
        PeerRetirementReason::Distrusted => "it sent this file bad data before",
    }
}

/// Why a dial to a source ended before its hello.
#[must_use]
pub const fn dial_end_words(cause: DialEnd) -> &'static str {
    match cause {
        DialEnd::CryptStanceUnknown => {
            "refused: its crypt stance is unknown and obfuscation is required"
        }
        DialEnd::CryptUnsupported => "refused: it cannot obfuscate and obfuscation is required",
        DialEnd::CryptRequiredByPeer => "refused: it requires obfuscation and yours is off",
        DialEnd::CryptKeyUnknown => "refused: obfuscation is required and its user hash is unknown",
        DialEnd::IpFiltered => "not dialled: the IP filter blocks it",
        DialEnd::Banned => "not dialled: it is banned",
        DialEnd::ConnectionRefused => "connection refused",
        DialEnd::TimedOut => "no answer",
        DialEnd::Reset => "reset",
        DialEnd::Os { kind } => super::os::kind_words(kind),
        DialEnd::ClosedBeforeHello => "it hung up before its hello",
        DialEnd::NoHelloInTime => "no hello in time",
        DialEnd::ProtocolViolation => "it broke the protocol before its hello",
        DialEnd::ClosedLocally => "closed here before its hello",
    }
}

/// Why a reask reply changed nothing.
#[must_use]
pub const fn ignored_reask_reply_words(reason: IgnoredReaskReply) -> &'static str {
    match reason {
        IgnoredReaskReply::Runt => "it was too short to read",
        IgnoredReaskReply::UnexpectedOpcode => "it was not a reask answer",
        IgnoredReaskReply::NoPooledSource => "no queued source holds that address",
        IgnoredReaskReply::Misframed => "its body did not read as the answer owed",
    }
}

/// Why a part went back to the pool for another source.
#[must_use]
pub const fn release_words(reason: PartReleaseReason) -> &'static str {
    match reason {
        PartReleaseReason::PeerRetired(retired) => retirement_words(retired),
        PartReleaseReason::Paused => "the download was paused",
        PartReleaseReason::Cancelled => "the download was cancelled",
    }
}

/// The state a download came back in after a restart.
#[must_use]
pub const fn lifecycle_words(lifecycle: DownloadLifecycle) -> &'static str {
    match lifecycle {
        DownloadLifecycle::Queued => "queued",
        DownloadLifecycle::Active => "running",
        DownloadLifecycle::Paused => "paused",
        DownloadLifecycle::Failed => "failed",
        DownloadLifecycle::Completed => "completed",
        DownloadLifecycle::Cancelled => "cancelled",
    }
}

/// The download as the operator knows it: its name, or its number before any
/// edge named it.
#[must_use]
pub fn download_name(metadata: Option<&DownloadMetadata>, download_id: DownloadId) -> String {
    metadata
        .map(|metadata| metadata.name.to_display_string())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| format!("download {}", download_id.as_u64()))
}

/// What a run found at its part file's path.
#[must_use]
pub fn part_file_change_words(found: PartFileChange) -> String {
    match found {
        PartFileChange::Gone => "part file removed".to_string(),
        PartFileChange::Replaced => "part file replaced by another file".to_string(),
        PartFileChange::Truncated { len } => {
            format!("part file cut short to {}", human_size(len))
        }
    }
}

/// What a changed part file cost, or that the store could not say.
#[must_use]
pub fn parts_lost_words(lost: PartsLost) -> String {
    match lost {
        PartsLost::Counted { parts, bytes } => parts_to_fetch_again(parts, bytes),
        PartsLost::NotCounted => {
            "rmule's store could not say which verified parts were lost, so the download stopped"
                .to_string()
        }
    }
}

/// What a loss costs.
#[must_use]
pub fn parts_to_fetch_again(parts: u32, bytes: u64) -> String {
    match parts {
        0 => "no verified part was lost".to_string(),
        1 => format!("1 verified part ({}) to fetch again", human_size(bytes)),
        n => format!("{n} verified parts ({}) to fetch again", human_size(bytes)),
    }
}

/// "1 checked part" / "N checked parts".
fn checked_parts(parts: u32) -> String {
    count(u64::from(parts), "checked part", "checked parts")
}

/// What a Restart did: continued from what holds, or started over with
/// nothing on disk to continue from — and the cost.
#[must_use]
pub fn restart_words(outcome: &RestartOutcome) -> String {
    match outcome {
        RestartOutcome::Continued {
            kept_parts: 0,
            dropped_parts: 0,
            ..
        } => "nothing was checked yet; it starts from 0 %".to_string(),
        RestartOutcome::Continued {
            kept_parts,
            kept_bytes,
            dropped_parts: 0,
            ..
        } => format!(
            "continuing from {} ({})",
            checked_parts(*kept_parts),
            human_size(*kept_bytes)
        ),
        RestartOutcome::Continued {
            kept_parts,
            kept_bytes,
            dropped_parts,
            dropped_bytes,
        } => format!(
            "continuing from {} ({}); {} damaged ({}) dropped, fetched again",
            checked_parts(*kept_parts),
            human_size(*kept_bytes),
            checked_parts(*dropped_parts),
            human_size(*dropped_bytes)
        ),
        RestartOutcome::StartedOver {
            fault,
            dropped_parts,
            dropped_bytes,
        } => {
            let why = integrity_fault_words(fault);
            match dropped_parts {
                0 => format!("nothing on disk to continue from ({why}), starting from 0 %"),
                _ => format!(
                    "nothing on disk to continue from ({why}), starting from 0 %; {} ({}) fetched again",
                    checked_parts(*dropped_parts),
                    human_size(*dropped_bytes)
                ),
            }
        }
    }
}

/// The status bar's note for a download edge that notes a fixed fact.
pub const QUEUED: Sentence = Sentence::fixed("download queued");
/// A download came back from the store at attach.
pub const RECOVERED: Sentence = Sentence::fixed("download recovered");
/// A download finished.
pub const COMPLETED: Sentence = Sentence::fixed("download completed");
/// A download was cancelled.
pub const CANCELLED: Sentence = Sentence::fixed("download cancelled");
/// A completed download left the list.
pub const CLEARED: Sentence = Sentence::fixed("download cleared");
/// What a download with no source to try waits on (ADR-0051's amendment):
/// the global sweep asks only while a server session is up, so without one
/// the server's sources wait for it, and Kad — when it runs — asks alone.
#[must_use]
pub const fn source_wait_words(reason: SourceWait) -> &'static str {
    match reason {
        SourceWait::Asking => "waiting for sources",
        SourceWait::KadAlone => "asking Kad; no server session for more sources",
        SourceWait::NoSession => {
            "no source left to try; waiting for a server session or Kad: connect to a server, or enable Kad"
        }
    }
}

/// [`source_wait_words`] as the status bar's note.
#[must_use]
pub const fn waiting_for_sources(reason: SourceWait) -> Sentence {
    Sentence::fixed(source_wait_words(reason))
}

/// A download failed — or, when it was already Failed, its Restart failed
/// again, which the row itself cannot show.
#[must_use]
pub fn failed(name: &str, reason: &DownloadFailure, again: bool) -> Sentence {
    let words = download_failure_words(reason);
    Sentence::owned(if again {
        format!("{name}: restart failed again: {words}")
    } else {
        format!("{name} failed: {words}")
    })
}

/// Checked parts that no longer matched on disk were dropped.
#[must_use]
pub fn damaged_parts(name: &str, damaged: &[PartFault]) -> Sentence {
    let details = damaged
        .iter()
        .map(part_fault_words)
        .collect::<Vec<_>>()
        .join("; ");
    Sentence::owned(format!(
        "{name}: {} no longer matched on disk and will be fetched again ({details})",
        checked_parts(u32::try_from(damaged.len()).unwrap_or(u32::MAX))
    ))
}

/// The part file changed under the run (ADR-0094): said at once, with what it
/// cost.
#[must_use]
pub fn part_file_lost(name: &str, found: PartFileChange, lost: PartsLost) -> Sentence {
    Sentence::owned(format!(
        "{name}: {} — {}",
        part_file_change_words(found),
        parts_lost_words(lost)
    ))
}

/// The finished file did not match its hash and no part could be named.
#[must_use]
pub fn finished_file_rejected(name: &str, parts: u32, bytes: u64) -> Sentence {
    Sentence::owned(format!(
        "{name}: the finished file did not match its hash and no part could be named — {}",
        parts_to_fetch_again(parts, bytes)
    ))
}

/// The store could not record a failure just told.
#[must_use]
pub fn failure_not_recorded(name: &str) -> Sentence {
    Sentence::owned(format!(
        "{name}: rmule's store could not record that it failed — the next start shows it as it was before"
    ))
}

/// What the operator's Restart did.
#[must_use]
pub fn restarted(name: &str, outcome: &RestartOutcome) -> Sentence {
    Sentence::owned(format!("{name} restarted: {}", restart_words(outcome)))
}

/// Transfers' clear with nothing completed to clear.
pub const NOTHING_TO_CLEAR: Sentence = Sentence::fixed("no completed downloads to clear");
/// Pause on a completed row.
pub const NOTHING_TO_PAUSE: Sentence =
    Sentence::fixed("completed: nothing to pause (m ▸ Clear from list)");
/// Resume or Restart with no session config to take credentials from.
pub const RESUME_NEEDS_CREDENTIALS: Sentence =
    Sentence::fixed("no session config — resume needs credentials (rmule-cli identity)");
/// A download asked for with no session config to take credentials from.
pub const START_NEEDS_CREDENTIALS: Sentence =
    Sentence::fixed("no session config — a download needs credentials (rmule-cli identity)");
/// A Restart from the Failed mark's confirm, with no session config.
pub const RESTART_NEEDS_CREDENTIALS: Sentence =
    Sentence::fixed("no session config — a restart needs credentials (rmule-cli identity)");
/// A download asked for with no download directory set.
pub const NO_DOWNLOAD_DIR: Sentence =
    Sentence::fixed("no download dir — set one with rmule-cli config set-download-dir");

/// A re-add of a file already downloading.
#[must_use]
pub fn already_downloading(name: &str) -> Sentence {
    Sentence::owned(format!("already downloading as {name} — see Transfers (3)"))
}

/// Why the Transfers tab's Add-link form refused what was pasted: each code
/// the form can reach, so its sentence is chosen here and nowhere else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkRefusal {
    /// Nothing was pasted.
    Empty,
    /// The text does not read as an eD2k link at all, or breaks its layout.
    Unreadable,
    /// The file hash or a part hash does not read.
    BadHash,
    /// The size is past what eD2k carries.
    TooLarge,
    /// The size is zero.
    ZeroSize,
    /// A field appears twice; the name is the link's own text.
    DuplicateField(String),
    /// A server or server-list link: it names no file.
    NotAFileLink,
    /// A download of the file is in Transfers and the link names no source
    /// that could join it (a link that does is sent: core adds its sources).
    AlreadyDownloading {
        /// The name the download runs under.
        name: String,
    },
}

/// The Add-link form's refusal, under its field.
#[must_use]
pub fn link_refused(refusal: &LinkRefusal) -> Sentence {
    Sentence::owned(match refusal {
        LinkRefusal::Empty => "paste an eD2k file link: ed2k://|file|name|size|hash|/".to_string(),
        LinkRefusal::Unreadable => {
            "not a readable eD2k link — check that it was copied whole".to_string()
        }
        LinkRefusal::BadHash => {
            "the link's hash does not read — check that it was copied whole".to_string()
        }
        LinkRefusal::TooLarge => {
            "the link names a file larger than eD2k allows (256 GiB)".to_string()
        }
        LinkRefusal::ZeroSize => "the link names a file of zero bytes".to_string(),
        LinkRefusal::DuplicateField(field) => {
            format!("the link carries its `{field}` field twice")
        }
        LinkRefusal::NotAFileLink => {
            "a server link, not a file link — add servers in Networks (1)".to_string()
        }
        LinkRefusal::AlreadyDownloading { name } => {
            format!("already downloading as {name}; the link names no source to add")
        }
    })
}

/// The fields a pasted link carried that no client reads, said once it is
/// added (ADR-0089); `None` when it carried none.
#[must_use]
pub fn link_fields_skipped(fields: &[String]) -> Option<Sentence> {
    let quoted: Vec<String> = fields.iter().map(|name| format!("`{name}`")).collect();
    match quoted.as_slice() {
        [] => None,
        [one] => Some(Sentence::owned(format!(
            "ignored the field {one} the link carried, which no client reads"
        ))),
        many => Some(Sentence::owned(format!(
            "ignored the fields {} the link carried, which no client reads",
            many.join(", ")
        ))),
    }
}

/// A second link for a running download: its sources joined the run instead
/// of a second download being made (ADR-0089). `new` counts
/// only the sources the run did not already know.
#[must_use]
pub fn link_sources_added(name: &str, new: usize) -> Sentence {
    Sentence::owned(format!(
        "already downloading {name}; {} from the link",
        count(
            u64::try_from(new).unwrap_or(u64::MAX),
            "new source",
            "new sources"
        )
    ))
}

/// The mark a source dialed from the download's **Source Seeds** carries in
/// the Sources pane (ADR-0109): a peer the last run knew, dialed before
/// anyone was asked.
pub const REMEMBERED: &str = "remembered";

/// What a saved `Remember peers` keeps, for the Settings receipt.
#[must_use]
pub fn remember_peers_receipt(peers: rmule_core::RememberPeers) -> String {
    format!(
        "remember {} per download",
        count(u64::from(peers.get().get()), "peer", "peers")
    )
}

/// Why a typed `Remember peers` was refused.
pub const REMEMBER_PEERS_REFUSED: &str = "remember peers: a whole number from 1 to 255";

/// The `Remember peers` row's note: what the count is for.
pub const REMEMBER_PEERS_NOTE: &str = "per download, dialled first after a restart";

/// Attach's one line about the **Source Seeds** it loaded (ADR-0109): how
/// many remembered peers go first for how many downloads, and how many were
/// too old to dial.
#[must_use]
pub fn seeds_loaded(downloads: usize, seeds: usize, expired: usize) -> String {
    let peers = |n: usize| {
        count(
            u64::try_from(n).unwrap_or(u64::MAX),
            "remembered peer",
            "remembered peers",
        )
    };
    let dropped = format!("{} older than a day dropped", peers(expired));
    match (downloads, expired) {
        (0, _) => format!("{dropped}; none to dial"),
        (_, 0) => format!(
            "dialling {} for {} first",
            peers(seeds),
            count(
                u64::try_from(downloads).unwrap_or(u64::MAX),
                "download",
                "downloads"
            )
        ),
        _ => format!("{}; {dropped}", seeds_loaded(downloads, seeds, 0)),
    }
}

/// A download event's line in the Networks log: terse, no ids or hashes.
#[must_use]
pub fn log_line(event: &DownloadEvent) -> Sentence {
    use DownloadEvent as D;
    let named = |what: &str, metadata: &DownloadMetadata| {
        let name = metadata.name.to_display_string();
        if name.trim().is_empty() {
            what.to_string()
        } else {
            format!("{what}: {name}")
        }
    };
    Sentence::owned(match event {
        D::DownloadQueued { metadata, .. } => named("download queued", metadata),
        D::DownloadRecovered {
            state, metadata, ..
        } => named(
            &format!("download recovered ({})", lifecycle_words(*state)),
            metadata,
        ),
        D::DownloadProgressRestored { verified_parts, .. } => {
            format!("progress restored: {verified_parts} parts")
        }
        D::DamagedPartsDropped { damaged, .. } => format!(
            "damaged parts dropped, fetching again: {}",
            damaged
                .iter()
                .map(part_fault_words)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        D::PartFileLost { found, lost, .. } => format!(
            "{}: {}",
            part_file_change_words(*found),
            parts_lost_words(*lost)
        ),
        D::FinishedFileRejected {
            parts_dropped,
            bytes_dropped,
            ..
        } => format!(
            "finished file did not match its hash: {}",
            parts_to_fetch_again(*parts_dropped, *bytes_dropped)
        ),
        D::DownloadRestarted { outcome, .. } => {
            format!("download restarted: {}", restart_words(outcome))
        }
        D::ServerLoginAccepted { client_id, .. } => format!(
            "eD2k login accepted ({})",
            if client_id.is_high_id() {
                "HighID"
            } else {
                "LowID"
            }
        ),
        D::SourcesFound {
            total,
            usable_high_id,
            ..
        } => format!("{total} sources found ({usable_high_id} usable)"),
        D::LinkSourcesAdded {
            named,
            admitted,
            new,
            ..
        } => format!(
            "a second link named {} ({admitted} admitted, {new} new)",
            count(
                u64::try_from(*named).unwrap_or(u64::MAX),
                "source",
                "sources"
            )
        ),
        D::SeedsLoaded {
            downloads,
            seeds,
            expired,
        } => seeds_loaded(*downloads, *seeds, *expired),
        D::SeedsDialled {
            dialled, answered, ..
        } => format!(
            "{answered} of {} answered",
            count(
                u64::try_from(*dialled).unwrap_or(u64::MAX),
                "remembered peer",
                "remembered peers"
            )
        ),
        D::SourcesExchanged {
            peer,
            received,
            admitted,
            ..
        } => format!(
            "peer {} exchanged {received} sources ({admitted} admitted)",
            address(*peer)
        ),
        D::PeerSelected { peer, .. } => format!("peer {} selected", address(*peer)),
        D::PeerQueued { peer, rank, .. } => {
            format!("peer {} queued us at rank {rank}", address(*peer))
        }
        D::PeerSlotGranted { peer, .. } => format!("peer {} granted a slot", address(*peer)),
        D::PeerSlotTimeout { peer, .. } => {
            format!("peer {} took too long to grant a slot", address(*peer))
        }
        D::SourceRemoteQueued { peer, rank, .. } => {
            format!("peer {} keeps us queued at rank {rank}", address(*peer))
        }
        D::SourceReaskAcked { peer, rank, .. } => {
            format!("peer {} answered the reask: rank {rank}", address(*peer))
        }
        D::SourceReaskQueueFull { peer, .. } => {
            format!(
                "peer {} answered the reask: its queue is full",
                address(*peer)
            )
        }
        D::SourceReaskDropped { peer, .. } => {
            format!("peer {} did not answer the reask; dropped", address(*peer))
        }
        D::ReaskReplyIgnored { peer, reason, .. } => format!(
            "a reask answer from {} was ignored: {}",
            address(*peer),
            ignored_reask_reply_words(*reason)
        ),
        D::DialEnded { peer, cause, .. } => format!(
            "dial to {} ended before its hello: {}",
            address(*peer),
            dial_end_words(*cause)
        ),
        D::HashSetReceived { part_count, .. } => {
            format!("hash set received ({part_count} parts)")
        }
        D::PartAssigned {
            peer, part_index, ..
        } => format!("part {part_index} assigned to {}", address(*peer)),
        D::PartReleased {
            part_index, reason, ..
        } => format!("part {part_index} released: {}", release_words(*reason)),
        D::PeerRetired { peer, reason, .. } => format!(
            "peer {} retired: {}",
            address(*peer),
            retirement_words(*reason)
        ),
        D::PartVerified { part_index, .. } => format!("part {part_index} verified"),
        D::DownloadCompleted { .. } => "download completed".to_string(),
        D::DownloadCancelled { .. } => "download cancelled".to_string(),
        D::DownloadCleared { .. } => "download cleared".to_string(),
        D::DownloadPaused { .. } => "download paused".to_string(),
        D::DownloadResumed { .. } => "download resumed".to_string(),
        D::DownloadFailed { reason, .. } => {
            format!("download failed: {}", download_failure_words(reason))
        }
        D::FailureNotRecorded { .. } => {
            "the store could not record that failure; the next start shows the download as it was"
                .to_string()
        }
        D::WaitingForSources { reason, .. } => source_wait_words(*reason).to_string(),
        D::WaitingForConnection { .. } => {
            "waiting for a connection (no server session, Kad off)".to_string()
        }
    })
}
