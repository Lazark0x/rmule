//! The operator's words for the codes core hands the download surface: why a
//! download failed, why a part went back to the pool, why a source left, the
//! state a recovered download came back in, what a Restart did, and every
//! download event's line in the Networks log. Core carries codes and the TUI
//! owns every sentence, so the app can be translated; each match is
//! exhaustive, so a code core adds cannot reach the screen without its words.
//! Each domain's words live in a child module; this one re-exports them, and
//! holds the edges' fixed notes and the Networks log line.

use std::path::Path;

use rmule_core::{DownloadEvent, DownloadId, DownloadLifecycle, DownloadMetadata};

use super::Sentence;
use super::units::{address, count};

mod completion;
mod failure;
mod hole_verdict;
mod link;
mod part_file;
mod source;

pub use completion::{
    completing, completing_line, completing_status, completion_progress, completion_step_words,
};
pub use failure::{
    FAILURE_NOT_RECORDED, download_failure_words, failed, failure_not_recorded,
    integrity_fault_words, part_fault_words,
};
use hole_verdict::{HOLE_LESS_REMEDY, hole_less_where};
pub use hole_verdict::{hole_less_destination, on_disk};
pub use link::{
    LinkRefusal, already_downloading, link_fields_skipped, link_refused, link_sources_added,
};
pub use part_file::{
    damaged_parts, finished_file_rejected, part_file_change_words, part_file_lost, parts_disproved,
    parts_lost_words, parts_to_fetch_again, restart_words, restarted,
};
pub use source::link_turn_words;
use source::purged_source_words;
pub use source::{
    NO_NETWORK_WAIT, NO_NETWORK_WAIT_NOTE, REMEMBER_PEERS_NOTE, REMEMBER_PEERS_REFUSED, REMEMBERED,
    ceiling_lowered, dial_end_words, ignored_reask_reply_words, phase_words, release_words,
    remember_peers_receipt, retirement_words, seeds_loaded, source_activity_words,
    source_purge_reason_words, source_wait_words, waiting_for_sources,
};

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
        DownloadLifecycle::Completing => "completing",
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

/// The line a one-shot download ends on: which download completed, and the
/// file core made, at the path it placed it — which names the file as it
/// landed, a numbered name included.
#[must_use]
pub fn completed_line(download_id: DownloadId, final_path: &Path) -> String {
    format!(
        "completed id={} at {}",
        download_id.as_u64(),
        final_path.display()
    )
}

/// Transfers' clear with nothing completed to clear.
pub const NOTHING_TO_CLEAR: Sentence = Sentence::fixed("no completed downloads to clear");
/// Pause on a completed row.
pub const NOTHING_TO_PAUSE: Sentence =
    Sentence::fixed("completed: nothing to pause (m ▸ Clear from list)");
/// A download asked for with no download directory set.
pub const NO_DOWNLOAD_DIR: Sentence =
    Sentence::fixed("no download dir — set one with rmule-cli config set-download-dir");

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
        D::PartsDisproved { parts, bytes, .. } => format!(
            "parts fetched before the hash set did not match it: {}",
            parts_to_fetch_again(*parts, *bytes)
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
        D::SourceRemoteQueued {
            peer,
            rank: Some(rank),
            ..
        } => format!("peer {} keeps us queued at rank {rank}", address(*peer)),
        D::SourceRemoteQueued {
            peer, rank: None, ..
        } => format!(
            "peer {} keeps us queued, at a rank not yet known",
            address(*peer)
        ),
        D::SourceWaitsOnStanding { peer, .. } => format!(
            "peer {} already queues us for another download; this one waits on that place and asks nothing",
            address(*peer)
        ),
        D::SourceReaskAcked { peer, rank, .. } => {
            format!("peer {} answered the reask: rank {rank}", address(*peer))
        }
        D::SourceReaskQueueFull { peer, .. } => {
            format!(
                "peer {} answered the reask: its queue is full",
                address(*peer)
            )
        }
        D::SourceReaskedOverTcp { peer, .. } => {
            format!("peer {} is asked again over TCP", address(*peer))
        }
        D::SlotOffered { peer, .. } => format!(
            "peer {} offered us an upload slot from its queue; downloading over its connection",
            address(*peer)
        ),
        D::SourcePurged { source, reason, .. } => format!(
            "{} {} while the file neared its source limit; dropped",
            purged_source_words(*source),
            source_purge_reason_words(*reason)
        ),
        D::SourceReaskDropped { peer, .. } => {
            format!("peer {} no longer shares the file; dropped", address(*peer))
        }
        D::ReaskReplyIgnored { peer, reason, .. } => format!(
            "a reask answer from {} was ignored: {}",
            address(*peer),
            ignored_reask_reply_words(*reason)
        ),
        D::LinkShared { peer, turn, .. } => match turn {
            rmule_core::LinkTurn::Waiting => format!(
                "{} is busy with another download; this one waits for its link",
                address(*peer)
            ),
            rmule_core::LinkTurn::Riding => {
                format!("asks {} over the link already open to it", address(*peer))
            }
        },
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
        D::EndGameBlocks {
            peer,
            part_index,
            blocks,
            ..
        } => format!(
            "end game: {} of part {part_index} asked of {} as well",
            match blocks {
                1 => "1 block".to_string(),
                n => format!("{n} blocks"),
            },
            address(*peer)
        ),
        D::KadAichRootContested { .. } => "its sources agree on another AICH root than the Kad \
             search named; trusting neither, a part that fails its check is fetched again whole"
            .to_string(),
        D::PartCorrupt {
            part_index,
            writers,
            named,
            ..
        } => format!(
            "part {part_index} failed its check; {}; fetching it again",
            match (*named, *writers) {
                (0, writers) => format!(
                    "which of its {} sent bad data is not known yet",
                    count(u64::from(writers), "source", "sources")
                ),
                (1, 1) => "its only source sent bad data".to_string(),
                (1, writers) => format!("1 of its {writers} sources is held to blame"),
                (named, writers) => format!("{named} of its {writers} sources are held to blame"),
            }
        ),
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
        D::HoleLessDestination { directory, .. } => {
            format!("{}; {HOLE_LESS_REMEDY}", hole_less_where(directory))
        }
        // The line a one-shot download prints, so the two front ends say a
        // step of the move one way.
        D::Completing { to, step, .. } => completing_line(*step, to),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rmule_core::{CompletionStep, DownloadEvent, DownloadId};

    use super::{hole_less_destination, log_line};

    /// The Networks log words a step of the completion move as the one-shot
    /// download prints it: one shape on both front ends.
    #[test]
    fn a_completing_step_logs_the_line_the_cli_prints() {
        let line = log_line(&DownloadEvent::Completing {
            download_id: DownloadId::from_u64(1),
            to: Path::new("/Downloads/Мой фильм (1).mkv").to_path_buf(),
            step: CompletionStep::Copying,
        });
        assert_eq!(
            line.as_str(),
            "completing: copying the finished file to the disk it goes to \
             (/Downloads/Мой фильм (1).mkv)"
        );
    }

    /// A directory with spaces and non-ASCII names reads whole in the edge's
    /// sentence and its Networks-log line: no quoting, no escape, no cut.
    #[test]
    fn a_hole_less_directory_with_spaces_and_non_ascii_names_reads_whole() {
        let directory = Path::new("/Volumes/Мой диск/Temp files");
        assert_eq!(
            hole_less_destination("Ünïcode film.mkv", directory).as_str(),
            "Ünïcode film.mkv: its part file lies in /Volumes/Мой диск/Temp files; this disk \
             holds no holes, so the part file takes its full length on disk up to its last \
             verified part; the download goes on — downloads started with the Temp Directory \
             on another disk avoid this"
        );
        let line = log_line(&DownloadEvent::HoleLessDestination {
            download_id: DownloadId::from_u64(1),
            directory: directory.to_path_buf(),
        });
        assert!(
            line.contains("its part file lies in /Volumes/Мой диск/Temp files; this disk"),
            "{line}"
        );
    }
}
