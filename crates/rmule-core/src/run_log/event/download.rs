//! The Run Log's record of each download event.

use crate::{DownloadEvent, PurgedSource, RestartOutcome};

use crate::run_log::codes;
use crate::run_log::record::Record;

impl DownloadEvent {
    /// The Run Log's record of this download event.
    #[must_use]
    pub fn record(&self) -> Record {
        use DownloadEvent as D;
        match self {
            D::DownloadQueued {
                download_id,
                file_hash,
                metadata,
                file_path,
            } => Record::new("download.queued")
                .count("id", download_id.as_u64())
                .file_hash("file_hash", file_hash)
                .file_name("name", &metadata.name.to_display_string())
                .file_size("size", metadata.size)
                .path("file_path", file_path),
            D::DownloadRecovered {
                download_id,
                state,
                failure,
                file_hash,
                metadata,
                file_path,
            } => {
                let record = Record::new("download.recovered")
                    .count("id", download_id.as_u64())
                    .code("state", codes::lifecycle(*state))
                    .file_hash("file_hash", file_hash)
                    .file_name("name", &metadata.name.to_display_string())
                    .file_size("size", metadata.size)
                    .path("file_path", file_path);
                match failure {
                    Some(failure) => codes::failure(record, failure),
                    None => record,
                }
            }
            D::DownloadProgressRestored {
                download_id,
                verified_parts,
                verified_bytes,
            } => Record::new("download.progress_restored")
                .count("id", download_id.as_u64())
                .count("verified_parts", *verified_parts)
                .count("verified_bytes", *verified_bytes),
            D::DamagedPartsDropped {
                download_id,
                damaged,
            } => {
                let mut record = Record::new("download.damaged_parts_dropped")
                    .count("id", download_id.as_u64())
                    .count("parts", damaged.len());
                for fault in damaged {
                    record = codes::part_fault(record, fault);
                }
                record
            }
            D::PartFileLost {
                download_id,
                found,
                lost,
            } => codes::parts_lost(
                codes::part_file_change(
                    Record::new("download.part_file_lost").count("id", download_id.as_u64()),
                    *found,
                ),
                *lost,
            ),
            D::PartsDisproved {
                download_id,
                parts,
                bytes,
            } => Record::new("download.parts_disproved")
                .count("id", download_id.as_u64())
                .count("parts", *parts)
                .count("bytes", *bytes),
            D::FinishedFileRejected {
                download_id,
                parts_dropped,
                bytes_dropped,
            } => Record::new("download.finished_file_rejected")
                .count("id", download_id.as_u64())
                .count("parts_dropped", *parts_dropped)
                .count("bytes_dropped", *bytes_dropped),
            D::DownloadRestarted {
                download_id,
                outcome,
            } => {
                let record = Record::new("download.restarted").count("id", download_id.as_u64());
                match outcome {
                    RestartOutcome::Continued {
                        kept_parts,
                        kept_bytes,
                        dropped_parts,
                        dropped_bytes,
                    } => record
                        .code("outcome", "continued")
                        .count("kept_parts", *kept_parts)
                        .count("kept_bytes", *kept_bytes)
                        .count("dropped_parts", *dropped_parts)
                        .count("dropped_bytes", *dropped_bytes),
                    RestartOutcome::StartedOver {
                        fault,
                        dropped_parts,
                        dropped_bytes,
                    } => codes::storage_fault(record.code("outcome", "started_over"), fault)
                        .count("dropped_parts", *dropped_parts)
                        .count("dropped_bytes", *dropped_bytes),
                }
            }
            D::ServerLoginAccepted {
                download_id,
                client_id,
            } => Record::new("download.server_login_accepted")
                .count("id", download_id.as_u64())
                .own_id("client_id", *client_id),
            D::SourcesFound {
                download_id,
                total,
                usable_high_id,
            } => Record::new("download.sources_found")
                .count("id", download_id.as_u64())
                .count("total", *total)
                .count("usable_high_id", *usable_high_id),
            D::LinkSourcesAdded {
                download_id,
                named,
                admitted,
                new,
            } => Record::new("download.link_sources_added")
                .count("id", download_id.as_u64())
                .count("named", *named)
                .count("admitted", *admitted)
                .count("new", *new),
            D::SeedsLoaded {
                downloads,
                seeds,
                expired,
            } => Record::new("download.seeds_loaded")
                .count("downloads", *downloads)
                .count("seeds", *seeds)
                .count("expired", *expired),
            D::SeedsDialled {
                download_id,
                written,
                dialled,
                answered,
            } => Record::new("download.seeds_dialled")
                .count("id", download_id.as_u64())
                .count("written", *written)
                .count("dialled", *dialled)
                .count("answered", *answered),
            D::SourcesExchanged {
                download_id,
                peer,
                received,
                admitted,
            } => Record::new("download.sources_exchanged")
                .count("id", download_id.as_u64())
                .peer_address("peer", peer)
                .count("received", *received)
                .count("admitted", *admitted),
            D::PeerSelected { download_id, peer } => Record::new("download.peer_selected")
                .count("id", download_id.as_u64())
                .peer_address("peer", peer),
            D::PeerQueued {
                download_id,
                peer,
                rank,
            } => Record::new("download.peer_queued")
                .count("id", download_id.as_u64())
                .peer_address("peer", peer)
                .count("rank", *rank),
            D::PeerSlotGranted { download_id, peer } => Record::new("download.peer_slot_granted")
                .count("id", download_id.as_u64())
                .peer_address("peer", peer),
            D::PeerSlotTimeout { download_id, peer } => Record::new("download.peer_slot_timeout")
                .count("id", download_id.as_u64())
                .peer_address("peer", peer),
            D::SourceRemoteQueued {
                download_id,
                peer,
                rank,
            } => {
                let record = Record::new("download.source_remote_queued")
                    .count("id", download_id.as_u64())
                    .peer_address("peer", peer);
                match rank {
                    Some(rank) => record.count("rank", *rank),
                    None => record.code("rank", "unknown"),
                }
            }
            D::SourceReaskAcked {
                download_id,
                peer,
                rank,
            } => Record::new("download.source_reask_acked")
                .count("id", download_id.as_u64())
                .peer_address("peer", peer)
                .count("rank", *rank),
            D::SourceReaskQueueFull { download_id, peer } => {
                Record::new("download.source_reask_queue_full")
                    .count("id", download_id.as_u64())
                    .peer_address("peer", peer)
            }
            D::SourceReaskedOverTcp { download_id, peer } => {
                Record::new("download.source_reasked_over_tcp")
                    .count("id", download_id.as_u64())
                    .peer_address("peer", peer)
            }
            D::SourcePurged {
                download_id,
                source,
                reason,
            } => {
                let record = Record::new("download.source_purged")
                    .count("id", download_id.as_u64())
                    .code("reason", codes::source_purge_reason(*reason));
                match source {
                    PurgedSource::Endpoint(peer) => record.peer_address("peer", peer),
                    PurgedSource::LowId { low_id, server } => {
                        let record = record.peer_id("low_id", *low_id);
                        match server {
                            Some(server) => record.server_address("server", server),
                            None => record,
                        }
                    }
                }
            }
            D::SourceReaskDropped { download_id, peer } => {
                Record::new("download.source_reask_dropped")
                    .count("id", download_id.as_u64())
                    .peer_address("peer", peer)
            }
            D::ReaskReplyIgnored {
                download_id,
                peer,
                reason,
            } => Record::new("download.reask_reply_ignored")
                .count("id", download_id.as_u64())
                .code("reason", codes::ignored_reask_reply(*reason))
                .peer_address("peer", peer),
            D::DialEnded {
                download_id,
                peer,
                cause,
            } => codes::dial_end(
                Record::new("download.dial_ended").count("id", download_id.as_u64()),
                *cause,
            )
            .peer_address("peer", peer),
            D::HashSetReceived {
                download_id,
                part_count,
                authority,
            } => Record::new("download.hash_set_received")
                .count("id", download_id.as_u64())
                .count("part_count", *part_count)
                .code("authority", codes::authority(*authority)),
            D::PartAssigned {
                download_id,
                peer,
                part_index,
            } => Record::new("download.part_assigned")
                .count("id", download_id.as_u64())
                .peer_address("peer", peer)
                .count("part_index", *part_index),
            D::PartReleased {
                download_id,
                peer,
                part_index,
                reason,
            } => codes::part_release(
                Record::new("download.part_released")
                    .count("id", download_id.as_u64())
                    .peer_address("peer", peer)
                    .count("part_index", *part_index),
                *reason,
            ),
            D::PeerRetired {
                download_id,
                peer,
                reason,
            } => Record::new("download.peer_retired")
                .count("id", download_id.as_u64())
                .peer_address("peer", peer)
                .code("reason", codes::retirement(*reason)),
            D::PartVerified {
                download_id,
                part_index,
            } => Record::new("download.part_verified")
                .count("id", download_id.as_u64())
                .count("part_index", *part_index),
            D::DownloadCompleted { download_id, .. } => {
                Record::new("download.completed").count("id", download_id.as_u64())
            }
            D::DownloadCancelled { download_id } => {
                Record::new("download.cancelled").count("id", download_id.as_u64())
            }
            D::DownloadCleared { download_id } => {
                Record::new("download.cleared").count("id", download_id.as_u64())
            }
            D::DownloadPaused { download_id } => {
                Record::new("download.paused").count("id", download_id.as_u64())
            }
            D::DownloadResumed { download_id } => {
                Record::new("download.resumed").count("id", download_id.as_u64())
            }
            D::DownloadFailed {
                download_id,
                reason,
            } => codes::failure(
                Record::new("download.failed").count("id", download_id.as_u64()),
                reason,
            ),
            D::FailureNotRecorded { download_id } => {
                Record::new("download.failure_not_recorded").count("id", download_id.as_u64())
            }
            D::WaitingForSources {
                download_id,
                reason,
            } => Record::new("download.waiting_for_sources")
                .count("id", download_id.as_u64())
                .code("reason", codes::source_wait(*reason)),
            D::WaitingForConnection { download_id } => {
                Record::new("download.waiting_for_connection").count("id", download_id.as_u64())
            }
            D::HoleLessDestination {
                download_id,
                directory,
            } => Record::new("download.hole_less_destination")
                .count("id", download_id.as_u64())
                .path("directory", directory),
            D::Completing {
                download_id,
                to,
                step,
            } => Record::new("download.completing")
                .count("id", download_id.as_u64())
                .path("to", to)
                .code("step", codes::completion_step(*step)),
        }
    }
}
