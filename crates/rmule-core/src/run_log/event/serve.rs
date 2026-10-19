//! The Run Log's record of each serve event.

use crate::ServeEvent;

use crate::run_log::codes;
use crate::run_log::record::Record;

/// A peer's announced software: its family as a code, its version in that
/// family's notation and the mod it sent, each a value of its own.
fn software(record: Record, software: Option<&crate::diagnostics::ClientSoftware>) -> Record {
    use crate::diagnostics::ClientMod;
    let Some(software) = software else {
        return record;
    };
    let mut record = record.peer_software("software", &codes::client_family(software.family()));
    if let Some(version) = crate::diagnostics::software_parts(software).version {
        record = record.peer_software("software_version", &version);
    }
    match software.client_mod() {
        Some(ClientMod::Named(text)) => {
            record.peer_software("software_mod", &text.to_display_string())
        }
        Some(ClientMod::Numbered(id)) => record.count("software_mod_id", *id),
        None => record,
    }
}

impl ServeEvent {
    /// The Run Log's record of this serve event.
    #[must_use]
    pub fn record(&self) -> Record {
        use ServeEvent as S;
        match self {
            S::FileShared { file_hash } => {
                Record::new("serve.file_shared").file_hash("file_hash", file_hash)
            }
            S::FileUnshared { file_hash } => {
                Record::new("serve.file_unshared").file_hash("file_hash", file_hash)
            }
            S::FileWithheld {
                file_hash, reason, ..
            } => codes::withheld(
                Record::new("serve.file_withheld").file_hash("file_hash", file_hash),
                *reason,
            ),
            S::FileOffered { file_hash } => {
                Record::new("serve.file_offered").file_hash("file_hash", file_hash)
            }
            S::PartialOffered { file_hash } => {
                Record::new("serve.partial_offered").file_hash("file_hash", file_hash)
            }
            S::PartialWithdrawn { file_hash, cause } => Record::new("serve.partial_withdrawn")
                .file_hash("file_hash", file_hash)
                .code("cause", codes::partial_end(*cause)),
            S::OfferChecked {
                file_hash,
                bytes_read,
                took,
            } => Record::new("serve.offer_checked")
                .file_hash("file_hash", file_hash)
                .count("bytes_read", *bytes_read)
                .count("took_ms", took.as_millis()),
            S::SharesUnwatched => Record::new("serve.shares_unwatched"),
            S::ShareRejected { reason } => {
                Record::new("serve.share_rejected").code("reason", codes::share_rejected(*reason))
            }
            S::ServingStarted { listen_addr } => {
                Record::new("serve.serving_started").own_address("listen_addr", listen_addr)
            }
            S::ServingFailed { reason } => {
                codes::serve_start_failure(Record::new("serve.serving_failed"), *reason)
            }
            S::FilesAnnounced { file_count } => {
                Record::new("serve.files_announced").count("file_count", *file_count)
            }
            S::FilesWithheld { file_count, reason } => Record::new("serve.files_withheld")
                .count("file_count", *file_count)
                .code("reason", codes::shares_withheld(*reason)),
            S::UploadSlotGranted {
                peer,
                file_hash,
                software: announced,
                road,
            } => software(
                Record::new("serve.upload_slot_granted")
                    .peer_address("peer", peer)
                    .file_hash("file_hash", file_hash)
                    .code("road", codes::grant_road(*road)),
                announced.as_ref(),
            ),
            S::UploadDialBack {
                peer,
                file_hash,
                software: announced,
            } => software(
                Record::new("serve.upload_dial_back")
                    .peer_address("peer", peer)
                    .file_hash("file_hash", file_hash),
                announced.as_ref(),
            ),
            S::UploadDialBackFailed { peer, cause } => codes::dial_back_end(
                Record::new("serve.upload_dial_back_failed").peer_address("peer", peer),
                *cause,
            ),
            S::PeerQueued {
                peer,
                rank,
                file_hash,
                software: announced,
            } => software(
                Record::new("serve.peer_queued")
                    .peer_address("peer", peer)
                    .count("rank", *rank)
                    .file_hash("file_hash", file_hash),
                announced.as_ref(),
            ),
            S::UploadQueueFull { peer } => {
                Record::new("serve.upload_queue_full").peer_address("peer", peer)
            }
            S::UploadLowIdAbuseRefused { peer } => {
                Record::new("serve.upload_low_id_abuse_refused").peer_address("peer", peer)
            }
            S::ReaskPingMalformed { peer } => {
                Record::new("serve.reask_ping_malformed").peer_address("peer", peer)
            }
            S::NameAskMalformed { peer } => {
                Record::new("serve.name_ask_malformed").peer_address("peer", peer)
            }
            S::UploadAddressCapReached { peer } => {
                Record::new("serve.upload_address_cap_reached").peer_address("peer", peer)
            }
            S::BlockAskRefused {
                peer,
                file_hash,
                fault,
            } => Record::new("serve.block_ask_refused")
                .peer_address("peer", peer)
                .file_hash("file_hash", file_hash)
                .code("fault", codes::block_ask_fault(*fault)),
            S::UploadSlotReleased { peer } => {
                Record::new("serve.upload_slot_released").peer_address("peer", peer)
            }
            S::WaiterLeft { peer, cause } => Record::new("serve.waiter_left")
                .peer_address("peer", peer)
                .code("cause", codes::waiter_left(*cause)),
            S::WaiterRelinked { from, to } => Record::new("serve.waiter_relinked")
                .peer_address("from", from)
                .peer_address("to", to),
            S::CrossedLinkLetGo { peer } => {
                Record::new("serve.crossed_link_let_go").peer_address("peer", peer)
            }
            S::SourcesServed {
                peer,
                file_hash,
                count,
            } => Record::new("serve.sources_served")
                .peer_address("peer", peer)
                .file_hash("file_hash", file_hash)
                .count("count", *count),
            S::ServingStopped { reason } => {
                Record::new("serve.serving_stopped").code("reason", codes::serve_stop(*reason))
            }
        }
    }
}
