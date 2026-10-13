//! The actor's side of the **Served Downloads** (ADR-0113): it installs a
//! download's entry when the download is queued or found at attach, holds
//! the lease while the download is queued or paused, hands it to each run and
//! takes it back once the run has ended, holds an entry back while its
//! destination lies under a refused entry, and ends it at cancel, failure and
//! completion. Whatever moves the offer reaches the one share trigger here,
//! with the events that tell it.

use rmule_primitives::{FileHash, PartHash};

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::served_downloads::{OfferChange, PartialEnd, RunLease};
use crate::service::{DownloadId, ServeEvent};
use crate::storage::{DownloadRepository, ResolvedAuthority};
use crate::{DownloadLifecycle, DurableDownloadRecord};

use super::{CoreActor, send_event};

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Make `record`'s download a Served Download if it is one and has no
    /// entry yet, `set` its part hash set, and hold it back when its
    /// destination lies under a refused entry.
    pub(super) fn install_served(&self, record: &DurableDownloadRecord, set: &[PartHash]) {
        let served = &self.wiring.served_downloads;
        if served.install(record, set) && self.directories.refuses(record.paths().final_path()) {
            served.hold_back(record.file_hash(), true);
        }
    }

    /// The part hash set the store holds in force for `download_id`; empty
    /// when it holds none.
    pub(super) fn recorded_set(&self, download_id: DownloadId) -> Vec<PartHash> {
        match self.wiring.store.hash_authority(download_id) {
            Ok(ResolvedAuthority::Link(hashes) | ResolvedAuthority::Provisional(hashes)) => hashes,
            Ok(ResolvedAuthority::FileHashOnly) | Err(_) => Vec::new(),
        }
    }

    /// The lease on `file_hash`'s entry for run `run`; `None` when the file
    /// has no entry.
    pub(super) fn lease_to_run(&self, file_hash: FileHash, run: u64) -> Option<RunLease> {
        self.wiring.served_downloads.hand_to_run(file_hash, run)
    }

    /// Run `run` of the download of `file_hash` has ended: the actor writes
    /// its entry again.
    pub(super) fn take_back_served(&self, file_hash: FileHash, run: u64) {
        self.wiring.served_downloads.take_back(file_hash, run);
    }

    /// End `download_id`'s Served Download for `cause` and say what that
    /// moved, with one trigger.
    pub(super) async fn end_served(&mut self, download_id: DownloadId, cause: PartialEnd) {
        self.wiring.served_downloads.end(download_id, cause);
        self.served_moved().await;
    }

    /// Look at what moved since the last look: say each offer and withdrawal,
    /// and fire the one share trigger when anything moved.
    pub(super) async fn served_moved(&mut self) {
        if self.look_served().await {
            self.share_set_changed();
        }
    }

    /// Say each offer and withdrawal since the last look; `true` when the
    /// membership or the offer moved at all.
    async fn look_served(&mut self) -> bool {
        let changes = self.wiring.served_downloads.look();
        for change in &changes {
            let event = match *change {
                OfferChange::Offered(file_hash) => {
                    tracing::info!(file_hash = %file_hash.to_hex_upper(), "download offers its verified parts");
                    ServeEvent::PartialOffered { file_hash }
                }
                OfferChange::Withdrawn(file_hash, cause) => {
                    tracing::info!(file_hash = %file_hash.to_hex_upper(), ?cause, "download no longer offers its parts");
                    ServeEvent::PartialWithdrawn { file_hash, cause }
                }
                OfferChange::Joined(_) | OfferChange::Left(_) => continue,
            };
            send_event(&self.evt_tx, event.into()).await;
        }
        !changes.is_empty()
    }

    /// Hold back every entry whose destination lies under a refused entry
    /// of the list as it stands, and release the others.
    pub(super) async fn match_served_refusals(&mut self) {
        for (file_hash, destination) in self.wiring.served_downloads.destinations() {
            let refused = self.directories.refuses(&destination);
            self.wiring.served_downloads.hold_back(file_hash, refused);
        }
        self.served_moved().await;
    }

    /// A run ended on its own, or a stop's run finished: a completed
    /// download's row is written before its entry ends, and both before the
    /// one trigger, so the share set holds the file at every step; a failed
    /// one's entry ends.
    pub(super) async fn download_finished(&mut self, download_id: DownloadId) {
        let shared = self.share_completed(download_id).await;
        let cause = match self.wiring.store.load_download(download_id) {
            Ok(record) if record.lifecycle() == DownloadLifecycle::Completed => {
                Some(PartialEnd::Completed)
            }
            Ok(record) if record.lifecycle() == DownloadLifecycle::Failed => {
                Some(PartialEnd::Ended)
            }
            _ => None,
        };
        if let Some(cause) = cause {
            self.wiring.served_downloads.end(download_id, cause);
        }
        if self.look_served().await || shared {
            self.share_set_changed();
        }
    }
}
