//! Attach (ADR-0094, "Attach"): every download the store still lists — each
//! that holds its file's place, and each completed one not yet cleared — is
//! reported as the last process left it, with its part picture at rest, and
//! the ones the operator left running are started again by core — one per
//! restore pace, never all in one tick.

use std::collections::{HashMap, VecDeque};
use std::time::SystemTime;

use tokio::sync::mpsc;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::diagnostics::DiagnosticsState;
use crate::download::source_seeds::SourceSeed;
use crate::served_downloads::ServedDownloads;
use crate::service::{CoreEvent, DownloadEvent, DownloadId, send_download_event};
use crate::storage::{DownloadRepository, recorded_part_hashes};
use crate::store::download::DurableDownloadRepository;
use crate::{DownloadFailure, DownloadLifecycle};

use super::super::CoreActor;

/// Report every download Transfers lists — each that still holds its file's
/// place, and each completed one until it is cleared, so "Clear completed"
/// never clears a row the operator was not shown — open its resting
/// diagnostics row, and return the ones to start again, in store order: those
/// the operator left running (`Active`) or never saw start (`Queued`) — when
/// `can_restore`, since only a core built to restore at attach runs them —
/// each with its **Source Seeds** under a day old (ADR-0109), the older ones
/// dropped, said once for all of them.
///
/// Each that is a Served Download is installed with an empty range and no
/// identity, its lease with the actor (ADR-0113).
pub(in crate::service::actor) async fn attach_downloads(
    store: &DurableDownloadRepository,
    diagnostics: &DiagnosticsState,
    evt_tx: &mpsc::Sender<CoreEvent>,
    can_restore: bool,
    served: &ServedDownloads,
) -> (VecDeque<DownloadId>, HashMap<DownloadId, Vec<SourceSeed>>) {
    let records = match store.listed_downloads() {
        Ok(records) => records,
        Err(error) => {
            tracing::warn!(%error, "the store's downloads could not be read at attach");
            return (VecDeque::new(), HashMap::new());
        }
    };
    let mut restoring = VecDeque::new();
    for record in records {
        let download_id = record.id();
        let parts = store.verified_parts(download_id).unwrap_or_default();
        let verified_bytes = parts.iter().map(|part| part.len).sum();
        let held: Vec<u32> = parts.iter().map(|part| part.part_index).collect();
        served.install(&record, &recorded_part_hashes(store, download_id));
        diagnostics.rest_download(
            download_id,
            record.file_hash(),
            record.metadata().clone(),
            &held,
        );
        send_download_event(
            evt_tx,
            DownloadEvent::DownloadRecovered {
                download_id,
                state: record.lifecycle(),
                failure: record.failure().cloned(),
                file_hash: record.file_hash(),
                metadata: record.metadata().clone(),
                file_path: record.file_path().to_path_buf(),
            },
        )
        .await;
        send_download_event(
            evt_tx,
            DownloadEvent::DownloadProgressRestored {
                download_id,
                verified_parts: parts.len(),
                verified_bytes,
            },
        )
        .await;
        // A completing row's run goes straight to its move (ADR-0115).
        let wants_run = matches!(
            record.lifecycle(),
            DownloadLifecycle::Active | DownloadLifecycle::Queued | DownloadLifecycle::Completing
        );
        if wants_run && can_restore {
            restoring.push_back(download_id);
        }
    }
    let remembered = load_seeds(store, evt_tx, &restoring).await;
    (restoring, remembered)
}

/// The fresh seeds of each download in `restoring`, the stale ones dropped,
/// and the one [`DownloadEvent::SeedsLoaded`] that says so when there was
/// any to load or to drop.
async fn load_seeds(
    store: &DurableDownloadRepository,
    evt_tx: &mpsc::Sender<CoreEvent>,
    restoring: &VecDeque<DownloadId>,
) -> HashMap<DownloadId, Vec<SourceSeed>> {
    let now = SystemTime::now();
    let mut remembered = HashMap::new();
    let mut expired = 0;
    for &download_id in restoring {
        match store.load_source_seeds(download_id, now) {
            Ok(loaded) => {
                expired += loaded.expired;
                if !loaded.fresh.is_empty() {
                    remembered.insert(download_id, loaded.fresh);
                }
            }
            Err(error) => tracing::warn!(
                download_id = download_id.as_u64(),
                %error,
                "a download's seeds could not be read at attach"
            ),
        }
    }
    if !remembered.is_empty() || expired > 0 {
        send_download_event(
            evt_tx,
            DownloadEvent::SeedsLoaded {
                downloads: remembered.len(),
                seeds: remembered.values().map(Vec::len).sum(),
                expired,
            },
        )
        .await;
    }
    remembered
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Start the next download attach found running — one per restore tick.
    pub(in crate::service::actor) async fn restore_next(&mut self) {
        let Some((download_id, remembered)) = self.activities.next_restoring() else {
            return;
        };
        tracing::info!(download_id = download_id.as_u64(), "download restored");
        // Every refusal here is the store's: attach just listed the row, and
        // no other run holds it. The download is failed by that cause, so
        // no row reads as running with no run behind it.
        if let Err(refusal) = self.resume(download_id, remembered).await {
            tracing::warn!(
                download_id = download_id.as_u64(),
                ?refusal,
                "a download attach found running could not start",
            );
            self.fail_at_rest(download_id, DownloadFailure::StoreFailed)
                .await;
        }
    }

    /// The download's seeds under a day old, the older ones dropped — for a
    /// run the operator starts by hand, which attach loaded none for. None
    /// when the store cannot read them: the run starts without.
    pub(in crate::service::actor) fn stored_seeds(
        &self,
        download_id: DownloadId,
    ) -> Vec<SourceSeed> {
        match self
            .wiring
            .store
            .load_source_seeds(download_id, SystemTime::now())
        {
            Ok(loaded) => loaded.fresh,
            Err(error) => {
                tracing::warn!(
                    download_id = download_id.as_u64(),
                    %error,
                    "a download's seeds could not be read at resume"
                );
                Vec::new()
            }
        }
    }
}
