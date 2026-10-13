//! The actor's side of the completion move (ADR-0115): the in-place step a
//! run reports, the Pause and Cancel that reach a move through its
//! **Completion Gate**, and the start of a run for a row attach found
//! `Completing`, which goes straight to the move's recovery.

use std::sync::Arc;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::download::source_seeds::SourceSeed;
use crate::download::{FinalFileInPlace, Recovered, StopAnswer, file_link_from_record};
use crate::registry::SharedFileRegistry;
use crate::service::{CoreCommandRejectReason, DownloadId};
use crate::storage::DownloadRepository;
use crate::{DownloadLifecycle, DurableDownloadRecord};

use super::super::CoreActor;
use super::{SpawnDownload, spawn_download};

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// A run's finished file is in place: write its row and end its Served
    /// Download in one step, and answer whether the row is written. A report
    /// from a run the ledger no longer holds writes nothing.
    pub(in crate::service::actor) async fn on_final_file_in_place(
        &mut self,
        report: FinalFileInPlace,
    ) {
        let FinalFileInPlace {
            download_id,
            run,
            path,
            written,
        } = report;
        let file_hash = self
            .activities
            .download(download_id)
            .filter(|active| active.run == run)
            .map(|active| active.file_hash);
        let shared = match file_hash {
            Some(file_hash) => {
                self.completion_in_place(download_id, file_hash, run, &path)
                    .await
            }
            None => false,
        };
        if !shared {
            tracing::warn!(
                download_id = download_id.as_u64(),
                "the finished file's registry row could not be written; the move reports again",
            );
        }
        let _ = written.send(shared);
    }

    /// A Pause or a Cancel reaches a completing download through its gate: a
    /// `Completing` row with no run is given one first, whose look at the
    /// disk says whether its file is in place. Refused with
    /// [`CoreCommandRejectReason::DownloadCompleting`] once it is; otherwise
    /// the gate is closed and the caller stops the run.
    pub(in crate::service::actor) async fn stop_completion(
        &mut self,
        download_id: DownloadId,
    ) -> Result<(), CoreCommandRejectReason> {
        let completing = self
            .wiring
            .store
            .load_download(download_id)
            .is_ok_and(|record| record.lifecycle() == DownloadLifecycle::Completing);
        if completing && !self.activities.has_download(download_id) {
            let remembered = self
                .activities
                .take_restoring(download_id)
                .unwrap_or_default();
            self.resume(download_id, remembered).await?;
        }
        let Some(gate) = self
            .activities
            .download(download_id)
            .map(|active| Arc::clone(&active.completion))
        else {
            return Ok(());
        };
        match gate.stop().await {
            StopAnswer::Stopped => Ok(()),
            StopAnswer::InPlace => Err(CoreCommandRejectReason::DownloadCompleting),
        }
    }

    /// Start the run of a row found `Completing`: no revalidation, since its
    /// part file may already be gone into place, and no `Active`, since the
    /// row names the destination its move resolves (ADR-0115).
    pub(in crate::service::actor) async fn resume_completing(
        &mut self,
        record: &DurableDownloadRecord,
        remembered: Vec<SourceSeed>,
    ) -> Result<(), CoreCommandRejectReason> {
        let download_id = record.id();
        let file = match file_link_from_record(record) {
            Ok(file) => file,
            Err(reason) => {
                self.fail_at_rest(download_id, reason).await;
                return Ok(());
            }
        };
        let Ok(parts) = self.wiring.store.verified_parts(download_id) else {
            return Err(CoreCommandRejectReason::UnknownDownload);
        };
        let row_written = self
            .wiring
            .registry
            .get(record.file_hash())
            .is_ok_and(|row| row.is_some_and(|row| row.path == record.paths().final_path()));
        self.diagnostics.ensure_download(
            download_id,
            record.file_hash(),
            record.metadata().clone(),
        );
        self.wiring.file_known.download_started(record.file_hash());
        let set = self.recorded_set(download_id);
        self.install_served(record, &set);
        let run = self.activities.take_download_run();
        let served = self.lease_to_run(record.file_hash(), run);
        let active = spawn_download(SpawnDownload {
            runtime: &self.download_runtime,
            download_id,
            file,
            identity: self.settings_identity(),
            verified_part_indexes: parts.iter().map(|part| part.part_index).collect(),
            streaming_priority: record.metadata().is_streaming_priority(),
            run,
            remembered,
            served,
            recovered: Some(Recovered { row_written }),
        });
        self.activities.download_started(download_id, active);
        self.served_moved().await;
        Ok(())
    }
}
