//! The download command arms: starting a download against the connected
//! server, and the cancel / pause / resume asks that reach the runner through
//! its stop signal. Every road that starts a run ends in the one
//! [`start_run`](CoreActor::start_run), so each assembles the same task.

use rmule_primitives::Ed2kFileLink;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::content::{ContentFileStore, free_space, on_pool};
use crate::download::part_check::{PartCheck, Restart};
use crate::download::source_seeds::SourceSeed;
use crate::download::{RunNumber, StopReason};
use crate::service::activity::ActiveDownload;
use crate::service::{
    CoreCommandRejectReason, CoreEvent, DownloadCommand, DownloadEvent, DownloadId,
    send_download_event,
};
use crate::storage::DownloadRepository;
use crate::{CoreError, DownloadFailure, DownloadLifecycle, DownloadPaths, DurableDownloadRecord};

use super::{CoreActor, send_event};

mod completion;
mod placement;
mod restore;
mod run;
mod seeds;
mod stopping;

pub(super) use restore::{adopt_part_files, attach_downloads};
pub(super) use run::DownloadRuntime;
use run::RunStart;
pub(super) use stopping::Stopping;

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Enact one download command against the live activity ledger.
    pub(super) async fn on_download_command(&mut self, command: DownloadCommand) {
        // A download in the middle of a stop answers once it has stopped, so
        // commands about it run in the order they were sent.
        let Some(command) = self.stopping.hold(command) else {
            return;
        };
        match command {
            DownloadCommand::StartDownload {
                file,
                source_hint,
                name,
                if_taken,
                kad_aich_root,
            } => {
                // A link for a file the Download Set already holds is a second
                // link, not a second download (ADR-0089's amendment).
                if self.second_link(&file).await {
                    return;
                }
                let paths = match self.place_download(&file, &name, if_taken) {
                    Ok(paths) => paths,
                    Err(reason) => {
                        tracing::warn!(
                            file_hash = %file.file_hash.to_hex_upper(),
                            ?reason,
                            "download start refused",
                        );
                        return self.reject(reason).await;
                    }
                };
                // The Download Set admits any number of downloads; the store
                // refuses the one thing that cannot coexist — a second live
                // row for the same file or the same output — and says which.
                let record = match self.wiring.store.create_download(
                    &file,
                    source_hint.as_ref(),
                    &paths,
                    kad_aich_root,
                ) {
                    Ok(record) => record,
                    Err(error) => {
                        let reason = start_refusal(&error);
                        tracing::warn!(
                            file_hash = %file.file_hash.to_hex_upper(),
                            %error,
                            ?reason,
                            "download start refused",
                        );
                        send_event(&self.evt_tx, CoreEvent::CommandRejected { reason });
                        return;
                    }
                };
                let download_id = record.id();
                // The stored record is the one source of the name and
                // size both surfaces report — never the command's copy
                // of the link — so what a consumer sees is what a
                // restart will replay.
                let metadata = record.metadata().clone();
                self.diagnostics
                    .ensure_download(download_id, file.file_hash, metadata.clone());
                tracing::info!(
                    download_id = download_id.as_u64(),
                    file_hash = %file.file_hash.to_hex_upper(),
                    file_name = %metadata.name,
                    file_size = metadata.size,
                    "download started",
                );
                send_download_event(
                    &self.evt_tx,
                    DownloadEvent::DownloadQueued {
                        download_id,
                        file_hash: file.file_hash,
                        metadata,
                        file_path: record.file_path().to_path_buf(),
                    },
                );

                // A Served Download from its queueing on, against the link's
                // set (ADR-0113).
                let link_set = file
                    .part_hash_set
                    .as_ref()
                    .map(|set| set.hashes().to_vec())
                    .unwrap_or_default();
                let start = RunStart {
                    file,
                    verified_part_indexes: Vec::new(),
                    remembered: Vec::new(),
                    recovered: None,
                    part_check: None,
                };
                self.start_run(&record, &link_set, start).await;
            }
            DownloadCommand::CancelDownload { download_id } => {
                match self.stop_run(download_id, StopReason::Cancel).await {
                    Err(reason) => return self.reject(reason).await,
                    // `on_run_ended` finishes it.
                    Ok(true) => return,
                    Ok(false) if !self.holds_place(download_id) => {
                        return self.reject(CoreCommandRejectReason::UnknownDownload).await;
                    }
                    Ok(false) => {}
                }
                // Waiting its turn or at rest alike: a download with no run
                // is still the operator's to drop (ADR-0094).
                self.activities.take_restoring(download_id);
                self.cancel(download_id).await;
            }
            DownloadCommand::PauseDownload { download_id } => {
                // A paused download keeps its offer: its run hands the lease
                // back as it lets its part file go (ADR-0113).
                match self.stop_run(download_id, StopReason::Pause).await {
                    Err(reason) => return self.reject(reason).await,
                    // `on_run_ended` finishes it.
                    Ok(true) => return,
                    // A download waiting for free space is at rest already:
                    // the operator's Pause ends the wait (ADR-0094).
                    Ok(false)
                        if self.activities.take_restoring(download_id).is_none()
                            && !self.activities.end_space_wait(download_id) =>
                    {
                        return self.reject(CoreCommandRejectReason::UnknownDownload).await;
                    }
                    Ok(false) => {}
                }
                self.paused(download_id).await;
            }
            DownloadCommand::ClearDownload { download_id } => {
                if let Err(reason) = self.clear(download_id).await {
                    self.reject(reason).await;
                }
            }
            DownloadCommand::ClearDownloads { download_ids } => {
                self.clear_every(&download_ids);
            }
            DownloadCommand::ResumeDownload { download_id } => {
                // One waiting its turn after attach starts now instead, with
                // the seeds attach loaded for it; any other — a paused row
                // the operator resumes, a failed one restarted — reads its
                // own, as attach would have (ADR-0109, "Source Seeds").
                let remembered = match self.activities.take_restoring(download_id) {
                    Some(remembered) => remembered,
                    None => self.stored_seeds(download_id),
                };
                self.activities.end_space_wait(download_id);
                if let Err(reason) = self.resume(download_id, remembered).await {
                    self.reject(reason).await;
                }
            }
        }
    }

    /// A download with no run left is paused: the row says so, and the front
    /// end hears it.
    async fn paused(&mut self, download_id: DownloadId) {
        let _ = self
            .wiring
            .store
            .set_lifecycle(download_id, DownloadLifecycle::Paused);
        tracing::info!(download_id = download_id.as_u64(), "download paused");
        send_download_event(&self.evt_tx, DownloadEvent::DownloadPaused { download_id });
    }

    /// A `StartDownload` whose file a live download already holds: its
    /// sources join that download's run, as aMule (`DownloadQueue.cpp:1461-1500`)
    /// and eMule (`DownloadQueue.cpp:271-295`) add a second link's sources to
    /// the running file. A link that names no source, or a download with no
    /// run to take them — paused, failed, waiting its turn — is refused as the
    /// duplicate it is: the candidate pool lives with the run and is not
    /// stored. `false` when no live download holds the file.
    async fn second_link(&mut self, file: &Ed2kFileLink) -> bool {
        let holder = self.wiring.store.live_downloads().ok().and_then(|rows| {
            rows.into_iter()
                .find(|row| row.file_hash() == file.file_hash && row.file_size() == file.size())
        });
        let Some(holder) = holder else {
            return false;
        };
        let running = self.activities.download(holder.id());
        match running {
            Some(active) if crate::download::names_sources(file) => {
                // Resolved off the actor, as a first link's are: a named
                // source may take the resolver's whole bound.
                let later_links = active.later_links.clone();
                let resolver = self.download_runtime.shared.resolver.clone();
                let file = file.clone();
                tokio::spawn(async move {
                    let now = crate::server_list::unix_seconds(std::time::SystemTime::now());
                    let sources = crate::download::link_sources(&file, &resolver, now).await;
                    let _ = later_links.send(sources);
                });
            }
            _ => {
                self.reject(CoreCommandRejectReason::DuplicateDownload)
                    .await
            }
        }
        true
    }

    /// Start a fresh run for a download that has none — the operator's
    /// `ResumeDownload`, a re-add of a failed one, and attach's restore alike
    /// (ADR-0094). For a failed download this is Restart: rmule continues from
    /// what is on disk, or starts over when nothing there can be continued
    /// from. The refusal is the caller's to report.
    pub(super) async fn resume(
        &mut self,
        download_id: DownloadId,
        remembered: Vec<SourceSeed>,
    ) -> Result<(), CoreCommandRejectReason> {
        if self.activities.has_download(download_id) {
            return Err(CoreCommandRejectReason::DownloadAlreadyActive);
        }
        // The run's own revalidation below takes over from an Offer Check
        // still waiting or running for this row (ADR-0113).
        self.offer_checks.stop(download_id);
        let Ok(record) = self.wiring.store.load_download(download_id) else {
            return Err(CoreCommandRejectReason::UnknownDownload);
        };
        if record.lifecycle() == DownloadLifecycle::Completing {
            return self.resume_completing(&record, remembered).await;
        }
        let file = match record.file_link() {
            Ok(file) => file,
            Err(reason) => {
                self.fail_at_rest(download_id, reason).await;
                return Ok(());
            }
        };
        let restart = (record.lifecycle() == DownloadLifecycle::Failed).then(|| Restart {
            failure: record.failure().cloned(),
            moved_to: self.moved_part_candidate(&record),
        });
        if self
            .wiring
            .store
            .set_lifecycle(download_id, DownloadLifecycle::Active)
            .is_err()
        {
            return Err(CoreCommandRejectReason::UnknownDownload);
        }
        send_download_event(&self.evt_tx, DownloadEvent::DownloadResumed { download_id });

        // The run opens on the row at rest when there is one — its part
        // picture stands until the runner's first settle — and the level
        // path's copy of the stored name + size.
        self.diagnostics.ensure_download(
            download_id,
            record.file_hash(),
            record.metadata().clone(),
        );
        // A restarted failed row is a Served Download again, as it stands
        // now; a paused one's entry is the actor's to hand on (ADR-0113).
        let active_row = self.wiring.store.load_download(download_id);
        let set = self.recorded_set(download_id);
        // The re-hash is the run's first stage, so nothing here waits on the
        // disk: its parts arrive from the check, and a part that no longer
        // holds is fetched again (ADR-0094, "Damaged parts").
        let start = RunStart {
            file,
            verified_part_indexes: Vec::new(),
            remembered,
            recovered: None,
            part_check: Some(PartCheck { restart }),
        };
        self.start_run(active_row.as_ref().unwrap_or(&record), &set, start)
            .await;
        Ok(())
    }

    /// End a download that has no run as failed: the store row, and the
    /// event the operator must see.
    pub(super) async fn fail_at_rest(&mut self, download_id: DownloadId, reason: DownloadFailure) {
        crate::download::persist::record_failure(
            &self.wiring.store,
            &self.evt_tx,
            download_id,
            reason,
        )
        .await;
        self.end_served(download_id, crate::PartialEnd::Ended).await;
    }

    /// Drop a download whose run, if it had one, has ended: its `.part` file,
    /// its row's lifecycle, and its diagnostics row — the one road that
    /// removes it (ADR-0094).
    async fn cancel(&mut self, download_id: DownloadId) {
        let paths = self
            .wiring
            .store
            .load_download(download_id)
            .ok()
            .map(|record| record.paths().clone());
        // Stored first: a row that says Cancelled with its file still there
        // is swept at the next attach, and a row still live with its file
        // gone fails its next start.
        match self
            .wiring
            .store
            .set_lifecycle(download_id, DownloadLifecycle::Cancelled)
        {
            Ok(()) => {
                if let Some(paths) = paths {
                    self.delete_cancelled(download_id, &paths).await;
                }
            }
            Err(CoreError::UnknownDownload | CoreError::InvalidLifecycleTransition) => {}
            Err(error) => {
                tracing::warn!(
                    download_id = download_id.as_u64(),
                    %error,
                    "a cancel could not be stored, so the download stands"
                );
                self.reject(CoreCommandRejectReason::DownloadStoreFailed)
                    .await;
                crate::download::persist::tell_store_stop(&self.wiring.store, &self.evt_tx);
                return;
            }
        }
        self.diagnostics.remove_download(download_id);
        tracing::info!(download_id = download_id.as_u64(), "download cancelled");
        send_download_event(
            &self.evt_tx,
            DownloadEvent::DownloadCancelled { download_id },
        );
        self.end_served(download_id, crate::PartialEnd::Ended).await;
    }

    /// Where a Restart that found the part file gone would look before
    /// throwing it away: the name in the current Temp Directory (ADR-0094).
    fn moved_part_candidate(&self, record: &DurableDownloadRecord) -> Option<std::path::PathBuf> {
        let temp_dir = self.directories.temp_dir.as_deref()?;
        Some(temp_dir.join(record.paths().part_path().file_name()?))
    }

    /// Delete a cancelled download's files. A delete that is refused is told;
    /// the row keeps the path, and each attach tries again.
    async fn delete_cancelled(&mut self, download_id: DownloadId, paths: &DownloadPaths) {
        if let Err(error) = ContentFileStore::delete_part(paths).await {
            tracing::warn!(%error, "a cancelled download's part file could not be deleted");
            send_download_event(
                &self.evt_tx,
                DownloadEvent::CancelledFileLeft {
                    download_id,
                    part_path: paths.part_path().to_path_buf(),
                },
            );
            return;
        }
        if let Err(error) = self.wiring.store.part_file_gone(download_id) {
            tracing::warn!(%error, "a deleted part file could not be taken off its row");
        }
    }

    /// Forget one completed download: its record and its resting row, then
    /// the event. A run still in the **Download Set** is refused like any
    /// download not completed, unless it has stored `Completed`: its file is
    /// in place and shared, and all it has left is to end, which the clear
    /// does not wait on.
    async fn clear(&mut self, download_id: DownloadId) -> Result<(), CoreCommandRejectReason> {
        if self.activities.has_download(download_id) {
            let completed = self
                .wiring
                .store
                .load_download(download_id)
                .is_ok_and(|record| record.lifecycle() == DownloadLifecycle::Completed);
            if !completed {
                return Err(CoreCommandRejectReason::DownloadNotCompleted);
            }
            self.retire_download(download_id);
        }
        match self.wiring.store.clear_completed(download_id) {
            Ok(()) => {}
            Err(CoreError::UnknownDownload) => {
                return Err(CoreCommandRejectReason::UnknownDownload);
            }
            Err(CoreError::InvalidLifecycleTransition) => {
                return Err(CoreCommandRejectReason::DownloadNotCompleted);
            }
            Err(error) => {
                tracing::warn!(%error, download_id = download_id.as_u64(), "clear failed");
                return Err(CoreCommandRejectReason::DownloadStoreFailed);
            }
        }
        self.diagnostics.remove_download(download_id);
        tracing::info!(download_id = download_id.as_u64(), "download cleared");
        send_download_event(&self.evt_tx, DownloadEvent::DownloadCleared { download_id });
        Ok(())
    }

    /// Forget every completed download of `download_ids`, in one transaction.
    /// One whose completion is still being shared, or that is no longer
    /// completed, is passed over; the next clear takes it.
    fn clear_every(&mut self, download_ids: &[DownloadId]) {
        let cleared = match self.wiring.store.clear_every_completed(download_ids) {
            Ok(cleared) => cleared,
            Err(error) => {
                tracing::warn!(%error, "the completed downloads could not be cleared");
                return;
            }
        };
        for download_id in cleared {
            self.retire_download(download_id);
            self.diagnostics.remove_download(download_id);
            tracing::info!(download_id = download_id.as_u64(), "download cleared");
            send_download_event(&self.evt_tx, DownloadEvent::DownloadCleared { download_id });
        }
    }

    /// Whether the store holds `download_id` as a row that still holds its
    /// file's place — one a cancel may drop though no run exists.
    fn holds_place(&self, download_id: DownloadId) -> bool {
        self.wiring
            .store
            .load_download(download_id)
            .is_ok_and(|record| {
                matches!(
                    record.lifecycle(),
                    DownloadLifecycle::Queued
                        | DownloadLifecycle::Active
                        | DownloadLifecycle::Paused
                        | DownloadLifecycle::Failed
                        | DownloadLifecycle::Completing
                )
            })
    }

    async fn reject(&mut self, reason: CoreCommandRejectReason) {
        send_event(&self.evt_tx, CoreEvent::CommandRejected { reason });
    }

    /// The once-a-minute look at the downloads a Volume Stop paused for free
    /// space (ADR-0094): each still paused with room for all it has left, the
    /// floor over that, resumes, as `CDownloadQueue::CheckDiskspace` resumes an
    /// insufficient file (`DownloadQueue.cpp:1267-1269`), so a resume does not
    /// stop again. A row no longer paused left the wait.
    pub(super) async fn resume_for_space(&mut self) {
        for download_id in self.activities.awaiting_space() {
            let paused = self
                .wiring
                .store
                .load_download(download_id)
                .ok()
                .filter(|record| record.lifecycle() == DownloadLifecycle::Paused)
                .map(|record| (record.paths().part_path().to_path_buf(), record.file_size()));
            let Some((part_path, file_size)) = paused else {
                self.activities.end_space_wait(download_id);
                continue;
            };
            let store_dir = self.wiring.store.store_directory();
            let fits = on_pool(move || {
                free_space::fits_what_is_left(&part_path, store_dir.as_deref(), file_size)
            });
            if !fits.await {
                continue;
            }
            self.activities.end_space_wait(download_id);
            let remembered = self.stored_seeds(download_id);
            if let Err(reason) = self.resume(download_id, remembered).await {
                tracing::warn!(
                    ?reason,
                    "a download could not resume with its free space back"
                );
            }
        }
    }

    /// A run's finish notice. A download that ended on its own (a death,
    /// ADR-0093) retires here; one a stop already retired is gone from the
    /// ledger, or replaced by a later run, so its late notice retires nothing.
    pub(super) fn on_run_finished(
        &mut self,
        download_id: DownloadId,
        run: RunNumber,
        awaits_space: bool,
    ) {
        if let Some(active) = self
            .activities
            .take_finished(download_id, run, awaits_space)
        {
            self.wiring.file_known.download_ended(active.file_hash);
            self.take_back_served(active.file_hash, active.run);
        }
    }

    /// Retire one download (ADR-0093): take it out of the **Download Set**
    /// and return the **file-known** entry its start stamped, here at the
    /// stop rather than at the task's later finish notice — a notice that
    /// arrives after a new start must not clear the new download's hash.
    /// `None` when the set holds no such download. The caller owns the task
    /// it hands back: a stop signals and joins it, a death finds it already
    /// ended.
    pub(super) fn retire_download(&mut self, download_id: DownloadId) -> Option<ActiveDownload> {
        let active = self.activities.take_download(download_id)?;
        self.wiring.file_known.download_ended(active.file_hash);
        Some(active)
    }
}

/// Why the store's refusal to mint a row refuses the `StartDownload`.
fn start_refusal(error: &CoreError) -> CoreCommandRejectReason {
    match error {
        CoreError::DuplicateDownloadIdentity => CoreCommandRejectReason::DuplicateDownload,
        CoreError::PathConflict => CoreCommandRejectReason::DownloadPathConflict,
        CoreError::DownloadAlreadyExists
        | CoreError::UnknownDownload
        | CoreError::InvalidLifecycleTransition
        | CoreError::PartOutOfBounds
        | CoreError::Repository(_)
        | CoreError::StoreRefused { .. }
        | CoreError::ProvisionalAuthorityConflict
        | CoreError::KadUnavailable(_)
        | CoreError::ListenerBind(_)
        | CoreError::ServiceStopped => CoreCommandRejectReason::DownloadStoreFailed,
    }
}
