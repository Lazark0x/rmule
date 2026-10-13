//! The download command arms: starting a download against the connected
//! server, and the cancel / pause / resume asks that reach the runner through
//! its stop signal. Spawning itself is the shared [`spawn_download`], so both
//! start paths assemble the same task.

use std::sync::Arc;

use rmule_primitives::Ed2kFileLink;
use tokio::sync::{Mutex, mpsc, watch};
use tracing::Instrument;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::content::{ContentFileStore, RestoredProgress, Revalidation};
use crate::download::source_seeds::SourceSeed;
use crate::download::{
    DownloadRequest, DownloadTask, RunnerContext, SharedRuntime, StopReason, file_link_from_record,
};
use crate::service::activity::ActiveDownload;
use crate::service::{
    CoreCommandRejectReason, CoreEvent, DownloadCommand, DownloadEvent, DownloadId,
    FinishedActivity, RestartOutcome, send_download_event,
};
use crate::storage::DownloadRepository;
use crate::{
    CoreError, DownloadFailure, DownloadLifecycle, DurableDownloadRecord, PartFault,
    StorageIntegrityFault, VerifiedPartRecord,
};

use super::{CoreActor, send_event};

mod completion;
mod placement;
mod restore;
mod seeds;

pub(super) use restore::attach_downloads;

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Enact one download command against the live activity ledger.
    pub(super) async fn on_download_command(&mut self, command: DownloadCommand) {
        match command {
            DownloadCommand::StartDownload {
                file,
                source_hint,
                name,
                if_taken,
            } => {
                // A link for a file the Download Set already holds is a second
                // link, not a second download (ADR-0089's amendment).
                if self.second_link(&file).await {
                    return;
                }
                let paths = match self.place_download(&name, if_taken) {
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
                let record =
                    match self
                        .wiring
                        .store
                        .create_download(&file, source_hint.as_ref(), &paths)
                    {
                        Ok(record) => record,
                        Err(error) => {
                            let reason = start_refusal(&error);
                            tracing::warn!(
                                file_hash = %file.file_hash.to_hex_upper(),
                                %error,
                                ?reason,
                                "download start refused",
                            );
                            send_event(&self.evt_tx, CoreEvent::CommandRejected { reason }).await;
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
                )
                .await;

                // The file-known predicate: this download's
                // hash, mirrored inline for the firewalled front's `0x99` gate.
                self.wiring.file_known.download_started(file.file_hash);
                // A Served Download from its queueing on, its lease handed to
                // the run (ADR-0113).
                let link_set = file
                    .part_hash_set
                    .as_ref()
                    .map(|set| set.hashes().to_vec())
                    .unwrap_or_default();
                self.install_served(&record, &link_set);
                let run = self.activities.take_download_run();
                let served = self.lease_to_run(file.file_hash, run);
                let active = spawn_download(SpawnDownload {
                    runtime: &self.download_runtime,
                    download_id,
                    file,
                    identity: self.settings_identity(),
                    verified_part_indexes: Vec::new(),
                    streaming_priority: record.metadata().is_streaming_priority(),
                    run,
                    remembered: Vec::new(),
                    served,
                    recovered: None,
                });
                self.activities.download_started(download_id, active);
                self.served_moved().await;
            }
            DownloadCommand::CancelDownload { download_id } => {
                // A move whose file is in place is no longer the operator's
                // to stop (ADR-0115).
                if let Err(reason) = self.stop_completion(download_id).await {
                    return self.reject(reason).await;
                }
                if let Some(active) = self.retire_download(download_id) {
                    let _ = active.stop_tx.send(StopReason::Cancel);
                    let _ = active.handle.await;
                    self.take_back_served(active.file_hash, active.run);
                } else if !self.holds_place(download_id) {
                    self.reject(CoreCommandRejectReason::UnknownDownload).await;
                    return;
                }
                // Running, waiting its turn or at rest alike: a download with
                // no run is still the operator's to drop (ADR-0094).
                self.activities.take_restoring(download_id);
                self.cancel(download_id).await;
            }
            DownloadCommand::PauseDownload { download_id } => {
                if let Err(reason) = self.stop_completion(download_id).await {
                    return self.reject(reason).await;
                }
                // A paused download keeps its offer: its run hands the lease
                // back as it lets its part file go (ADR-0113).
                if let Some(active) = self.retire_download(download_id) {
                    let _ = active.stop_tx.send(StopReason::Pause);
                    let _ = active.handle.await;
                    self.take_back_served(active.file_hash, active.run);
                } else if self.activities.take_restoring(download_id).is_none() {
                    self.reject(CoreCommandRejectReason::UnknownDownload).await;
                    return;
                }
                let _ = self
                    .wiring
                    .store
                    .set_lifecycle(download_id, DownloadLifecycle::Paused);
                tracing::info!(download_id = download_id.as_u64(), "download paused");
                send_download_event(&self.evt_tx, DownloadEvent::DownloadPaused { download_id })
                    .await;
            }
            DownloadCommand::ClearDownload { download_id } => {
                if let Err(reason) = self.clear(download_id).await {
                    self.reject(reason).await;
                }
            }
            DownloadCommand::ClearCompletedDownloads => {
                let completed = match self.wiring.store.completed_downloads() {
                    Ok(completed) => completed,
                    Err(error) => {
                        tracing::warn!(%error, "the completed downloads could not be read");
                        return;
                    }
                };
                for download_id in completed {
                    // One whose completion is still being shared is skipped;
                    // the next clear takes it.
                    let _ = self.clear(download_id).await;
                }
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
                if let Err(reason) = self.resume(download_id, remembered).await {
                    self.reject(reason).await;
                }
            }
        }
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
                .find(|row| row.file_hash() == file.file_hash && row.file_size() == file.size)
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
        let Ok(record) = self.wiring.store.load_download(download_id) else {
            return Err(CoreCommandRejectReason::UnknownDownload);
        };
        if record.lifecycle() == DownloadLifecycle::Completing {
            return self.resume_completing(&record, remembered).await;
        }
        let restart = record.lifecycle() == DownloadLifecycle::Failed;
        let Ok(recorded) = self.wiring.store.verified_parts(download_id) else {
            return Err(CoreCommandRejectReason::UnknownDownload);
        };
        let (recorded_parts, recorded_bytes) = tally(&recorded);
        // Resume-time revalidation lives behind the repository seam: the
        // store re-hashes whatever it persisted against the durable
        // verified-part records and drops the record of any part that no
        // longer holds, so it is fetched again (ADR-0094, "Damaged parts").
        // Only a part file that backs nothing recorded fails the download —
        // or, on the operator's Restart, starts it over.
        let (restored, restarted) = match self.wiring.store.revalidate(download_id).await {
            Ok(Revalidation::Restored { progress, damaged }) => {
                self.drop_damaged(download_id, &record, damaged).await;
                let kept_parts = u32::try_from(progress.verified_parts()).unwrap_or(u32::MAX);
                let outcome = RestartOutcome::Continued {
                    kept_parts,
                    kept_bytes: progress.verified_bytes(),
                    dropped_parts: recorded_parts.saturating_sub(kept_parts),
                    dropped_bytes: recorded_bytes.saturating_sub(progress.verified_bytes()),
                };
                (progress, restart.then_some(outcome))
            }
            Ok(Revalidation::Condemned(fault)) if restart && starts_over(&fault) => {
                self.discard(download_id, &record).await?;
                let outcome = RestartOutcome::StartedOver {
                    fault,
                    dropped_parts: recorded_parts,
                    dropped_bytes: recorded_bytes,
                };
                (RestoredProgress::new(0, 0), Some(outcome))
            }
            Ok(Revalidation::Condemned(fault)) => {
                tracing::warn!(
                    download_id = download_id.as_u64(),
                    %fault,
                    "download failed: its part file backs none of its verified parts"
                );
                self.fail_at_rest(download_id, DownloadFailure::StorageIntegrityFailed(fault))
                    .await;
                return Ok(());
            }
            Err(error) => {
                tracing::warn!(
                    download_id = download_id.as_u64(),
                    %error,
                    "the store could not revalidate a download's verified parts"
                );
                return Err(CoreCommandRejectReason::DownloadStoreFailed);
            }
        };
        let Ok(parts) = self.wiring.store.verified_parts(download_id) else {
            return Err(CoreCommandRejectReason::UnknownDownload);
        };
        send_download_event(
            &self.evt_tx,
            DownloadEvent::DownloadProgressRestored {
                download_id,
                verified_parts: restored.verified_parts(),
                verified_bytes: restored.verified_bytes(),
            },
        )
        .await;
        if let Some(outcome) = restarted {
            tracing::info!(
                download_id = download_id.as_u64(),
                ?outcome,
                "download restarted"
            );
            send_download_event(
                &self.evt_tx,
                DownloadEvent::DownloadRestarted {
                    download_id,
                    outcome,
                },
            )
            .await;
        }

        let file = match file_link_from_record(&record) {
            Ok(file) => file,
            Err(reason) => {
                self.fail_at_rest(download_id, reason).await;
                return Ok(());
            }
        };
        let verified_part_indexes = parts.iter().map(|part| part.part_index).collect::<Vec<_>>();
        if self
            .wiring
            .store
            .set_lifecycle(download_id, DownloadLifecycle::Active)
            .is_err()
        {
            return Err(CoreCommandRejectReason::UnknownDownload);
        }
        send_download_event(&self.evt_tx, DownloadEvent::DownloadResumed { download_id }).await;

        // The run opens on the row at rest when there is one — its part
        // picture stands until the runner's first settle — and the level
        // path's copy of the stored name + size.
        self.diagnostics.ensure_download(
            download_id,
            record.file_hash(),
            record.metadata().clone(),
        );
        // The file-known predicate, mirrored the same way
        // `StartDownload` mirrors it.
        self.wiring.file_known.download_started(record.file_hash());
        // A restarted failed row is a Served Download again; a paused one's
        // entry is the actor's to hand on (ADR-0113).
        if let Ok(active_row) = self.wiring.store.load_download(download_id) {
            let set = self.recorded_set(download_id);
            self.install_served(&active_row, &set);
        }
        let run = self.activities.take_download_run();
        let served = self.lease_to_run(record.file_hash(), run);
        let active = spawn_download(SpawnDownload {
            runtime: &self.download_runtime,
            download_id,
            file,
            identity: self.settings_identity(),
            verified_part_indexes,
            streaming_priority: record.metadata().is_streaming_priority(),
            run,
            remembered,
            served,
            recovered: None,
        });
        self.activities.download_started(download_id, active);
        self.served_moved().await;
        Ok(())
    }

    /// Tell of the parts revalidation dropped, and rest the part picture on
    /// the verified set that is left.
    async fn drop_damaged(
        &mut self,
        download_id: DownloadId,
        record: &DurableDownloadRecord,
        damaged: Vec<PartFault>,
    ) {
        if damaged.is_empty() {
            return;
        }
        let dropped = damaged
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        tracing::warn!(
            download_id = download_id.as_u64(),
            damaged = damaged.len(),
            %dropped,
            "verified parts no longer hold on disk; fetching them again"
        );
        let held = self
            .wiring
            .store
            .verified_parts(download_id)
            .map(|parts| parts.iter().map(|part| part.part_index).collect::<Vec<_>>())
            .unwrap_or_default();
        self.diagnostics.rest_download(
            download_id,
            record.file_hash(),
            record.metadata().clone(),
            &held,
        );
        send_download_event(
            &self.evt_tx,
            DownloadEvent::DamagedPartsDropped {
                download_id,
                damaged,
            },
        )
        .await;
    }

    /// Discard what a failed download recorded and the part file its row
    /// names, keeping its identity and place, so its run starts from nothing.
    /// The part file is removed only here, with no run holding it: `resume`
    /// refuses a download that has one.
    async fn discard(
        &mut self,
        download_id: DownloadId,
        record: &DurableDownloadRecord,
    ) -> Result<(), CoreCommandRejectReason> {
        if let Err(error) = self.wiring.store.discard_progress(download_id) {
            tracing::warn!(%error, "a failed download's progress could not be discarded");
            return Err(CoreCommandRejectReason::DownloadStoreFailed);
        }
        if let Err(error) = ContentFileStore::delete_part(record.paths()).await {
            tracing::warn!(%error, "a failed download's part file could not be removed");
        }
        self.diagnostics.rest_download(
            download_id,
            record.file_hash(),
            record.metadata().clone(),
            &[],
        );
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
        if let Some(paths) = paths {
            let _ = ContentFileStore::delete_part(&paths).await;
        }
        let _ = self
            .wiring
            .store
            .set_lifecycle(download_id, DownloadLifecycle::Cancelled);
        self.diagnostics.remove_download(download_id);
        tracing::info!(download_id = download_id.as_u64(), "download cancelled");
        send_download_event(
            &self.evt_tx,
            DownloadEvent::DownloadCancelled { download_id },
        )
        .await;
        self.end_served(download_id, crate::PartialEnd::Ended).await;
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
        send_download_event(&self.evt_tx, DownloadEvent::DownloadCleared { download_id }).await;
        Ok(())
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
        send_event(&self.evt_tx, CoreEvent::CommandRejected { reason }).await;
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
        _ => CoreCommandRejectReason::DownloadStoreFailed,
    }
}

/// What the actor keeps to spawn download runners: the core-wide
/// [`SharedRuntime`] every run clones by one `Arc`, and the three handles
/// only the actor reads. Built once; [`spawn_download`] clones out of it, so a
/// new runner handle is added in one place instead of in both the
/// `StartDownload` and `ResumeDownload` arms.
pub(super) struct DownloadRuntime<S, P> {
    /// The handles every run shares. Its `download_reach_tx` clone is the
    /// actor's own, which keeps the reach arm from ever closing.
    pub(super) shared: Arc<SharedRuntime<S, P>>,
    pub(super) peer_concurrency: usize,
    /// The Streaming Window's width every Streaming Priority run ranks by
    /// (`CoreConfig::streaming_window_parts`, ADR-0112).
    pub(super) streaming_window_parts: u32,
    pub(super) finished_tx: mpsc::Sender<FinishedActivity>,
    /// The discovery channels every runner waits on, read live (ADR-0093):
    /// the managed global server list and the Kad activity's liveness.
    pub(super) discovery: crate::download::DiscoveryLiveness,
}

/// The per-spawn inputs for one download: the request identity. Nothing
/// about another activity's liveness rides here (ADR-0093) — the discovery
/// channels, like the listener conjunct and Self Reach,
/// are live handles on the shared [`DownloadRuntime`]. Borrows the shared `DownloadRuntime`;
/// [`spawn_download`] assembles the `DownloadTask` from the two.
struct SpawnDownload<'a, S, P> {
    runtime: &'a DownloadRuntime<S, P>,
    download_id: DownloadId,
    file: Ed2kFileLink,
    /// The node's wire identity: the Core Settings' credentials as the
    /// build-time hash, a TCP port of `0` read live at each hello.
    identity: rmule_primitives::ClientIdentity,
    verified_part_indexes: Vec<u32>,
    /// The download is Streaming Priority, off its stored metadata.
    streaming_priority: bool,
    /// Which run of the download this is.
    run: u64,
    /// The seeds attach loaded for a restored run (ADR-0109); empty otherwise.
    remembered: Vec<SourceSeed>,
    /// The lease on the download's Served Download, handed to the run
    /// (ADR-0113); `None` for a download that has none.
    served: Option<crate::served_downloads::RunLease>,
    /// What attach found of a row it found `Completing` (ADR-0115); `None`
    /// for every other run.
    recovered: Option<crate::download::Recovered>,
}

/// Spawn one download runner and return its live handle. The single
/// `DownloadTask` construction site: both the `StartDownload` and
/// `ResumeDownload` arms build a [`SpawnDownload`] and call this, so the
/// ~12-field request + runner-context block is written once and a new field is
/// a one-place edit. The watch channel, tracing span, and `ActiveDownload`
/// bookkeeping ride inside.
fn spawn_download<S, P>(spawn: SpawnDownload<'_, S, P>) -> ActiveDownload
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    let SpawnDownload {
        runtime,
        download_id,
        file,
        identity,
        verified_part_indexes,
        streaming_priority,
        run,
        remembered,
        served,
        recovered,
    } = spawn;
    let file_hash = file.file_hash;
    // A recovered move's gate settles once its run has looked at the disk.
    let completion = Arc::new(if recovered.is_some() {
        crate::download::CompletionGate::settling()
    } else {
        crate::download::CompletionGate::open()
    });
    let (stop_tx, stop_rx) = watch::channel(StopReason::Active);
    let (later_links, later_inbox) = mpsc::unbounded_channel();
    let (seeds_tx, seeds) = watch::channel(Vec::new());
    let download_span = tracing::info_span!("download", download_id = download_id.as_u64());
    let handle = tokio::spawn(
        DownloadTask {
            request: DownloadRequest {
                download_id,
                file,
                identity,
                verified_part_indexes,
                peer_concurrency: runtime.peer_concurrency,
                streaming_priority,
                streaming_window_parts: runtime.streaming_window_parts,
                discovery: runtime.discovery.clone(),
                remembered,
                recovered,
            },
            run,
            runner: RunnerContext {
                rt: Arc::clone(&runtime.shared),
                stop_rx,
                part_file: Mutex::new(None),
                later_links: Mutex::new(later_inbox),
                repair: std::sync::atomic::AtomicBool::new(false),
                seeds_tx,
                served,
                run,
                completion: Arc::clone(&completion),
            },
            finished_tx: runtime.finished_tx.clone(),
        }
        .run()
        .instrument(download_span),
    );
    ActiveDownload {
        run,
        file_hash,
        stop_tx,
        handle,
        later_links,
        seeds,
        completion,
    }
}

/// How many verified parts `parts` records, and the bytes they hold.
fn tally(parts: &[VerifiedPartRecord]) -> (u32, u64) {
    let count = u32::try_from(parts.len()).unwrap_or(u32::MAX);
    (count, parts.iter().map(|part| part.len).sum())
}

/// Whether a Restart that met `fault` starts over rather than failing again:
/// the part file is gone, or none of what it recorded matches it. A part file
/// that exists but cannot be read may read again once its disk or its
/// permissions are back, so what it holds is not thrown away for it.
const fn starts_over(fault: &StorageIntegrityFault) -> bool {
    match fault {
        StorageIntegrityFault::PartFileMissing | StorageIntegrityFault::NoPartHolds { .. } => true,
        StorageIntegrityFault::PartFileUnreadable { .. } => false,
    }
}
