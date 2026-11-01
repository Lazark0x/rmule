//! Starting one run of a download, for every road that starts one — a new
//! download, a Resume or a Restart, attach's restore and a row found
//! `Completing`: its Served Download installed and leased to the run
//! (ADR-0113), the runner spawned, and the run entered in the Download Set —
//! and stopping it for a Pause or a Cancel, through its Completion Gate
//! (ADR-0115), its Served Download taken back when its task has ended.

use std::sync::Arc;

use rmule_primitives::{Ed2kFileLink, PartHash};
use tokio::sync::{Mutex, mpsc, watch};
use tracing::Instrument;

use crate::DurableDownloadRecord;
use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::download::part_check::PartCheck;
use crate::download::source_seeds::SourceSeed;
use crate::download::{DownloadRequest, DownloadTask, RunnerContext, SharedRuntime, StopReason};
use crate::service::activity::{ActiveDownload, JOIN_GRACE};
use crate::service::{CoreCommandRejectReason, DownloadCommand, DownloadId, FinishedActivity};

use super::super::CoreActor;
use super::stopping::Stop;

/// What a run starts from besides its row.
pub(in crate::service::actor) struct RunStart {
    /// The file the row's link names.
    pub(in crate::service::actor) file: Ed2kFileLink,
    /// The parts the store records verified.
    pub(in crate::service::actor) verified_part_indexes: Vec<u32>,
    /// The seeds attach loaded for a restored run (ADR-0109); empty
    /// otherwise.
    pub(in crate::service::actor) remembered: Vec<SourceSeed>,
    /// What attach found of a row it found `Completing` (ADR-0115); `None`
    /// for every other run.
    pub(in crate::service::actor) recovered: Option<crate::download::Recovered>,
    /// The part check the run opens with (ADR-0094); `None` for a new
    /// download and a row found `Completing`.
    pub(in crate::service::actor) part_check: Option<PartCheck>,
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Start a run of the download `row` holds: its file is known while it
    /// runs (the firewalled front's `0x99` gate reads it), its Served
    /// Download is installed against `set` when it has none and leased to
    /// the run, and the run joins the Download Set.
    pub(in crate::service::actor) async fn start_run(
        &mut self,
        row: &DurableDownloadRecord,
        set: &[PartHash],
        start: RunStart,
    ) {
        let RunStart {
            file,
            verified_part_indexes,
            remembered,
            recovered,
            part_check,
        } = start;
        let download_id = row.id();
        self.wiring.file_known.download_started(row.file_hash());
        self.install_served(row, set);
        let run = self.activities.take_download_run();
        let served = self.lease_to_run(row.file_hash(), run);
        let active = spawn_download(SpawnDownload {
            runtime: &self.download_runtime,
            download_id,
            file,
            identity: self.settings_identity(),
            verified_part_indexes,
            streaming_priority: row.metadata().is_streaming_priority(),
            run,
            remembered,
            served,
            recovered,
            part_check,
        });
        self.activities.download_started(download_id, active);
        self.served_moved().await;
    }

    /// Tell the run of `download_id` to stop for `reason`. Its act finishes
    /// in [`Self::on_run_ended`], once its task has ended: `Ok(true)` says so,
    /// `Ok(false)` that the download has no run. A move whose file is in place
    /// is no longer the operator's to stop: it refuses with
    /// [`CoreCommandRejectReason::DownloadCompleting`].
    pub(in crate::service::actor) async fn stop_run(
        &mut self,
        download_id: DownloadId,
        reason: StopReason,
    ) -> Result<bool, CoreCommandRejectReason> {
        self.stop_completion(download_id).await?;
        let Some(active) = self.retire_download(download_id) else {
            return Ok(false);
        };
        let _ = active.stop_tx.send(reason);
        let stop = Stop {
            file_hash: active.file_hash,
            run: active.run,
            reason,
            held: Vec::new(),
        };
        self.stopping.begin(download_id, active.handle, stop);
        Ok(true)
    }

    /// A stopped run's task has ended: take back its Served Download, finish
    /// the act that stopped it, and take up what waited for it.
    pub(in crate::service::actor) async fn on_run_ended(&mut self, download_id: DownloadId) {
        for command in self.finish_stop(download_id).await {
            self.on_download_command(command).await;
        }
    }

    /// The commands that waited for this stop.
    async fn finish_stop(&mut self, download_id: DownloadId) -> Vec<DownloadCommand> {
        let Some(stop) = self.stopping.finish(download_id) else {
            return Vec::new();
        };
        self.take_back_served(stop.file_hash, stop.run);
        match stop.reason {
            StopReason::Pause => self.paused(download_id).await,
            StopReason::Cancel => {
                // Running, waiting its turn or at rest alike: a download with
                // no run is still the operator's to drop (ADR-0094).
                self.activities.take_restoring(download_id);
                self.cancel(download_id).await;
            }
            // Nothing stops a run for this; it is a run's standing order.
            StopReason::Active => {}
        }
        stop.held
    }

    /// Finish every stop under way before Quit goes on, bounded so a run that
    /// cannot end costs Quit one wait. Each act is the operator's and is kept;
    /// what waited behind it is dropped with the session.
    pub(in crate::service::actor) async fn finish_stops(&mut self) {
        let _ = tokio::time::timeout(JOIN_GRACE, async {
            while !self.stopping.is_empty() {
                let download_id = self.stopping.next_ended().await;
                self.finish_stop(download_id).await;
            }
        })
        .await;
        for download_id in self.stopping.abort_all() {
            self.finish_stop(download_id).await;
        }
    }
}

/// What the actor keeps to spawn download runners: the core-wide
/// [`SharedRuntime`] every run clones by one `Arc`, and the three handles
/// only the actor reads. Built once; [`spawn_download`] clones out of it, so a
/// new runner handle is added in one place.
pub(in crate::service::actor) struct DownloadRuntime<S, P> {
    /// The handles every run shares. Its `download_reach_tx` clone is the
    /// actor's own, which keeps the reach arm from ever closing.
    pub(in crate::service::actor) shared: Arc<SharedRuntime<S, P>>,
    /// The Streaming Window's width every Streaming Priority run ranks by
    /// (`CoreConfig::streaming_window_parts`, ADR-0112).
    pub(in crate::service::actor) streaming_window_parts: u32,
    pub(in crate::service::actor) finished_tx: mpsc::Sender<FinishedActivity>,
    /// The discovery channels every runner waits on, read live (ADR-0093):
    /// the managed global server list and the Kad activity's liveness.
    pub(in crate::service::actor) discovery: crate::download::DiscoveryLiveness,
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
    run: crate::download::RunNumber,
    /// The seeds attach loaded for a restored run (ADR-0109); empty otherwise.
    remembered: Vec<SourceSeed>,
    /// The lease on the download's Served Download, handed to the run
    /// (ADR-0113); `None` for a download that has none.
    served: Option<crate::served_downloads::RunLease>,
    /// What attach found of a row it found `Completing` (ADR-0115); `None`
    /// for every other run.
    recovered: Option<crate::download::Recovered>,
    /// The part check the run opens with (ADR-0094).
    part_check: Option<PartCheck>,
}

/// Spawn one download runner and return its live handle. The single
/// `DownloadTask` construction site, so the request + runner-context block is
/// written once and a new field is a one-place edit. The watch channel,
/// tracing span, and `ActiveDownload` bookkeeping ride inside.
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
        part_check,
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
                order: crate::scheduler::PartOrder::of(
                    streaming_priority,
                    runtime.streaming_window_parts,
                ),
                discovery: runtime.discovery.clone(),
                remembered,
                recovered,
                part_check,
            },
            run,
            runner: RunnerContext {
                rt: Arc::clone(&runtime.shared),
                stop_rx,
                part_file: Mutex::new(None),
                later_links: Mutex::new(later_inbox),
                repair: std::sync::atomic::AtomicBool::new(false),
                volume_stop: std::sync::Mutex::new(None),
                hole_probed: std::sync::atomic::AtomicBool::new(false),
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
