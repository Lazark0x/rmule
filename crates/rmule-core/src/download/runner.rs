//! The download runner: the enactor that drives one download activity from the
//! initial source lookup to a finalized file. The scheduling policy lives in the
//! sans-I/O brain ([`DownloadState`](crate::download::state::DownloadState)),
//! time included; this module owns the live runtime around it — the worker
//! [`fleet`], the decision [`enact`]or, and the [`reply_sink`] the brain's
//! reask replies arrive through — plus the stop signal that pauses or cancels
//! the run.

use std::sync::Arc;
use std::time::Duration;

use crate::DurableDownloadRecord;
use crate::adapters::{PeerTransferService, SourceLookupService};
use crate::download::state::SourcingPosture;
use crate::download::{RunNumber, SharedRuntime};
use crate::durable::DownloadLifecycle;
use crate::error::DownloadFailure;
use crate::global_sources::SharedServerList;
use crate::scheduler::PartOrder;
use crate::server_session::live_peer_handshake_context;
use crate::service::{
    DownloadEvent, DownloadId, FinishedActivity, SourceWait, send_download_event,
};
use crate::storage::DownloadRepository;
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{Ed2kFileLink, Ed2kLink, SourceSighting};
use tokio::sync::{Mutex, mpsc, watch};

mod adopt;
mod awaited_grants;
mod callbacks;
mod capability;
mod completion;
mod enact;
mod fleet;
mod intake;
mod link_sources;
mod lookup;
mod reply_sink;
mod served;
mod server_leg;
#[cfg(test)]
pub(super) mod test_context;

pub(crate) use capability::CallbackFacts;
pub(crate) use completion::{
    CompletionFs, CompletionGate, FinalFileInPlace, OsCompletionFs, Recovered, StopAnswer,
};
use fleet::{FleetStart, StartSources, apply_peer_workers_download};
pub(crate) use link_sources::{LaterLinkSources, link_sources, names_sources};

const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// The instant the runner hands the brain (ADR-0026): the runtime's clock, so
/// the brain and every timer the runner sleeps on read the same time.
fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    Active,
    Pause,
    Cancel,
}

impl StopReason {
    pub(crate) const fn failure(self) -> Option<DownloadFailure> {
        match self {
            Self::Active => None,
            Self::Pause => Some(DownloadFailure::Paused),
            Self::Cancel => Some(DownloadFailure::Cancelled),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DownloadRequest {
    pub(crate) download_id: DownloadId,
    pub(crate) file: Ed2kFileLink,
    /// The node's wire identity: the Core Settings' credentials as the
    /// build-time hash (ADR-0048 "Identity ownership").
    pub(crate) identity: rmule_primitives::ClientIdentity,
    pub(crate) verified_part_indexes: Vec<u32>,
    /// How the download ranks its parts: Streaming Priority, read off its
    /// stored metadata, ranks by a window of
    /// `CoreConfig::streaming_window_parts` (ADR-0112 §5).
    pub(crate) order: PartOrder,
    /// The background source-discovery channels, read live (ADR-0093).
    pub(crate) discovery: DiscoveryLiveness,
    /// The download's **Source Seeds** under a day old, handed to a run attach
    /// restores (ADR-0109); empty for every other run.
    pub(crate) remembered: Vec<crate::download::source_seeds::SourceSeed>,
    /// What attach found of a row it found `Completing`: its run goes
    /// straight to the move's recovery (ADR-0115). `None` for every other run.
    pub(crate) recovered: Option<Recovered>,
}

/// The source-discovery channels a download may wait on — server-UDP global
/// sweep (ADR-0051) and Kad (ADR-0043) — read at each decision rather than
/// sampled at spawn (ADR-0093): a Kad node that dies mid-download must turn
/// "wait for sources" back into the failure it would have been, and one that
/// starts later must be waited on.
#[derive(Clone)]
pub(crate) struct DiscoveryLiveness {
    /// The managed server list the global sweep asks; armed while non-empty.
    pub(crate) global_servers: SharedServerList,
    /// **Self Reach**, whose "Kad running" is the Kad Activity's own lease
    /// (ADR-0093).
    pub(crate) reach: crate::reachability::SharedSelfReach,
    /// The level whose connected server gates the global sweep's asks
    /// (ADR-0051's amendment) — the same fact the sweep reads, so the
    /// reason a download gives for waiting never disagrees with it.
    pub(crate) session: crate::diagnostics::DiagnosticsState,
}

impl DiscoveryLiveness {
    /// Whether the Kad node is running: besides letting a starved download
    /// wait, it lets a *failed server login* degrade to a sourceless start —
    /// Kad needs no server, so the serverless world stays downloadable.
    pub(crate) fn kad_running(&self) -> bool {
        self.reach.kad_running()
    }

    /// Whether any channel may still backfill, so no usable source right now
    /// is a wait (`WaitingForSources`) rather than `NoUsableSources`. The
    /// sweep counts while armed, session or not: the first sweep after a
    /// login asks for it (ADR-0051's amendment).
    pub(crate) fn any_active(&self) -> bool {
        self.kad_running() || self.sweep_armed()
    }

    /// Why a starved download waits, or `None` when nothing can backfill and
    /// it fails instead.
    pub(crate) fn source_wait(&self) -> Option<SourceWait> {
        source_wait(
            self.session.server_session_up(),
            self.kad_running(),
            self.sweep_armed(),
        )
    }

    fn sweep_armed(&self) -> bool {
        !self
            .global_servers
            .lock()
            .expect("global source server list")
            .is_empty()
    }
}

/// The wait the three channel facts leave a starved download in.
fn source_wait(session: bool, kad: bool, sweep_armed: bool) -> Option<SourceWait> {
    match (session, kad, sweep_armed) {
        (_, false, false) => None,
        (true, _, _) => Some(SourceWait::Asking),
        (false, true, _) => Some(SourceWait::KadAlone),
        (false, false, true) => Some(SourceWait::NoSession),
    }
}

/// What one download run holds: the core-wide [`SharedRuntime`] every run
/// shares through one `Arc`, and the handles that are this run's own.
pub(crate) struct RunnerContext<S, P> {
    /// The handles the core hands every run, one `Arc` clone per spawn.
    pub(crate) rt: Arc<SharedRuntime<S, P>>,
    pub(crate) stop_rx: watch::Receiver<StopReason>,
    /// The run's **Held Part File** (ADR-0094): opened when the run starts and
    /// the one handle every verified part is written through. `None` before
    /// that, and after finalize hands the file over.
    pub(crate) part_file: Mutex<Option<crate::content::HeldPartFile>>,
    /// The sources later links for this file bring while the run runs
    /// (ADR-0089's amendment); the fleet loop holds it for its life.
    pub(crate) later_links: Mutex<link_sources::LaterLinkInbox>,
    /// Set when the run lost parts it can fetch again — a part file cut short,
    /// a finished file that did not hash — so its end starts it over in place
    /// instead of failing the download.
    pub(crate) repair: std::sync::atomic::AtomicBool,
    /// Set once the run's **Hole Probe** has run (ADR-0111): a run that
    /// holds its part file again after a repair probes nothing and tells
    /// nothing again, so the probe and its `HoleLess` notice come once per
    /// run.
    pub(crate) hole_probed: std::sync::atomic::AtomicBool,
    /// Where the run publishes its **Source Seeds** ranking each reask sweep
    /// (ADR-0109), for the core actor to write.
    pub(crate) seeds_tx: watch::Sender<Vec<crate::download::source_seeds::SourceSeed>>,
    /// The run's lease on its **Served Download** (ADR-0113); `None` for a
    /// download of one part, which has none.
    pub(crate) served: Option<crate::served_downloads::RunLease>,
    /// Which run of the download this is, carried on its in-place report.
    pub(crate) run: RunNumber,
    /// The run's **Completion Gate**, shared with the actor's ledger entry
    /// (ADR-0115).
    pub(crate) completion: Arc<CompletionGate>,
}

impl<S, P> RunnerContext<S, P> {
    /// Mark this run to start over in place when it ends (see `repair`).
    pub(crate) fn mark_for_repair(&self) {
        self.repair.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether the run that just ended was marked for repair, clearing it.
    fn take_repair(&self) -> bool {
        self.repair.swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    /// `work`, unless the run's stop arrives first: the stop is looked at
    /// first, and ends the wait with the failure it stands for.
    pub(crate) async fn until_stop<T>(
        &self,
        work: impl std::future::Future<Output = T>,
    ) -> Result<T, DownloadFailure> {
        let mut stop_rx = self.stop_rx.clone();
        tokio::select! {
            biased;
            () = wait_until_stop(&mut stop_rx) => {
                Err(stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled))
            }
            done = work => Ok(done),
        }
    }

    /// Our own half of the family question, read fresh — the chooser's verdict
    /// is re-derived on every advert, never cached, because an IPv6 prefix
    /// renumber is routine.
    pub(crate) fn dial_position(&self) -> crate::dialable::DialPosition {
        crate::dialable::DialPosition {
            known_ipv6: self.rt.ipv6_advert.get(),
        }
    }
}

pub(crate) struct DownloadTask<S, P> {
    pub(crate) request: DownloadRequest,
    /// Which run of the download this is, carried on its finish notice.
    pub(crate) run: RunNumber,
    pub(crate) runner: RunnerContext<S, P>,
    pub(crate) finished_tx: mpsc::Sender<FinishedActivity>,
}

impl<S, P> DownloadTask<S, P>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    pub(crate) async fn run(self) {
        let download_id = self.request.download_id;
        let mut request = self.request;
        // A run that ends, however it ends, leaves its gate open: a stop
        // never waits on a run that is gone.
        let _release = ReleaseGate(Arc::clone(&self.runner.completion));
        // A run that lost parts it can fetch again starts over in place, in
        // the Download Set, from what still holds (ADR-0094).
        let result = loop {
            let result = orchestrate_download(request.clone(), &self.runner).await;
            if !self.runner.take_repair() {
                break result;
            }
            match self.runner.rt.store.verified_parts(download_id) {
                Err(_) => break Err(DownloadFailure::StoreFailed),
                Ok(parts) => {
                    request.recovered = None;
                    request.verified_part_indexes =
                        parts.iter().map(|part| part.part_index).collect();
                    tracing::info!(
                        download_id = download_id.as_u64(),
                        held = request.verified_part_indexes.len(),
                        "the run starts over in place, fetching the parts it lost"
                    );
                }
            }
        };
        if matches!(result, Err(DownloadFailure::Paused)) {
            served::let_go(&self.runner).await;
        }
        let completed = result.is_ok();

        if let Err(reason) = result
            && !matches!(reason, DownloadFailure::Cancelled | DownloadFailure::Paused)
            && *self.runner.stop_rx.borrow() == StopReason::Active
        {
            crate::download::persist::record_failure(
                &self.runner.rt.store,
                &self.runner.rt.evt_tx,
                download_id,
                reason,
            )
            .await;
        }
        // The row outlives the run (ADR-0094): what the download holds is its
        // own fact, and only a cancel removes it.
        self.runner.rt.diagnostics.end_run(download_id, completed);
        let _ = self
            .finished_tx
            .send(FinishedActivity::Download(download_id, self.run))
            .await;
    }
}

/// Opens its gate when the run ends.
struct ReleaseGate(Arc<CompletionGate>);

impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

async fn orchestrate_download<S, P>(
    request: DownloadRequest,
    runner: &RunnerContext<S, P>,
) -> Result<(), DownloadFailure>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    check_stop(&runner.stop_rx)?;
    // A row attach found completing goes straight to the move (ADR-0115).
    if let Some(recovered) = request.recovered {
        return completion::recover(runner, request.download_id, &request.file, recovered).await;
    }
    // The run holds its part file from its first act (ADR-0094).
    crate::download::persist::hold_part_file(runner, request.download_id).await?;
    served::lease_started(runner, request.download_id).await;
    // Every part already verified — a move a Pause stopped, a run that
    // ended between its last part and its move: nothing to fetch.
    let parts = rmule_primitives::part_count(request.file.size) as usize;
    if request.verified_part_indexes.len() >= parts {
        return completion::complete(runner, request.download_id, &request.file, Vec::new()).await;
    }
    let file = request.file.clone();
    let target =
        rmule_primitives::SourceLookupTarget::new(request.file.file_hash, request.file.size);
    // Subscribed before the first lookup: a session that comes up after it
    // is asked too.
    let server_leg = server_leg::ServerLeg::new(runner.rt.server_session.session_changes(), target);
    // The link's own sources come first (ADR-0089's amendment), and a
    // link that carries one can feed the run without a server, as Kad can.
    let now = crate::server_list::unix_seconds(std::time::SystemTime::now());
    let link_sources = runner
        .until_stop(link_sources::link_sources(
            &request.file,
            &runner.rt.resolver,
            now,
        ))
        .await?;
    // The seeds attach handed this run go first (ADR-0109, "Source Seeds");
    // every source of the start passes the same gate, inside the brain. A run
    // whose seeds can be dialed starts its fleet at once and makes its first
    // lookup its server leg's first ask.
    let seeds: Vec<SourceSighting> = request
        .remembered
        .iter()
        .map(|seed| seed.as_source())
        .collect();
    let lookup_owed = intake::any_admitted(runner, &seeds);
    let link_fed = intake::any_admitted(runner, &link_sources);
    let mut server_leg = server_leg;
    let source_outcome = if lookup_owed {
        server_leg.ask_first(runner);
        None
    } else {
        lookup::find_sources(&request, runner, target, link_fed, &mut server_leg).await?
    };
    runner
        .rt
        .store
        .set_lifecycle(request.download_id, DownloadLifecycle::Active)
        .map_err(|_| DownloadFailure::StoreFailed)?;
    check_stop(&runner.stop_rx)?;
    if let Some(outcome) = &source_outcome {
        send_download_event(
            &runner.rt.evt_tx,
            DownloadEvent::ServerLoginAccepted {
                download_id: request.download_id,
                client_id: outcome.client_id,
            },
        )
        .await;
    }

    // A degraded (serverless) start has no server sources: the book starts
    // with the link's own, and only an open Kad verdict can make it callable.
    let server_sources = source_outcome
        .map(|outcome| outcome.sources)
        .unwrap_or_default();

    // rmule can be called back only if it is itself reachable — a server High
    // ID or an open Kad TCP verdict — **and** its inbound listener is bound:
    // aMule's `CanDoCallback`, read from the live self-facts rather than this
    // run's login answer, the listener conjunct included (a serve
    // started or stopped after this spawn now lands on the
    // runner's next sample too). Where it admits nobody, no callback is asked
    // for — and a Low-ID candidate is reachable only by the other road, a
    // punch a Rendezvous coordinator introduces (ADR-0091 rung 1).
    let callback_facts = CallbackFacts {
        reach: runner.rt.reach.clone(),
        our_tcp_port: request.identity.tcp_port(),
    };
    let callback_capability = callback_facts.sample();
    let dial = runner.dial_position();
    // The peer hello carries only the minimal identity. The server-login
    // capability tags the application advertises (e.g. CT_SERVER_FLAGS)
    // are server-only and must not leak into the peer hello, where their
    // tag IDs mean different things and advertise capabilities the peer
    // protocol does not implement (ADR-0047).
    // The hello names the live session's server and id, read again at every
    // spawn — never the server this download was once started on — and so
    // the TCP port: the fleet keeps the identity as the settings name it, so
    // a port of 0 is the listener's bound one at each spawn, not this one.
    let ctx = PeerHandshakeContext {
        identity: request.identity.clone(),
        ..live_peer_handshake_context(&request.identity, &runner.rt.reach)
    };
    check_stop(&runner.stop_rx)?;

    // The peers this download distrusts, as its durable record holds them.
    let distrusted = crate::download::persist::distrusted_at_start(runner, request.download_id)?;
    // The Kad AICH root its record keeps, under the link's `h=` (ADR-0038).
    let kad_aich_root =
        crate::download::persist::kad_aich_root_at_start(runner, request.download_id)?;

    let file_hash_only_parts = apply_peer_workers_download(
        FleetStart {
            download_id: request.download_id,
            file: request.file,
            kad_aich_root,
            ctx,
            verified_part_indexes: request.verified_part_indexes,
            order: request.order,
            sources: StartSources {
                seeds,
                seeds_written: request.remembered.len(),
                link: link_sources,
                server: server_sources,
                distrusted,
            },
            callback_facts,
            posture: SourcingPosture {
                callback_capability,
                dial,
                discovery_active: request.discovery.any_active() || lookup_owed,
                client_udp: runner.rt.client_udp_tx.is_some(),
            },
            discovery: request.discovery,
            server_leg,
            lookup_owed,
        },
        runner,
    )
    .await?;
    completion::complete(runner, request.download_id, &file, file_hash_only_parts).await
}

pub(crate) fn file_link_from_record(
    record: &DurableDownloadRecord,
) -> Result<Ed2kFileLink, DownloadFailure> {
    match Ed2kLink::parse(record.canonical_link()) {
        Ok(Ed2kLink::File(file)) => Ok(file),
        _ => Err(DownloadFailure::PartVerificationFailed),
    }
}

fn check_stop(rx: &watch::Receiver<StopReason>) -> Result<(), DownloadFailure> {
    match stop_reason(rx) {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

fn stop_reason(rx: &watch::Receiver<StopReason>) -> Option<DownloadFailure> {
    rx.borrow().failure()
}

async fn wait_until_stop(rx: &mut watch::Receiver<StopReason>) {
    while *rx.borrow() == StopReason::Active {
        if rx.changed().await.is_err() {
            return;
        }
    }
}
