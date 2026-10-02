//! The download runner: the enactor that drives one download activity from the
//! initial source lookup to a finalized file. The scheduling policy lives in the
//! sans-I/O brain ([`DownloadState`](crate::download::state::DownloadState));
//! this module owns the live runtime around it — the worker [`fleet`], the
//! decision [`enact`]or, and the [`reask`] leg that keeps remote-queued sources
//! warm — plus the stop signal that pauses or cancels the run.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::DurableDownloadRecord;
use crate::adapters::{PeerTransferService, SharedCallbackTable, SourceLookupService};
use crate::callback::DownloadReach;
use crate::client_udp::ClientUdpSend;
use crate::credit::SharedCreditStore;
use crate::dialable::admits_family;
use crate::download::state::{
    LowIdCandidate, LowIdRoute, RememberedSeeds, SourcingPosture, StartingCandidates,
};
use crate::durable::DownloadLifecycle;
use crate::error::DownloadFailure;
use crate::global_sources::{GlobalCallbackSender, GlobalSourceRegistry, SharedServerList};
use crate::ip_filter::{SharedIpFilter, admits_source};
use crate::kad_sources::KadSourceRegistry;
use crate::server_session::{SharedServerSession, live_peer_handshake_context};
use crate::service::{
    CoreEvent, DownloadEvent, DownloadId, FinishedActivity, SharedReaskReplySink, SourceWait,
    send_download_event,
};
use crate::storage::DownloadRepository;
use crate::store::download::DurableDownloadRepository;
use rmule_primitives::{Ed2kFileLink, Ed2kLink, ExchangedSource, PeerCrypt, PeerEndpoint};
use tokio::sync::{Mutex, mpsc, watch};

mod callbacks;
mod capability;
mod enact;
mod fleet;
mod link_sources;
mod lookup;
mod reask;
mod server_leg;
#[cfg(test)]
pub(super) mod test_context;

pub(crate) use capability::CallbackFacts;
use fleet::{FleetStart, apply_peer_workers_download};
pub(crate) use link_sources::{LaterLinkSources, link_sources, names_sources};

const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

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
    /// The node's wire identity: the command's credentials as the
    /// build-time hash (ADR-0048 "Identity ownership").
    pub(crate) identity: rmule_primitives::ClientIdentity,
    pub(crate) verified_part_indexes: Vec<u32>,
    pub(crate) peer_concurrency: usize,
    /// The background source-discovery channels, read live (ADR-0093).
    pub(crate) discovery: DiscoveryLiveness,
    /// The download's **Source Seeds** under a day old, handed to a run attach
    /// restores (ADR-0109); empty for every other run.
    pub(crate) remembered: Vec<crate::download::source_seeds::SourceSeed>,
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

pub(crate) struct RunnerContext<S, P> {
    pub(crate) store: Arc<DurableDownloadRepository>,
    /// The core's one lookup handle: each ask clones it and runs on its own
    /// copy, so the lock is held only for the clone (ADR-0107).
    pub(crate) source_lookup: Arc<Mutex<S>>,
    /// The core's **Source Ask Budget** (ADR-0107), shared by every run.
    pub(crate) source_asks: crate::download::source_asks::SharedSourceAskBudget,
    pub(crate) peer_transfer: Arc<Mutex<P>>,
    pub(crate) credit: SharedCreditStore,
    pub(crate) evt_tx: mpsc::Sender<CoreEvent>,
    pub(crate) stop_rx: watch::Receiver<StopReason>,
    pub(crate) diagnostics: crate::diagnostics::DiagnosticsState,
    /// The shared server session, used to relay a Low-ID `OP_CALLBACKREQUEST`
    /// when enacting a `RequestCallback` decision (ADR-0039).
    pub(crate) server_session: SharedServerSession,
    /// The core-owned pending-callback table; the runner registers an entry per
    /// requested callback so the accept-router can adopt the called-back peer.
    pub(crate) pending_callbacks: SharedCallbackTable,
    /// How long the initial source lookup waits on the connected server
    /// before giving up (`CoreConfig::source_lookup_timeout`):
    /// bounds a sourceless file's `download start` so it terminates by
    /// default instead of parking forever on an `OP_FOUNDSOURCES` that may
    /// never come.
    pub(crate) source_lookup_timeout: Duration,
    /// How long a requested callback holds its slot before the runner times it
    /// out and tries the next candidate (`CoreConfig::callback_timeout`).
    pub(crate) callback_timeout: Duration,
    /// The core-owned global-source registry (ADR-0051): the runner registers
    /// `(file_hash, sink)` so the discovery task routes server-UDP-found sources
    /// to this download.
    pub(crate) global_source_registry: GlobalSourceRegistry,
    /// The runner → discovery-task channel for per-server Low-ID callbacks (ADR-0051): a
    /// `RequestGlobalCallback` is enacted by sending the encode inputs here (the
    /// discovery owns the UDP socket). Read by the `RequestGlobalCallback`
    /// enactment arm.
    pub(crate) global_callback_tx: GlobalCallbackSender,
    /// The core-owned Kad source registry (ADR-0043): the runner registers
    /// `(file_hash → (size, sink))` so the Kad discovery task routes projected
    /// sources to this download. Registered unconditionally — with Kad
    /// disabled nothing reads it.
    pub(crate) kad_source_registry: KadSourceRegistry,
    /// The installs for every **Remote-Queued Pool** reply sink in the
    /// **Download Set**: the shared client-UDP forwarder offers the reask
    /// reply quartet (`0x91`/`0x92`/`0x93`) to each (ADR-0057). This download
    /// installs its own under its id, leased for its run.
    pub(crate) reask_reply_sink: SharedReaskReplySink,
    /// The client-UDP send half a downloader `OP_REASKFILEPING` (`0x90`) rides
    /// out (ADR-0057); `None` when the shared client-UDP socket did not bind, in
    /// which case every reask falls to the TCP full ask.
    pub(crate) client_udp_tx: Option<mpsc::Sender<ClientUdpSend>>,
    /// The core-owned IP filter: every source-ingest path — the
    /// initial server snapshot, global-UDP, Kad, and source-exchange — drops
    /// filtered High-ID rows here, before they reach any candidate pool
    /// (aMule filters in `PartFile::AddSources`/`AddClientSources` and
    /// `DownloadQueue::KademliaSearchFile` for the same reason).
    pub(crate) ip_filter: SharedIpFilter,
    /// The **Advertised IPv6** (ADR-0087): the Dial Chooser's own half of the
    /// family question, published by the actor when the advert is settled. An
    /// IPv6 source is pooled only while this holds an address — there would be
    /// nowhere to dial it from otherwise, and a worker slot spent on a
    /// conversation that cannot start is worse than an honest drop.
    pub(crate) ipv6_advert: crate::adapters::SharedIpv6Advert,
    /// **Self Reach** (ADR-0060): the one owner the **Callback
    /// Capability** and the reask gate ask, read at use and subscribed to.
    pub(crate) reach: crate::reachability::SharedSelfReach,
    /// The runner → core-actor channel for a callback that has gone silent for
    /// twelve seconds (ADR-0091). The route decision needs *our* position —
    /// reachability, the client-UDP bind, the server's `0xF9` keepalive, Kad —
    /// which only the actor holds, so the runner sends the candidate's facts
    /// there rather than keeping a second chooser (ADR-0061: one selector,
    /// every caller). A full or closed channel costs a punch attempt, never a
    /// download.
    pub(crate) download_reach_tx: mpsc::Sender<DownloadReach>,
    /// The core-owned **Pending Tunnel Claim** table (ADR-0091). A fallback
    /// whose candidate carries a User Hash registers here before the
    /// `SilentCallback` goes out, so a Dialer Tunnel that rises toward that
    /// hash is handed to this download instead of taking the serve road. The
    /// entry is retracted by the same `CancelCallbackTimeout` that ends the
    /// callback, whichever road landed.
    pub(crate) tunnel_claims: crate::adapters::SharedTunnelClaims,
    /// The core-owned Peer Roster (ADR-0059): the fleet loop
    /// marks it when a worker's peer session connects (the hello completes)
    /// and forgets it when the worker ends — the download leg beside the
    /// upload queue's own `mark_known`/`forget`. A peer this
    /// download is also uploading to stays known through the upload queue's
    /// own membership; the roster is kept per endpoint, so the two writers
    /// never retire each other's reason.
    pub(crate) peer_roster: crate::peer_roster::SharedPeerRoster,
    /// The **Name Resolver** a link's named sources are resolved through
    /// (ADR-0089's amendment), off the actor and bounded.
    pub(crate) resolver: crate::name_resolver::SharedNameResolver,
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
    /// Where the run publishes its **Source Seeds** ranking each reask sweep
    /// (ADR-0109), for the core actor to write.
    pub(crate) seeds_tx: watch::Sender<Vec<crate::download::source_seeds::SourceSeed>>,
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

    /// Our own half of the family question, read fresh — the chooser's verdict
    /// is re-derived on every advert, never cached, because an IPv6 prefix
    /// renumber is routine.
    pub(crate) fn dial_position(&self) -> crate::dialable::DialPosition {
        crate::dialable::DialPosition {
            known_ipv6: self.ipv6_advert.get(),
        }
    }
}

pub(crate) struct DownloadTask<S, P> {
    pub(crate) request: DownloadRequest,
    /// Which run of the download this is, carried on its finish notice.
    pub(crate) run: u64,
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
        // A run that lost parts it can fetch again starts over in place, in
        // the Download Set, from what still holds (ADR-0094).
        let result = loop {
            let result = orchestrate_download(request.clone(), &self.runner).await;
            if !self.runner.take_repair() {
                break result;
            }
            match self.runner.store.verified_parts(download_id) {
                Err(_) => break Err(DownloadFailure::StoreFailed),
                Ok(parts) => {
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
        let completed = result.is_ok();

        if let Err(reason) = result
            && !matches!(reason, DownloadFailure::Cancelled | DownloadFailure::Paused)
            && *self.runner.stop_rx.borrow() == StopReason::Active
        {
            crate::download::persist::record_failure(
                &self.runner.store,
                &self.runner.evt_tx,
                download_id,
                reason,
            )
            .await;
        }
        // The row outlives the run (ADR-0094): what the download holds is its
        // own fact, and only a cancel removes it.
        self.runner.diagnostics.end_run(download_id, completed);
        let _ = self
            .finished_tx
            .send(FinishedActivity::Download(download_id, self.run))
            .await;
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
    // The run holds its part file from its first act (ADR-0094).
    crate::download::persist::hold_part_file(runner, request.download_id).await?;
    let target =
        rmule_primitives::SourceLookupTarget::new(request.file.file_hash, request.file.size);
    // Subscribed before the first lookup: a session that comes up after it
    // is asked too.
    let server_leg = server_leg::ServerLeg::new(runner.server_session.session_changes(), target);
    // The link's own sources come first (ADR-0089's amendment), and a
    // link that carries one can feed the run without a server, as Kad can.
    let link_sources = {
        let mut stop_rx = runner.stop_rx.clone();
        let now = crate::server_list::unix_seconds(std::time::SystemTime::now());
        tokio::select! {
            biased;
            _ = wait_until_stop(&mut stop_rx) => {
                return Err(stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled));
            }
            sources = link_sources::link_sources(&request.file, &runner.resolver, now) => sources,
        }
    };
    let mut link_sources = link_sources;
    admit_sources(runner, &mut link_sources);
    // The seeds attach handed this run go first (ADR-0109, "Source Seeds"),
    // through the same gates; a run that has any starts its fleet at once and
    // makes its first lookup its server leg's first ask.
    let mut seeds: Vec<ExchangedSource> = request
        .remembered
        .iter()
        .map(|seed| seed.as_source())
        .collect();
    admit_sources(runner, &mut seeds);
    let lookup_owed = !seeds.is_empty();
    // The brain reports the seeds' dials once each has answered or ended.
    let remembered = RememberedSeeds {
        written: request.remembered.len(),
        endpoints: seeds
            .iter()
            .filter_map(|seed| seed.as_peer_endpoint())
            .collect(),
    };
    let mut server_leg = server_leg;
    let source_outcome = if lookup_owed {
        server_leg.ask_first(runner);
        None
    } else {
        lookup::find_sources(
            &request,
            runner,
            target,
            !link_sources.is_empty(),
            &mut server_leg,
        )
        .await?
    };
    let link_sources = link_sources::ahead_of(seeds, link_sources);
    runner
        .store
        .set_lifecycle(request.download_id, DownloadLifecycle::Active)
        .map_err(|_| DownloadFailure::StoreFailed)?;
    check_stop(&runner.stop_rx)?;
    if let Some(outcome) = &source_outcome {
        send_download_event(
            &runner.evt_tx,
            DownloadEvent::ServerLoginAccepted {
                download_id: request.download_id,
                client_id: outcome.client_id,
            },
        )
        .await;
    }

    // A degraded (serverless) start has no server sources: pools start with
    // the link's own, and only an open Kad verdict can make it callable.
    let mut server_sources = link_sources::ahead_of(
        link_sources,
        source_outcome
            .map(|outcome| outcome.sources)
            .unwrap_or_default(),
    );

    admit_sources(runner, &mut server_sources);

    let usable_high_id = server_sources
        .iter()
        .filter(|source| source.as_peer_endpoint().is_some())
        .count();
    send_download_event(
        &runner.evt_tx,
        DownloadEvent::SourcesFound {
            download_id: request.download_id,
            total: server_sources.len(),
            usable_high_id,
        },
    )
    .await;

    // Keep every usable High-ID source from the single snapshot as an ordered
    // candidate pool (ADR-0030); the runner spawns up to `peer_concurrency`
    // workers from it and backfills replacements on failure rather than
    // discarding the unused sources.
    let candidate_pool = server_sources
        .iter()
        .filter_map(|source| source.as_peer_endpoint())
        .collect::<Vec<_>>();
    // The obfuscated-dial unlock (ADR-0046): the crypt side the
    // obfuscation-aware `0x44` reply stated for each source — its crypt byte
    // and User Hash — keyed by the endpoint the runner spawns against, and met
    // with our policy at the dial (ADR-0049). Empty for a plain `0x42` reply —
    // those sources stated nothing and read as `PeerCrypt::unknown`.
    let peer_crypts: HashMap<PeerEndpoint, PeerCrypt> = server_sources
        .iter()
        .filter_map(|source| Some((source.as_peer_endpoint()?, source.peer_crypt())))
        .filter(|(_, crypt)| !crypt.is_unknown())
        .collect();
    // Low-ID sources have no dialable endpoint; with Callback Capability the
    // runner asks the connected server to call them back (ADR-0039). A low id of
    // 0 is unassigned and never callback-able, so it is dropped here. Each keeps
    // what the answer said about it — the obfuscation-aware `0x44` carries the
    // source's User Hash (ADR-0046), which the plain `0x42` does not, and rung 1
    // of the route tree needs it (ADR-0091).
    let low_id_candidates = server_sources
        .iter()
        .filter_map(|source| LowIdCandidate::from_connected_server(*source))
        .collect::<Vec<_>>();
    // rmule can be called back only if it is itself reachable — a server High
    // ID or an open Kad TCP verdict — **and** its inbound listener is bound:
    // aMule's `CanDoCallback`, read from the live self-facts rather than this
    // run's login answer, the listener conjunct included (a serve
    // started or stopped after this spawn now lands on the
    // runner's next sample too). Where it admits nobody, no callback is asked
    // for — and a Low-ID candidate is reachable only by the other road, a
    // punch a Rendezvous coordinator introduces (ADR-0091 rung 1).
    let callback_facts = CallbackFacts {
        reach: runner.reach.clone(),
        our_tcp_port: request.identity.tcp_port(),
    };
    let callback_capability = callback_facts.sample();
    // The same admission rule the brain fills slots by (ADR-0091),
    // asked once before a fleet exists: a Low-ID candidate counts as usable when
    // its IPv6 half is dialable from ours (rung 0), a callback can be
    // relayed to it, **or** a coordinator could introduce us to it. Failing here
    // for a pool the brain would have dialed or punched from is the defect this
    // check used to be.
    let dial = runner.dial_position();
    let usable_low_id = low_id_candidates.iter().any(|candidate| {
        LowIdRoute::of(&callback_capability, dial, &candidate.into_inner()).is_some()
    });
    if candidate_pool.is_empty()
        && !usable_low_id
        && !request.discovery.any_active()
        && !lookup_owed
    {
        return Err(DownloadFailure::NoUsableSources);
    }
    // The peer hello carries only the minimal identity. The server-login
    // capability tags the application advertises (e.g. CT_SERVER_FLAGS)
    // are server-only and must not leak into the peer hello, where their
    // tag IDs mean different things and advertise capabilities the peer
    // protocol does not implement (ADR-0047).
    // The hello names the live session's server and id, read again at every
    // spawn — never the server this download was once started on.
    let ctx = live_peer_handshake_context(&request.identity, runner.server_session.own_identity());
    check_stop(&runner.stop_rx)?;

    // The peers this download distrusts, as its durable record holds
    // them: a resumed run does not dial again a peer that served it bad data.
    let distrusted = runner
        .store
        .distrusted_peers(request.download_id)
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "could not read the download's distrusted peers");
            Vec::new()
        })
        .into_iter()
        .collect();

    apply_peer_workers_download(
        FleetStart {
            download_id: request.download_id,
            file: request.file,
            ctx,
            peer_concurrency: request.peer_concurrency,
            verified_part_indexes: request.verified_part_indexes,
            candidates: StartingCandidates {
                high_id: candidate_pool,
                peer_crypts,
                low_id: low_id_candidates,
                distrusted,
                remembered,
            },
            callback_facts,
            posture: SourcingPosture {
                callback_capability,
                dial,
                discovery_active: request.discovery.any_active() || lookup_owed,
            },
            discovery: request.discovery,
            server_leg,
            lookup_owed,
        },
        runner,
    )
    .await
}

/// The ingest gates every source of the run's first snapshot passes, the
/// link's and the server's alike.
///
/// The IP filter, aMule `CPartFile::AddSources`: filtered High-ID rows are
/// dropped at ingest — before the counts and pools — so a filtered source
/// never exists for this download. Low-ID rows pass (no IP to test, aMule's
/// `!IsLowID` guard); their real address is enforced at the accept/dial gates.
/// A source whose Address Family this build cannot dial *right now* is
/// dropped on the same pass and counted (ADR-0085/0087). The dialect is no
/// longer the reason — it is implemented — so the only remaining one is
/// holding no address in that family to dial *from*, which is why the
/// counter reads zero for a server-supplied IPv6 source on a dual-stack node
/// and never zero on an IPv4-only one.
fn admit_sources<S, P>(runner: &RunnerContext<S, P>, sources: &mut Vec<ExchangedSource>) {
    let ip_filter = runner.ip_filter.read().expect("ip filter lock");
    sources.retain(|source| {
        admits_family(
            &runner.diagnostics,
            source.as_peer_endpoint(),
            runner.dial_position(),
        ) && admits_source(&ip_filter, source.as_peer_endpoint())
    });
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
