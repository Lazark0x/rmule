//! The live peer-worker fleet for one download: it builds the worker pool from
//! the candidate set, runs the `select!` loop that feeds worker facts, adopted
//! callbacks and reask replies to the scheduling brain, and holds the Low-ID
//! callback enactment state (ADR-0039) that loop sleeps on. Policy stays in the
//! sans-I/O brain — this module only keeps the live fleet in step with it.

use std::collections::{HashSet, VecDeque};

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{Ed2kFileLink, SourceSighting, UserHash};
use tokio::sync::mpsc;

use crate::adapters::{
    CallbackKey, LinkOffer, PeerTransferService, PeerWorker, PeerWorkerEvent, SourceLookupService,
};
use crate::client_udp::ClientUdpDatagram;
use crate::download::state::{
    AichRootAuthority, Channel, ContentFacts, Decision, DownloadState, SourcingPosture,
    StartingFacts, Tally,
};
use crate::download::worker_pool::{WorkerChannels, WorkerPool};
use crate::error::DownloadFailure;
use crate::hashing::{
    ResolvedHashSet, hash_set_proves_file, proven_link_hash_set, resolve_hash_set_authority,
};
use crate::peer_roster::{PeerRelation, RelationLease};
use crate::scheduler::PartOrder;
use crate::service::{
    DownloadEvent, DownloadId, SourceWait, VerificationAuthority, send_download_event,
};
use crate::source_discovery::register;
use crate::storage::DownloadRepository;

use super::adopt::adopt;
use super::awaited_grants::AwaitedGrants;
use super::callbacks::CallbackContext;
use super::enact::{LoopCtx, enact_drain};
use super::intake;
use super::reply_sink::ReaskSinkLease;
use super::{CallbackFacts, RunnerContext, now, stop_reason, wait_until_stop};

/// How often the runner re-reads the facts the brain holds samples of and no
/// change notice reaches: the Callback Capability (besides its Reach
/// Generation), our Known IPv6 and the discovery channels' liveness. aMule's
/// download queue `Process` runs about once a second.
const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Atomic update to a single worker's diagnostics row plus a DEBUG trace
/// event mirroring the new phase. Single helper keeps the trace and the
/// map in lockstep (ADR-0028).
pub(super) fn enter_phase(
    diagnostics: &crate::diagnostics::DiagnosticsState,
    download_id: DownloadId,
    slot: crate::diagnostics::WorkerSlot,
    new: crate::diagnostics::WorkerPhase,
) {
    tracing::debug!(
        download_id = download_id.as_u64(),
        worker_slot = slot.as_usize(),
        phase = ?new,
        "worker phase",
    );
    diagnostics.update_worker(download_id, slot, |entry| entry.transition(new));
}

/// Republish the download's positional part map into its diagnostics row
/// (ADR-0079). The scheduler is the only place a part's status is decided, so
/// the whole vector is re-read from it rather than patched index by index —
/// every consumer count is then a tally of that one vector.
pub(super) fn refresh_parts(
    diagnostics: &crate::diagnostics::DiagnosticsState,
    download_id: DownloadId,
    state: &DownloadState,
) {
    let (parts, retired) = state.part_map();
    diagnostics.set_part_map(
        download_id,
        parts,
        retired,
        state.known_sources(),
        state.source_activity(),
    );
}

/// Everything one download run starts from, bundled so the fleet entry point
/// takes the run and the runtime instead of fifteen positional arguments.
pub(super) struct FleetStart<'a> {
    /// The activity id every event and diagnostics row of this run is tagged with.
    pub(super) download_id: DownloadId,
    /// The link the run is pinned to: file hash, size, part hash set and AICH root.
    pub(super) file: Ed2kFileLink,
    /// The Kad AICH root the download's record keeps, or the contest that
    /// ended it (ADR-0038).
    pub(super) kad_aich_root: Option<crate::KadAichRoot>,
    /// The peer-side handshake identity every worker dials with — server-login
    /// capability tags deliberately excluded (ADR-0047).
    pub(super) ctx: PeerHandshakeContext,
    /// Parts an earlier run already verified on disk; they are never re-fetched.
    pub(super) verified_part_indexes: Vec<u32>,
    /// How the download ranks its parts (ADR-0112 §5).
    pub(super) order: PartOrder,
    /// The run's first sightings, by channel.
    pub(super) sources: StartSources,
    /// Where the **Callback Capability** is re-read from for the rest of the run.
    pub(super) callback_facts: CallbackFacts,
    /// The gates that turn on rmule's own network position, not on any source.
    pub(super) posture: SourcingPosture,
    /// Where `posture.discovery_active` is re-read from for the rest of the
    /// run (ADR-0093).
    pub(super) discovery: super::DiscoveryLiveness,
    /// Each server session that comes up while the run runs, and the sources
    /// it answers.
    pub(super) server_leg: super::server_leg::ServerLeg<'a>,
    /// The run started from its seeds before its first lookup (ADR-0109,
    /// "Source Seeds"): until a server answers, running out of sources waits
    /// for a connection instead of failing.
    pub(super) lookup_owed: bool,
}

/// What a run's book starts from: each channel's first sightings, taken in the
/// order a pool is built — seeds, then the link's, then the server's — and the
/// distrust the download's record holds.
pub(super) struct StartSources {
    /// The sightings of the download's **Source Seeds** (ADR-0109).
    pub(super) seeds: Vec<SourceSighting>,
    /// How many seeds the last run wrote that were under a day old.
    pub(super) seeds_written: usize,
    /// The link's own sources.
    pub(super) link: Vec<SourceSighting>,
    /// The server lookup's answer, empty when the run started without one.
    pub(super) server: Vec<SourceSighting>,
    /// The peers the download's record distrusts.
    pub(super) distrusted: HashSet<UserHash>,
}

pub(super) async fn apply_peer_workers_download<'a, S, P>(
    start: FleetStart<'a>,
    runner: &'a RunnerContext<S, P>,
) -> Result<Vec<u32>, DownloadFailure>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    let FleetStart {
        download_id,
        file,
        kad_aich_root,
        ctx,
        verified_part_indexes,
        order,
        sources,
        callback_facts,
        posture,
        discovery,
        mut server_leg,
        mut lookup_owed,
    } = start;
    let file = &file;
    let evt_tx = &runner.rt.evt_tx;
    let persisted_provisional_hashes = {
        let store = &runner.rt.store;
        store
            .provisional_part_hashes(download_id)
            .map_err(|_| DownloadFailure::PartVerificationFailed)?
    };
    // The link's set counts only when it is the file's own; otherwise
    // the peer's proven set wins.
    let link_hash_set = proven_link_hash_set(file);
    // A provisional set is kept only while it is still the file's own: one
    // persisted before sets were proven on arrival may not be.
    let resolved = if link_hash_set.is_none()
        && !persisted_provisional_hashes.is_empty()
        && hash_set_proves_file(file.file_hash, file.size, &persisted_provisional_hashes)
    {
        ResolvedHashSet {
            authority: VerificationAuthority::PeerHashSet,
            hashes: persisted_provisional_hashes,
        }
    } else {
        resolve_hash_set_authority(link_hash_set.as_ref(), None)?
    };
    let hash_set_received = DownloadEvent::HashSetReceived {
        download_id,
        part_count: resolved.hashes.len(),
        authority: resolved.authority,
    };

    let (fact_tx, fact_rx) = mpsc::channel(32);
    let command_channels = WorkerChannels::default();
    // A persist-side accumulator of parts written under file-hash-only
    // authority, verified together at finalize. It drives no scheduling
    // decision, so it stays runner-side rather than in `DownloadState`.
    let file_hash_only_parts: Vec<u32> = Vec::new();
    // Low-ID callback plumbing (ADR-0039): `adopt_rx` receives the worker the
    // accept-router builds from a called-back inbound peer; the brain's road
    // deadlines release a held slot if the peer never dials in.
    let (adopt_tx, mut adopt_rx) = mpsc::channel::<(CallbackKey, PeerWorker)>(8);
    // The punch road's other end (ADR-0091): where the NAT-T front
    // reports a retired **Traversal Attempt**. Bounded and never awaited by the
    // front — a full queue costs this download its early notice, not the
    // front's loop.
    let (retire_tx, mut retire_rx) =
        mpsc::channel::<(CallbackKey, crate::diagnostics::NattRetirement)>(8);
    let callbacks = CallbackContext::new(
        callback_facts,
        adopt_tx,
        retire_tx,
        runner.rt.awaited_inbound.clone(),
    );
    // This download's Download and Queued relations end with the run on every
    // road (ADR-0093 invariant 1), a quit's abort included, which no
    // whole-fleet terminal runs for.
    let _download_relations = RelationLease::new(
        runner.rt.peer_roster.clone(),
        PeerRelation::Download(download_id),
    );
    let _queued_relations = RelationLease::new(
        runner.rt.peer_roster.clone(),
        PeerRelation::Queued(download_id),
    );
    // Source discovery (ADR-0051 / ADR-0043): register this download on each
    // channel's engine so found sources route to `*_sources_rx`; the one RAII
    // guard deregisters on any exit (including `?`-propagated failures). The
    // global channel ignores the size; the Kad channel carries it on the wire.
    let (global_sources_tx, mut global_sources_rx) = mpsc::channel(16);
    let _global_source_guard = register(
        &runner.rt.global_source_registry,
        file.file_hash,
        file.size,
        global_sources_tx,
    );
    let (kad_sources_tx, mut kad_sources_rx) = mpsc::channel(16);
    let _kad_source_guard = register(
        &runner.rt.kad_source_registry,
        file.file_hash,
        file.size,
        kad_sources_tx,
    );
    // A later link's sources for this file (ADR-0089's amendment): the
    // run holds the inbox for its life, so none is taken by a repair's rerun
    // while this one still runs.
    let mut later_links = runner.later_links.lock().await;
    // The peers that ask us about this file while it downloads (ADR-0113):
    // the serve side hands each to this run as a candidate source. A run
    // with no lease — a download of one part — takes none.
    let mut askers = runner.served.as_ref().and_then(|lease| lease.take_askers());
    // `fact_tx` is moved in and kept alive for the whole run so a worker
    // backfilled mid-download can join the shared event stream by cloning it
    // (ADR-0030).
    let worker_pool = WorkerPool {
        runner,
        file,
        ctx,
        fact_tx,
    };
    // The sans-I/O scheduling brain (ADR-0026/0029/0030): it owns the
    // candidate pool, the free diagnostics slots, the scheduler, and the
    // cross-peer assembly, and turns each worker event into an ordered
    // `Vec<Decision>` the runner enacts. Parts are assigned on each worker's
    // probe answer, not up front, so a failed handshake never strands a part.
    let mut state = DownloadState::new(
        download_id,
        ContentFacts {
            file_hash: file.file_hash,
            file_size: file.size,
            link_part_hash_set: link_hash_set,
            resolved,
            aich_root: AichRootAuthority::at_start(file.aich_root, kad_aich_root),
            verified_parts: verified_part_indexes,
            order,
        },
        StartingFacts {
            distrusted: sources.distrusted,
            seeds_written: sources.seeds_written,
        },
        posture,
        runner.rt.callback_timeout,
        crate::download::connection_budget::BudgetSeat::new(
            std::sync::Arc::clone(&runner.rt.connection_budget),
            download_id,
        ),
    )
    .with_standings(crate::download::queue_standings::StandingSeat::new(
        std::sync::Arc::clone(&runner.rt.queue_standings),
        download_id,
    ));
    // The snapshot is sighted in the order a pool is built; nothing fills a
    // slot until `start`.
    let found = [
        (Channel::Seed, sources.seeds),
        (Channel::Link, sources.link),
        (Channel::Server, sources.server),
    ]
    .into_iter()
    .map(|(channel, sightings)| intake::sight(runner, &mut state, channel, sightings).tally)
    .fold(Tally::default(), |all, tally| all + tally);
    send_download_event(
        evt_tx,
        DownloadEvent::SourcesFound {
            download_id,
            total: found.distinct(),
            usable_high_id: found.distinct_dialable(),
        },
    )
    .await;
    if state.no_usable_candidate() {
        return Err(DownloadFailure::NoUsableSources);
    }
    send_download_event(evt_tx, hash_set_received).await;

    // The `PeerHandshakeContext` binding `ctx` was consumed into `worker_pool`
    // above, so the name is free for the loop-carried state here.
    // The sources the run waits in an uploader's queue for, filed so a link
    // that reads the uploader's unasked grant hands it here (ADR-0057).
    let awaited_grants = AwaitedGrants::new(runner.rt.peer_links.clone());
    let mut ctx = LoopCtx {
        state,
        runner,
        download_id,
        file,
        evt_tx,
        worker_pool,
        command_channels,
        file_hash_only_parts,
        fact_rx,
        callbacks,
        queued_relations: std::collections::HashSet::new(),
        awaited_grants,
        held_places: runner.rt.held_places.seat(download_id),
    };

    // Enact the initial fill: one `Spawn` per candidate the Connection Budget
    // admits (ADR-0116).
    // The wait this run last told, while it still waits on it.
    let mut told_wait: Option<SourceWait> = None;
    let mut queue: VecDeque<Decision> = ctx.state.start(now()).into();
    enact_drain(&mut queue, &mut ctx).await?;
    publish_seeds(&ctx);
    publish_exchange_pool(&ctx);
    if ctx.command_channels.is_empty()
        && !ctx.state.has_pending_callbacks()
        && !ctx.state.is_complete()
    {
        // No candidate could even start a worker and none is callback-pending:
        // the pool is exhausted. A requested callback (ADR-0039) keeps the
        // download alive with no live worker yet, so it is not a failure here.
        // A discovery channel is armed (server-UDP sweep, ADR-0051, or Kad,
        // ADR-0043): wait for it to backfill rather than failing. The select!
        // loop below already waits on `global_sources_rx` and `kad_sources_rx`
        // (and `fact_rx`, kept alive by `worker_pool`).
        let Some(reason) = source_wait(&discovery, lookup_owed) else {
            return Err(DownloadFailure::NoUsableSources);
        };
        send_download_event(
            evt_tx,
            DownloadEvent::WaitingForSources {
                download_id,
                reason,
            },
        )
        .await;
        told_wait = Some(reason);
    }

    // ADR-0057 live wiring: a source that queues us and then hangs up keeps
    // its standing on its Source Book record, and the brain's tick keeps it
    // alive over the shared client-UDP socket (`0x90` out, `0x91`/`0x92`/
    // `0x93` in). Install this download's reply sink — leased for its
    // lifetime — so the socket's forwarder routes the reply quartet here.
    let (reask_reply_tx, mut reask_reply_rx) = mpsc::channel::<ClientUdpDatagram>(16);
    let _reply_sink = ReaskSinkLease::install(
        runner.rt.reask_reply_sink.clone(),
        download_id,
        reask_reply_tx,
    );
    // The facts the brain holds samples of and no change notice reaches —
    // the Known IPv6, the discovery channels' liveness — are re-read on
    // this tick, beside the part file and the seeds.
    let mut sample = tokio::time::interval(SAMPLE_INTERVAL);
    sample.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    sample.tick().await; // consume the immediate first tick

    // The **Reach Generation**: the brain's Callback Capability
    // is a cache of Self Reach, re-derived on every move of it.
    let mut reach_generation = ctx.callbacks.facts.reach.changes();
    let mut stop_rx = runner.stop_rx.clone();
    while !ctx.state.is_complete() {
        // When the brain next has something due (ADR-0026): it names the
        // instant, the runner only sleeps until it.
        let next_wake = ctx.state.next_wake().map(tokio::time::Instant::from_std);
        let (worker, peer, event) = tokio::select! {
            biased;
            _ = wait_until_stop(&mut stop_rx) => {
                let failure = stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled);
                // The Peer Roster's Download leg (ADR-0059):
                // `on_stop` ends in `Fail`, whose whole-fleet shutdown
                // forgets every still-live worker's relation off the live set
                // — no worker's own `Disconnected` is needed, and none racing
                // into `fact_rx` is lost to it.
                // `on_stop` releases the in-flight parts and ends in
                // `Fail(failure)`; enacting it runs the releases, the worker
                // shutdown, and the fact-stream drain, then returns the failure.
                // `Fail` short-circuits before the diagnostics refresh inside
                // `enact_drain`, so the stop path skips it exactly as before.
                let mut q: VecDeque<Decision> = ctx.state.on_stop(failure.clone()).into();
                enact_drain(&mut q, &mut ctx).await?;
                return Err(failure);
            }
            () = sleep_until_optional(next_wake) => {
                // Something the brain holds fell due: a callback road's
                // deadline (ADR-0039, ADR-0091), a standing's reask
                // (ADR-0057), the spent endpoints' period (ADR-0090).
                let mut q: VecDeque<Decision> = ctx.state.on_tick(now()).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some((reported, worker)) = adopt_rx.recv() => {
                // The accept-router adopted a called-back Low-ID peer (ADR-0039 /
                // ADR-0051): it lands in the slot the brain names, or not at all.
                adopt(&mut ctx, reported, worker).await?;
                continue;
            }
            Some((key, reason)) = retire_rx.recv() => {
                // The **Traversal Attempt** beside this callback retired
                // (ADR-0091): every Rendezvous coordinator the
                // candidate's facts admitted was asked and none produced a
                // Tunnel. The brain marks the source temporarily unreachable
                // by that road and retracts the claim; the callback keeps its
                // slot and its 30 s, because the server may still relay it.
                tracing::debug!(
                    low_id = key.low_id.as_u32(),
                    ?reason,
                    "a NAT traversal attempt retired; the source is temporarily unreachable"
                );
                let mut q: VecDeque<Decision> = ctx.state.on_traversal_retired(now(), key, reason).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some((source_server, sources)) = global_sources_rx.recv() => {
                // Server-UDP global sources (ADR-0051): a Low-ID row is held
                // for a per-server callback to `source_server`.
                let taken = intake::sight(ctx.runner, &mut ctx.state, Channel::Global(source_server), intake::global_answer(source_server, sources));
                let mut q: VecDeque<Decision> = taken.decisions.into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some(sources) = later_links.recv() => {
                // A second link for this file named sources: they join the
                // pool as a mid-run server answer does, through the same
                // gate (ADR-0089). A source the run already knows merges.
                let taken = intake::sight(ctx.runner, &mut ctx.state, Channel::Link, sources);
                send_download_event(
                    evt_tx,
                    DownloadEvent::LinkSourcesAdded {
                        download_id,
                        named: taken.tally.received,
                        admitted: taken.tally.admitted,
                        new: taken.tally.fresh,
                    },
                )
                .await;
                let mut q: VecDeque<Decision> = taken.decisions.into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            sources = server_leg.next_answer(runner) => {
                // A server session came up mid-run and answered: its
                // sources join as the run's first answer would have, through
                // the same gate (ADR-0085/0087). A seed-fed run's owed lookup
                // is paid by it.
                lookup_owed = false;
                let taken = intake::sight(ctx.runner, &mut ctx.state, Channel::Server, sources);
                send_download_event(
                    evt_tx,
                    DownloadEvent::SourcesFound {
                        download_id,
                        total: taken.tally.admitted,
                        usable_high_id: taken.tally.dialable,
                    },
                )
                .await;
                let mut q: VecDeque<Decision> = taken.decisions.into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some(sighting) = recv_asker(&mut askers) => {
                // A peer asked us about the file: one more candidate, under
                // the run's source cap.
                let taken = intake::sight(ctx.runner, &mut ctx.state, Channel::Prober, [sighting]);
                let mut q: VecDeque<Decision> = taken.decisions.into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some(offer) = ctx.awaited_grants.next() => {
                // An uploader granted a source waiting in its queue a slot on
                // a link of its own (ADR-0057): the record's worker rides it.
                // Or the download holding that peer's Queue Standing was
                // granted, and the record's worker joins its link (ADR-0107).
                let decisions = match offer {
                    LinkOffer::Grant(peer) => ctx.state.on_slot_offered(now(), peer),
                    LinkOffer::Call(peer) => ctx.state.on_link_called(now(), peer),
                };
                let mut q: VecDeque<Decision> = decisions.into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some(sources) = kad_sources_rx.recv() => {
                // Kad sources (ADR-0043): a dialable row pools, a buddy or
                // type-6 row becomes a callback candidate.
                let taken = intake::sight(ctx.runner, &mut ctx.state, Channel::Kad, sources);
                let mut q: VecDeque<Decision> = taken.decisions.into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            recv = ctx.fact_rx.recv() => match recv {
                Some(item) => item,
                // `fact_tx` is held for the whole run so a backfilled worker
                // can join the stream, so this is reached only if every worker
                // stream has closed with the download still incomplete.
                None => return Err(DownloadFailure::NoUsableSources),
            },
            () = reach_generation.changed() => {
                // **Self Reach** moved (ADR-0060) — a listener
                // bind or clear included: the brain's capability
                // re-derives now, not at the next tick.
                let sample = ctx.callbacks.facts.sample();
                let mut q: VecDeque<Decision> = ctx.state.on_callback_capability(now(), sample).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            _ = sample.tick() => {
                // A run waiting for sources — no worker, no callback out —
                // writes nothing, so its part file is looked at on this tick
                // instead: gone or cut short is said now, not when a
                // part next arrives.
                if ctx.command_channels.is_empty() && !ctx.state.has_pending_callbacks() {
                    crate::download::persist::check_held_part_file(ctx.runner, download_id)
                        .await?;
                }
                // The **Callback Capability**'s facts, re-read: a
                // re-assignment, a session's end or a Kad verdict flip reaches
                // admission within a tick — aMule's `CPartFile::Process`
                // re-asks `CanDoCallback` of its waiting sources on its own
                // tick. A no-op when nothing moved.
                let sample = ctx.callbacks.facts.sample();
                let mut q: VecDeque<Decision> = ctx.state.on_callback_capability(now(), sample).into();
                // Our Known IPv6, re-read on the same tick (ADR-0087): a prefix
                // that arrives or renumbers reaches rung 0 of the Low-ID route.
                q.extend(ctx.state.on_dial_position(now(), ctx.runner.dial_position()));
                // The discovery channels' liveness, re-read on the same tick
                // (ADR-0093): a Kad node that died or started since spawn.
                q.extend(ctx.state.on_discovery_active(now(), discovery.any_active() || lookup_owed));
                enact_drain(&mut q, &mut ctx).await?;
                told_wait = retell_wait(&ctx, &discovery, lookup_owed, told_wait).await;
                publish_seeds(&ctx);
                publish_exchange_pool(&ctx);
                continue;
            }
            Some((udp_src, datagram)) = reask_reply_rx.recv() => {
                // A pooled source's reask reply (`0x91`/`0x92`/`0x93`) fanned from
                // the shared client-UDP front: the brain reads it into its standing.
                let mut q: VecDeque<Decision> =
                    ctx.state.on_reask_reply(now(), udp_src, &datagram).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
        };
        // Download byte accounting (ADR-0077) at the wire boundary: every
        // block a worker delivered counts, before the brain decides whether it
        // was wanted. A duplicate range, a block a later hash check discards,
        // or a block a released worker was still streaming still crossed the
        // socket, so it is still a received byte.
        if let PeerWorkerEvent::BlockReceived { bytes, .. } = &event {
            ctx.runner
                .rt
                .diagnostics
                .add_received_bytes(ctx.download_id, bytes.len() as u64);
        }
        // A released worker's late fact — its `Disconnected` after the
        // `Shutdown`, a block it was still streaming — is stale: the brain
        // already released it, and a re-spawn may hold the endpoint now.
        if !ctx.command_channels.is_live(worker) {
            continue;
        }
        // A dial that ended before the hello is counted on the row and named
        // on the slot that held it, for the Sources pane.
        if let PeerWorkerEvent::DialEnded { cause } = &event {
            ctx.runner
                .rt
                .diagnostics
                .dial_ended(ctx.download_id, peer, *cause);
        }
        // A source reached over its peer's link is marked on its slot for
        // the Sources pane (ADR-0107).
        if let PeerWorkerEvent::LinkShared { turn } = &event {
            ctx.runner
                .rt
                .diagnostics
                .link_turn(ctx.download_id, peer, *turn);
        }
        // The Peer Roster's download leg (ADR-0059): the hello
        // completing (`Connected`, right after `Identity`) is the one mark
        // site; the brain releasing the worker (`EndWorker`, every retirement)
        // is the one forget site. A peer this download also uploads to
        // over the same dialed connection (ADR-0031) keeps its own `Upload`
        // relation on the identical endpoint, so that forget never un-knows it
        // early.
        if matches!(event, PeerWorkerEvent::Connected)
            && let Some(v4) = peer.as_v4()
        {
            ctx.runner
                .rt
                .peer_roster
                .mark_known(PeerRelation::Download(ctx.download_id), v4);
        }
        let mut q: VecDeque<Decision> = if let PeerWorkerEvent::SourcesReceived { sources } = event
        {
            // The answer's sources pass the gate like any channel's (aMule
            // `CPartFile::AddClientSources`); the brain stamps the answer.
            intake::sight(
                ctx.runner,
                &mut ctx.state,
                Channel::Exchanged(peer),
                sources,
            )
            .decisions
            .into()
        } else {
            ctx.state.on_worker_event(now(), peer, event).into()
        };
        enact_drain(&mut q, &mut ctx).await?;
        // A hello, a rank or the first bytes change what the seeds would
        // say: published now, so a quit a moment later writes them.
        if ctx.state.take_seeds_moved() {
            publish_seeds(&ctx);
        }
    }
    // The `Finalize` decision shuts the fleet down the moment the last part
    // verifies; the loop then observes `is_complete` and exits, handing the
    // run the parts its completion move verifies by the file hash.
    Ok(std::mem::take(&mut ctx.file_hash_only_parts))
}

#[cfg(test)]
mod tests;

/// A run that told it waits for sources tells again when the reason moves —
/// a server session ending or arriving, Kad starting or stopping — so the
/// operator reads who can still find it a source, not the reason it had at
/// spawn. Once a worker or callback is out, the wait it told is over.
async fn retell_wait<S, P>(
    ctx: &LoopCtx<'_, S, P>,
    discovery: &super::DiscoveryLiveness,
    lookup_owed: bool,
    told: Option<SourceWait>,
) -> Option<SourceWait> {
    let told = told?;
    if !ctx.command_channels.is_empty() || ctx.state.has_pending_callbacks() {
        return None;
    }
    let reason = source_wait(discovery, lookup_owed)?;
    if reason != told {
        send_download_event(
            ctx.evt_tx,
            DownloadEvent::WaitingForSources {
                download_id: ctx.download_id,
                reason,
            },
        )
        .await;
    }
    Some(reason)
}

/// Why a starved run waits: the channels' reason, or — for a run that started
/// from its seeds and has not had its first lookup answered — a wait for the
/// connection that lookup needs (ADR-0109, "Source Seeds").
fn source_wait(discovery: &super::DiscoveryLiveness, lookup_owed: bool) -> Option<SourceWait> {
    discovery
        .source_wait()
        .or_else(|| lookup_owed.then_some(SourceWait::NoSession))
}

/// Publish the run's **Source Seeds** ranking for the actor's next write
/// (ADR-0109): after the first fill, then each sample tick, so it is one
/// sweep old at most.
/// Hand the serve side the run's source-exchange pool (ADR-0113): after the
/// first fill, then each sample tick — aMule builds its answer from the
/// source list at the ask, and a pool a second old is that list.
fn publish_exchange_pool<S, P>(ctx: &LoopCtx<'_, S, P>) {
    if let Some(lease) = &ctx.runner.served {
        lease.record_pool(ctx.state.exchange_pool());
    }
}

fn publish_seeds<S, P>(ctx: &LoopCtx<'_, S, P>) {
    let ranking = ctx.state.source_seeds();
    ctx.runner.seeds_tx.send_if_modified(|held| {
        let moved = *held != ranking;
        if moved {
            *held = ranking;
        }
        moved
    });
}

/// The next asker the serve side handed this run; pending forever for a run
/// with no inbox.
async fn recv_asker(askers: &mut Option<mpsc::Receiver<SourceSighting>>) -> Option<SourceSighting> {
    match askers {
        Some(askers) => askers.recv().await,
        None => std::future::pending().await,
    }
}

/// Sleep until `deadline`, or never while the brain names none (ADR-0026).
async fn sleep_until_optional(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}
