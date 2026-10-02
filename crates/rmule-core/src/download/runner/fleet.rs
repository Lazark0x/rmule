//! The live peer-worker fleet for one download: it builds the worker pool from
//! the candidate set, runs the `select!` loop that feeds worker facts, adopted
//! callbacks and reask replies to the scheduling brain, and holds the Low-ID
//! callback enactment state (ADR-0039) that loop sleeps on. Policy stays in the
//! sans-I/O brain — this module only keeps the live fleet in step with it.

use crate::download::source_ask_clock::{AskName, SourceAskClock};
use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::Ed2kFileLink;
use tokio::sync::mpsc;

use crate::adapters::{
    CallbackKey, PeerTransferService, PeerWorker, PeerWorkerEvent, SourceLookupService,
};
use crate::client_udp::ClientUdpDatagram;
use crate::dialable::{admit_exchanged_halves, admit_kad_halves, admits_family};
use crate::download::remote_queue::{FILE_REASK_TIME, RemoteQueuedPool};
use crate::download::state::{
    ContentFacts, Decision, DownloadState, SourcingPosture, StartingCandidates,
};
use crate::download::worker_pool::{WorkerChannels, WorkerPool};
use crate::error::DownloadFailure;
use crate::hashing::{
    ResolvedHashSet, hash_set_proves_file, proven_link_hash_set, resolve_hash_set_authority,
};
use crate::ip_filter::admits_source;
use crate::peer_roster::{PeerRelation, RelationLease};
use crate::service::{
    DownloadEvent, DownloadId, SourceWait, VerificationAuthority, send_download_event,
};
use crate::source_discovery::register;
use crate::storage::DownloadRepository;

use super::callbacks::{CallbackContext, CallbackDeadline, sleep_until_optional};
use super::enact::{LoopCtx, enact_drain};
use super::reask::{
    REASK_SWEEP_INTERVAL, ReaskSinkLease, ReaskWiring, consume_reask_reply, drive_reask_sweep,
    observe_worker_event_for_reask,
};
use super::{CallbackFacts, RunnerContext, stop_reason, wait_until_stop};

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
    diagnostics.set_part_map(download_id, parts, retired, state.known_sources());
}

/// Everything one download run starts from, bundled so the fleet entry point
/// takes the run and the runtime instead of fifteen positional arguments.
pub(super) struct FleetStart<'a> {
    /// The activity id every event and diagnostics row of this run is tagged with.
    pub(super) download_id: DownloadId,
    /// The link the run is pinned to: file hash, size, part hash set and AICH root.
    pub(super) file: Ed2kFileLink,
    /// The peer-side handshake identity every worker dials with — server-login
    /// capability tags deliberately excluded (ADR-0047).
    pub(super) ctx: PeerHandshakeContext,
    /// The fleet cap: active + connecting workers plus outstanding callbacks.
    pub(super) peer_concurrency: usize,
    /// Parts an earlier run already verified on disk; they are never re-fetched.
    pub(super) verified_part_indexes: Vec<u32>,
    /// The server-lookup snapshot, split by what the runner can do with each source.
    pub(super) candidates: StartingCandidates,
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

pub(super) async fn apply_peer_workers_download<'a, S, P>(
    start: FleetStart<'a>,
    runner: &'a RunnerContext<S, P>,
) -> Result<(), DownloadFailure>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    let FleetStart {
        download_id,
        file,
        ctx,
        peer_concurrency,
        verified_part_indexes,
        candidates,
        callback_facts,
        posture,
        discovery,
        mut server_leg,
        mut lookup_owed,
    } = start;
    let file = &file;
    let evt_tx = &runner.evt_tx;
    let persisted_provisional_hashes = {
        let store = &runner.store;
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
    send_download_event(
        evt_tx,
        DownloadEvent::HashSetReceived {
            download_id,
            part_count: resolved.hashes.len(),
            authority: resolved.authority,
        },
    )
    .await;

    let (fact_tx, fact_rx) = mpsc::channel(32);
    let command_channels = WorkerChannels::default();
    // A persist-side accumulator of parts written under file-hash-only
    // authority, verified together at finalize. It drives no scheduling
    // decision, so it stays runner-side rather than in `DownloadState`.
    let file_hash_only_parts: Vec<u32> = Vec::new();
    // Low-ID callback plumbing (ADR-0039): `server_key` (rmule's connected
    // server) namespaces the shared pending-callback table; `adopt_rx` receives
    // the worker the accept-router builds from a called-back inbound peer; the
    // deadline heap releases a held slot if the peer never dials in. Read the
    // server key before `ctx` moves into the worker pool.
    let (adopt_tx, mut adopt_rx) = mpsc::channel::<(CallbackKey, PeerWorker)>(8);
    // The punch road's other end (ADR-0091): where the NAT-T front
    // reports a retired **Traversal Attempt**. Bounded and never awaited by the
    // front — a full queue costs this download its early notice, not the
    // front's loop.
    let (retire_tx, mut retire_rx) =
        mpsc::channel::<(CallbackKey, crate::diagnostics::NattRetirement)>(8);
    let callbacks = CallbackContext::new(
        ctx.connected_server,
        callback_facts,
        adopt_tx,
        retire_tx,
        runner.pending_callbacks.clone(),
        runner.tunnel_claims.clone(),
    );
    // This download's Download relations end with the run on every road
    // (ADR-0093 invariant 1), a quit's abort included, which no
    // whole-fleet terminal runs for. Its Queued relations end with
    // `ReaskWiring`'s drop.
    let _download_relations = RelationLease::new(
        runner.peer_roster.clone(),
        PeerRelation::Download(download_id),
    );
    // Source discovery (ADR-0051 / ADR-0043): register this download on each
    // channel's engine so found sources route to `*_sources_rx`; the one RAII
    // guard deregisters on any exit (including `?`-propagated failures). The
    // global channel ignores the size; the Kad channel carries it on the wire.
    let (global_sources_tx, mut global_sources_rx) = mpsc::channel(16);
    let _global_source_guard = register(
        &runner.global_source_registry,
        file.file_hash,
        file.size,
        global_sources_tx,
    );
    let (kad_sources_tx, mut kad_sources_rx) = mpsc::channel(16);
    let _kad_source_guard = register(
        &runner.kad_source_registry,
        file.file_hash,
        file.size,
        kad_sources_tx,
    );
    // A later link's sources for this file (ADR-0089's amendment): the
    // run holds the inbox for its life, so none is taken by a repair's rerun
    // while this one still runs.
    let mut later_links = runner.later_links.lock().await;
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
    // `Vec<Decision>` the runner enacts. Parts are assigned on the `Connected`
    // event, not up front, so a failed handshake never strands a part.
    let state = DownloadState::new(
        download_id,
        ContentFacts {
            file_hash: file.file_hash,
            file_size: file.size,
            link_part_hash_set: link_hash_set,
            resolved,
            trusted_aich_root: file.aich_root,
            verified_parts: verified_part_indexes,
        },
        candidates,
        posture,
        runner.callback_timeout,
        peer_concurrency,
    );

    // The `PeerHandshakeContext` binding `ctx` was consumed into `worker_pool`
    // above, so the name is free for the loop-carried state here.
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
        source_ask_clock: SourceAskClock::default(),
    };

    // Enact the initial fill: one `Spawn` per candidate up to concurrency.
    // The wait this run last told, while it still waits on it.
    let mut told_wait: Option<SourceWait> = None;
    let mut queue: VecDeque<Decision> = ctx.state.start().into();
    enact_drain(&mut queue, &mut ctx).await?;
    publish_seeds(&ctx);
    if ctx.command_channels.is_empty()
        && ctx.callbacks.deadlines.is_empty()
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

    // ADR-0057 live wiring: a source that queues us and then hangs up moves
    // to the **Remote-Queued Pool**, whose reask sweep keeps its earned standing
    // alive over the shared client-UDP socket (`0x90` out, `0x91`/`0x92`/`0x93`
    // in) instead of forfeiting it. Install this download's reply sink — leased
    // for its lifetime — so the socket's forwarder routes the reply quartet here.
    let (reask_reply_tx, mut reask_reply_rx) = mpsc::channel::<ClientUdpDatagram>(16);
    let mut reask = ReaskWiring {
        // No reachability here: the reask gate reads Self Reach at every
        // sweep, so the pool holds no copy of it.
        pool: RemoteQueuedPool::new(runner.client_udp_tx.is_some()),
        observed: HashMap::new(),
        client_udp_tx: runner.client_udp_tx.clone(),
        _sink_lease: ReaskSinkLease::install(
            runner.reask_reply_sink.clone(),
            download_id,
            reask_reply_tx,
        ),
        peer_roster: runner.peer_roster.clone(),
        download_id,
    };
    let mut reask_sweep = tokio::time::interval(REASK_SWEEP_INTERVAL);
    reask_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    reask_sweep.tick().await; // consume the immediate first tick
    // The spent-endpoint generations turn once a `FILEREASKTIME` (ADR-0090):
    // the brain is clock-free, so the runner's clock paces it.
    let mut reask_period = tokio::time::interval(FILE_REASK_TIME);
    reask_period.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    reask_period.tick().await; // consume the immediate first tick

    // The **Reach Generation**: the brain's Callback Capability
    // is a cache of Self Reach, re-derived on every move of it.
    let mut reach_generation = ctx.callbacks.facts.reach.changes();
    let mut stop_rx = runner.stop_rx.clone();
    while !ctx.state.is_complete() {
        // The earliest pending-callback deadline, read as a value so the select!
        // future holds no borrow of `ctx.callbacks` (the arms mutate it). `None`
        // when no callback is outstanding — the timer then never fires (ADR-0039).
        let next_deadline = ctx
            .callbacks
            .deadlines
            .peek()
            .map(|Reverse((deadline, ..))| *deadline);
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
                let mut q: VecDeque<Decision> = ctx.state.on_stop(failure).into();
                return enact_drain(&mut q, &mut ctx).await;
            }
            () = sleep_until_optional(next_deadline) => {
                // A pending callback's deadline came due. Pop each expired one and
                // drive the brain with its key: a `SlotRelease` means the callback
                // lapsed without the peer dialing in (ADR-0039 / ADR-0051), so the
                // brain releases its slot, retracts its routing-index entry (a
                // `CancelCallbackTimeout`) and refills; a `SilenceFallback` means
                // twelve seconds of nothing (ADR-0091), so the brain raises the
                // candidate's facts toward the one selector and leaves the callback
                // alone. Popping here — not the decision — is what guarantees
                // progress; the heap is a dumb enactor holding the brain's key
                // verbatim, so no runner-side policy or table poke is involved.
                let now = tokio::time::Instant::now();
                while ctx
                    .callbacks
                    .deadlines
                    .peek()
                    .is_some_and(|Reverse((deadline, ..))| *deadline <= now)
                {
                    let Reverse((_, key, kind)) = ctx.callbacks.deadlines.pop().expect("peeked");
                    let decisions = match kind {
                        CallbackDeadline::SlotRelease => ctx.state.on_callback_timeout(key),
                        CallbackDeadline::SilenceFallback => ctx.state.on_callback_silence(key),
                        CallbackDeadline::TraversalBound => ctx.state.on_traversal_bound(key),
                    };
                    let mut q: VecDeque<Decision> = decisions.into();
                    enact_drain(&mut q, &mut ctx).await?;
                }
                continue;
            }
            Some((reported, worker)) = adopt_rx.recv() => {
                // The accept-router adopted a called-back Low-ID peer (ADR-0039 / ADR-0051):
                // it reports the concrete server it dialed from. The brain matches that
                // to the pending callback — a per-server global one keyed by that
                // server, else the connected-server form (key `None`) — and hands back
                // the brain key + held slot. Register the worker's channel on the slot,
                // then bind it (bind-without-assign): its own `Connected` event flows
                // the normal assignment path, so it is forwarded, not dropped. A miss
                // means the callback already lapsed — drop the late worker.
                let peer = worker.peer();
                if let Some((key, slot)) = ctx.state.match_inbound_callback(reported) {
                    // The connection is the Low-ID peer the callback named:
                    // its endpoint takes on the callback's Ask Name (ADR-0108).
                    ctx.source_ask_clock
                        .bind(peer, AskName::LowId(ctx.callbacks.routing_key(key)));
                    ctx.worker_pool.register_adopted(
                        download_id,
                        peer,
                        slot,
                        worker,
                        &mut ctx.command_channels,
                    );
                    let mut q: VecDeque<Decision> = ctx.state.on_callback_connected(key, peer).into();
                    enact_drain(&mut q, &mut ctx).await?;
                }
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
                let mut q: VecDeque<Decision> = ctx.state.on_traversal_retired(key, reason).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some((source_server, mut sources)) = global_sources_rx.recv() => {
                // Server-UDP global sources (ADR-0051): the brain pools the High-ID
                // ones and (ADR-0051) holds Low-ID globals for a per-server callback to
                // `source_server`, then fills free slots. Filtered High-ID rows are
                // dropped first (aMule `CPartFile::AddSources`).
                {
                    let ip_filter = ctx.runner.ip_filter.read().expect("ip filter lock");
                    sources.retain(|source| {
                        admits_family(
                            &ctx.runner.diagnostics,
                            source.as_peer_endpoint(),
                            ctx.runner.dial_position(),
                        )
                            && admits_source(&ip_filter, source.as_peer_endpoint())
                    });
                }
                let mut q: VecDeque<Decision> = ctx.state.on_global_sources(source_server, sources).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some(mut sources) = later_links.recv() => {
                // A second link for this file named sources: they join the
                // pool as a mid-run server answer does, through the same
                // gates (ADR-0089).
                let named = sources.len();
                super::admit_sources(ctx.runner, &mut sources);
                let admitted = sources.len();
                // A source the run already knows — the first link's, a
                // server's, one it dialed — is not new, nor is one the link
                // names twice: only the rest join, once each.
                let mut seen = Vec::with_capacity(sources.len());
                sources.retain(|&source| {
                    let fresh = !ctx.state.knows_source(source) && !seen.contains(&source);
                    seen.push(source);
                    fresh
                });
                send_download_event(
                    evt_tx,
                    DownloadEvent::LinkSourcesAdded {
                        download_id,
                        named,
                        admitted,
                        new: sources.len(),
                    },
                )
                .await;
                let mut q: VecDeque<Decision> = ctx.state.on_server_sources(sources).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            mut sources = server_leg.next_answer(runner) => {
                // A server session came up mid-run and answered: its
                // sources join as the run's first answer would have, filtered
                // the same way (ADR-0085/0087). A seed-fed run's owed lookup
                // is paid by it.
                lookup_owed = false;
                {
                    let ip_filter = ctx.runner.ip_filter.read().expect("ip filter lock");
                    sources.retain(|source| {
                        admits_family(
                            &ctx.runner.diagnostics,
                            source.as_peer_endpoint(),
                            ctx.runner.dial_position(),
                        ) && admits_source(&ip_filter, source.as_peer_endpoint())
                    });
                }
                send_download_event(
                    evt_tx,
                    DownloadEvent::SourcesFound {
                        download_id,
                        total: sources.len(),
                        usable_high_id: sources
                            .iter()
                            .filter(|source| source.as_peer_endpoint().is_some())
                            .count(),
                    },
                )
                .await;
                let mut q: VecDeque<Decision> = ctx.state.on_server_sources(sources).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            Some(mut sources) = kad_sources_rx.recv() => {
                // Kad sources (ADR-0043): projected direct High-ID rows pool
                // and fill free slots; buddy and type-6 rows become callback
                // candidates. A High-ID row whose `ip6` rode beside it keeps
                // both addresses, each judged by the IP filter, since either
                // may be dialed (ADR-0087); the brain picks the
                // family. A callback row's rung-0 `ip6` is judged too.
                // Filtered rows are dropped (aMule `CDownloadQueue::KademliaSearchFile`).
                {
                    let ip_filter = ctx.runner.ip_filter.read().expect("ip filter lock");
                    let position = ctx.runner.dial_position();
                    sources = sources
                        .into_iter()
                        .filter_map(|source| {
                            admit_kad_halves(source, |half| admits_source(&ip_filter, Some(half)))
                        })
                        .filter(|source| {
                            admits_family(&ctx.runner.diagnostics, source.filter_endpoint(), position)
                                && admits_source(&ip_filter, source.filter_endpoint())
                        })
                        .collect();
                }
                let mut q: VecDeque<Decision> = ctx.state.on_kad_sources(sources).into();
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
                let mut q: VecDeque<Decision> = ctx.state.on_callback_capability(sample).into();
                enact_drain(&mut q, &mut ctx).await?;
                continue;
            }
            _ = reask_sweep.tick() => {
                // A run waiting for sources — no worker, no callback out —
                // writes nothing, so its part file is looked at on this tick
                // instead: gone or cut short is said now, not when a
                // part next arrives.
                if ctx.command_channels.is_empty() && ctx.callbacks.deadlines.is_empty() {
                    crate::download::persist::check_held_part_file(ctx.runner, download_id)
                        .await?;
                }
                // The **Callback Capability**'s facts, re-read: a
                // re-assignment, a session's end or a Kad verdict flip reaches
                // admission within a tick — aMule's `CPartFile::Process`
                // re-asks `CanDoCallback` of its waiting sources on its own
                // tick. A no-op when nothing moved.
                let sample = ctx.callbacks.facts.sample();
                let mut q: VecDeque<Decision> = ctx.state.on_callback_capability(sample).into();
                // Our Known IPv6, re-read on the same tick (ADR-0087): a prefix
                // that arrives or renumbers reaches rung 0 of the Low-ID route.
                q.extend(ctx.state.on_dial_position(ctx.runner.dial_position()));
                // The discovery channels' liveness, re-read on the same tick
                // (ADR-0093): a Kad node that died or started since spawn.
                q.extend(ctx.state.on_discovery_active(discovery.any_active() || lookup_owed));
                enact_drain(&mut q, &mut ctx).await?;
                told_wait = retell_wait(&ctx, &discovery, lookup_owed, told_wait).await;
                publish_seeds(&ctx);
                // The ADR-0057 reask sweep: for each pooled source, fire its UDP
                // ping (`0x90`) at `FILEREASKTIME − 20 s` or its TCP full ask at
                // `FILEREASKTIME`. Lowest priority — worker facts come first.
                drive_reask_sweep(&mut reask, &mut ctx).await?;
                continue;
            }
            _ = reask_period.tick() => {
                // A re-ask period passed: endpoints spent two periods ago may
                // be dialed again when next sighted. Nothing to enact.
                ctx.state.on_reask_period();
                continue;
            }
            Some((udp_src, datagram)) = reask_reply_rx.recv() => {
                // A pooled source's reask reply (`0x91`/`0x92`/`0x93`) fanned from
                // the shared client-UDP front: consume it into its standing.
                consume_reask_reply(&mut reask, &mut ctx, udp_src, &datagram).await;
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
                .diagnostics
                .dial_ended(ctx.download_id, peer, *cause);
        }
        // Observe the worker event for reask standing (ADR-0057) *before* the
        // brain acts on it: a retire-while-queued must pool the source and enter
        // it in the brain's remote-queued set before the release runs its terminal
        // `NoUsableSources` check, so earned standing keeps the download alive.
        observe_worker_event_for_reask(&mut reask, &mut ctx, peer, &event).await;
        // The Peer Roster's download leg (ADR-0059): the hello
        // completing (`Connected`, right after `Identified`) is the one mark
        // site; the brain releasing the worker (`EndWorker`, every retirement)
        // is the one forget site. A peer this download also uploads to
        // over the same dialed connection (ADR-0031) keeps its own `Upload`
        // relation on the identical endpoint, so that forget never un-knows it
        // early.
        if matches!(event, PeerWorkerEvent::Connected)
            && let Some(v4) = peer.as_v4()
        {
            ctx.runner
                .peer_roster
                .mark_known(PeerRelation::Download(ctx.download_id), v4);
        }
        // Source-exchange ingest gate (aMule `CPartFile::AddClientSources`):
        // filtered High-ID exchanged rows are
        // dropped before the brain pools them — a dual-stack row keeps both
        // addresses, each judged, since either may be dialed (ADR-0087);
        // the brain picks the family. Low-ID rows pass to the callback path,
        // their rung-0 IPv6 half judged the same way.
        let mut event = event;
        // The ask went out on this connection (ADR-0108): stamp it now, not
        // when the download decided it wanted sources — aMule stamps inside
        // `SendFileRequest` (stock 2.3.3 `DownloadClient.cpp:260-261`).
        match &event {
            // The hello names the peer: its hash joins the Ask Names this
            // connection is known by (ADR-0108).
            PeerWorkerEvent::Identified { user_hash, .. } => {
                ctx.source_ask_clock.bind(peer, AskName::User(*user_hash))
            }
            PeerWorkerEvent::SourcesAsked => {
                ctx.source_ask_clock.asked(peer, std::time::Instant::now())
            }
            PeerWorkerEvent::PartsAdvertised { complete } => {
                ctx.source_ask_clock
                    .advertised(peer, *complete, std::time::Instant::now())
            }
            _ => {}
        }
        if let PeerWorkerEvent::SourcesReceived { sources } = &mut event {
            // aMule stamps both clocks on any answer, empty or not
            // (stock 2.3.3 `ClientTCPSocket.cpp:1513-1515`).
            ctx.source_ask_clock
                .answered(peer, std::time::Instant::now());
            let received = sources.len();
            {
                let ip_filter = ctx.runner.ip_filter.read().expect("ip filter lock");
                let position = ctx.runner.dial_position();
                *sources = sources
                    .iter()
                    .filter_map(|&source| {
                        admit_exchanged_halves(source, |half| admits_source(&ip_filter, Some(half)))
                    })
                    .filter(|source| {
                        admits_family(&ctx.runner.diagnostics, source.as_peer_endpoint(), position)
                            && admits_source(&ip_filter, source.as_peer_endpoint())
                    })
                    .collect();
            }
            send_download_event(
                ctx.evt_tx,
                DownloadEvent::SourcesExchanged {
                    download_id: ctx.download_id,
                    peer,
                    received,
                    admitted: sources.len(),
                },
            )
            .await;
        }
        let mut q: VecDeque<Decision> = ctx.state.on_worker_event(peer, event).into();
        enact_drain(&mut q, &mut ctx).await?;
        // A hello, a rank or the first bytes change what the seeds would
        // say: published now, so a quit a moment later writes them.
        if ctx.state.take_seeds_moved() {
            publish_seeds(&ctx);
        }
    }
    // Completion is enacted by the `Finalize` decision (worker shutdown +
    // `finalize_download`) the moment the last part verifies; the loop then
    // observes `is_complete` and exits.
    Ok(())
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
    if !ctx.command_channels.is_empty() || !ctx.callbacks.deadlines.is_empty() {
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
/// (ADR-0109): after the first fill, then each reask sweep, so it is one
/// sweep old at most.
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
