//! Carrying the scheduling brain's decisions out against the live runtime: the
//! loop-carried context ([`LoopCtx`]) the fleet loop and the enactor share, and
//! the drain that turns a `Vec<Decision>` into worker commands, persisted parts
//! and emitted events. The only async surface in the download loop.

use std::collections::{HashSet, VecDeque};

use rmule_primitives::{Ed2kFileLink, Ipv4Endpoint, PeerEndpoint};
use tokio::sync::mpsc;

use crate::adapters::{
    AdoptionBrief, CallbackKey, PeerTransferService, PeerWorkerCommand, PeerWorkerEvent,
    SourceLookupService, WorkerBrief,
};
use crate::callback::{DownloadAsk, DownloadReach, PendingCallback};
use crate::download::persist::{PersistError, persist_streamed_part};
use crate::download::state::{Decision, DownloadState};
use crate::download::worker_pool::{WorkerChannels, WorkerFact, WorkerId, WorkerPool};
use crate::error::DownloadFailure;
use crate::global_sources::GlobCallbackSend;
use crate::peer_roster::PeerRelation;
use crate::service::{CoreEvent, DownloadEvent, DownloadId, send_download_event};
use crate::storage::DownloadRepository;

use super::callbacks::CallbackContext;
use super::fleet::{enter_phase, refresh_parts};
use super::{RunnerContext, WORKER_SHUTDOWN_TIMEOUT, now, served};

/// Everything one download run carries across loop turns, owned as one value so
/// the `select!` loop and [`enact_drain`] share a single `&mut ctx`: the
/// scheduling brain (`state`), the live worker fleet (`worker_pool`,
/// `command_channels`), the file-hash-only accumulator, the peer fact stream,
/// and the callback enactment state. The runtime handles (`runner`, `file`,
/// `evt_tx`) ride as borrows for the run's lifetime; `evt_tx` is `&runner.rt.evt_tx`
/// held separately so the enactor names its event sink directly.
pub(super) struct LoopCtx<'a, S, P> {
    pub(super) state: DownloadState,
    pub(super) runner: &'a RunnerContext<S, P>,
    pub(super) download_id: DownloadId,
    pub(super) file: &'a Ed2kFileLink,
    pub(super) evt_tx: &'a mpsc::Sender<CoreEvent>,
    pub(super) worker_pool: WorkerPool<'a, S, P>,
    pub(super) command_channels: WorkerChannels,
    pub(super) file_hash_only_parts: Vec<u32>,
    pub(super) fact_rx: mpsc::Receiver<WorkerFact>,
    pub(super) callbacks: CallbackContext,
    /// The endpoints this run holds the Peer Roster's `Queued` relation on —
    /// the RemoteQueued stage of its Source Book as the last drain left it
    /// ([`hold_queued_relations`]).
    pub(super) queued_relations: HashSet<Ipv4Endpoint>,
    /// The sources this run awaits an uploader's grant from, filed in the
    /// Peer Links and held to the same stage (ADR-0057).
    pub(super) awaited_grants: super::awaited_grants::AwaitedGrants,
    /// This run's **Held Places**, republished after every drain and
    /// withdrawn when the run ends (ADR-0116).
    pub(super) held_places: crate::held_places::HeldPlacesSeat,
}

/// Carry out one `Vec<Decision>` against the live runtime — the only async
/// surface in the download loop. Decisions drain in order; a `PersistPart` or
/// a failed `Spawn` feeds its follow-up decisions back onto the queue (the
/// persist / spawn round-trips), so the loop stays flat — no recursion.
/// `Fail` tears the fleet down and returns the reason. Every successful drain
/// ends by refreshing the diagnostics scheduler counts from `ctx.state`, so no
/// individual enact site repeats it and none can forget it; a `Fail` returns
/// before the refresh, leaving the counts of a torn-down fleet untouched.
pub(super) async fn enact_drain<S, P>(
    queue: &mut VecDeque<Decision>,
    ctx: &mut LoopCtx<'_, S, P>,
) -> Result<(), DownloadFailure>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    while let Some(decision) = queue.pop_front() {
        match decision {
            Decision::Emit(event) => {
                follow_event(ctx, &event);
                send_download_event(ctx.evt_tx, event).await;
            }
            Decision::Phase { slot, phase } => {
                enter_phase(&ctx.runner.rt.diagnostics, ctx.download_id, slot, phase);
            }
            Decision::Identify { slot, software } => {
                tracing::info!(
                    download_id = ctx.download_id.as_u64(),
                    worker_slot = slot.as_usize(),
                    software = ?software,
                    "worker identified",
                );
                ctx.runner
                    .rt
                    .diagnostics
                    .update_worker(ctx.download_id, slot, |entry| entry.identify(software));
            }
            Decision::Send { peer, command } => ctx.command_channels.send(peer, command).await,
            Decision::EndWorker { peer, cancel } => {
                // The brain released the worker: it ends, and its channel with
                // it. The Peer Roster's download leg (ADR-0059)
                // forgets it here, the one site every retirement passes —
                // its own later `Disconnected` is a released worker's, stale.
                ctx.command_channels.end(peer, cancel).await;
                if let Some(v4) = peer.as_v4() {
                    ctx.runner
                        .rt
                        .peer_roster
                        .forget(PeerRelation::Download(ctx.download_id), v4);
                }
            }
            Decision::RecordCredit { user_hash, bytes } => {
                let _ = ctx.runner.rt.credit.record_download(user_hash, bytes);
            }
            Decision::PersistPart {
                part_index,
                peer,
                offset,
                bytes,
            } => {
                let result = persist_streamed_part(
                    ctx.runner,
                    ctx.download_id,
                    ctx.file,
                    ctx.state.resolved(),
                    part_index,
                    offset,
                    &bytes,
                    &mut ctx.file_hash_only_parts,
                    ctx.evt_tx,
                )
                .await;
                match result {
                    // The part file changed under the run (what it cost is
                    // said and dropped, ADR-0094), or the store could not
                    // record the part: the run ends.
                    Err(PersistError::Ended(end)) => queue.push_front(Decision::Fail(end)),
                    Err(PersistError::Rejected(reason)) => {
                        queue.extend(ctx.state.on_persist_result(
                            now(),
                            part_index,
                            peer,
                            Err(reason),
                        ));
                    }
                    Ok(()) => {
                        queue.extend(ctx.state.on_persist_result(now(), part_index, peer, Ok(())))
                    }
                }
                // Before any decision that result returned is enacted, so
                // no status the run sends names a part the serve side
                // lacks (ADR-0113).
                served::rule_range_of(ctx.runner, ctx.download_id, &ctx.state);
            }
            Decision::PersistProvisionalHashes(hashes) => {
                // A store that cannot keep the set fails the run through the
                // one whole-fleet terminal, so every worker is
                // told `Shutdown` and every roster relation ends — never a
                // bare early return that leaves the fleet running unowned.
                match ctx
                    .runner
                    .rt
                    .store
                    .record_provisional_part_hashes(ctx.download_id, &hashes)
                {
                    Err(_) => queue.push_front(Decision::Fail(DownloadFailure::StoreFailed)),
                    Ok(disproved) => {
                        refetch_disproved(ctx, &disproved, queue);
                        served::rule_range(ctx.runner, ctx.download_id, &hashes);
                    }
                }
            }
            Decision::DistrustPeer { user_hash } => {
                // Durable beside the download's record. A write that fails
                // fails the run through the one whole-fleet terminal, as a
                // provisional set the store cannot keep does: a run that
                // went on believing the peer persisted would let a resumed
                // one dial it again.
                if let Err(error) = ctx
                    .runner
                    .rt
                    .store
                    .distrust_peer(ctx.download_id, user_hash)
                {
                    tracing::warn!(%error, "could not persist a distrusted peer");
                    queue.push_front(Decision::Fail(DownloadFailure::StoreFailed));
                }
            }
            Decision::ContestKadAichRoot => {
                // Durable beside the download's record, as a distrusted peer
                // is: a resumed run that trusted the contested root again
                // would let its recovery data blame honest cells.
                if let Err(error) = ctx.runner.rt.store.contest_kad_aich_root(ctx.download_id) {
                    tracing::warn!(%error, "could not persist a contested Kad AICH root");
                    queue.push_front(Decision::Fail(DownloadFailure::StoreFailed));
                }
            }
            Decision::Spawn {
                peer,
                slot,
                want_sources,
                opening,
            } => {
                // The crypt side this peer's record stated — the server-lookup
                // reply (ADR-0046), a source-exchange answer (ADR-0042), a Kad
                // row, or a rung-0 Low-ID candidate's record — met
                // with our policy at the dial (ADR-0049), and what we hold now
                // for the connect-time name ask.
                let brief = WorkerBrief {
                    peer_crypt: ctx.state.peer_crypt(peer),
                    own_status: ctx.state.our_part_status(),
                    want_sources,
                    opening,
                };
                if ctx
                    .worker_pool
                    .spawn_one(
                        ctx.download_id,
                        peer,
                        slot,
                        brief,
                        &mut ctx.command_channels,
                    )
                    .await
                    .is_err()
                {
                    queue.extend(ctx.state.on_spawn_failed(now(), peer));
                } else if ctx.state.is_remembered(peer) {
                    ctx.runner
                        .rt
                        .diagnostics
                        .update_worker(ctx.download_id, slot, |entry| entry.mark_remembered());
                }
            }
            Decision::SendReaskPing {
                peer,
                ping,
                answered_from,
            } => {
                // One reask in flight per answering endpoint across the
                // Download Set (ADR-0107): the reply names no file, so a
                // second download's reask answered there waits, its latch
                // handed back to the brain, until the first is answered or
                // lapses.
                let at = now();
                let claimed = ctx
                    .runner
                    .rt
                    .reask_reply_sink
                    .lock()
                    .expect("reask reply sink mutex")
                    .claim_ping(answered_from, ctx.download_id, at);
                if !claimed {
                    ctx.state.on_ping_held(at, peer);
                    continue;
                }
                if let Some(tx) = &ctx.runner.rt.client_udp_tx {
                    let _ = tx.send(ping).await;
                }
            }
            Decision::CallStandingWaiters { peer } => {
                // A grant on the peer's Queue Standing: every other download
                // waiting on it joins this link (ADR-0107), found under the
                // names the granted worker's hello proved.
                let mut names = vec![crate::adapters::LinkName::Endpoint(peer)];
                names.extend(
                    ctx.state
                        .peer_crypt(peer)
                        .user_hash()
                        .map(crate::adapters::LinkName::User),
                );
                ctx.runner.rt.peer_links.call_waiters(&names);
            }
            Decision::Finalize => {
                // Normal completion: release each held slot silently, no
                // `OP_CANCELTRANSFER` (ADR-0056). The fleet loop sees every
                // part verified and ends; the completion move follows it
                // (ADR-0115).
                shut_down_every_worker(ctx, false).await;
            }
            Decision::RequestCallback {
                low_id,
                server,
                want_sources,
            } => {
                // File the server-relayed road so the accept-router can adopt the
                // called-back peer, then ask the server to relay the callback
                // (ADR-0039). The peer reports rmule's own connected server, so the
                // road is filed under the candidate's key — one minted with no
                // server known is resolved to the live one. Filing precedes the
                // request so an unusually fast dial-back always finds it.
                let key = CallbackKey {
                    server,
                    low_id,
                    kad_port: None,
                };
                let brief = AdoptionBrief {
                    file: ctx.file.clone(),
                    own_status: ctx.state.our_part_status(),
                    want_sources,
                };
                ctx.callbacks.await_callback(key, brief);
                // A Low-ID peer linked to us already is ridden over that link
                // (ADR-0107, "One peer, one link"): asked for a callback it
                // would open nothing, its `TryToConnect` finding the socket
                // it holds.
                if ride_callback_link(ctx, key, want_sources).await {
                    continue;
                }
                let session = {
                    let slot = ctx.runner.rt.server_session.slot().lock().await;
                    slot.as_ref().filter(|handle| handle.is_alive()).cloned()
                };
                let sent = match session {
                    Some(session) => {
                        tracing::info!(
                            low_id = low_id.as_u32(),
                            "server callback: asking the connected server to relay OP_CALLBACK"
                        );
                        session.request_callback(low_id).await
                    }
                    None => false,
                };
                if !sent {
                    queue.extend(never_left(ctx, key));
                }
            }
            Decision::RequestGlobalCallback {
                low_id,
                source_server,
                want_sources,
            } => {
                // Per-server (global) callback (ADR-0051): file the server-relayed road
                // under `{ server: Some(source_server), low_id }` (already concrete — the
                // called-back peer dials in reporting `connected_server =
                // source_server`), then ask the discovery task to UDP-send
                // OP_GLOBCALLBACKREQUEST to that server carrying rmule's own contact.
                // Filing precedes the send so an unusually fast dial-back always
                // finds it.
                let key = CallbackKey {
                    server: Some(source_server),
                    low_id,
                    kad_port: None,
                };
                let brief = AdoptionBrief {
                    file: ctx.file.clone(),
                    own_status: ctx.state.our_part_status(),
                    want_sources,
                };
                ctx.callbacks.await_callback(key, brief);
                let sent = match ctx.callbacks.facts.requester() {
                    Some(requester) => ctx
                        .runner
                        .rt
                        .global_callback_tx
                        .send(GlobCallbackSend {
                            requester,
                            low_id,
                            source_server,
                        })
                        .await
                        .is_ok(),
                    None => false,
                };
                if !sent {
                    queue.extend(never_left(ctx, key));
                }
            }
            Decision::RequestBuddyCallback {
                candidate,
                want_sources,
            } => {
                // ADR-0061 route 4. The dial-back claim goes in
                // before the ask for the reason every registration here does:
                // a target that answers the relayed callback before the entry
                // exists would be served, not adopted.
                ctx.callbacks.claim_dial_back(
                    &candidate,
                    ctx.file,
                    ctx.state.our_part_status(),
                    want_sources,
                );
                let _ = ctx
                    .runner
                    .rt
                    .download_reach_tx
                    .send(DownloadReach {
                        peer: candidate.reach(ctx.callbacks.facts.server()),
                        pending: PendingCallback {
                            road: DownloadAsk::BuddyCallback {
                                file_hash: ctx.file.file_hash,
                            },
                            key: candidate.key(),
                            retire_tx: ctx.callbacks.retire_tx.clone(),
                        },
                    })
                    .await;
            }
            Decision::RequestFallbackBuddyCallback {
                candidate,
                want_sources,
            } => {
                // The other `TAG_BUDDYHASH` spelling, enacted as
                // any buddy callback is — the candidate already names the
                // fallback ID — and counted apart, because it is the leg a
                // source reading rather than a capture stands behind.
                ctx.runner
                    .rt
                    .diagnostics
                    .count_callback_fallback_spelling_sent();
                tracing::info!(
                    buddy_id = ?candidate.buddy.map(|buddy| buddy.buddy_id),
                    "buddy callback: primary spelling drew no dial-back; \
                     asking once more under the other TAG_BUDDYHASH spelling"
                );
                queue.push_front(Decision::RequestBuddyCallback {
                    candidate,
                    want_sources,
                });
            }
            Decision::RequestDirectUdpCallback {
                candidate,
                want_sources,
            } => {
                // ADR-0061 route 2 for a download's Kad-sourced candidate
                // The dial-back claim goes in before the ask,
                // exactly as `RequestBuddyCallback`'s does: a target that
                // answers the `0x95` before the entry exists would be served,
                // not adopted, and the two roads share the same claim
                // mechanism because neither candidate's `CallbackKey` is an
                // id any hello reports.
                ctx.callbacks.claim_dial_back(
                    &candidate,
                    ctx.file,
                    ctx.state.our_part_status(),
                    want_sources,
                );
                let _ = ctx
                    .runner
                    .rt
                    .download_reach_tx
                    .send(DownloadReach {
                        peer: candidate.reach(ctx.callbacks.facts.server()),
                        pending: PendingCallback {
                            road: DownloadAsk::DirectUdp,
                            key: candidate.key(),
                            retire_tx: ctx.callbacks.retire_tx.clone(),
                        },
                    })
                    .await;
            }
            Decision::FallToNatTraversal {
                candidate,
                silence,
                want_sources,
            } => {
                // ADR-0061's "one selector, every caller" across a task boundary:
                // the download runner holds the counterparty's facts and Self
                // Reach answers ours, so the facts travel to the actor's Peer
                // Reach, which asks `select_natt_for_download`. Nothing is *awaited* on the answer,
                // but the ask carries a way back: it can be refused on our own
                // facts, and the retire channel is how that
                // reaches the brain — under the callback's key, because a
                // candidate with no User Hash has no claim filed to be told
                // through.
                //
                // Claim the Tunnel first (ADR-0091). Registration precedes
                // the ask for the reason the callback's does: the rendezvous
                // is enacted off this task, and a Tunnel that rose before the
                // entry existed would take the serve road and be lost to this
                // download.
                let claimed = ctx.callbacks.claim_tunnel(
                    &candidate,
                    ctx.file,
                    ctx.state.our_part_status(),
                    want_sources,
                );
                ctx.runner
                    .rt
                    .diagnostics
                    .count_natt_download_fallback(claimed);
                let _ = ctx
                    .runner
                    .rt
                    .download_reach_tx
                    .send(DownloadReach {
                        peer: candidate.reach(ctx.callbacks.facts.server()),
                        pending: PendingCallback {
                            road: DownloadAsk::Traversal(silence),
                            key: candidate.key(),
                            retire_tx: ctx.callbacks.retire_tx.clone(),
                        },
                    })
                    .await;
            }
            Decision::RetractTunnelClaim { key } => {
                // Only the punch road is over (ADR-0091): the
                // callback keeps its slot, its deadline and its routing
                // entry, so this retracts the claim and nothing else.
                ctx.callbacks.retract_claim(key);
            }
            Decision::EndCallback { key } => {
                // The callback is over, and its deadlines went with its
                // record's road: its registration goes, both roads with it.
                ctx.callbacks.end_callback(key);
            }
            Decision::Fail(reason) => {
                // A local-reason abandon — the download was cancelled or paused
                // (ADR-0056) — emits `OP_CANCELTRANSFER` from each worker still
                // holding a slot before it releases; an involuntary failure
                // (no sources, hash mismatch, peer loss) releases silently.
                let cancel = matches!(reason, DownloadFailure::Cancelled | DownloadFailure::Paused);
                for channel in ctx.command_channels.iter() {
                    enter_phase(
                        &ctx.runner.rt.diagnostics,
                        ctx.download_id,
                        channel.slot,
                        crate::diagnostics::WorkerPhase::ShutDown,
                    );
                }
                shut_down_every_worker(ctx, cancel).await;
                let live = ctx.command_channels.iter().map(|c| c.id).collect();
                await_worker_shutdown(&mut ctx.fact_rx, live).await;
                return Err(reason);
            }
        }
    }
    // The diagnostics refresh rides inside every successful drain:
    // each of the seven enact sites bundled an identical refresh before, so
    // folding it here means a new site cannot forget it. `Fail` returns above
    // without refreshing — matching the stop path's prior behaviour (the
    // diagnostics row is removed on teardown regardless).
    refresh_parts(&ctx.runner.rt.diagnostics, ctx.download_id, &ctx.state);
    ctx.state.hold_connections();
    ctx.state.hold_standings();
    ctx.held_places.hold(ctx.state.held_places());
    hold_queued_relations(ctx);
    ctx.awaited_grants.hold(&ctx.state);
    Ok(())
}

/// A server-relayed ask for `key`'s callback that never left — no live
/// session, no requester endpoint to name, or a send nothing took: the brain
/// hears it now, so the slot goes to the candidate's next road rather than
/// waiting out the callback deadline for an invitation nobody carried. The
/// answer is the brain's decisions, for the queue.
fn never_left<S, P>(ctx: &mut LoopCtx<'_, S, P>, key: CallbackKey) -> Vec<Decision> {
    tracing::debug!(
        low_id = key.low_id.as_u32(),
        "server callback ask never left; its road ends now"
    );
    ctx.state.on_traversal_retired(
        now(),
        key,
        crate::diagnostics::NattRetirement::CallbackNotSent,
    )
}

/// The parts a part hash set disproved as it arrived, dropped by the store in
/// the write that recorded it: no longer verified by the file hash at
/// finalize, said, and fetched again.
fn refetch_disproved<S, P>(
    ctx: &mut LoopCtx<'_, S, P>,
    disproved: &[crate::VerifiedPartRecord],
    queue: &mut VecDeque<Decision>,
) {
    if disproved.is_empty() {
        return;
    }
    let lost: Vec<u32> = disproved.iter().map(|part| part.part_index).collect();
    tracing::warn!(
        download_id = ctx.download_id.as_u64(),
        parts = lost.len(),
        "parts fetched before the part hash set arrived do not match it; fetching them again"
    );
    ctx.file_hash_only_parts.retain(|part| !lost.contains(part));
    ctx.runner.rt.diagnostics.parts_lost(ctx.download_id, &lost);
    queue.push_back(Decision::Emit(DownloadEvent::PartsDisproved {
        download_id: ctx.download_id,
        parts: u32::try_from(lost.len()).unwrap_or(u32::MAX),
        bytes: disproved.iter().map(|part| part.len).sum(),
    }));
    queue.extend(ctx.state.refetch(now(), &lost));
}

/// The Peer Roster's `Queued` leg (ADR-0059 "Roster relations"): this run
/// holds the relation on exactly the endpoints its Source Book records stand
/// at in their RemoteQueued stage — aMule's `DS_ONQUEUE` clients, known after
/// their sockets closed. Held to the stage after every drain, so however a
/// record leaves it — the TCP full ask, a `0x92`, a merge into the record
/// that proved it the same peer, an endpoint another record took — its
/// relation goes with it; the run's lease ends whatever is left.
fn hold_queued_relations<S, P>(ctx: &mut LoopCtx<'_, S, P>) {
    let roster = &ctx.runner.rt.peer_roster;
    let queued = PeerRelation::Queued(ctx.download_id);
    let standing: HashSet<Ipv4Endpoint> = ctx
        .state
        .remote_queued()
        .filter_map(PeerEndpoint::as_v4)
        .collect();
    for &left in ctx.queued_relations.difference(&standing) {
        roster.forget(queued, left);
    }
    for &entered in standing.difference(&ctx.queued_relations) {
        roster.mark_known(queued, entered);
    }
    ctx.queued_relations = standing;
}

/// What follows from an event the brain emits, besides its delivery: the
/// diagnostics count of reask replies that changed nothing.
fn follow_event<S, P>(ctx: &LoopCtx<'_, S, P>, event: &DownloadEvent) {
    if let DownloadEvent::ReaskReplyIgnored { .. } = event {
        ctx.runner
            .rt
            .diagnostics
            .count_reask_reply_ignored(ctx.download_id);
    }
}

/// The fleet's whole-fleet terminal — a completion's `Finalize` or any
/// `Fail` (cancel, pause, or an involuntary failure): tell every still-live
/// worker to shut down and end each one's Peer Roster `Download` relation
/// right here, read off the fleet's own live set (ADR-0059 "Roster relations").
/// Neither path passes `EndWorker`, and a worker's
/// own later `Disconnected` is never read by the loop again — nor sent at all
/// by an aborted task — so this is the one terminal these relations
/// get.
async fn shut_down_every_worker<S, P>(ctx: &mut LoopCtx<'_, S, P>, cancel: bool)
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    for channel in ctx.command_channels.iter() {
        channel.send(PeerWorkerCommand::Shutdown { cancel }).await;
        if let Some(v4) = channel.peer.as_v4() {
            ctx.runner
                .rt
                .peer_roster
                .forget(PeerRelation::Download(ctx.download_id), v4);
        }
    }
}

/// Wait for every worker just told to shut down — the `live` incarnations —
/// to report its terminal `Disconnected` fact, capped by
/// `WORKER_SHUTDOWN_TIMEOUT` for one that never does; a released worker's late
/// fact counts for nothing. `fact_rx` cannot close here to end the wait on its
/// own: `WorkerPool` keeps its own `fact_tx` clone alive for the run's whole
/// lifetime so a worker backfilled after this point can still join the stream
/// (ADR-0030), and that clone outlives this drain — it only drops with `ctx`
/// itself, after `enact_drain` returns. Counting the still-shutting-down
/// workers down to none, instead of waiting on channel closure, is what lets a
/// cancel with no live workers return immediately rather than burning the full
/// timeout.
async fn await_worker_shutdown(
    fact_rx: &mut mpsc::Receiver<WorkerFact>,
    mut still_shutting_down: HashSet<WorkerId>,
) {
    if still_shutting_down.is_empty() {
        return;
    }
    let _ = tokio::time::timeout(WORKER_SHUTDOWN_TIMEOUT, async {
        while !still_shutting_down.is_empty() {
            match fact_rx.recv().await {
                Some((
                    worker,
                    _,
                    PeerWorkerEvent::Disconnected | PeerWorkerEvent::CryptIncompatible,
                )) => {
                    still_shutting_down.remove(&worker);
                }
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
}

#[cfg(test)]
mod tests;

/// Hand the run a worker riding `key`'s peer over its Peer Link, when one is
/// filed under the callback the key names; whether one was.
async fn ride_callback_link<S, P>(
    ctx: &mut LoopCtx<'_, S, P>,
    key: CallbackKey,
    want_sources: bool,
) -> bool
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    let Some(server) = ctx.callbacks.routing_key(key).server else {
        return false;
    };
    let brief = WorkerBrief {
        peer_crypt: rmule_primitives::PeerCrypt::unknown(),
        own_status: ctx.state.our_part_status(),
        want_sources,
        opening: crate::adapters::WorkerOpening::Probe,
    };
    let ridden = ctx.runner.rt.peer_transfer.lock().await.ride_callback_link(
        key.low_id,
        server,
        ctx.file.clone(),
        brief,
    );
    ridden.is_some_and(|worker| ctx.callbacks.hand_ridden(key, worker).is_ok())
}
