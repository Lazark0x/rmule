//! Carrying the scheduling brain's decisions out against the live runtime: the
//! loop-carried context ([`LoopCtx`]) the fleet loop and the enactor share, and
//! the drain that turns a `Vec<Decision>` into worker commands, persisted parts
//! and emitted events. The only async surface in the download loop.

use std::cmp::Reverse;
use std::collections::{HashSet, VecDeque};

use rmule_primitives::{Ed2kFileLink, PeerEndpoint};
use tokio::sync::mpsc;

use crate::adapters::{
    CallbackKey, PeerTransferService, PeerWorkerCommand, PeerWorkerEvent, PendingCallbackEntry,
    SourceLookupService, WorkerBrief,
};
use crate::callback::{DownloadAsk, DownloadReach};
use crate::credit::KeyBinding;
use crate::download::persist::{PersistError, finalize_download, persist_streamed_part};
use crate::download::source_ask_clock::{AskName, SourceAskClock};
use crate::download::state::{Decision, DownloadState, LowIdCandidate};
use crate::download::worker_pool::{WorkerChannels, WorkerFact, WorkerId, WorkerPool};
use crate::error::DownloadFailure;
use crate::global_sources::GlobCallbackSend;
use crate::peer_roster::PeerRelation;
use crate::service::{CoreEvent, DownloadId, send_download_event};
use crate::storage::DownloadRepository;

use super::callbacks::{CallbackContext, CallbackDeadline};
use super::fleet::{enter_phase, refresh_parts};
use super::{RunnerContext, WORKER_SHUTDOWN_TIMEOUT};

/// Everything one download run carries across loop turns, owned as one value so
/// the `select!` loop and [`enact_drain`] share a single `&mut ctx`: the
/// scheduling brain (`state`), the live worker fleet (`worker_pool`,
/// `command_channels`), the file-hash-only accumulator, the peer fact stream,
/// and the callback enactment state. The runtime handles (`runner`, `file`,
/// `evt_tx`) ride as borrows for the run's lifetime; `evt_tx` is `&runner.evt_tx`
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
    /// Whether each new connection asks for sources (ADR-0108).
    pub(super) source_ask_clock: SourceAskClock,
}

/// The download's half of the source-ask decision for one connection to the
/// peer known by `names` (ADR-0108, aMule `IsSourceRequestAllowed`). Nothing
/// is stamped: the ask is stamped when the worker reports it went out, after
/// the peer's hello had its say.
fn wants_sources(clock: &SourceAskClock, state: &DownloadState, names: &[AskName]) -> bool {
    clock.wants(names, std::time::Instant::now(), state.source_counts())
}

/// The Ask Names a High-ID source is known by before its dial: its endpoint,
/// and the User Hash its record or an earlier hello stated.
fn high_id_names(state: &DownloadState, peer: PeerEndpoint) -> Vec<AskName> {
    std::iter::once(AskName::Endpoint(peer))
        .chain(state.peer_crypt(peer).user_hash().map(AskName::User))
        .collect()
}

/// The Ask Names a Low-ID candidate is known by before it connects: its
/// callback's routing key, and its User Hash when its record carried one.
fn low_id_names(callbacks: &CallbackContext, candidate: &LowIdCandidate) -> Vec<AskName> {
    std::iter::once(AskName::LowId(callbacks.routing_key(candidate.key())))
        .chain(candidate.user_hash.map(AskName::User))
        .collect()
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
            Decision::Emit(event) => send_download_event(ctx.evt_tx, event).await,
            Decision::Phase { slot, phase } => {
                enter_phase(&ctx.runner.diagnostics, ctx.download_id, slot, phase);
            }
            Decision::Identify { slot, software } => {
                tracing::info!(
                    download_id = ctx.download_id.as_u64(),
                    worker_slot = slot.as_usize(),
                    software = ?software,
                    "worker identified",
                );
                ctx.runner
                    .diagnostics
                    .update_worker(ctx.download_id, slot, |entry| entry.identify(software));
            }
            Decision::Send { peer, command } => ctx.command_channels.send(peer, command).await,
            Decision::EndWorker { peer } => {
                ctx.source_ask_clock.unbind(peer);
                // The brain released the worker: it ends, and its channel with
                // it. The Peer Roster's download leg (ADR-0059)
                // forgets it here, the one site every retirement passes —
                // its own later `Disconnected` is a released worker's, stale.
                ctx.command_channels.end(peer).await;
                if let Some(v4) = peer.as_v4() {
                    ctx.runner
                        .peer_roster
                        .forget(PeerRelation::Download(ctx.download_id), v4);
                }
            }
            Decision::RecordCredit { user_hash, bytes } => {
                let _ = ctx.runner.credit.record_download(user_hash, bytes);
            }
            Decision::BindIdentity {
                user_hash,
                public_key,
            } => {
                // Atomic compare-and-set in the ledger (ADR-0041); the
                // *consequence* of a mismatch lives here: report the theft.
                // The stored key is untouched and unsecured accrual continues.
                let binding = ctx.runner.credit.bind_public_key(user_hash, &public_key);
                if matches!(binding, Ok(KeyBinding::Mismatch)) {
                    let _ = ctx
                        .evt_tx
                        .send(CoreEvent::SecuredIdentityMismatch { user_hash })
                        .await;
                }
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
                        queue.extend(ctx.state.on_persist_result(part_index, peer, Err(reason)));
                    }
                    Ok(()) => queue.extend(ctx.state.on_persist_result(part_index, peer, Ok(()))),
                }
            }
            Decision::PersistProvisionalHashes(hashes) => {
                // A store that cannot keep the set fails the run through the
                // one whole-fleet terminal, so every worker is
                // told `Shutdown` and every roster relation ends — never a
                // bare early return that leaves the fleet running unowned.
                if ctx
                    .runner
                    .store
                    .record_provisional_part_hashes(ctx.download_id, &hashes)
                    .is_err()
                {
                    queue.push_front(Decision::Fail(DownloadFailure::StoreFailed));
                }
            }
            Decision::DistrustPeer { user_hash } => {
                // Durable beside the download's record; the brain
                // already holds it for this run, so a failed write costs only
                // a resumed run's memory of it.
                if let Err(error) = ctx.runner.store.distrust_peer(ctx.download_id, user_hash) {
                    tracing::warn!(%error, "could not persist a distrusted peer");
                }
            }
            Decision::Spawn { peer, slot } => {
                // The crypt side this peer's record stated — the server-lookup
                // reply (ADR-0046), a source-exchange answer (ADR-0042), a Kad
                // row, or a rung-0 Low-ID candidate's record — met
                // with our policy at the dial (ADR-0049), and what we hold now
                // for the connect-time name ask.
                let brief = WorkerBrief {
                    peer_crypt: ctx.state.peer_crypt(peer),
                    own_status: ctx.state.our_part_status(),
                    want_sources: wants_sources(
                        &ctx.source_ask_clock,
                        &ctx.state,
                        &high_id_names(&ctx.state, peer),
                    ),
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
                    queue.extend(ctx.state.on_spawn_failed(peer));
                } else if ctx.state.is_remembered(peer) {
                    ctx.runner
                        .diagnostics
                        .update_worker(ctx.download_id, slot, |entry| entry.mark_remembered());
                }
            }
            Decision::Finalize => {
                // Normal completion: release each held slot silently, no
                // `OP_CANCELTRANSFER` (ADR-0056).
                shut_down_every_worker(ctx, false).await;
                finalize_download(
                    ctx.runner,
                    ctx.download_id,
                    ctx.file,
                    std::mem::take(&mut ctx.file_hash_only_parts),
                    ctx.evt_tx,
                )
                .await?;
            }
            Decision::RequestCallback { low_id } => {
                // Register the routing index so the accept-router can adopt the
                // called-back peer, then ask the server to relay the callback
                // (ADR-0039). The peer reports rmule's own connected server, so the
                // index is keyed by it — the brain leaves the connected-server key
                // `None` and the runner resolves it here (a runtime fact the sans-I/O
                // brain does not hold). Registration precedes the request so an
                // unusually fast dial-back always finds its entry. The paired
                // `ArmCallbackTimeout` decision arms the slot-release deadline.
                let key = CallbackKey {
                    server: ctx.callbacks.server_key,
                    low_id,
                };
                ctx.runner.pending_callbacks.lock().await.register(
                    key,
                    PendingCallbackEntry {
                        file: ctx.file.clone(),
                        own_status: ctx.state.our_part_status(),
                        want_sources: wants_sources(
                            &ctx.source_ask_clock,
                            &ctx.state,
                            &[AskName::LowId(key)],
                        ),
                        adopt_tx: ctx.callbacks.adopt_tx.clone(),
                    },
                );
                let session = {
                    let slot = ctx.runner.server_session.slot().lock().await;
                    slot.as_ref().filter(|handle| handle.is_alive()).cloned()
                };
                if let Some(session) = session {
                    tracing::info!(
                        low_id = low_id.as_u32(),
                        "server callback: asking the connected server to relay OP_CALLBACK"
                    );
                    session.request_callback(low_id).await;
                }
            }
            Decision::RequestGlobalCallback {
                low_id,
                source_server,
            } => {
                // Per-server (global) callback (ADR-0051): register the routing index keyed
                // `{ server: Some(source_server), low_id }` (already concrete — the
                // called-back peer dials in reporting `connected_server =
                // source_server`), then ask the discovery task to UDP-send
                // OP_GLOBCALLBACKREQUEST to that server carrying rmule's own contact.
                // Registration precedes the send so an unusually fast dial-back always
                // finds its entry. The paired `ArmCallbackTimeout` arms the deadline.
                let key = CallbackKey {
                    server: Some(source_server),
                    low_id,
                };
                ctx.runner.pending_callbacks.lock().await.register(
                    key,
                    PendingCallbackEntry {
                        file: ctx.file.clone(),
                        own_status: ctx.state.our_part_status(),
                        want_sources: wants_sources(
                            &ctx.source_ask_clock,
                            &ctx.state,
                            &[AskName::LowId(key)],
                        ),
                        adopt_tx: ctx.callbacks.adopt_tx.clone(),
                    },
                );
                if let Some(requester) = ctx.callbacks.facts.requester() {
                    let _ = ctx
                        .runner
                        .global_callback_tx
                        .send(GlobCallbackSend {
                            requester,
                            low_id,
                            source_server,
                        })
                        .await;
                }
            }
            Decision::RequestBuddyCallback { candidate } => {
                // ADR-0061 route 4. The dial-back claim goes in
                // before the ask for the reason every registration here does:
                // a target that answers the relayed callback before the entry
                // exists would be served, not adopted.
                ctx.callbacks
                    .claim_dial_back(
                        &ctx.runner.tunnel_claims,
                        &candidate,
                        ctx.file,
                        ctx.state.our_part_status(),
                        wants_sources(
                            &ctx.source_ask_clock,
                            &ctx.state,
                            &low_id_names(&ctx.callbacks, &candidate),
                        ),
                    )
                    .await;
                let _ = ctx
                    .runner
                    .download_reach_tx
                    .send(DownloadReach {
                        peer: candidate.reach(),
                        ask: DownloadAsk::BuddyCallback {
                            file_hash: ctx.file.file_hash,
                        },
                        callback: candidate.key(),
                        retire_tx: ctx.callbacks.retire_tx.clone(),
                    })
                    .await;
            }
            Decision::RequestFallbackBuddyCallback { candidate } => {
                // The other `TAG_BUDDYHASH` spelling, enacted as
                // any buddy callback is — the candidate already names the
                // fallback ID — and counted apart, because it is the leg a
                // source reading rather than a capture stands behind.
                ctx.runner
                    .diagnostics
                    .count_callback_fallback_spelling_sent();
                tracing::info!(
                    buddy_id = ?candidate.buddy.map(|buddy| buddy.buddy_id),
                    "buddy callback: primary spelling drew no dial-back; \
                     asking once more under the other TAG_BUDDYHASH spelling"
                );
                queue.push_front(Decision::RequestBuddyCallback { candidate });
            }
            Decision::RequestDirectUdpCallback { candidate } => {
                // ADR-0061 route 2 for a download's Kad-sourced candidate
                // The dial-back claim goes in before the ask,
                // exactly as `RequestBuddyCallback`'s does: a target that
                // answers the `0x95` before the entry exists would be served,
                // not adopted, and the two roads share the same claim
                // mechanism because neither candidate's `CallbackKey` is an
                // id any hello reports.
                ctx.callbacks
                    .claim_dial_back(
                        &ctx.runner.tunnel_claims,
                        &candidate,
                        ctx.file,
                        ctx.state.our_part_status(),
                        wants_sources(
                            &ctx.source_ask_clock,
                            &ctx.state,
                            &low_id_names(&ctx.callbacks, &candidate),
                        ),
                    )
                    .await;
                let _ = ctx
                    .runner
                    .download_reach_tx
                    .send(DownloadReach {
                        peer: candidate.reach(),
                        ask: DownloadAsk::DirectUdp,
                        callback: candidate.key(),
                        retire_tx: ctx.callbacks.retire_tx.clone(),
                    })
                    .await;
            }
            Decision::ArmCallbackTimeout { key, after } => {
                // Dumb enactor: resolve the brain's `after` span against the clock and
                // push its key onto the deadline heap. All callback policy (which key,
                // how long, what a lapse releases) is the brain's; this arm only turns
                // the span into an `Instant`. The heap holds brain keys verbatim, so a
                // fire calls `on_callback_timeout(key)` with no resolution.
                let deadline = tokio::time::Instant::now() + after;
                ctx.callbacks.deadlines.push(Reverse((
                    deadline,
                    key,
                    CallbackDeadline::SlotRelease,
                )));
            }
            Decision::ArmCallbackSilenceFallback { key, after } => {
                // The same dumb enactor for the shorter (12 s) deadline — a
                // second entry under the same key, distinguished by its kind, so
                // one `CancelCallbackTimeout` still ends the whole callback.
                let deadline = tokio::time::Instant::now() + after;
                ctx.callbacks.deadlines.push(Reverse((
                    deadline,
                    key,
                    CallbackDeadline::SilenceFallback,
                )));
            }
            Decision::ArmTraversalBound { key, after } => {
                // The same dumb enactor for the attempt's bound.
                let deadline = tokio::time::Instant::now() + after;
                ctx.callbacks.deadlines.push(Reverse((
                    deadline,
                    key,
                    CallbackDeadline::TraversalBound,
                )));
            }
            Decision::FallToNatTraversal { candidate, silence } => {
                // ADR-0061's "one selector, every caller" across a task boundary:
                // the download runner holds the counterparty's facts, the core
                // actor holds ours, so the facts travel and the actor asks
                // `select_natt_for_download`. Nothing is *awaited* on the answer,
                // but the ask carries a way back: it can be refused on our own
                // facts, and the retire channel is how that
                // reaches the brain — under the callback's key, because a
                // candidate with no User Hash has no entry in the claim table to
                // be told through.
                //
                // Claim the Tunnel first (ADR-0091). Registration precedes
                // the ask for the reason the callback's does: the rendezvous
                // is enacted off this task, and a Tunnel that rose before the
                // entry existed would take the serve road and be lost to this
                // download.
                let claimed = ctx
                    .callbacks
                    .claim_tunnel(
                        &ctx.runner.tunnel_claims,
                        &candidate,
                        ctx.file,
                        ctx.state.our_part_status(),
                        wants_sources(
                            &ctx.source_ask_clock,
                            &ctx.state,
                            &low_id_names(&ctx.callbacks, &candidate),
                        ),
                    )
                    .await;
                ctx.runner.diagnostics.count_natt_download_fallback(claimed);
                let _ = ctx
                    .runner
                    .download_reach_tx
                    .send(DownloadReach {
                        peer: candidate.reach(),
                        ask: DownloadAsk::Traversal(silence),
                        callback: candidate.key(),
                        retire_tx: ctx.callbacks.retire_tx.clone(),
                    })
                    .await;
            }
            Decision::RetractTunnelClaim { key } => {
                // Only the punch road is over (ADR-0091): the
                // callback keeps its slot, its deadline and its routing
                // entry, so this retracts the claim and nothing else.
                ctx.callbacks
                    .retract_claim(key, &ctx.runner.tunnel_claims)
                    .await;
            }
            Decision::CancelCallbackTimeout { key } => {
                // Dumb enactor: the callback is over, so both its deadlines
                // and both its routing registrations go — the server-relayed
                // road's pending-callback entry and the punch's tunnel claim.
                // Whichever road landed, the other must not be left able to
                // adopt a second worker for a slot already taken; the rule
                // itself lives with the state it governs.
                ctx.callbacks
                    .end_callback(
                        key,
                        &ctx.runner.pending_callbacks,
                        &ctx.runner.tunnel_claims,
                    )
                    .await;
            }
            Decision::Fail(reason) => {
                // A local-reason abandon — the download was cancelled or paused
                // (ADR-0056) — emits `OP_CANCELTRANSFER` from each worker still
                // holding a slot before it releases; an involuntary failure
                // (no sources, hash mismatch, peer loss) releases silently.
                let cancel = matches!(reason, DownloadFailure::Cancelled | DownloadFailure::Paused);
                for channel in ctx.command_channels.iter() {
                    enter_phase(
                        &ctx.runner.diagnostics,
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
    refresh_parts(&ctx.runner.diagnostics, ctx.download_id, &ctx.state);
    Ok(())
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
