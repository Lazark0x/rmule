//! The serve activity's enactor: the [`ServeTask`] select loop that feeds
//! connection events, share-set snapshots, and rerank ticks into the sans-I/O
//! [`ServeState`] and carries out the returned decisions — channel sends,
//! event emission, the credit-ledger lock, `ContentFileStore` reads, and
//! `OP_OFFERFILES` announces. No policy branches live here (cf. the download
//! [`runner`](crate::download)).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_peer::{PeerIdentity, ServerCommand};
use rmule_primitives::PeerEndpoint;
use tokio::sync::{mpsc, watch};

use crate::adapters::{
    AnnounceOutcome, DialBackOutcome, ServeConnection, ServeInput, ServeOutput, ServeRuntimeService,
};
use crate::client_udp::{ClientUdpDatagram, ClientUdpSend};
use crate::content::{CheckedReadError, ContentFileStore};
use crate::credit::{KeyBinding, SharedCreditStore};
use crate::held_places::{RECIPROCITY_FACTOR, SharedHeldPlaces};
use crate::peer_roster::{PeerRelation, RelationLease};
use crate::registry::{SharedFileEntry, SharedFileRegistry};
use crate::serve::state::{ServeDecision, ServeSelfPosition, ServeState};
use crate::served_downloads::ServedDownloads;
use crate::service::{CoreEvent, ServeEvent, ServeStopReason};
use crate::store::registry::DurableSharedFileRegistry;
use crate::upload_queue::UploadSlotQueue;

/// The serve activity's task, over a runtime whose listener is **already
/// bound**: the actor binds, announces `ServingStarted`, and
/// spawns this only on success, so a start that fails never reaches a task at
/// all — and never takes the adapter with it.
pub(crate) struct ServeTask<L> {
    pub(crate) registry: Arc<DurableSharedFileRegistry>,
    pub(crate) serve_runtime: L,
    /// Seeds the brain's **Upload Slot Queue** (budget + cap from config).
    pub(crate) queue: UploadSlotQueue,
    pub(crate) evt_tx: mpsc::Sender<CoreEvent>,
    pub(crate) stop_rx: watch::Receiver<bool>,
    pub(crate) share_changed_rx: mpsc::Receiver<()>,
    /// Serve halves of connections rmule *dialed* (to download) that the peer
    /// also pulls from, on the same socket (ADR-0031). `None` when no
    /// dialed source is wired. Registered exactly like accepted connections.
    pub(crate) dialed_serve_rx: Option<mpsc::Receiver<ServeConnection>>,
    /// The shared, `UserHash`-keyed credit ledger. The serve task records
    /// served bytes here and reads each waiter's modifier to rank the queue.
    pub(crate) credit: SharedCreditStore,
    /// The node's **Held Places** (ADR-0116): a waiter at whose queue one of
    /// our downloads stands ranks by the Reciprocity Factor too.
    pub(crate) held_places: SharedHeldPlaces,
    /// The node's peer bans (ADR-0064): where the address of a second link
    /// naming an identified client's User Hash goes (ADR-0107).
    pub(crate) bans: crate::ban_store::SharedBanStore,
    /// How often idle waiters are re-ranked by live credit.
    pub(crate) rerank_interval: Duration,
    /// Inbound `OP_REASKFILEPING` datagrams from the shared client-UDP front
    /// (ADR-0057). `None` until the live front binds (socket unification), so
    /// the serve task is reask-ready without yet owning a client-UDP socket.
    pub(crate) reask_rx: Option<mpsc::Receiver<ClientUdpDatagram>>,
    /// The client-UDP send half a reask reply (`SendClientUdp`) rides back to
    /// the pinger, carrying the resolved waiter's crypt target so the socket
    /// boundary can obfuscate it (ADR-0046). `None` until the live front
    /// binds.
    pub(crate) client_udp_tx: Option<mpsc::Sender<ClientUdpSend>>,
    /// How often stale/unshared waiters are purged (aMule `CUploadQueue::Process`).
    pub(crate) purge_interval: Duration,
    /// A waiter's reask-silence deadline before purge (aMule
    /// `MAX_PURGEQUEUETIME`, 1 h).
    pub(crate) purge_after: Duration,
    /// The shared counter state [`crate::Core::diagnostics_snapshot`] reads
    /// (ADR-0077). The serve task is the only writer of the upload rows and of
    /// the session's up total.
    pub(crate) diagnostics: crate::diagnostics::DiagnosticsState,
    /// The session's self-facts (ADR-0032), read for the **Low-ID abuse
    /// guard**'s half of the decision that is about *us*: are we
    /// Low-ID, and which server are we on. `None` for a serve task woven
    /// without one, whose brain then holds the default — un-firewalled — and
    /// so never refuses on this ground.
    pub(crate) own_identity: Option<crate::own_identity::SharedOwnIdentity>,
    /// The core-owned Peer Roster (ADR-0059): a granted or queued
    /// upload slot marks the peer's IP known here, and its release forgets
    /// it — the "queued upload" leg of aMule's helper-bias rule
    /// (`BaseClient.cpp:4002-4003`), read by inbound triage. A queued waiter
    /// the purge sweep drops without ever granting a slot forgets it too
    /// (`WaiterLeft`) — no wait-list mark outlives the wait.
    pub(crate) peer_roster: crate::peer_roster::SharedPeerRoster,
    /// The **Withheld Row**s (ADR-0106): the snapshot is the registry's
    /// offered rows, never a withheld one.
    pub(crate) withheld: crate::registry_check::WithheldRows,
    /// Where a failed read of a shared file goes: the **Registry Check**.
    /// `None` for a serve task woven without one.
    pub(crate) read_failed_tx: Option<std::sync::mpsc::Sender<crate::registry_check::CheckInput>>,
    /// The **Served Downloads** (ADR-0113): read afresh before every peer
    /// input, reask ping and share trigger, and where a running download's
    /// askers are handed to its run.
    pub(crate) served: ServedDownloads,
}

/// Project the session's self-facts into the brain's [`ServeSelfPosition`].
///
/// No live session reads as Low-ID with no server, which is the references'
/// own posture at `clientid == 0`: a node between sessions cannot be dialed
/// back through one and shares its server with nobody.
fn self_position(own: Option<&crate::own_identity::SharedOwnIdentity>) -> ServeSelfPosition {
    let Some(session) = own.and_then(crate::own_identity::SharedOwnIdentity::connected_session)
    else {
        return ServeSelfPosition {
            low_id: own.is_some(),
            server: None,
        };
    };
    ServeSelfPosition {
        low_id: !session.client_id.is_high_id(),
        server: session.server,
    }
}

/// What a finished serve activity hands back to the actor: the
/// one-per-core resources the start took by value, released and startable
/// again, plus why the activity ended.
///
/// The adapter travels on the task's `JoinHandle` rather than through a
/// channel because it is the task's *result*: there is exactly one, it exists
/// only once the loop is over, and a handle cannot lose it to a full inbox.
pub(crate) struct ServeOutcome<L> {
    /// The serve adapter, [released](ServeRuntimeService::release) — its
    /// listener is down and its port is free, so the next start may bind it.
    pub(crate) serve_runtime: L,
    /// The `0x90` reask inbox this activity was handed, given back so a later
    /// activity is not reask-less. `None` when there was none, or when the
    /// client-UDP front closed under this one.
    pub(crate) reask_rx: Option<mpsc::Receiver<ClientUdpDatagram>>,
    pub(crate) reason: ServeStopReason,
}

impl<L> ServeTask<L>
where
    L: ServeRuntimeService,
{
    /// Serve until stopped or until the listener ends, then hand the adapter
    /// back. `ServingStopped` is *not* emitted here: the actor emits it once
    /// this outcome is back in the wiring, which is what makes the event mean
    /// "startable again".
    pub(crate) async fn run(self) -> ServeOutcome<L> {
        // Destructured into locals so no future ever captures `&ServeTask`
        // (`ServeRuntimeService` is `Send`, not `Sync`).
        let Self {
            registry,
            mut serve_runtime,
            queue,
            evt_tx,
            mut stop_rx,
            mut share_changed_rx,
            mut dialed_serve_rx,
            credit,
            held_places,
            bans,
            rerank_interval,
            mut reask_rx,
            client_udp_tx,
            purge_interval,
            purge_after,
            diagnostics,
            own_identity,
            peer_roster,
            withheld,
            read_failed_tx,
            served,
        } = self;
        // Every Upload relation this activity marks ends with it (ADR-0093 invariant 1):
        // a stop, a listener death or a panic
        // leaves no holder or waiter known. The serve activity is the one
        // owner of `Upload`, so ending the relation whole ends only its own.
        let _upload_relations = RelationLease::new(peer_roster.clone(), PeerRelation::Upload);
        // Per-connection command senders, keyed by requester endpoint.
        let mut conns: HashMap<PeerEndpoint, mpsc::Sender<ServeOutput>> = HashMap::new();
        // The sans-I/O serving brain (**Serve State**): it owns the share-set
        // snapshot, the upload slot queue, the served ranges, the peer
        // identities, and the AICH cache, and turns each input into an ordered
        // `Vec<ServeDecision>` this task enacts.
        let mut state = ServeState::new(queue);
        // The cell's version the brain's copy was last read at.
        let mut served_seen = 0;
        // Every connection's events funnel into one stream the task selects on
        // (cf. the download runner's `fact_rx`).
        let (fact_tx, mut fact_rx) = mpsc::channel::<(PeerEndpoint, ServeInput)>(64);
        // What each session made after an announce was told of the set.
        let mut session_told_rx = serve_runtime.take_session_told();
        // How each dial-back the serve adapter makes ended (ADR-0057). The
        // loop holds a sender, so the receiver never closes under it.
        let (dial_back_tx, mut dial_back_rx) = mpsc::channel::<DialBackOutcome>(16);

        // The write-through handles every enactment shares, bound once.
        let sinks = ServeSinks {
            credit: &credit,
            held_places: &held_places,
            bans: &bans,
            evt_tx: &evt_tx,
            client_udp_tx: &client_udp_tx,
            diagnostics: &diagnostics,
            peer_roster: &peer_roster,
            read_failed_tx: read_failed_tx.as_ref(),
            served: &served,
            dial_backs: &dial_back_tx,
        };

        // Announce the share set as of serve start — once the Registry
        // Check's start look has said what it is. Before that the look's own
        // end fires the share trigger, which announces.
        if withheld.is_looked() {
            // A trigger sent before this read signals a change the read
            // already holds: announcing again for it would say nothing new.
            while share_changed_rx.try_recv().is_ok() {}
            refresh_served(&served, &mut served_seen, &mut state);
            let mut decisions: VecDeque<ServeDecision> = state
                .on_share_set(
                    read_share_set(&registry, &withheld),
                    Instant::now(),
                    &HashMap::new(),
                )
                .into();
            enact(
                &mut decisions,
                &mut state,
                &conns,
                &mut serve_runtime,
                sinks,
            )
            .await;
        }

        let mut rerank_tick = tokio::time::interval(rerank_interval);
        rerank_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        rerank_tick.tick().await; // consume the immediate first tick

        let mut purge_tick = tokio::time::interval(purge_interval);
        purge_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        purge_tick.tick().await; // consume the immediate first tick

        // Every way out but one is the owner's doing; the listener ending is
        // the one nothing asked for, and the only one a front end could not
        // have predicted.
        let mut reason = ServeStopReason::Requested;
        loop {
            tokio::select! {
                biased;
                // A stop, or a dropped sender. A closed watch channel means
                // the actor that owns this activity is gone, which is
                // strictly stronger than "stop" — and it must be read as one:
                // `changed()` answers `Err` *immediately, forever* once the
                // sender drops, so discarding that error spins this loop at
                // full speed and never leaves it, holding the event sender
                // `Core::shutdown` waits to see dropped.
                stopped = stop_rx.changed() => {
                    if stopped.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
                changed = share_changed_rx.recv() => {
                    // The share trigger and the stop signal live and die
                    // together on the actor's `ServeActivity`, so a closed
                    // trigger is the same "owner is gone" fact — never a
                    // reason to re-read the share set on every poll.
                    if changed.is_none() {
                        break;
                    }
                    let modifiers = current_modifiers(&credit, &held_places, state.identities()).await;
                    refresh_served(&served, &mut served_seen, &mut state);
                    let mut decisions: VecDeque<ServeDecision> = state
                        .on_share_set(read_share_set(&registry, &withheld), Instant::now(), &modifiers)
                        .into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &conns,
                        &mut serve_runtime,
                        sinks,
                    )
                    .await;
                }
                accepted = serve_runtime.accept() => {
                    match accepted {
                        Some(conn) => {
                            // The accept backlog's high-water mark,
                            // sampled here because this is the deepest the
                            // channel is ever seen: the loop has just come
                            // back from whatever it was doing, so what is
                            // queued is what arrived while it was away. The
                            // peer just taken is counted, so the gauge reads
                            // as a depth and not as a remainder.
                            if let Some(queued) = serve_runtime.accept_backlog() {
                                diagnostics.observe_serve_accept_backlog(queued + 1);
                            }
                            register_serve_connection(conn, &mut conns, &fact_tx);
                        }
                        None => {
                            reason = ServeStopReason::ListenerClosed;
                            break;
                        }
                    }
                }
                outcome = dial_back_rx.recv() => {
                    let Some(outcome) = outcome else { continue };
                    let modifiers = current_modifiers(&credit, &held_places, state.identities()).await;
                    state.on_self_position(self_position(own_identity.as_ref()));
                    refresh_served(&served, &mut served_seen, &mut state);
                    let now = Instant::now();
                    let mut decisions: VecDeque<ServeDecision> = match outcome {
                        // The link is registered before its hello is folded,
                        // so the grant the fold decides finds it.
                        DialBackOutcome::Linked { waiter, conn, identity } => {
                            let link = conn.peer();
                            register_serve_connection(conn, &mut conns, &fact_tx);
                            state.on_dial_back_linked(now, waiter, link, *identity, &modifiers)
                        }
                        DialBackOutcome::Failed { waiter, cause } => {
                            state.on_dial_back_failed(now, waiter, cause, &modifiers)
                        }
                    }
                    .into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &conns,
                        &mut serve_runtime,
                        sinks,
                    )
                    .await;
                }
                told = recv_session_told(&mut session_told_rx) => match told {
                    Some(told) => say_told(&evt_tx, told).await,
                    None => session_told_rx = None,
                },
                dialed = recv_dialed(&mut dialed_serve_rx) => {
                    match dialed {
                        // A connection rmule dialed is also serving the peer:
                        // admit it to the same queue as an accepted one.
                        Some(conn) => register_serve_connection(conn, &mut conns, &fact_tx),
                        // The dialed source closed (core shutdown); stop polling
                        // it but keep serving accepted connections.
                        None => dialed_serve_rx = None,
                    }
                }
                fact = fact_rx.recv() => {
                    let Some((peer, event)) = fact else { continue };
                    let closing = event.is_disconnect() || event == ServeInput::Readopted;
                    let modifiers = current_modifiers(&credit, &held_places, state.identities()).await;
                    // Our own position, read fresh from the session's
                    // self-facts. A synchronous cell read, not a round
                    // trip: it must be current at the decision, because a
                    // login that just made us High-ID must stop the guard
                    // refusing on the very next ask.
                    state.on_self_position(self_position(own_identity.as_ref()));
                    // The downloads' Verified Ranges likewise: a part a run
                    // just verified is answered for on this very input.
                    refresh_served(&served, &mut served_seen, &mut state);
                    let mut decisions: VecDeque<ServeDecision> = state
                        .on_conn_event(Instant::now(), peer, event, &modifiers)
                        .into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &conns,
                        &mut serve_runtime,
                        sinks,
                    )
                    .await;
                    if closing {
                        conns.remove(&peer);
                    }
                }
                _ = rerank_tick.tick() => {
                    let modifiers = current_modifiers(&credit, &held_places, state.identities()).await;
                    let mut decisions: VecDeque<ServeDecision> =
                        state.on_rerank_tick(Instant::now(), &modifiers).into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &conns,
                        &mut serve_runtime,
                        sinks,
                    )
                    .await;
                }
                _ = purge_tick.tick() => {
                    // Reap waiters silent past the reask deadline or whose file
                    // stopped being shared (ADR-0057 disconnected standing).
                    let modifiers = current_modifiers(&credit, &held_places, state.identities()).await;
                    let mut decisions: VecDeque<ServeDecision> = state
                        .on_purge(Instant::now(), purge_after, &modifiers)
                        .into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &conns,
                        &mut serve_runtime,
                        sinks,
                    )
                    .await;
                }
                reask = recv_reask(&mut reask_rx) => match reask {
                    // One inbound OP_REASKFILEPING from the client-UDP front:
                    // answer the reply matrix, refresh the waiter's standing.
                    Some((udp_src, datagram)) => {
                        refresh_served(&served, &mut served_seen, &mut state);
                        let mut decisions: VecDeque<ServeDecision> = state
                            .on_reask_ping(Instant::now(), udp_src, &datagram)
                            .into();
                        enact(
                            &mut decisions,
                            &mut state,
                            &conns,
                            &mut serve_runtime,
                            sinks,
                        )
                        .await;
                    }
                    // The front closed (core shutdown); stop polling it.
                    None => reask_rx = None,
                },
            }
        }
        // Release before handing the adapter back, and await it: the accept
        // pump holds the bound port until its channel closes, so an adapter
        // returned mid-teardown would fail the very same-port restart this
        // outcome promises.
        serve_runtime.release().await;
        ServeOutcome {
            serve_runtime,
            reask_rx,
            reason,
        }
    }
}

/// The loop-invariant handles every enactment writes through, bundled so the
/// enactor reads as "decisions, working set, sinks" instead of a positional
/// telescope (the download runner's `LoopCtx` shape). Borrowed for the serve
/// loop's whole life; nothing here is ever swapped out.
#[derive(Clone, Copy)]
struct ServeSinks<'a> {
    /// The shared, `UserHash`-keyed credit ledger.
    credit: &'a SharedCreditStore,
    /// The node's **Held Places**, read with the credit at every rank.
    held_places: &'a SharedHeldPlaces,
    /// The node's peer bans, where a hash thief's address goes.
    bans: &'a crate::ban_store::SharedBanStore,
    evt_tx: &'a mpsc::Sender<CoreEvent>,
    /// The client-UDP send half reask replies ride out on; `None` until the
    /// live front binds.
    client_udp_tx: &'a Option<mpsc::Sender<ClientUdpSend>>,
    /// The **Transfer Byte Counters** state (ADR-0077).
    diagnostics: &'a crate::diagnostics::DiagnosticsState,
    /// The core-owned Peer Roster (ADR-0059): marked on a
    /// granted or queued upload slot, forgotten on its release or on the
    /// purge sweep dropping it unpromoted.
    peer_roster: &'a crate::peer_roster::SharedPeerRoster,
    /// The **Registry Check**'s inputs, where a failed read goes.
    read_failed_tx: Option<&'a std::sync::mpsc::Sender<crate::registry_check::CheckInput>>,
    /// The **Served Downloads**, whose runs take their askers.
    served: &'a ServedDownloads,
    /// Where the serve adapter says how each dial-back ended.
    dial_backs: &'a mpsc::Sender<DialBackOutcome>,
}

/// Carry out one `Vec<ServeDecision>` against the live runtime — the only
/// async surface in the serve loop. Decisions drain in order; a `ReadRange`
/// feeds its follow-up decisions back onto the queue (the read round trip),
/// so the loop stays flat — no recursion.
///
/// This is also where upload byte accounting happens (ADR-0077): the sinks'
/// `diagnostics` learns a peer's slot lifetime from the emitted grant/release
/// facts, and its `bytes_sent` from every `SendBlock` the connection writer
/// accepted — the last core-owned step before the socket.
async fn enact<L: ServeRuntimeService>(
    decisions: &mut VecDeque<ServeDecision>,
    state: &mut ServeState,
    conns: &HashMap<PeerEndpoint, mpsc::Sender<ServeOutput>>,
    serve_runtime: &mut L,
    sinks: ServeSinks<'_>,
) {
    let ServeSinks {
        credit,
        held_places,
        bans,
        evt_tx,
        client_udp_tx,
        diagnostics,
        peer_roster,
        read_failed_tx,
        served,
        dial_backs,
    } = sinks;
    while let Some(decision) = decisions.pop_front() {
        match decision {
            ServeDecision::Send { peer, command } => {
                // Payload size read before the command moves; counted only
                // once the connection task actually took it, so bytes a dead
                // connection never wrote are never claimed as uploaded.
                let block = match &command {
                    ServerCommand::SendBlock {
                        file_hash, bytes, ..
                    } => Some((*file_hash, bytes.len() as u64)),
                    _ => None,
                };
                let delivered = send_conn(conns, peer, ServeOutput::Server(command)).await;
                if delivered && let Some((file_hash, len)) = block {
                    diagnostics.add_sent_bytes(peer, file_hash, len);
                }
            }
            ServeDecision::Disconnect { peer } => {
                send_conn(conns, peer, ServeOutput::Disconnect).await;
            }
            ServeDecision::Emit(event) => {
                match event {
                    ServeEvent::UploadSlotGranted {
                        peer, file_hash, ..
                    } => {
                        diagnostics.open_upload(peer, file_hash);
                        diagnostics.count_upload_accept(file_hash);
                        if let Some(v4) = peer.as_v4() {
                            peer_roster.mark_known(PeerRelation::Upload, v4);
                        }
                    }
                    ServeEvent::PeerQueued { peer, .. } => {
                        // aMule's `US_ONQUEUE` is a nonzero upload state too
                        // (`GetUploadState() != US_NONE`, `BaseClient.cpp:4002`):
                        // a waiter is known the same as a granted holder.
                        if let Some(v4) = peer.as_v4() {
                            peer_roster.mark_known(PeerRelation::Upload, v4);
                        }
                    }
                    ServeEvent::UploadSlotReleased { peer } => {
                        diagnostics.close_upload(peer);
                        if let Some(v4) = peer.as_v4() {
                            peer_roster.forget(PeerRelation::Upload, v4);
                        }
                    }
                    ServeEvent::WaiterLeft { peer, .. }
                    | ServeEvent::UploadDialBackFailed { peer, .. } => {
                        // A waiter that left — or whose dial-back ended
                        // unsent — never had an upload open, so there is
                        // nothing to close: only the roster mark `PeerQueued`
                        // set.
                        if let Some(v4) = peer.as_v4() {
                            peer_roster.forget(PeerRelation::Upload, v4);
                        }
                    }
                    ServeEvent::WaiterRelinked { from, to } => {
                        // The mark `PeerQueued` set moves with the place.
                        if let Some(v4) = from.as_v4() {
                            peer_roster.forget(PeerRelation::Upload, v4);
                        }
                        if let Some(v4) = to.as_v4() {
                            peer_roster.mark_known(PeerRelation::Upload, v4);
                        }
                    }
                    ServeEvent::UploadAddressCapReached { .. } => {
                        diagnostics.record_upload_address_cap_refusal();
                    }
                    ServeEvent::UploadLowIdAbuseRefused { .. } => {
                        diagnostics.record_upload_low_id_abuse_refusal();
                    }
                    ServeEvent::ReaskPingMalformed { .. } => {
                        diagnostics.record_malformed_reask_ping();
                    }
                    ServeEvent::NameAskMalformed { .. } => {
                        diagnostics.record_malformed_name_ask();
                    }
                    _ => {}
                }
                send_serve_event(evt_tx, event).await;
            }
            ServeDecision::RecordCredit { user_hash, bytes } => {
                let _ = credit.record_upload(user_hash, bytes);
            }
            ServeDecision::BindIdentity {
                peer,
                user_hash,
                public_key,
            } => {
                // Bind the proven key as the peer's Secured Identity (ADR-0041).
                // Mismatch = eMule IS_IDFAILED: deny, keep the stored key, report
                // the theft; unsecured accrual continues untouched. Mirrors the
                // download runner's Decision::BindIdentity enactment.
                let binding = credit.bind_public_key(user_hash, &public_key);
                if matches!(binding, Ok(KeyBinding::Mismatch)) {
                    let _ = evt_tx
                        .send(CoreEvent::SecuredIdentityMismatch { user_hash })
                        .await;
                }
                let bound = matches!(binding, Ok(KeyBinding::Adopted | KeyBinding::AlreadyBound));
                state.on_identity_bound(peer, user_hash, bound);
            }
            ServeDecision::Ban { peer } => {
                tracing::info!(
                    %peer,
                    "a second link named an identified client's user hash; its address is banned"
                );
                bans.lock().await.ban(peer.ip(), std::time::Instant::now());
            }
            ServeDecision::ReadRange {
                peer,
                path,
                offset,
                len,
                purpose,
                check: None,
            } => match ContentFileStore::read_range(&path, offset, len).await {
                Ok(bytes) => decisions.extend(state.on_read_result(peer, purpose, bytes)),
                Err(error) => {
                    tracing::warn!(%error, ?purpose, path = %path.display(), "serve read failed; the file is no longer offered");
                    let modifiers =
                        current_modifiers(credit, held_places, state.identities()).await;
                    decisions.extend(state.on_read_failed(
                        Instant::now(),
                        peer,
                        purpose,
                        &modifiers,
                    ));
                }
            },
            // A Served Download's bytes: read only through a handle proven to
            // be the file its range was read from (ADR-0113).
            ServeDecision::ReadRange {
                peer,
                path,
                offset,
                len,
                purpose,
                check: Some(check),
            } => match ContentFileStore::read_checked(&path, &check, offset, len).await {
                Ok(bytes) => decisions.extend(state.on_read_result(peer, purpose, bytes)),
                Err(refused) => {
                    let modifiers =
                        current_modifiers(credit, held_places, state.identities()).await;
                    decisions.extend(match refused {
                        CheckedReadError::Changed => {
                            tracing::warn!(?purpose, path = %path.display(), "a download's part file changed; its parts are no longer offered");
                            state.on_part_file_changed(Instant::now(), peer, purpose, &modifiers)
                        }
                        CheckedReadError::Unreadable(error) => {
                            tracing::warn!(%error, ?purpose, path = %path.display(), "a download's part file could not be read; its parts are no longer offered");
                            state.on_part_file_unreadable(Instant::now(), peer, purpose, &modifiers)
                        }
                    });
                }
            },
            ServeDecision::EmptyRange {
                file_hash,
                checked,
                cause,
            } => {
                served.empty_range(file_hash, checked, cause);
            }
            ServeDecision::ReadFailed(file_hash) => {
                if let Some(tx) = read_failed_tx {
                    let _ = tx.send(crate::registry_check::CheckInput::ReadFailed(file_hash));
                }
            }
            ServeDecision::CountUploadRequest { file_hash } => {
                diagnostics.count_upload_request(file_hash);
            }
            ServeDecision::Announce(files) => match serve_runtime.announce(files).await {
                Ok(outcome) => say_told(evt_tx, outcome).await,
                Err(error) => {
                    tracing::warn!(%error, "serve: announce failed; peers will not discover shared files");
                }
            },
            ServeDecision::SendClientUdp {
                to,
                datagram,
                crypt_target,
            } => match client_udp_tx {
                Some(tx) => {
                    // Plaintext plus the target's crypt facts: the socket
                    // boundary applies the ADR-0046 send gate (aMule encrypts in
                    // `SendControlData`, not where the reply was built).
                    let _ = tx
                        .send(ClientUdpSend::to_peer(to, datagram, crypt_target))
                        .await;
                }
                // No bound client-UDP socket (the advert then stays empty, so
                // no peer expects a UDP reply): trace the reply, do not send.
                None => {
                    tracing::trace!(
                        ?to,
                        "reask reply before the client-UDP front is live; dropped"
                    );
                }
            },
            // A run that is gone, or whose inbox is full, takes nothing:
            // the asker was answered all the same.
            ServeDecision::KeepAsker {
                file_hash,
                sighting,
            } => {
                served.sight(file_hash, sighting);
            }
            // The adapter dials on a task of its own and says how it ended on
            // the loop's dial-back inbox (ADR-0057).
            ServeDecision::DialBack(dial) => serve_runtime.dial_back(dial, dial_backs.clone()),
        }
    }
}

/// The offered share set, for a snapshot refresh: the registry's rows less
/// the withheld ones (ADR-0106). Errors degrade to an empty set (the
/// registry is the durable truth; the serve side just stops answering).
fn read_share_set(
    registry: &DurableSharedFileRegistry,
    withheld: &crate::registry_check::WithheldRows,
) -> Vec<SharedFileEntry> {
    withheld.offered(registry.list().unwrap_or_default())
}

/// Refresh the brain's copy of the **Served Downloads** when the cell moved
/// since the read at `seen` (ADR-0113 rule 5): a level, read before every
/// decision that answers for a download.
fn refresh_served(served: &ServedDownloads, seen: &mut u64, state: &mut ServeState) {
    if let Some(read) = served.read_since(*seen) {
        *seen = read.version;
        state.on_served(read.entries);
    }
}

/// Register one identified serve connection (accepted *or* dialed): record its
/// command sender keyed by endpoint and spawn a forwarder that drains its
/// events into the shared `fact_tx` and relays core's commands to it. The one
/// path both connection sources go through, so the queue treats a same-socket
/// (dialed) requester identically to an accepted one.
fn register_serve_connection(
    mut conn: ServeConnection,
    conns: &mut HashMap<PeerEndpoint, mpsc::Sender<ServeOutput>>,
    fact_tx: &mpsc::Sender<(PeerEndpoint, ServeInput)>,
) {
    let peer = conn.peer();
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ServeOutput>(16);
    conns.insert(peer, cmd_tx);
    let fact_tx = fact_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                command = cmd_rx.recv() => {
                    let Some(command) = command else { break };
                    if conn.send(command).await.is_err() { break; }
                }
                event = conn.next_event() => {
                    let Some(event) = event else {
                        let _ = fact_tx.send((peer, ServeInput::closed_here())).await;
                        break;
                    };
                    let disconnected = event.is_disconnect();
                    if fact_tx.send((peer, event)).await.is_err() || disconnected {
                        break;
                    }
                }
            }
        }
    });
}

/// Await the next dialed serve connection, or park forever when no dialed
/// source is wired (download-only / fake adapters), so the select arm never
/// busy-loops.
/// The next outcome the follower said of a later session; pending with none.
async fn recv_session_told(
    rx: &mut Option<mpsc::UnboundedReceiver<AnnounceOutcome>>,
) -> Option<AnnounceOutcome> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_dialed(rx: &mut Option<mpsc::Receiver<ServeConnection>>) -> Option<ServeConnection> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Await the next inbound reask datagram, or park forever when no client-UDP
/// front is wired (the socket never bound), so the select arm never
/// busy-loops — the [`recv_dialed`] shape.
async fn recv_reask(
    rx: &mut Option<mpsc::Receiver<ClientUdpDatagram>>,
) -> Option<ClientUdpDatagram> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Hand one command to `peer`'s connection task. `true` when it was accepted;
/// `false` when the peer has no live connection or its task already ended
/// (the command is dropped — its `Disconnected` will clean the peer up).
async fn send_conn(
    conns: &HashMap<PeerEndpoint, mpsc::Sender<ServeOutput>>,
    peer: PeerEndpoint,
    command: ServeOutput,
) -> bool {
    match conns.get(&peer) {
        Some(tx) => tx.send(command).await.is_ok(),
        None => false,
    }
}

/// Raise what an announce did with the share set; an unsaid one raises
/// nothing.
async fn say_told(evt_tx: &mpsc::Sender<CoreEvent>, outcome: AnnounceOutcome) {
    let event = match outcome {
        AnnounceOutcome::Announced { file_count } => ServeEvent::FilesAnnounced { file_count },
        AnnounceOutcome::Withheld { file_count, reason } => {
            ServeEvent::FilesWithheld { file_count, reason }
        }
        AnnounceOutcome::Unsaid => return,
    };
    send_serve_event(evt_tx, event).await;
}

async fn send_serve_event(evt_tx: &mpsc::Sender<CoreEvent>, event: ServeEvent) {
    let _ = evt_tx.send(CoreEvent::Serve(event)).await;
}

/// Read the current score modifier for every peer rmule has identified, so the
/// brain can rank its queue by `wait * modifier`: its credit (ADR-0041), times
/// the **Reciprocity Factor** when its link's address and its User Hash name
/// one of the node's **Held Places** (ADR-0116). One store read per peer; the
/// map covers a superset of the waiting set, which is all the queue needs.
async fn current_modifiers(
    credit: &SharedCreditStore,
    held_places: &SharedHeldPlaces,
    identities: &HashMap<PeerEndpoint, PeerIdentity>,
) -> HashMap<PeerEndpoint, f64> {
    let store = &**credit;
    identities
        .iter()
        .map(|(peer, identity)| {
            let credit = store.modifier(identity.user_hash()).unwrap_or(1.0);
            let place = if held_places.holds(identity.user_hash(), peer.ip()) {
                RECIPROCITY_FACTOR
            } else {
                1.0
            };
            (*peer, credit * place)
        })
        .collect()
}

#[cfg(test)]
mod tests;
