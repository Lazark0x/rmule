//! The serve activity's enactor: the [`ServeTask`] select loop that feeds
//! connection events, share-set snapshots, and rerank ticks into the sans-I/O
//! [`ServeState`] and carries out the returned decisions — sends into each
//! link's **Link Outbox**, event emission, the credit ledger's memory, block
//! reads on their own tasks, and `OP_OFFERFILES` announces. No policy branches
//! live here (cf. the download [`runner`](crate::download)).
//!
//! The loop never waits on a peer, a disk or the store (ADR-0031): it parks in
//! its `select!`, and a decision is a memory step, a `try_send`, or the start
//! of a task whose end is one more input.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rmule_peer::PeerIdentity;
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, mpsc, watch};

use crate::adapters::{
    AnnounceOutcome, DialBackOutcome, LinkServeHalf, ServeConnection, ServeInput, ServeOutput,
    ServeRuntimeService,
};
use crate::client_udp::{ClientUdpDatagram, ClientUdpSend};
use crate::content::on_pool;
use crate::credit::SharedCreditStore;
use crate::held_places::{RECIPROCITY_FACTOR, SharedHeldPlaces};
use crate::peer_roster::{PeerRelation, RelationLease};
use crate::registry::{SharedFileEntry, SharedFileRegistry};
use crate::serve::aich_builder::{AichBuilder, AichLanded};
use crate::serve::block_reader::{BlockReader, FlowRead, ReadEnd, ReadLanded};
use crate::serve::link_output::LinkOutput;
use crate::serve::state::{ServeDecision, ServeSelfPosition, ServeState};
use crate::served_downloads::ServedDownloads;
use crate::service::{CoreEvent, ServeEvent, ServeStopReason};
use crate::store::registry::DurableSharedFileRegistry;
use crate::upload_queue::UploadSlotQueue;

/// How many outputs a **Link Outbox** holds. The Send-Ahead keeps blocks to ten
/// of them, so a full one is a peer asking faster than it reads (ADR-0031).
const LINK_OUTBOX_LEN: usize = 64;

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
    pub(crate) dialed_serve_rx: Option<mpsc::Receiver<LinkServeHalf>>,
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
        // Every link, keyed by requester endpoint.
        let mut links: HashMap<PeerEndpoint, Link> = HashMap::new();
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

        // Where an AICH build says it ended (ADR-0038). The builder holds a
        // sender, so the receiver never closes under the loop.
        let (aich_landed_tx, mut aich_landed_rx) = mpsc::channel::<AichLanded>(1);
        let mut aich = AichBuilder::new(aich_landed_tx);

        // Where each block read says it ended. The reader holds a sender, so
        // the receiver never closes under the loop.
        let (read_landed_tx, mut read_landed_rx) = mpsc::channel::<ReadLanded>(16);
        let reader = BlockReader::new(read_landed_tx);

        // Where a read of the share set lands, one out at a time; a trigger
        // meanwhile asks for one more after it.
        let (share_read_tx, mut share_read_rx) = mpsc::channel::<Vec<SharedFileEntry>>(1);
        let mut share_read_out = false;
        let mut share_read_owed = false;
        // No set has been read yet. While the first read is out a peer's input
        // waits for it, so the first ask is answered from it (ADR-0031).
        let mut share_set_known = withheld.is_looked();

        // The write-through handles every enactment shares, bound once.
        let sinks = ServeSinks {
            credit: &credit,
            bans: &bans,
            evt_tx: &evt_tx,
            client_udp_tx: &client_udp_tx,
            diagnostics: &diagnostics,
            peer_roster: &peer_roster,
            read_failed_tx: read_failed_tx.as_ref(),
            served: &served,
            dial_backs: &dial_back_tx,
            reader: &reader,
        };

        // Announce the share set as of serve start — once the Registry
        // Check's start look has said what it is. Before that the look's own
        // end fires the share trigger, which announces.
        if withheld.is_looked() {
            // A trigger sent before this read signals a change the read
            // already holds: announcing again for it would say nothing new.
            while share_changed_rx.try_recv().is_ok() {}
            // Awaited, off the runtime: no peer is served yet, and the first
            // ask is answered from this set.
            let rows = read_share_set(registry.clone(), withheld.clone()).await;
            refresh_served(&served, &mut served_seen, &mut state);
            let mut decisions: VecDeque<ServeDecision> = state
                .on_share_set(rows, Instant::now(), &HashMap::new())
                .into();
            enact(
                &mut decisions,
                &mut state,
                &links,
                &mut serve_runtime,
                &mut aich,
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
                    if share_read_out {
                        share_read_owed = true;
                    } else {
                        share_read_out = true;
                        start_share_read(&registry, &withheld, &share_read_tx);
                    }
                }
                rows = share_read_rx.recv() => {
                    let Some(rows) = rows else { continue };
                    share_set_known = true;
                    share_read_out = share_read_owed;
                    if std::mem::take(&mut share_read_owed) {
                        start_share_read(&registry, &withheld, &share_read_tx);
                    }
                    let modifiers = current_modifiers(&credit, &held_places, state.identities());
                    refresh_served(&served, &mut served_seen, &mut state);
                    let mut decisions: VecDeque<ServeDecision> =
                        state.on_share_set(rows, Instant::now(), &modifiers).into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &links,
                        &mut serve_runtime,
                        &mut aich,
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
                            register_serve_connection(conn, &mut links, &fact_tx);
                        }
                        None => {
                            reason = ServeStopReason::ListenerClosed;
                            break;
                        }
                    }
                }
                outcome = dial_back_rx.recv() => {
                    let Some(outcome) = outcome else { continue };
                    let modifiers = current_modifiers(&credit, &held_places, state.identities());
                    state.on_self_position(self_position(own_identity.as_ref()));
                    refresh_served(&served, &mut served_seen, &mut state);
                    let now = Instant::now();
                    let mut decisions: VecDeque<ServeDecision> = match outcome {
                        // The link is registered before its hello is folded,
                        // so the grant the fold decides finds it.
                        DialBackOutcome::Linked { waiter, conn, identity, far_end } => {
                            let link = conn.peer();
                            register_serve_connection(conn, &mut links, &fact_tx);
                            state.on_dial_back_linked(now, waiter, link, *identity, far_end, &modifiers)
                        }
                        DialBackOutcome::Failed { waiter, cause } => {
                            state.on_dial_back_failed(now, waiter, cause, &modifiers)
                        }
                    }
                    .into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &links,
                        &mut serve_runtime,
                        &mut aich,
                        sinks,
                    )
                    .await;
                }
                landed = read_landed_rx.recv() => {
                    let Some(ReadLanded { peer, flow, block, end }) = landed else { continue };
                    let modifiers = current_modifiers(&credit, &held_places, state.identities());
                    refresh_served(&served, &mut served_seen, &mut state);
                    let now = Instant::now();
                    let file = block.file_hash;
                    let mut decisions: VecDeque<ServeDecision> = match end {
                        ReadEnd::Bytes(bytes) => state.on_read_result(peer, flow, block, bytes),
                        ReadEnd::Failed => state.on_read_failed(now, peer, flow, file, &modifiers),
                        ReadEnd::Changed { checked } => {
                            state.on_part_file_changed(now, peer, flow, (file, checked), &modifiers)
                        }
                        ReadEnd::Unreadable { checked } => {
                            state.on_part_file_unreadable(now, peer, flow, (file, checked), &modifiers)
                        }
                    }
                    .into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &links,
                        &mut serve_runtime,
                        &mut aich,
                        sinks,
                    )
                    .await;
                }
                landed = aich_landed_rx.recv() => {
                    let Some(AichLanded { file_hash, built }) = landed else { continue };
                    let modifiers = current_modifiers(&credit, &held_places, state.identities());
                    let mut decisions: VecDeque<ServeDecision> = state
                        .on_aich_landed(Instant::now(), file_hash, built, &modifiers)
                        .into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &links,
                        &mut serve_runtime,
                        &mut aich,
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
                        // A connection a download holds also serves the
                        // peer: admit it to the same queue as an accepted
                        // one. An adopted callback comes this way too, a
                        // link the peer opened, so only a link rmule dialed
                        // is marked so.
                        Some(LinkServeHalf { conn, dialed }) => {
                            if let Some(far_end) = dialed {
                                state.on_link_dialed(conn.peer(), far_end);
                            }
                            register_serve_connection(conn, &mut links, &fact_tx);
                        }
                        // The dialed source closed (core shutdown); stop polling
                        // it but keep serving accepted connections.
                        None => dialed_serve_rx = None,
                    }
                }
                fact = fact_rx.recv(), if share_set_known || !share_read_out => {
                    let Some((peer, event)) = fact else { continue };
                    let closing = event.is_disconnect() || event == ServeInput::Readopted;
                    let modifiers = current_modifiers(&credit, &held_places, state.identities());
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
                        &links,
                        &mut serve_runtime,
                        &mut aich,
                        sinks,
                    )
                    .await;
                    if closing {
                        links.remove(&peer);
                    }
                }
                _ = rerank_tick.tick() => {
                    let modifiers = current_modifiers(&credit, &held_places, state.identities());
                    let now = Instant::now();
                    let mut decisions: VecDeque<ServeDecision> =
                        state.on_rerank_tick(now, &modifiers).into();
                    decisions.extend(state.on_slot_sweep(now, &modifiers));
                    enact(
                        &mut decisions,
                        &mut state,
                        &links,
                        &mut serve_runtime,
                        &mut aich,
                        sinks,
                    )
                    .await;
                }
                _ = purge_tick.tick() => {
                    // Reap waiters silent past the reask deadline or whose file
                    // stopped being shared (ADR-0057 disconnected standing).
                    let modifiers = current_modifiers(&credit, &held_places, state.identities());
                    let mut decisions: VecDeque<ServeDecision> = state
                        .on_purge(Instant::now(), purge_after, &modifiers)
                        .into();
                    enact(
                        &mut decisions,
                        &mut state,
                        &links,
                        &mut serve_runtime,
                        &mut aich,
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
                            &links,
                            &mut serve_runtime,
                            &mut aich,
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
    /// Where block reads start.
    reader: &'a BlockReader,
}

/// The serve loop's handle on one link's task.
struct Link {
    /// The **Link Outbox**: filled without waiting.
    outbox: mpsc::Sender<LinkOutput>,
    /// The latest flow of this link that has ended, read by its reads and
    /// its task, so what is under way for it stops at the next look.
    ended_through: Arc<AtomicU64>,
    /// Ends the link now, whatever its outbox holds.
    stop: Arc<Notify>,
}

impl Link {
    /// Hand this link `output` without waiting. A full outbox ends the link:
    /// its peer is asking faster than it reads. A closed one has its end on
    /// the way already.
    fn offer(&self, peer: PeerEndpoint, output: LinkOutput) {
        if let Err(TrySendError::Full(_)) = self.outbox.try_send(output) {
            tracing::debug!(%peer, "a link's outbox filled; the peer is not reading, so its link ends");
            self.stop.notify_one();
        }
    }
}

/// Carry out one `Vec<ServeDecision>` against the live runtime, in order,
/// ending the flows whose slots the input ended. A `ReadRange` and a `BuildAichTree` are
/// not waited for: each runs on and comes back as an input of its own
/// (ADR-0031, ADR-0038). The one wait here is the event stream to core.
///
/// The sinks' `diagnostics` learns a peer's slot lifetime from the emitted
/// grant/release facts here, and its `bytes_sent` as each block's session says
/// it left (ADR-0077).
async fn enact<L: ServeRuntimeService>(
    decisions: &mut VecDeque<ServeDecision>,
    state: &mut ServeState,
    links: &HashMap<PeerEndpoint, Link>,
    serve_runtime: &mut L,
    aich: &mut AichBuilder,
    sinks: ServeSinks<'_>,
) {
    let ServeSinks {
        credit,
        bans,
        evt_tx,
        client_udp_tx,
        diagnostics,
        peer_roster,
        read_failed_tx,
        served,
        dial_backs,
        reader,
    } = sinks;
    decisions.extend(state.end_slotless_flows());
    let output_to = |peer, output: LinkOutput| {
        if let Some(link) = links.get(&peer) {
            link.offer(peer, output);
        }
    };
    while let Some(decision) = decisions.pop_front() {
        match decision {
            ServeDecision::Send { peer, command } => {
                output_to(peer, ServeOutput::Server(command).into());
            }
            ServeDecision::SendBlock {
                peer,
                flow,
                block,
                bytes,
                deflate,
            } => output_to(
                peer,
                LinkOutput::Block {
                    flow,
                    block,
                    bytes,
                    deflate,
                },
            ),
            ServeDecision::EndFlow { peer, flow } => {
                if let Some(link) = links.get(&peer) {
                    link.ended_through.fetch_max(flow, Ordering::Relaxed);
                }
            }
            ServeDecision::CountSent {
                peer,
                file_hash,
                bytes,
            } => diagnostics.add_sent_bytes(peer, file_hash, bytes),
            ServeDecision::Disconnect { peer } => {
                output_to(peer, ServeOutput::Disconnect.into());
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
                        // A slot's upload row rides on with it.
                        diagnostics.move_upload(from, to);
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
            ServeDecision::Ban { peer } => {
                tracing::info!(
                    %peer,
                    "a second link named an identified client's user hash; its address is banned"
                );
                bans.lock().await.ban(peer.ip(), std::time::Instant::now());
            }
            ServeDecision::ReadRange {
                peer,
                flow,
                path,
                block,
                check,
            } => {
                if let Some(link) = links.get(&peer) {
                    let read = FlowRead {
                        peer,
                        flow,
                        path,
                        block,
                        check,
                    };
                    reader.start(read, Arc::clone(&link.ended_through));
                }
            }
            ServeDecision::BuildAichTree {
                file_hash,
                path,
                file_size,
            } => aich.start(file_hash, path, file_size),
            ServeDecision::StopAichBuild => aich.stop(),
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
                    // `SendControlData`, not where the reply was built). A
                    // datagram no room takes is lost as any datagram may be.
                    let _ = tx.try_send(ClientUdpSend::to_peer(to, datagram, crypt_target));
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
/// the withheld ones (ADR-0106), read off the runtime. Errors degrade to an
/// empty set (the registry is the durable truth; the serve side just stops
/// answering).
async fn read_share_set(
    registry: Arc<DurableSharedFileRegistry>,
    withheld: crate::registry_check::WithheldRows,
) -> Vec<SharedFileEntry> {
    on_pool(move || withheld.offered(registry.list().unwrap_or_default())).await
}

/// Read the share set away from the serve loop; it lands on `landed_tx`.
fn start_share_read(
    registry: &Arc<DurableSharedFileRegistry>,
    withheld: &crate::registry_check::WithheldRows,
    landed_tx: &mpsc::Sender<Vec<SharedFileEntry>>,
) {
    let read = read_share_set(Arc::clone(registry), withheld.clone());
    let landed_tx = landed_tx.clone();
    tokio::spawn(async move {
        // The loop that would read this is gone: nothing is owed to it.
        let _ = landed_tx.send(read.await).await;
    });
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

/// Register one identified serve connection (accepted *or* dialed): keep its
/// [`Link`] keyed by endpoint and spawn the task that relays its outbox to it
/// and its events to the shared `fact_tx`. The one path both connection sources
/// go through, so the queue treats a same-socket (dialed) requester identically
/// to an accepted one.
///
/// The task parks on neither side alone. An output waits for room on the
/// connection while what the peer says still reaches the loop: the router
/// behind the connection may be holding that very room until it has handed its
/// event on (ADR-0031).
fn register_serve_connection(
    conn: ServeConnection,
    links: &mut HashMap<PeerEndpoint, Link>,
    fact_tx: &mpsc::Sender<(PeerEndpoint, ServeInput)>,
) {
    let peer = conn.peer();
    let (outbox, mut outbox_rx) = mpsc::channel::<LinkOutput>(LINK_OUTBOX_LEN);
    let ended_through = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(Notify::new());
    let link = Link {
        outbox,
        ended_through: Arc::clone(&ended_through),
        stop: Arc::clone(&stop),
    };
    links.insert(peer, link);
    let fact_tx = fact_tx.clone();
    let (command_tx, mut event_rx) = conn.into_halves();
    tokio::spawn(async move {
        // The output waiting for room on the connection.
        let mut waiting: Option<ServeOutput> = None;
        loop {
            tokio::select! {
                () = stop.notified() => {
                    let _ = fact_tx.send((peer, ServeInput::closed_here())).await;
                    break;
                }
                permit = command_tx.reserve(), if waiting.is_some() => {
                    // A connection gone under an output says so on its event
                    // stream, read below, which is what frees the peer's slot.
                    if let (Ok(permit), Some(output)) = (permit, waiting.take()) {
                        permit.send(output);
                    }
                }
                output = outbox_rx.recv(), if waiting.is_none() => {
                    let Some(output) = output else { break };
                    // Awaited here, the link's own task: a block costs only
                    // this link's next output (ADR-0031).
                    waiting = output.ready(&ended_through).await;
                }
                event = event_rx.recv() => {
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

/// The next outcome the follower said of a later session; pending with none.
async fn recv_session_told(
    rx: &mut Option<mpsc::UnboundedReceiver<AnnounceOutcome>>,
) -> Option<AnnounceOutcome> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Await the next dialed serve connection, or park forever when no dialed
/// source is wired (download-only / fake adapters), so the select arm never
/// busy-loops.
async fn recv_dialed(rx: &mut Option<mpsc::Receiver<LinkServeHalf>>) -> Option<LinkServeHalf> {
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
/// one of the node's **Held Places** (ADR-0116). Both are memory reads
/// (ADR-0031); the map covers a superset of the waiting set, which is all the
/// queue needs.
fn current_modifiers(
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
