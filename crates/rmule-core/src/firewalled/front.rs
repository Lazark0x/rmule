//! The **firewalled-node front**: the one task that turns
//! [`crate::firewalled`]'s decisions into a dialed buddy link, and everything
//! that arrives on that link into an answer.
//!
//! It is the [`natt::front`](crate::natt::front) shape applied to the other
//! ADR-0061 half: one task owning the held link, so the dial, the keepalive
//! clock and the consumes are read and written on one thread of control and no
//! lock has to order them against each other.
//!
//! # What it owns, and what it refuses to own
//!
//! The **recruit trigger** is not here. It reads the live ADR-0058
//! `Reachability` store — both verdicts and the recheck clock — and that store
//! is task-local to the Kad pump by design (single writer, fed by the node's
//! event stream). So the pump runs the trigger, commands the FINDBUDDY walk,
//! verifies the `0x5A` into the shared slot, and tells this front to dial. A
//! front that re-derived any of it would be a second answer to "are we
//! firewalled".
//!
//! The **burst** is not here either. A [`Punch`](crate::natt::acting::ActingVerdict::Punch) verdict is enacted by
//! asking the NAT-T front to punch and expect — one emitter for every
//! `OP_HOLEPUNCH` this node sends, because the burst and the punched-path
//! ledger it opens belong together (ADR-0091).
//!
//! # The three inlets
//!
//! - **the held link** — `0x99` to the relayed-callback consume and its
//!   dial-back; `0x9A` split by its forwarded tail into an ordinary reask
//!   (answered through the ADR-0057 reply matrix, over the client-UDP socket)
//!   or a rendezvous for the acting path;
//! - **a standalone `0xC5 0xA0`** from the client-UDP front — the same acting
//!   path with the UDP carrier, gated on our buddy's exact UDP endpoint;
//! - **an inbound `0x95`** from the client-UDP front — the buddy-free
//!   direct-callback route, rate-limited per source IP and dialed back.
//!
//! Every dial-back — `0x99`'s and `0x95`'s alike — is opened as an undriven
//! stream and handed to the serve pipeline's admit seam as the dialer's side
//! (`SharedTunnelAdmit::spawn_callback_dial_back`, the one enactment a served
//! link's `0x99` shares), so the requester that asked us to connect meets the IP filter, the ban store
//! and `inbound_triage`'s callback adoption exactly as if it had dialed us.
//! A `0x95`'s stream may be obfuscated first: the requester's own
//! body names the hash the crypt handshake keys on, so that dial runs the
//! handshake before the pipeline adopts it and everything above the stream sees
//! plaintext bytes regardless. A `0x99` cannot — its relay body carries neither
//! hash nor connect-options, and a key nobody named cannot be invented.

use std::time::{Duration, Instant};

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::natt::RendezvousBody;
use rmule_peer::{ClientUdpOpcode, PeerCommand, PeerEvent};

use crate::CoreEvent;
use crate::server_session::HelloSource;
use crate::service::{BuddyDialFailure, DialFailure};
use rmule_net::peer::PeerNetError;
use rmule_primitives::{PacketProtocol, PeerEndpoint};
use tokio::sync::mpsc;

use super::direct_callback::{
    DirectCallbackConsume, DirectCallbackContext, DirectCallbackRefusal, DirectCallbackVerdict,
};
use super::link::{ReaskRelayConsume, RecruitedBuddy};
use super::relayed_callback::{CallbackConsume, CallbackDrop, CallbackVerdict};
use crate::adapters::{HelloAdverts, SharedTunnelAdmit};
use crate::address_learning::SharedAddressLearning;
use crate::client_udp::ClientUdpDatagram;
use crate::diagnostics::DiagnosticsState;
use crate::known_files::SharedFileKnown;
use crate::natt::front::NattCommand;
use crate::reachability::SharedSelfReach;

#[cfg(test)]
mod tests;

/// How often the front re-reads its own clock: the keepalive deadline and the
/// slot state the diagnostics snapshot copies. One second is finer than
/// either needs and costs nothing on an idle node — the `natt::front` tick's
/// reasoning. Kad stopping is not polled here: the front awaits Kad
/// Presence's own change signal.
const TICK: Duration = Duration::from_secs(1);

/// How long a buddy dial is given. The buddy is an *open* node by
/// construction, so a connect that does not come up quickly is a buddy that is
/// gone; the recruit trigger's own pacing decides when to look for another.
const BUDDY_DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// How many commands the front's inbox holds. One per relayed callback, per
/// standalone rendezvous and per `0x95` — datagram-rate in the worst case, so
/// deep enough that a momentary stall costs a callback rather than the link.
const COMMAND_QUEUE_LEN: usize = 64;

/// What the running node asks the **firewalled front** to do.
#[derive(Debug)]
pub(crate) enum FirewalledCommand {
    /// A Kad node started: this is where the hello rmule presents when it
    /// dials its buddy is read — the Kad enable's identity (ADR-0069: the
    /// front-end owns identity) under the live session's id and server, read
    /// at the dial. Callback dial-backs enter the serve pipeline and
    /// present the listener's hello, which reads the same live session. Whether Kad
    /// itself runs is read from [`FirewalledWiring::kad_presence`],
    /// never carried here — the pump's own lease is the one place
    /// that fact is decided.
    KadStarted(Box<HelloSource>),
    /// A `0x5A` verified and the shared slot now holds the buddy: dial its TCP
    /// endpoint and hold the link.
    BuddyAdopted,
    /// A standalone `0xC5 0xA0` `OP_RENDEZVOUS` reached the client-UDP front.
    StandaloneRendezvous {
        /// The datagram's source — the carrier gate's whole subject.
        from: PeerEndpoint,
        /// The decoded body.
        body: Box<RendezvousBody>,
    },
    /// An `OP_DIRECTCALLBACKREQ` (`0x95`) reached the client-UDP front.
    DirectCallback(DirectCallbackConsume),
}

/// The firewalled front's wiring: every seam it reaches that is not the slot.
pub(crate) struct FirewalledWiring {
    /// The one **Hello Adverts** read: its firewalled slot is the
    /// shared enacted slot (`super::link`) — the decisions, the buddy and the
    /// held link's command half; its obfuscation policy (`CoreConfig::
    /// peer_crypt`, ADR-0046) is what a `0x95` dial-back is allowed to do
    /// about the crypt stance the requester advertised, read
    /// here to decide whether a socket is opened at all; and the whole bundle
    /// is what the buddy dial's hello states.
    pub(crate) hello: HelloAdverts,
    /// **Self Reach** (ADR-0060): the `0x95` gate's Kad TCP
    /// verdict, read at the request, and the generation whose move to open
    /// releases the buddy — never a pushed copy. Its NAT-T family is where an
    /// [`ActingVerdict::Punch`] is enacted: the NAT-T front fires the burst
    /// and records the Responder expectation.
    ///
    /// [`ActingVerdict::Punch`]: crate::natt::acting::ActingVerdict::Punch
    pub(crate) reach: SharedSelfReach,
    /// Where a dial-back enters the serve pipeline (ADR-0061 routes 2/4).
    pub(crate) admit: SharedTunnelAdmit,
    /// The serve task's `0x90` inbox: a relayed reask re-enters the ordinary
    /// reply matrix through it, tagged with the requester the buddy injected —
    /// aMule's own `ProcessPacket(..., OP_REASKFILEPING, destip, destport)`.
    ///
    /// Weak: the client-UDP front's own sender closing is what winds the serve
    /// task's reask arm down, and a strong clone here would hold it open. An
    /// upgrade that fails is a node with no socket left, which owes nobody a
    /// reask answer.
    pub(crate) reask_ping: mpsc::WeakSender<ClientUdpDatagram>,
    /// The self-punch guard's interface set (ADR-0084).
    pub(crate) addresses: SharedAddressLearning,
    /// The file-known predicate: aMule's `GetFileByID` mirrored
    /// from the Shared File Registry and the download queue's one active
    /// hash, so a `0x99` naming a file we do not have dials nothing.
    pub(crate) file_known: SharedFileKnown,
    pub(crate) diagnostics: DiagnosticsState,
    /// **Kad Presence**: whether a Kad node runs, and as which
    /// Kad ID — the `0x99`/`0x95` gates' whole "is Kad running" input.
    /// Threaded in the same way the serve runtime's is:
    /// the Kad factory's own view, so the pump that factory spawns is the
    /// gate's only writer, and no second, task-local copy can drift from it.
    pub(crate) kad_presence: crate::adapters::KadPresenceView,
    /// Where a buddy dial that did not hold is reported (ADR-0075, Run Log).
    /// Weak, as every long-lived task's event sender is: this front must not
    /// keep the actor's event channel open.
    pub(crate) events: Option<mpsc::WeakSender<CoreEvent>>,
}

/// The front's command half as the running node holds it — late-bound like the
/// NAT-T front's, because the client-UDP socket binds after the cells that
/// reach it were woven.
///
/// Empty means no firewalled front: no client-UDP socket bound, so this node
/// has no UDP surface to be called back on and no socket its buddy's hint
/// could name.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedFirewalledFront(
    std::sync::Arc<std::sync::OnceLock<mpsc::Sender<FirewalledCommand>>>,
);

impl SharedFirewalledFront {
    /// Install the running front's command half. Idempotent: one front per
    /// core.
    pub(crate) fn install(&self, commands: mpsc::Sender<FirewalledCommand>) {
        let _ = self.0.set(commands);
    }

    /// Ask the front for something, reporting whether there was a front to
    /// ask. `try_send`, never `send`: every caller runs inside another loop —
    /// the client-UDP demux, the Kad pump — and a full inbox must cost one
    /// callback rather than stall the socket behind it.
    pub(crate) fn send(&self, command: FirewalledCommand) -> bool {
        self.0
            .get()
            .is_some_and(|commands| commands.try_send(command).is_ok())
    }
}

/// The front itself.
struct FirewalledFront {
    wiring: FirewalledWiring,
    /// The buddy link we dialed, while it is up. Owned here rather than behind
    /// the slot's lock because its events are `select!`ed on.
    link: Option<PeerConnection>,
    /// Where a buddy dial reads its hello; `None` until a Kad node starts.
    hello: Option<HelloSource>,
    /// Where a finished dial reports back.
    dialed_tx: mpsc::Sender<DialOutcome>,
}

/// What a spawned buddy dial produced.
enum DialOutcome {
    /// The link to `buddy` is up and it identified, with the `CT_MOD_IP_V6`
    /// its hello carried — the `bi6` a firewalled publish names.
    Held {
        conn: Box<PeerConnection>,
        claimed_ipv6: Option<std::net::Ipv6Addr>,
        /// The buddy this dial was for — the slot holds the link only while
        /// it still holds this buddy.
        buddy: RecruitedBuddy,
    },
    /// The dial failed, or the buddy never finished its hello.
    Failed {
        /// The buddy this dial was for — the slot is freed only while it
        /// still holds this buddy.
        buddy: RecruitedBuddy,
        /// Why.
        cause: BuddyDialFailure,
    },
}

/// Why a buddy dial's connect returned `error`.
fn buddy_dial_failure(error: &PeerNetError) -> BuddyDialFailure {
    use rmule_net::driver::DriverError;
    let dial = |cause| BuddyDialFailure::Dial { cause };
    match error {
        PeerNetError::Connect { source } | PeerNetError::Driver(DriverError::Io(source)) => {
            dial(DialFailure::Os {
                kind: source.kind(),
                os_code: source.raw_os_error(),
            })
        }
        PeerNetError::Driver(DriverError::ConnectTimeout) => dial(DialFailure::TimedOut),
        PeerNetError::HandshakeIncomplete(_) => BuddyDialFailure::HelloIncomplete,
        PeerNetError::CryptIncompatible => BuddyDialFailure::CryptIncompatible,
        // A dial surfaces none of the listener's errors; `PeerNetError` is
        // non-exhaustive, so what remains is a driver that ended.
        _ => dial(DialFailure::DriverEnded),
    }
}

/// Spawn the front and yield its command half.
pub(crate) fn spawn(wiring: FirewalledWiring) -> mpsc::Sender<FirewalledCommand> {
    spawn_ticking(wiring, TICK)
}

/// [`spawn`] with the front's clock period chosen by the caller. A test that
/// must see the front move only on the events it sends — the clock pings the
/// held link and rewrites the diagnostics' buddy state — names a period its
/// whole leg fits inside, rather than racing [`TICK`].
fn spawn_ticking(wiring: FirewalledWiring, tick: Duration) -> mpsc::Sender<FirewalledCommand> {
    let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_LEN);
    let (dialed_tx, dialed_rx) = mpsc::channel(1);
    let front = FirewalledFront {
        wiring,
        link: None,
        hello: None,
        dialed_tx,
    };
    tokio::spawn(front.run(command_rx, dialed_rx, tick));
    command_tx
}

impl FirewalledFront {
    /// Drive the front until the running node is gone.
    async fn run(
        mut self,
        mut commands: mpsc::Receiver<FirewalledCommand>,
        mut dialed: mpsc::Receiver<DialOutcome>,
        period: Duration,
    ) {
        // The first tick is one period out, not immediate: an immediate tick
        // lands at a random point among the first commands (`select!` picks
        // ready arms at random), so what it saw — Kad up or down, a buddy or
        // none — would depend on scheduling rather than on the commands sent.
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut kad_presence = self.wiring.kad_presence.changes();
        let mut reach = self.wiring.reach.changes();
        loop {
            tokio::select! {
                command = commands.recv() => {
                    // Every sender is gone: the core actor is gone, so a
                    // closed channel ends the task rather than spinning it.
                    let Some(command) = command else { return };
                    self.on_command(command, Instant::now()).await;
                }
                // The front holds its own `dialed_tx`, so this never closes.
                Some(outcome) = dialed.recv() => self.on_dialed(outcome, Instant::now()).await,
                // `Connection::next_event` is an `mpsc::Receiver::recv`, so it
                // is cancel-safe and free to be raced. `pending`
                // parks the arm while no link is held.
                event = next_link_event(self.link.as_mut()) => {
                    self.on_link_event(event, Instant::now()).await;
                }
                () = kad_presence.changed() => self.on_kad_presence().await,
                () = reach.changed() => self.on_reach().await,
                _ = tick.tick() => self.on_tick(Instant::now()).await,
            }
        }
    }

    /// One command from the running node.
    async fn on_command(&mut self, command: FirewalledCommand, now: Instant) {
        match command {
            FirewalledCommand::KadStarted(hello) => {
                self.hello = Some(*hello);
            }
            // Read at use: a buddy adopted while Self Reach
            // already reads Kad-open is let go rather than dialed — the
            // generation that announced the open verdict may have been
            // served before this command.
            FirewalledCommand::BuddyAdopted if self.wiring.reach.kad_tcp_open() => {
                self.release_buddy().await;
            }
            FirewalledCommand::BuddyAdopted => self.dial_buddy(),
            FirewalledCommand::StandaloneRendezvous { from, body } => {
                let verdict = {
                    let addresses = self.wiring.addresses.clone();
                    self.wiring
                        .hello
                        .firewalled_slot
                        .consume_standalone_rendezvous(
                            &body,
                            from,
                            crate::natt::front::RMULE_NATT_CLAIM.quic,
                            |ip| addresses.holds_interface(ip),
                            now,
                        )
                };
                self.enact_acting_verdict(verdict);
            }
            FirewalledCommand::DirectCallback(req) => self.on_direct_callback(&req, now),
        }
    }

    /// Dial the buddy the slot holds and, once it identifies, hold the link.
    /// aMule dials its buddy on the `0x5A` (`ClientList.cpp#L877`); the dial
    /// runs on its own task so a slow connect never stalls the consumes.
    fn dial_buddy(&mut self) {
        let (Some(buddy), Some(ctx)) = (
            self.wiring.hello.firewalled_slot.buddy(),
            self.hello.as_ref().map(HelloSource::now),
        ) else {
            return;
        };
        if self.link.is_some() {
            // One buddy, one link. A second `BuddyAdopted` while a link is
            // held would open a socket the slot could never hold.
            return;
        }
        if self.wiring.kad_presence.running_as().is_none() {
            // The buddy mechanism is Kad-scoped (ADR-0061): with no node
            // running, a relay could never reach us. Let the buddy go now
            // rather than dial a link the Kad Presence release (`select!`ed
            // beside this command) could only tear down.
            self.wiring.hello.firewalled_slot.release();
            return;
        }
        if !self.wiring.hello.firewalled_slot.begin_dial(buddy) {
            // A second `BuddyAdopted` (a re-adopt, a duplicate `0x5A`) while
            // the first dial to this buddy is in flight: that
            // dial will hold the link, and a second would only race it.
            self.wiring.diagnostics.record_buddy_dial_refused();
            tracing::debug!(?buddy.tcp, "buddy dial refused: one already in flight");
            return;
        }
        let peer = PeerEndpoint::V4(buddy.tcp);
        let dialed = self.dialed_tx.clone();
        // The one hello every outbound connection sends: our
        // ports, Kad version, IPv6, crypt policy and SUI, read now. Our crypt
        // meets the stance the buddy's `0x5A` stated, keyed on the hash it
        // carried (aMule `RequestBuddy` → `SetConnectOptions`, `ClientList.cpp:1141-1144`):
        // obfuscated when both support and one
        // asks, plaintext otherwise. A pair that cannot meet never reaches
        // here — the slot refused it unseated — and a `Required` node
        // recruits no buddy at all.
        let options = rmule_net::peer::ConnectOptions {
            connect_timeout: BUDDY_DIAL_TIMEOUT,
            // No buddy tags, stated rather than left to the read:
            // this hello is what makes the link, and aMule and emule-qt name a
            // buddy only once its handshake completes (`m_pBuddy` linked at
            // `KS_CONNECTED_BUDDY`, aMule `ClientList.cpp:807-816`, emule-qt
            // `ClientList.cpp:567-571`). One buddy, one link, so no other
            // buddy can be held while this one is dialed.
            serving_buddy: None,
            ..self.wiring.hello.connect_options(buddy.peer_crypt())
        };
        tokio::spawn(async move {
            let outcome = match PeerConnection::connect_identified(peer, ctx, options).await {
                Ok((conn, identity)) if identity.user_hash() == buddy.hash => DialOutcome::Held {
                    conn: Box::new(conn),
                    claimed_ipv6: identity.peer_ipv6(),
                    buddy,
                },
                Ok((conn, _)) => {
                    // The node that answered is not the one the `0x5A` named.
                    // aMule keys its buddy by hash, so a mismatched link could
                    // never carry a relay the `0x99` check would accept.
                    let _ = conn.shutdown().await;
                    tracing::debug!(?peer, "buddy dial reached a stranger; link dropped");
                    DialOutcome::Failed {
                        buddy,
                        cause: BuddyDialFailure::Stranger,
                    }
                }
                Err(error) => {
                    tracing::debug!(?peer, %error, "buddy dial refused (ADR-0061)");
                    DialOutcome::Failed {
                        buddy,
                        cause: buddy_dial_failure(&error),
                    }
                }
            };
            let _ = dialed.send(outcome).await;
        });
    }

    /// A buddy dial finished.
    async fn on_dialed(&mut self, outcome: DialOutcome, now: Instant) {
        match outcome {
            DialOutcome::Held {
                conn,
                claimed_ipv6,
                buddy,
            } => {
                let remote = conn.peer_endpoint();
                if !self.wiring.hello.firewalled_slot.hold_link(
                    buddy,
                    remote,
                    conn.command_sender(),
                    claimed_ipv6,
                    now,
                ) {
                    // Released or replaced while the dial was in flight, or a
                    // link to it is already held: a link the
                    // slot does not hold would only keep a socket open.
                    let _ = conn.shutdown().await;
                    tracing::debug!(
                        ?remote,
                        "buddy dial landed for a buddy let go or already linked"
                    );
                    return;
                }
                self.link = Some(*conn);
                self.wiring.diagnostics.record_buddy_link(true);
                tracing::info!(?remote, "buddy link held (ADR-0061 firewalled node)");
            }
            DialOutcome::Failed { buddy, cause } => {
                self.wiring.diagnostics.record_buddy_dial_failed();
                if let Some(events) = self
                    .wiring
                    .events
                    .as_ref()
                    .and_then(mpsc::WeakSender::upgrade)
                {
                    let failed = CoreEvent::BuddyDialFailed {
                        buddy: buddy.tcp,
                        cause,
                    };
                    let _ = events.send(failed).await;
                }
                // The buddy we dialed is one we cannot reach: free it and arm
                // an instant recruit, exactly as a lost link does — unless it
                // was let go (and perhaps replaced) while the dial was in
                // flight, when the slot is no longer this dial's to free.
                if !self.wiring.hello.firewalled_slot.on_dial_failed(buddy) {
                    tracing::debug!(?buddy.tcp, "buddy dial failed after its buddy was let go");
                }
            }
        }
    }

    /// One event from the held buddy link.
    async fn on_link_event(&mut self, event: Option<PeerEvent>, now: Instant) {
        let Some(event) = event else {
            return self.on_link_lost().await;
        };
        match event {
            PeerEvent::Disconnected { .. } => self.on_link_lost().await,
            PeerEvent::BuddyCallbackReceived { callback } => {
                self.on_relayed_callback(&callback);
            }
            PeerEvent::BuddyReaskCallbackReceived { relay } => {
                self.on_relayed_reask(relay, now).await;
            }
            // Everything else on this link is the ordinary session's — a
            // buddy that also downloads from us is served by nobody here, and
            // the session's own rules already answered or dropped it.
            _ => {}
        }
    }

    /// The held link ended, for any reason: free the slot (which arms an
    /// instant recruit) and let the pump's next trigger tick walk again.
    async fn on_link_lost(&mut self) {
        let Some(conn) = self.link.take() else { return };
        let remote = conn.peer_endpoint();
        let _ = conn.shutdown().await;
        if self.wiring.hello.firewalled_slot.on_link_closed(remote) {
            self.wiring.diagnostics.record_buddy_link(false);
            tracing::info!(?remote, "buddy link lost; recruitment re-armed");
        }
    }

    /// Release the buddy on purpose — we became reachable, or Kad stopped.
    async fn release_buddy(&mut self) {
        let had_link = self.wiring.hello.firewalled_slot.release().is_some();
        if let Some(conn) = self.link.take() {
            let _ = conn.shutdown().await;
        }
        if had_link {
            self.wiring.diagnostics.record_buddy_link(false);
            tracing::info!("buddy released: this node no longer needs a relay");
        }
    }

    /// An `OP_CALLBACK` (`0x99`) our buddy relayed.
    fn on_relayed_callback(&self, callback: &rmule_peer::Callback) {
        let verdict = self.wiring.hello.firewalled_slot.consume_callback(
            &CallbackConsume {
                check_id: rmule_kad::KadId::from_bytes(callback.buddy_id),
                // aMule's `GetFileByID` across shared files and the download
                // queue: the mirrored predicate, read inline —
                // never a round trip through the actor, which could stall the loop.
                file_shared_or_downloading: self.wiring.file_known.contains(callback.file_hash),
                requester: callback.requester,
            },
            self.wiring.kad_presence.running_as().is_some(),
        );
        match verdict {
            CallbackVerdict::Dial {
                requester,
                swapped_spelling,
            } => {
                self.wiring.diagnostics.record_relayed_callback(true);
                if swapped_spelling {
                    self.wiring
                        .diagnostics
                        .record_relayed_callback_swapped_spelling();
                }
                // Plaintext, and it is the wire that says so: the `0x99` body is
                // `<buddyID><fileHash><reqIP><reqTCP>` and names no user hash
                // and no connect-options, so there is no key to derive and no
                // stance to honour. aMule reaches the same place from the other
                // end — its `OP_CALLBACK` arm builds a `CUpDownClient` with no
                // hash, and `Connect`'s `HasValidHash()` leg then dials in the
                // clear (`ClientTCPSocket.cpp#L1655`).
                self.wiring
                    .admit
                    .spawn_callback_dial_back(PeerEndpoint::V4(requester), None);
            }
            CallbackVerdict::Drop { reason } => {
                self.wiring.diagnostics.record_relayed_callback(false);
                if reason == CallbackDrop::NoBuddyHeld {
                    // Our own state, not a counterparty error: counted apart
                    // so a bench run can tell "nobody addressed us wrong" from
                    // "we have no buddy to address".
                    self.wiring.diagnostics.record_relayed_callback_no_buddy();
                }
                tracing::debug!(?reason, "relayed 0x99 callback dropped (ADR-0061)");
            }
        }
    }

    /// An `OP_REASKCALLBACKTCP` (`0x9A`) our buddy relayed.
    async fn on_relayed_reask(&mut self, relay: rmule_peer::ReaskCallbackTcp, now: Instant) {
        let consume = {
            let addresses = self.wiring.addresses.clone();
            self.wiring.hello.firewalled_slot.consume_reask_relay(
                relay,
                crate::natt::front::RMULE_NATT_CLAIM.quic,
                |ip| addresses.holds_interface(ip),
                now,
            )
        };
        match consume {
            ReaskRelayConsume::Reask {
                requester,
                forwarded,
            } => {
                // aMule re-enters its own `OP_REASKFILEPING` consume with the
                // injected endpoint standing in for the datagram source
                // (`ClientTCPSocket.cpp#L1695`). The forwarded tail is that
                // datagram's *body*, so the two-byte peer-UDP header the reply
                // matrix strips is put back here — one shape reaches
                // `ServeState`, whether it arrived by socket or by relay.
                let mut datagram = Vec::with_capacity(2 + forwarded.len());
                datagram.push(PacketProtocol::Emule.as_byte());
                datagram.push(ClientUdpOpcode::ReaskFilePing.as_u8());
                datagram.extend_from_slice(&forwarded);
                let sent = match self.wiring.reask_ping.upgrade() {
                    Some(inbox) => inbox.send((requester, datagram)).await.is_ok(),
                    None => false,
                };
                if !sent {
                    tracing::debug!("relayed reask dropped: the serve inbox is gone");
                }
            }
            ReaskRelayConsume::Rendezvous(verdict) => self.enact_acting_verdict(verdict),
            ReaskRelayConsume::MalformedRendezvous => {
                self.wiring.diagnostics.record_acting_refusal(None);
                tracing::debug!("malformed embedded rendezvous on the buddy link; dropped");
            }
            ReaskRelayConsume::NoHeldLink => {}
        }
    }

    /// An `OP_DIRECTCALLBACKREQ` (`0x95`): the buddy-free route.
    fn on_direct_callback(&self, req: &DirectCallbackConsume, now: Instant) {
        let verdict = self.wiring.hello.firewalled_slot.consume_direct_callback(
            req,
            &DirectCallbackContext {
                tcp: self.wiring.reach.kad_tcp(),
                kad_running: self.wiring.kad_presence.running_as().is_some(),
                crypt: self.wiring.hello.crypt_policy,
            },
            now,
        );
        match verdict {
            DirectCallbackVerdict::DialBack {
                requester,
                obfuscate_toward,
            } => {
                self.wiring.diagnostics.record_direct_callback(true);
                if obfuscate_toward.is_some() {
                    self.wiring.diagnostics.record_direct_callback_obfuscated();
                }
                self.wiring
                    .admit
                    .spawn_callback_dial_back(requester, obfuscate_toward);
            }
            DirectCallbackVerdict::Refuse { reason } => {
                self.wiring.diagnostics.record_direct_callback(false);
                if reason == DirectCallbackRefusal::CryptIncompatible {
                    // Our own policy turned a requester away, not the network:
                    // counted apart so an operator can see the cost of the
                    // obfuscation setting they chose.
                    self.wiring
                        .diagnostics
                        .record_direct_callback_crypt_incompatible();
                }
                tracing::debug!(?reason, "0x95 direct callback refused (ADR-0061)");
            }
        }
    }

    /// Turn one [`ActingVerdict`] into a punch, or count the refusal.
    ///
    /// [`ActingVerdict`]: crate::natt::acting::ActingVerdict
    fn enact_acting_verdict(&self, verdict: crate::natt::acting::ActingVerdict) {
        use crate::natt::acting::ActingVerdict;
        match verdict {
            ActingVerdict::Punch {
                requester, target, ..
            } => {
                // The requester asked for this introduction, so **it** dials
                // and we accept (ADR-0091). The burst is the
                // front's to fire: it owns the send half the pinhole belongs
                // to and the path ledger the burst opens.
                let sent = self.wiring.reach.natt().send(NattCommand::Introduced {
                    peer_hash: requester,
                    target: target.endpoint,
                    role: rmule_ed2k::HolepunchRole::Responder,
                    burst: true,
                    source: target.source,
                });
                self.wiring.diagnostics.record_acting_punch(sent);
                if !sent {
                    tracing::debug!(
                        ?target,
                        "acting punch dropped: no NAT-T front to fire the burst"
                    );
                }
            }
            ActingVerdict::Refuse(refusal) => {
                self.wiring.diagnostics.record_acting_refusal(Some(refusal));
                tracing::debug!(?refusal, "relayed rendezvous not acted on (ADR-0091)");
            }
        }
    }

    /// Kad Presence changed. With the `KadStopped` command gone, this
    /// is where a stopped node's buddy is let go — at once
    /// Not on the next tick: the buddy mechanism is Kad-scoped
    /// (ADR-0061), so a relay could never reach us, and a `0x99` would be
    /// dropped `KadDown` anyway once Kad Presence reads no node.
    async fn on_kad_presence(&mut self) {
        if (self.link.is_some() || self.wiring.hello.firewalled_slot.buddy().is_some())
            && self.wiring.kad_presence.running_as().is_none()
        {
            self.release_buddy().await;
        }
    }

    /// Self Reach moved. An open Kad TCP verdict releases the
    /// buddy we hold — an open node needs none (ADR-0061's recruit gate read
    /// the other way round), and holding one would keep a stranger's socket
    /// busy for a relay nobody will use.
    async fn on_reach(&mut self) {
        if self.wiring.reach.kad_tcp_open() {
            self.release_buddy().await;
        }
    }

    /// The front's clock: the buddy-link keepalive, and the one place the
    /// slot's state is copied into the diagnostics snapshot — the slot is its
    /// own single writer, so reading it here is the only way the snapshot
    /// cannot drift from it.
    async fn on_tick(&mut self, now: Instant) {
        let (state, held_since) = self.wiring.hello.firewalled_slot.state();
        self.wiring.diagnostics.set_buddy_state(
            state,
            held_since,
            self.wiring.hello.firewalled_slot.recruit_refusal(),
        );
        let Some(commands) = self.wiring.hello.firewalled_slot.due_keepalive(now) else {
            return;
        };
        // `try_send`, so a driver whose inbox is momentarily full costs one
        // ping rather than the tick; the next one is one interval away.
        if commands.try_send(PeerCommand::SendBuddyPing).is_err() {
            tracing::debug!("buddy keepalive not queued; the link driver is busy or gone");
        }
    }
}

/// Await the held link's next event, or park forever while no link is held.
async fn next_link_event(link: Option<&mut PeerConnection>) -> Option<PeerEvent> {
    match link {
        Some(conn) => conn.next_event().await,
        None => std::future::pending().await,
    }
}

/// Route one standalone `0xC5 0xA0` `OP_RENDEZVOUS` to the front, reporting
/// whether it took it. Family-generic: the acting path's carrier gate compares
/// the whole source endpoint against our buddy's, and an IPv6 source simply
/// never matches an IPv4 buddy — a refusal the gate already states, not a
/// dialect gap this front should invent a second answer for.
pub(crate) fn route_standalone_rendezvous(
    front: &SharedFirewalledFront,
    udp_src: PeerEndpoint,
    datagram: &[u8],
) -> bool {
    match RendezvousBody::decode_standalone(datagram) {
        Ok(body) => front.send(FirewalledCommand::StandaloneRendezvous {
            from: udp_src,
            body: Box::new(body),
        }),
        Err(error) => {
            tracing::debug!(%udp_src, %error, "malformed standalone 0xA0 rendezvous dropped");
            false
        }
    }
}

/// Route one `OP_DIRECTCALLBACKREQ` (`0x95`) to the front. `udp_src` is the
/// datagram's source — the body names no address, so the source *is* the
/// requester and the body only supplies the TCP port to dial. Family-generic
/// for exactly that reason: an IPv6 requester is dialed back where it stands.
pub(crate) fn route_direct_callback(
    front: &SharedFirewalledFront,
    udp_src: PeerEndpoint,
    datagram: &[u8],
) -> bool {
    match rmule_peer::DirectCallbackReq::decode_udp(datagram) {
        Ok(req) => front.send(FirewalledCommand::DirectCallback(DirectCallbackConsume {
            requester: udp_src.with_port(req.our_tcp_port),
            user_hash: req.our_user_hash,
            connect_options: req.connect_options,
        })),
        Err(error) => {
            tracing::trace!(%udp_src, %error, "malformed 0x95 direct callback dropped");
            false
        }
    }
}
