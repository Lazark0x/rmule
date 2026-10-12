//! The **firewalled-node front**: the one task that turns
//! [`crate::firewalled`]'s decisions into a dialed buddy link, and everything
//! that arrives on that link into an answer.
//!
//! It is the [`natt::front`](crate::natt::front) shape applied to the other
//! ADR-0061 half: one task owning the buddy slot and the held link, so the
//! adopt, the dial, the keepalive clock and the consumes are read and written
//! on one thread of control and no lock has to order them against each other.
//!
//! # What it owns, and what it refuses to own
//!
//! The **slot** is here, and nowhere else (ADR-0061): a plain
//! [`FirewalledSlot`] on this task. A verified `0x5A` reaches it as an
//! [`AdoptBuddy`](FirewalledCommand::AdoptBuddy) command from the Kad pump,
//! answered with an [`AdoptVerdict`]; every other reader — the hello's buddy
//! tags, the Kad publish row, the Run Log trail, the recruit rule — reads the
//! [`BuddySnapshot`] the slot publishes through [`SharedFirewalledFront`].
//! The buddy dial goes through the [`dialer`] seam.
//!
//! The **recruit trigger** is not here. It is the Kad pump's rule over that
//! snapshot, Self Reach's verdicts and the recheck clock the pump's own brain
//! holds; the pump starts the FINDBUDDY walk and hears it end. A front that
//! re-derived any of it would be a second answer to "should we walk".
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
//! Every dial-back — `0x99`'s and `0x95`'s alike — goes through the same
//! [`dialer`] seam as the buddy dial. The real adapter opens it as an undriven
//! stream and hands it to the serve pipeline's admit seam as the dialer's side
//! (`SharedTunnelAdmit::spawn_callback_dial_back`, the one enactment a served
//! link's `0x99` shares), so the requester that asked us to connect meets the
//! IP filter, the ban store and `inbound_triage`'s callback adoption exactly
//! as if it had dialed us.
//! A `0x95`'s stream may be obfuscated first: the requester's own
//! body names the hash the crypt handshake keys on, so that dial runs the
//! handshake before the pipeline adopts it and everything above the stream sees
//! plaintext bytes regardless. A `0x99` cannot — its relay body carries neither
//! hash nor connect-options, and a key nobody named cannot be invented.
//!
//! # Where each half lives
//!
//! This file is the task: its wiring, its commands and the loop that selects
//! over them. The buddy's own lifecycle — adopt, dial, hold, keepalive and
//! every release — is [`held_buddy`]; what arrives and is answered is
//! [`inlets`]. An inlet never changes which buddy is held: it reads the slot
//! only through its consumes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_kad::KadId;
use rmule_peer::PeerEvent;
use rmule_peer::natt::RendezvousBody;
use rmule_primitives::PeerEndpoint;
use tokio::sync::{mpsc, watch};

use super::direct_callback::DirectCallbackConsume;
use super::link::{BuddySnapshot, FirewalledSlot, RecruitedBuddy};
use super::recruit::{AdoptOutcome, FindBuddyRes};
use crate::CoreEvent;
use crate::adapters::{HelloAdverts, SharedTunnelAdmit};
use crate::address_learning::SharedAddressLearning;
use crate::client_udp::ClientUdpDatagram;
use crate::diagnostics::DiagnosticsState;
use crate::known_files::SharedFileKnown;
use crate::reachability::SharedSelfReach;
use crate::server_session::HelloSource;
use crate::service::BuddyDialFailure;

pub(crate) mod dialer;
mod held_buddy;
mod inlets;
mod published;
#[cfg(test)]
mod tests;

use dialer::{BuddyLink, Dialer, TcpDialer};

pub(crate) use inlets::{route_direct_callback, route_standalone_rendezvous};
pub(crate) use published::{BuddyView, SharedFirewalledFront};

/// How often the front re-reads its own clock: the keepalive deadline and the
/// slot state the diagnostics snapshot copies. One second is finer than
/// either needs and costs nothing on an idle node — the `natt::front` tick's
/// reasoning. Kad stopping is not polled here: the front awaits Kad
/// Presence's own change signal.
const TICK: Duration = Duration::from_secs(1);

/// How long a buddy dial is given. The buddy is an *open* node by
/// construction, so a connect that does not come up quickly is a buddy that is
/// gone; the recruit rule's own pacing decides when to look for another.
const BUDDY_DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// How many commands the front's inbox holds. One per relayed callback, per
/// standalone rendezvous and per `0x95` — datagram-rate in the worst case, so
/// deep enough that a momentary stall costs a callback rather than the link.
const COMMAND_QUEUE_LEN: usize = 64;

/// One Kad node's start, as the front re-seats its slot on it.
///
/// Not a command: it rides [`SharedFirewalledFront::kad_started`], a
/// latest-wins cell beside the inbox, so a burst of datagram-rate commands
/// that fills the inbox can never lose it, and two starts the front had no
/// chance to see between them collapse into the one the slot must be seated
/// on. The front applies an unseen start before every command it takes, so
/// an `AdoptBuddy` the new node's pump sends is verified against that node.
#[derive(Clone, Debug)]
pub(crate) struct KadStart {
    /// Where the hello rmule presents when it dials its buddy is read — the
    /// node's identity under the live session's id and server, read at the
    /// dial. Callback dial-backs enter the serve pipeline and present the
    /// listener's hello, which reads the same live session.
    pub(crate) hello: HelloSource,
    /// The node's Kad ID, which the slot is re-seated against: every `0x5A`
    /// and `0x99` check inverts the echoed ID against it. Whether Kad itself
    /// runs is read from [`FirewalledWiring::kad_presence`], never carried
    /// here — the pump's own lease is the one place that fact is decided.
    pub(crate) kad_id: KadId,
}

/// What the running node asks the **firewalled front** to do.
#[derive(Debug)]
pub(crate) enum FirewalledCommand {
    /// The Kad pump's walk was answered: a `0x5A` the node already checked
    /// against its tracked recruits. Verify it against the slot, seat it,
    /// and dial; answer the pump on `verdict` either way.
    AdoptBuddy {
        /// The answer, as the slot's XOR check reads it.
        answer: FindBuddyRes,
        /// The buddy it names.
        buddy: RecruitedBuddy,
        /// The asking pump's verdict inbox — weak, so a stopped node's is
        /// closed and its successor's is another.
        verdict: mpsc::WeakSender<AdoptVerdict>,
    },
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

/// The front's verdict on an [`AdoptBuddy`](FirewalledCommand::AdoptBuddy),
/// the Kad pump's input: the buddy it was asked to seat, what the slot did
/// with it, and the snapshot the slot published after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdoptVerdict {
    pub(crate) buddy: RecruitedBuddy,
    pub(crate) outcome: AdoptOutcome,
    pub(crate) snapshot: BuddySnapshot,
}

/// The firewalled front's wiring: every seam it reaches that is not the slot.
pub(crate) struct FirewalledWiring {
    /// The one **Hello Adverts** read: its obfuscation policy
    /// (`CoreConfig::peer_crypt`, ADR-0046) is our side of the buddy's crypt
    /// rule at the adopt, and what a `0x95` dial-back is allowed to do about
    /// the crypt stance the requester advertised, read here to decide whether
    /// a socket is opened at all; and the whole bundle is what the buddy
    /// dial's hello states.
    pub(crate) hello: HelloAdverts,
    /// **Self Reach** (ADR-0060): the `0x95` gate's Kad TCP
    /// verdict, read at the request, and the generation whose move to open
    /// releases the buddy — never a pushed copy.
    pub(crate) reach: SharedSelfReach,
    /// The **NAT-T Front**'s command half: where an
    /// [`ActingVerdict::Punch`] is enacted — the front fires the burst and
    /// records the Responder expectation.
    ///
    /// [`ActingVerdict::Punch`]: crate::natt::acting::ActingVerdict::Punch
    pub(crate) natt: crate::natt::front::SharedNattFront,
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

/// The front itself.
struct FirewalledFront<D: Dialer> {
    wiring: FirewalledWiring,
    /// The front's own shared face: where the Kad pump's Recruit Status is
    /// read for the diagnostics.
    shared: SharedFirewalledFront,
    /// The buddy slot, this task's alone.
    slot: FirewalledSlot,
    /// How a buddy link comes up.
    dialer: Arc<D>,
    /// The buddy link we dialed, while it is up. Owned beside the slot rather
    /// than in it because its events are `select!`ed on.
    link: Option<D::Link>,
    /// Where a buddy dial reads its hello; `None` until a Kad node starts.
    hello: Option<HelloSource>,
    /// The Kad Start cell's reader: a start not yet applied reads changed.
    kad_start: watch::Receiver<Option<KadStart>>,
    /// Where a finished dial reports back.
    dialed_tx: mpsc::Sender<DialOutcome<D::Link>>,
}

/// What a spawned buddy dial produced.
enum DialOutcome<L> {
    /// The link to `buddy` is up and it identified, with the `CT_MOD_IP_V6`
    /// its hello carried — the `bi6` a firewalled publish names.
    Held {
        link: L,
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

/// Spawn the front over the real dialer — its dial-backs entering the serve
/// pipeline through `admit` — and install its command half in `shared`.
pub(crate) fn spawn(
    shared: &SharedFirewalledFront,
    wiring: FirewalledWiring,
    admit: SharedTunnelAdmit,
) {
    shared.install(spawn_with(shared, wiring, TcpDialer { admit }, TICK));
}

/// [`spawn`] over `dialer`, with the front's clock period chosen by the
/// caller, yielding the command half.
///
/// The slot it owns is woven before any Kad node has named this node's place
/// in the keyspace: the all-zero Kad ID. Nothing can be adopted against it —
/// a `0x5A` verifies by inverting the echoed ID and no answer inverts to zero
/// unless it echoed all-ones, which no walk of ours ever asked for — so a
/// front with no Kad node holds no buddy by construction rather than by a
/// flag. A [`KadStart`] re-seats the real ID.
fn spawn_with<D: Dialer>(
    shared: &SharedFirewalledFront,
    wiring: FirewalledWiring,
    dialer: D,
    tick: Duration,
) -> mpsc::Sender<FirewalledCommand> {
    let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_LEN);
    let (dialed_tx, dialed_rx) = mpsc::channel(1);
    let front = FirewalledFront {
        wiring,
        shared: shared.clone(),
        slot: shared.slot(KadId::from_bytes([0; KadId::BYTE_LEN])),
        dialer: Arc::new(dialer),
        link: None,
        hello: None,
        kad_start: shared.kad_starts(),
        dialed_tx,
    };
    tokio::spawn(front.run(command_rx, dialed_rx, tick));
    command_tx
}

impl<D: Dialer> FirewalledFront<D> {
    /// Drive the front until the running node is gone.
    async fn run(
        mut self,
        mut commands: mpsc::Receiver<FirewalledCommand>,
        mut dialed: mpsc::Receiver<DialOutcome<D::Link>>,
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
                    self.on_command(command, runtime_now()).await;
                }
                // The front holds its own `dialed_tx`, so this never closes.
                Some(outcome) = dialed.recv() => self.on_dialed(outcome, runtime_now()).await,
                // A link's next event is cancel-safe (`BuddyLink`), so it is
                // free to be raced. `pending` parks the arm while no link is
                // held.
                event = next_link_event(self.link.as_mut()) => {
                    self.on_link_event(event, runtime_now()).await;
                }
                // The sender lives in `shared`, which this front holds, so
                // the cell never closes under it.
                Ok(()) = self.kad_start.changed() => self.apply_kad_start(runtime_now()).await,
                () = kad_presence.changed() => self.on_kad_presence().await,
                () = reach.changed() => self.on_reach().await,
                _ = tick.tick() => self.on_tick(runtime_now()).await,
            }
        }
    }

    /// One command from the running node, behind any Kad start the front
    /// has not applied yet: a node's pump exists only after its start was
    /// published, so whatever it asks is asked of the slot seated on it.
    async fn on_command(&mut self, command: FirewalledCommand, now: Instant) {
        if self.kad_start.has_changed().unwrap_or(false) {
            self.apply_kad_start(now).await;
        }
        match command {
            FirewalledCommand::AdoptBuddy {
                answer,
                buddy,
                verdict,
            } => self.adopt(&answer, buddy, &verdict, now).await,
            FirewalledCommand::StandaloneRendezvous { from, body } => {
                self.on_standalone_rendezvous(from, &body, now);
            }
            FirewalledCommand::DirectCallback(req) => self.on_direct_callback(&req, now),
        }
    }

    /// A Kad node started: whatever the last one left is let go, and the
    /// slot verifies against this node's ID from here on. Marks the start
    /// seen, so it is applied once however it was noticed.
    async fn apply_kad_start(&mut self, now: Instant) {
        let Some(start) = self.kad_start.borrow_and_update().clone() else {
            return;
        };
        self.hello = Some(start.hello);
        self.release_buddy(now).await;
        self.slot.reseat(start.kad_id);
    }
}

/// The front's clock: its runtime's, read as a std `Instant` because that is
/// what every slot decision takes. Outside a test it is the wall clock; a leg
/// that pauses the runtime moves it, so the keepalive and every stamp the
/// slot publishes follow the leg's time.
fn runtime_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Await the held link's next event, or park forever while no link is held.
async fn next_link_event<L: BuddyLink>(link: Option<&mut L>) -> Option<PeerEvent> {
    match link {
        Some(link) => link.next_event().await,
        None => std::future::pending().await,
    }
}
