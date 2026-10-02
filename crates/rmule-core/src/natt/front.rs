//! The **NAT-T Front** (ADR-0091): the one task that turns core's NAT-T
//! decisions into a risen [`Tunnel`], and a risen Tunnel into an ordinary peer
//! session.
//!
//! Everything else under [`crate::natt`] is pure and explicit-time — the
//! decisions and the two ledgers. This is where they meet a socket, and it is
//! deliberately **one task that owns them**: the requester ledger, the punched
//! paths and the expectation table are read and written on the same thread of
//! control, so no lock orders them and no two of them can observe the same
//! instant differently. The shape is the actor's, not a mutex's, for the same
//! reason `server_session` and the client-UDP front are tasks.
//!
//! # Who dials
//!
//! The asymmetry is the whole reason an rmule↔rmule pair raises **one** tunnel
//! rather than two. The side that *asked* for the introduction dials: the
//! rendezvous requester, and the `Requester` role of an ed2k-server `0x61`.
//! The other side records an **expectation** and accepts. A `0xA1` reaching a
//! Responder expectation therefore refreshes it and nothing more — the peer is
//! about to dial, and answering its punch with a dial of our own would put two
//! uTP handshakes on one pinhole.
//!
//! # What a `0xA1` is for
//!
//! An empty `OP_HOLEPUNCH` is purely a trigger: it refreshes the NAT
//! expectation for the sender's endpoint and asks the receiver to try a
//! transport connect. rmule dials the endpoint it **observed the punch from**,
//! not the one the hint named: the two differ exactly when the peer's NAT
//! mapped a different port than its buddy saw, and the observed one is the
//! mapping that demonstrably works. An unexpected `0xA1` is dropped in
//! silence — the dialect has no answer frame, and inventing one would make
//! rmule a reflector.
//!
//! One trigger may set at most one dial going. An address may hold several
//! **Punch Expectation**s — two peers behind one CGNAT share it — and the rules
//! for telling them apart, including when rmule refuses to guess, live in
//! [`expectations`]. What the dial then costs, and how often it is re-made,
//! lives in [`dialing`].
//!
//! # What this loop may never await
//!
//! Owning the ledgers on one task is the strength above; it is also the whole
//! hazard. This loop is the *only* thread of control that feeds
//! `NattDemux::on_datagram`, so anything it awaits on a consumer it does not
//! itself drain stops every tunnel on the node, not just the one being worked
//! on: the NAT-T inbox stops being read, the client-UDP engine drops each
//! `0xB2` at `route_natt`, live tunnels stall and dials in flight wait out
//! their whole [`dialing::DIAL_BUDGET`]. The serve accept channel is exactly such a
//! consumer — the serve runner races it against its own `enact` awaits — so a
//! risen Tunnel is handed to the **adopter task** through a bounded backlog
//! and never awaited here.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_ed2k::HolepunchRole;
use rmule_net::natt::{
    NattCrypt, NattDatagramSink, NattDemux, NattIdentity, NattOwnHash, NattSender, NattStartError,
    Tunnel, TunnelRegistry,
};
use rmule_peer::natt::{
    EndpointHint, RendezvousFailure, RendezvousStep, holepunch_datagram, is_holepunch, punch_burst,
};
use rmule_primitives::{AccountingKey, ClientId, Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::sync::mpsc;

use crate::adapters::{SharedPeerPin, SharedTunnelAdmit, SharedTunnelClaims};
use crate::address_learning::SharedAddressLearning;
use crate::client_udp::{ClientUdpDatagram, ClientUdpSend};
use crate::diagnostics::DiagnosticsState;
use crate::interval_limiter::IntervalLimiter;
use crate::service::CoreEvent;

use super::RendezvousOffer;
use super::acting::{ACTING_MIN_INTERVAL, ACTING_TRACKED_MAX};
use super::paths::PunchedPaths;
use super::requester::{HintVerdict, RendezvousRequester};

#[cfg(test)]
mod adoption;
mod attempts;
mod dialing;
mod expectations;
mod held;
mod identity;
#[cfg(test)]
mod live;
mod path_guard;
mod prediction;
#[cfg(test)]
mod tests;
mod tunnels;

pub(crate) use attempts::AttemptCoordinator;
pub use attempts::AttemptRetirement;
use attempts::Attempts;
use dialing::DialSchedule;
use expectations::{Expectations, PunchSide, PunchVerdict};
use held::{HeldBurst, HeldBursts};
use identity::os_punch_jitter;
pub(crate) use identity::{OwnIdentityNattCrypt, RMULE_NATT_CLAIM};
pub use prediction::PredictionRefusal;
pub(crate) use prediction::PredictionWiring;
use prediction::Predictions;

/// How often the front re-reads its own clock: overdue hints, due keepalives
/// and due re-dials. One second is finer than every deadline it serves (the
/// shortest is the 15 s hint timeout) and coarse enough to cost nothing on an
/// idle node. A **Held Burst**'s ½-RTT hold is far finer than this, so it is
/// never the tick's: the loop sleeps toward its own deadline.
const TICK: Duration = Duration::from_secs(1);

/// The front's clock: tokio's, read as a `std` instant.
///
/// The loop sleeps toward a **Held Burst**'s deadline on tokio's timer, so its
/// `now` must come from the same clock — otherwise a timer that fired on time
/// could read a `now` short of the deadline it fired for, and paused test time
/// could never reach one at all.
fn front_clock() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// How many commands the front's inbox holds. Commands are one per reach
/// decision, not one per datagram, so this is generous.
const COMMAND_QUEUE_LEN: usize = 32;

/// What the running node asks the **NAT-T Front** to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NattCommand {
    /// The route tree took rung 1 toward `target` through `coordinator`: own
    /// the introduction from here.
    ///
    /// The front begins a **Traversal Attempt**, which outlives the
    /// coordinator that opened it. On the buddy leg it also emits the
    /// rendezvous: the emit lives here rather than at the reach arm because
    /// the *retries* are the ledger's, and one emitter is the only way the two
    /// can agree on what went out. On the server leg the `0x60` has already
    /// left through the server session — the front holds no server link — and
    /// what this command buys is the owner that hears how it ends.
    Begin {
        /// The target's user hash — the ledger's key, and what a hint names.
        target: UserHash,
        /// Who introduces us first.
        coordinator: AttemptCoordinator,
        /// The candidate's own half of rung 1's condition, for picking the
        /// next coordinator when this one fails.
        facts: crate::callback::NattFacts,
        /// Our position as the route tree measured it, the other half of that
        /// decision.
        ours: crate::callback::SelfReach,
        /// What rmule says about itself in a rendezvous.
        offer: RendezvousOffer,
    },
    /// A coordinator settled an introduction without a transport: our server
    /// refused it (`OP_LOWID_HOLEPUNCH_FAIL`), or it waited out
    /// [`INTRODUCTION_TIMEOUT`](super::server_punch::INTRODUCTION_TIMEOUT)
    /// with no answer at all.
    ///
    /// It names a `ClientId` because that is the only name the server
    /// namespace has for a Low-ID peer; the attempt holds the join to the
    /// target's user hash, recorded when the attempt began.
    IntroductionFailed {
        /// The Low-ID the `0x60` named.
        target: ClientId,
        /// What the coordinator's outcome was.
        failure: super::server_punch::IntroductionFailure,
    },
    /// A coordinator introduced us to a peer at `target`: adopt the role for
    /// that endpoint and, as the side that asked, dial.
    ///
    /// Both coordinators end here, and they differ only in `burst`. The
    /// ed2k-server's `0x61` arrives with the burst **already fired** —
    /// `SharedServerPunch::on_info` sends it inside the session's own event
    /// loop, so it leaves before this command can — while the buddy path's
    /// acting verdict (`crate::firewalled`) arrives with nothing sent yet, and
    /// asks this front to fire it. One emitter for every punch is the point:
    /// the front owns the client-UDP send half and the path ledger a burst
    /// opens, and a second sender of the same datagrams would be a second
    /// answer to which pinhole is ours.
    Introduced {
        /// The peer the coordinator named.
        peer_hash: UserHash,
        /// The endpoint it observed for that peer.
        target: Ipv4Endpoint,
        /// Which side we are. `Initiator` means we asked, so we dial.
        role: HolepunchRole,
        /// Fire the burst at `target` before adopting the role.
        burst: bool,
        /// Which arm of the precedence rule chose `target`. Only an
        /// endpoint a coordinator observed may start a **Prediction Plan**
        /// The burst and the dial go wherever the rule said.
        source: rmule_peer::natt::PunchTargetSource,
    },
}

/// The front's command half as the running node holds it — late-bound like the
/// server coordinator's send half, because the client-UDP socket binds after
/// the cells that reach it were woven.
///
/// Empty means no NAT-T front: no client-UDP socket bound, so there is no
/// pinhole to punch and nothing to drive.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedNattFront(Arc<std::sync::OnceLock<mpsc::Sender<NattCommand>>>);

impl SharedNattFront {
    /// Install the running front's command half. Idempotent: one front per
    /// core.
    pub(crate) fn install(&self, commands: mpsc::Sender<NattCommand>) {
        let _ = self.0.set(commands);
    }

    /// Whether a front is installed **and still running** — read live, on
    /// every call, never cached (a `OnceLock::is_some` snapshot
    /// stays true forever once a front is ever installed, even after its
    /// `run` loop has returned).
    ///
    /// The signal is the installed command sender's own `is_closed`: `run`'s
    /// only two exit paths (the client-UDP inbox closing, every `NattCommand`
    /// sender dropped) both end by returning, which drops `run`'s `commands`
    /// receiver — and Tokio flips a sender's closed bit the instant its paired
    /// receiver drops, a plain memory read here, not a poll of the task.
    pub(crate) fn is_live(&self) -> bool {
        self.0.get().is_some_and(|commands| !commands.is_closed())
    }

    /// Resolve when the installed front's loop has ended — the NAT-T front
    /// family of the **Reach Generation**. Never resolves while
    /// no front is installed.
    pub(crate) async fn ended(&self) {
        match self.0.get() {
            Some(commands) => commands.closed().await,
            None => std::future::pending().await,
        }
    }

    /// Ask the front for something, reporting whether there was a front to ask.
    ///
    /// `try_send`, never `send`: both callers run inside another loop — the
    /// reach arm on the core actor, the introduction on the server session's
    /// multiplexer — and a full NAT-T inbox must cost a traversal attempt
    /// rather than stall either of them.
    pub(crate) fn send(&self, command: NattCommand) -> bool {
        self.0
            .get()
            .is_some_and(|commands| commands.try_send(command).is_ok())
    }
}

/// What a dial or an accept produced.
enum Risen {
    /// A tunnel rmule dialed, carrying the target it was dialed for.
    Dialed { tunnel: Tunnel, peer: UserHash },
    /// A tunnel a peer opened over a path we punched.
    Accepted { tunnel: Tunnel },
    /// One dial ended without a tunnel — refused, or bounded out at
    /// [`dialing::DIAL_ATTEMPT_TIMEOUT`]. The attempt is not over: the schedule
    /// decides whether its budget has room for another opener.
    DialSettled { peer: UserHash },
    /// A tunnel's peer session ended, so the path it rode is no longer held.
    Closed { at: Ipv4Endpoint },
    /// A Tunnel's own hello named `peer`, resolving an accepted path this
    /// front could not attribute by address alone — several pending peers
    /// behind one NAT-remapped address. Reported from
    /// downstream, once something reads the hello, through the same sender
    /// [`path_guard::PunchedPathGuard`] closes with.
    Identified { peer: UserHash },
    /// The download that claimed `peer` let go — its slot lapsed, or the
    /// callback beside the punch landed first — so the attempt has no
    /// claimant left to raise a Tunnel for.
    Abandoned { peer: UserHash },
}

/// A clone of the front's own risen-tunnel sender, held outside this module
/// What the **Pending Tunnel Claim** table reports a confirmed
/// adoption's hello through, exactly as [`path_guard::PunchedPathGuard::drop`]
/// reports a closed path. `Risen` itself never crosses this module's
/// boundary — only this one operation does.
#[derive(Clone)]
pub(crate) struct NattRisenSender(mpsc::Sender<Risen>);

impl NattRisenSender {
    /// A Tunnel's own hello named `peer`: report it back to the
    /// front's loop so it can end that peer's attempt and take any hold still
    /// waiting to dial them with it (`identified`). `try_send`, never `send`:
    /// the caller runs inside its own per-connection triage task, not the
    /// front's loop, and a full inbox costs one skipped report rather than a
    /// stalled adoption.
    pub(crate) fn identified(&self, peer: UserHash) {
        let _ = self.0.try_send(Risen::Identified { peer });
    }

    /// The download that claimed `peer` retracted its claim:
    /// report it so the front ends the attempt rather than dialing on for
    /// nobody. `try_send` for the reason [`Self::identified`] gives; a lost
    /// report leaves the attempt to its own deadlines.
    pub(crate) fn abandoned(&self, peer: UserHash) {
        let _ = self.0.try_send(Risen::Abandoned { peer });
    }

    /// A test double that never reaches a real front: every report surfaces
    /// on the returned receiver instead, so a test outside this module —
    /// where [`Risen`] is not visible at all — can assert one happened
    /// without seeing the type it happened through.
    #[cfg(test)]
    pub(crate) fn test_pair() -> (Self, mpsc::Receiver<ReportedToFront>) {
        let (risen_tx, mut risen_rx) = mpsc::channel(8);
        let (reported_tx, reported_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(risen) = risen_rx.recv().await {
                let reported = match risen {
                    Risen::Identified { peer } => ReportedToFront::Identified(peer),
                    Risen::Abandoned { peer } => ReportedToFront::Abandoned(peer),
                    _ => continue,
                };
                if reported_tx.send(reported).await.is_err() {
                    return;
                }
            }
        });
        (Self(risen_tx), reported_rx)
    }
}

/// What [`NattRisenSender::test_pair`] surfaces.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReportedToFront {
    /// [`NattRisenSender::identified`].
    Identified(UserHash),
    /// [`NattRisenSender::abandoned`].
    Abandoned(UserHash),
}

/// The front's wiring: every seam it reaches that is not its own ledger.
pub(crate) struct NattWiring {
    /// The client-UDP send half — where a rendezvous, a burst and a keepalive
    /// leave. It must be *this* socket: the pinhole a punch opened belongs to
    /// this bind.
    pub(crate) client_udp: mpsc::Sender<ClientUdpSend>,
    /// The one **Address Learning** store: the self-punch guard's interface
    /// set, the bound client-UDP port, and the external port a Mapping Grant
    /// reported for it.
    pub(crate) addresses: SharedAddressLearning,
    /// Where a risen tunnel enters the serve pipeline.
    pub(crate) admit: SharedTunnelAdmit,
    /// The **Pending Tunnel Claim** table: which download asked for a Tunnel
    /// toward which target. Read here for one thing only — telling a claimant
    /// that the attempt it is waiting on has retired. Adoption
    /// itself happens downstream, where the hello is.
    pub(crate) claims: SharedTunnelClaims,
    /// Where a punched path asks for its one PCP `PEER` pin.
    pub(crate) peer_pin: SharedPeerPin,
    pub(crate) diagnostics: DiagnosticsState,
    /// **Port Prediction** (ADR-0091's amendment): `None` while
    /// `natt.port_prediction` is off, which is every datagram as before.
    pub(crate) prediction: Option<PredictionWiring>,
    /// The core event bus, weakly held: the front must not keep it open past
    /// the actor that owns it.
    pub(crate) events: Option<mpsc::WeakSender<CoreEvent>>,
}

/// The **NAT-T Front** itself: the demux and the engines behind it, the two
/// ADR-0091 ledgers, and the expectations that join a punch to a dial.
pub(crate) struct NattFront<S> {
    demux: Arc<NattDemux<S>>,
    wiring: NattWiring,
    requester: RendezvousRequester,
    paths: PunchedPaths,
    /// Every **Traversal Attempt** this front owns: which coordinator is
    /// carrying each target, what a rendezvous re-emits on a retry, and the
    /// facts that pick the next coordinator. Keyed like the requester ledger,
    /// and dropped with it.
    attempts: Attempts,
    /// What rmule punched at and is expecting something from — a bounded set
    /// per address, because an address is not a peer.
    expectations: Expectations,
    /// Bursts waiting out their ½-RTT hold, each released by its own deadline.
    held: HeldBursts,
    /// Which targets are being dialed and when each may be dialed again. Keyed
    /// by the **target**, not by its address: two peers behind one CGNAT are
    /// two traversals.
    dials: DialSchedule,
    /// One punch burst per destination per window, the limit ADR-0091 sets
    /// for the acting path. Every burst this front fires stamps it; only the cadence
    /// re-dial's burst is *refused* by it, because the coordinator paths'
    /// bursts are the traversal itself.
    bursts: IntervalLimiter,
    risen_tx: mpsc::Sender<Risen>,
    /// The bounded hand-off to the adopter task. Filled with `try_send` only.
    adopt_tx: mpsc::Sender<tunnels::Adoption>,
    /// One **Prediction Plan** per introduced peer, while the knob is on.
    predictions: Predictions,
}

/// Assemble the front over `sink` and spawn it: the uTP accept pump, and the
/// loop that owns the ledgers.
///
/// # Errors
/// Whatever an engine rejected in its own configuration — a startup fault,
/// never a datagram's.
pub(crate) fn spawn<S: NattDatagramSink>(
    sink: S,
    identity: NattIdentity,
    own_hash: Arc<dyn NattOwnHash>,
    crypt: Option<Box<dyn NattCrypt>>,
    wiring: NattWiring,
    inbox: mpsc::Receiver<ClientUdpDatagram>,
) -> Result<mpsc::Sender<NattCommand>, NattStartError> {
    let Assembled {
        front,
        risen,
        adoptions,
    } = assemble(sink, identity, own_hash, crypt, wiring)?;
    let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_LEN);
    spawn_accept_pump(Arc::clone(&front.demux), front.risen_tx.clone());
    tunnels::spawn_adopter(
        adoptions,
        front.wiring.admit.clone(),
        front.wiring.events.clone(),
    );
    tokio::spawn(front.run(inbox, command_rx, risen));
    Ok(command_tx)
}

/// A front that is built but not running, with the two receiving halves whose
/// senders it holds: what `spawn` wires to tasks, and what a deterministic
/// test keeps alive while it drives the handlers by hand.
struct Assembled<S> {
    front: NattFront<S>,
    risen: mpsc::Receiver<Risen>,
    adoptions: mpsc::Receiver<tunnels::Adoption>,
}

/// Build the front and its risen-tunnel channel without starting either loop —
/// the seam a deterministic test drives the handlers through with an explicit
/// `now`, and the body `spawn` wraps.
///
/// # Errors
/// Whatever an engine rejected in its own configuration.
fn assemble<S: NattDatagramSink>(
    sink: S,
    identity: NattIdentity,
    own_hash: Arc<dyn NattOwnHash>,
    crypt: Option<Box<dyn NattCrypt>>,
    wiring: NattWiring,
) -> Result<Assembled<S>, NattStartError> {
    let sender = Arc::new(NattSender::new(sink, crypt));
    let demux = Arc::new(NattDemux::start(
        identity,
        own_hash,
        sender,
        Arc::new(std::sync::Mutex::new(TunnelRegistry::new())),
    )?);
    let (risen_tx, risen_rx) = mpsc::channel(COMMAND_QUEUE_LEN);
    // The claim table's report-back seam: the same channel
    // `PunchedPathGuard` closes with, so the adoption inbound triage confirms
    // through it can name a peer exactly as a closed path does.
    wiring
        .claims
        .install_risen(NattRisenSender(risen_tx.clone()));
    let (adopt_tx, adopt_rx) = mpsc::channel(tunnels::ADOPT_BACKLOG_LEN);
    Ok(Assembled {
        front: NattFront {
            demux,
            wiring,
            requester: RendezvousRequester::default(),
            paths: PunchedPaths::default(),
            attempts: Attempts::default(),
            expectations: Expectations::default(),
            held: HeldBursts::default(),
            dials: DialSchedule::default(),
            bursts: IntervalLimiter::new(ACTING_MIN_INTERVAL, ACTING_TRACKED_MAX),
            risen_tx,
            adopt_tx,
            predictions: Predictions::default(),
        },
        risen: risen_rx,
        adoptions: adopt_rx,
    })
}

/// The uTP accept pump, a task of its own for the reason the serve listener's
/// is: `accept` must never sit in a future some `select!` can
/// cancel, because a cancelled accept drops a handshake the peer already
/// completed. `mpsc::Receiver::recv` is cancel-safe; this is what makes the
/// front's loop free to race it.
fn spawn_accept_pump<S: NattDatagramSink>(demux: Arc<NattDemux<S>>, risen: mpsc::Sender<Risen>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // The front is gone: nothing would receive an accepted tunnel.
                () = risen.closed() => return,
                accepted = demux.utp().accept() => match accepted {
                    Ok(tunnel) => {
                        if risen.send(Risen::Accepted { tunnel }).await.is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        // `librqbit-utp` reports an accept failure only when
                        // its dispatcher is gone, so retrying would spin.
                        tracing::debug!(%error, "the NAT-T uTP accept loop ended");
                        return;
                    }
                },
            }
        }
    });
}

impl<S: NattDatagramSink> NattFront<S> {
    /// Drive the front until the client-UDP engine or the core actor is gone.
    async fn run(
        mut self,
        mut inbox: mpsc::Receiver<ClientUdpDatagram>,
        mut commands: mpsc::Receiver<NattCommand>,
        mut risen: mpsc::Receiver<Risen>,
    ) {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // Re-read every turn: a hint may have held an earlier burst, and a
            // retirement may have cancelled the one this arm slept toward.
            let release = self.held.next_deadline();
            tokio::select! {
                datagram = inbox.recv() => {
                    // The client-UDP front closed: this node has no socket to
                    // punch from any more, so the ledgers have nothing to
                    // rule on (a closed channel ends the task,
                    // never spins it).
                    let Some((from, datagram)) = datagram else { return };
                    self.on_datagram(from, datagram, front_clock()).await;
                }
                command = commands.recv() => {
                    // Every command sender is gone: the core actor is gone.
                    let Some(command) = command else { return };
                    self.on_command(command, front_clock()).await;
                }
                // The front holds its own `risen_tx`, so this never closes.
                Some(outcome) = risen.recv() => self.on_risen(outcome, front_clock()).await,
                () = held::hold_elapsed(release) => self.release_held(front_clock()).await,
                _ = tick.tick() => self.on_tick(front_clock()).await,
            }
        }
    }

    /// One datagram from the client-UDP front's NAT-T inbox: a `0xB2`
    /// transport frame, a `0xA1` trigger or a `0xAA` hint.
    async fn on_datagram(&mut self, from: PeerEndpoint, datagram: Vec<u8>, now: Instant) {
        if datagram.first() == Some(&rmule_peer::natt::NATT_PROTOCOL) {
            // A frame on a path we hold is the path proving itself: a busy
            // Tunnel is its own keepalive.
            if let Some(peer) = from.as_v4() {
                self.paths.on_activity(peer, now);
            }
            self.demux.on_datagram(from, &datagram, now).await;
            return;
        }
        if is_holepunch(&datagram) {
            self.on_holepunch(from, now).await;
            return;
        }
        match EndpointHint::decode_udp(&datagram) {
            Ok(hint) => self.on_hint(&hint, from, now),
            Err(error) => {
                tracing::trace!(%from, %error, "malformed NAT-T signalling dropped");
            }
        }
    }

    /// An `OP_HOLEPUNCH` arrived. It answers nothing; it refreshes every
    /// expectation behind its sender's address and, on the dialing side,
    /// corrects where the dial goes.
    async fn on_holepunch(&mut self, from: PeerEndpoint, now: Instant) {
        let Some(observed) = from.as_v4() else {
            // An IPv6 punch names an endpoint no hint and no `0x61` could have
            // aimed us at, so nothing can be expecting it.
            self.wiring.diagnostics.count_natt_unexpected_holepunch();
            return;
        };
        self.paths.on_activity(observed, now);
        if self.note_probe_answer(observed) {
            self.send_punch(observed).await;
        }
        match self.expectations.on_punch(observed, now) {
            PunchVerdict::Unexpected => {
                self.wiring.diagnostics.count_natt_unexpected_holepunch();
                tracing::trace!(%from, "unexpected OP_HOLEPUNCH; dropped, never answered");
            }
            // Every expectation behind this address is a Responder's: the peer
            // dials, and a dial of our own would put two uTP handshakes on one
            // pinhole.
            PunchVerdict::Refreshed => {}
            PunchVerdict::Ambiguous => {
                self.wiring.diagnostics.count_natt_ambiguous_holepunch();
                tracing::debug!(
                    %from,
                    "an OP_HOLEPUNCH names none of the peers expected behind its address; \
                     refreshed, dialed nothing"
                );
            }
            // The observed source outranks what the hint claimed (amule#1177
            // correction 1): if the peer's NAT mapped a different port, this
            // datagram just told us which one actually works.
            //
            // A punch is a trigger for a traversal that is still running — an
            // attempt, or a dial an introduction armed — never the start of
            // one: behind a lingering expectation, a peer whose attempt ended
            // (a Tunnel up, a retirement) keeps punching, and each of those
            // would otherwise open a fresh dial on a fresh budget.
            PunchVerdict::Dial(peer) if self.attempts.contains(&peer) || self.dials.holds(peer) => {
                self.dial(peer, observed, now).await;
            }
            PunchVerdict::Dial(_) => {}
        }
    }

    /// An `OP_NATT_ENDPOINT_HINT` arrived. Only the requester ledger decides
    /// whether it is believed; a refusal is silent and counted.
    fn on_hint(&mut self, hint: &EndpointHint, from: PeerEndpoint, now: Instant) {
        let Some(from) = from.as_v4() else {
            // Ruled out at the client-UDP front, which counts it.
            return;
        };
        let addresses = self.wiring.addresses.clone();
        match self
            .requester
            .on_hint(hint, from, |ip| addresses.holds_interface(ip), now)
        {
            HintVerdict::Punch { target, delay } => {
                self.record_expectation(hint.target, target, PunchSide::Dialer, now);
                self.held.hold(HeldBurst {
                    at: now + delay,
                    target,
                    peer: hint.target,
                });
                tracing::debug!(
                    ?target,
                    ?delay,
                    "endpoint hint accepted; burst held for half the measured round trip"
                );
            }
            HintVerdict::Refuse(refusal) => {
                self.wiring.diagnostics.record_natt_hint_refusal(refusal);
                tracing::debug!(?refusal, %from, "endpoint hint refused");
            }
        }
    }

    /// One command from the running node.
    async fn on_command(&mut self, command: NattCommand, now: Instant) {
        match command {
            NattCommand::Begin {
                target,
                coordinator,
                facts,
                ours,
                offer,
            } => {
                self.begin_attempt(target, coordinator, facts, ours, offer, now)
                    .await;
            }
            NattCommand::IntroductionFailed { target, failure } => {
                self.on_introduction_failed(target, failure, now).await;
            }
            NattCommand::Introduced {
                peer_hash,
                target,
                role,
                burst,
                source,
            } => {
                // The role byte is advisory for *timing* — a server tells both
                // sides at once, so there is no round trip to halve — but it
                // still names which side asked, and that is exactly the fact
                // that decides who dials. An unknown byte is read as the
                // responder: accepting costs nothing, and two dials on one
                // pinhole cost the traversal.
                let side = match role {
                    HolepunchRole::Initiator => PunchSide::Dialer,
                    HolepunchRole::Responder | HolepunchRole::Other(_) => PunchSide::Responder,
                };
                // The expectation is recorded **before** the burst: the peer
                // may punch back inside the same millisecond, and a `0xA1`
                // that arrives ahead of its own expectation is dropped as
                // unsolicited and counted as one.
                self.record_expectation(peer_hash, target, side, now);
                self.attempts.introduced(&peer_hash);
                if burst {
                    self.fire_burst(target, now).await;
                }
                self.plan_introduced_prediction(peer_hash, target, source, now);
                if side == PunchSide::Dialer {
                    self.dial(peer_hash, target, now).await;
                }
            }
        }
    }

    /// Enact what the schedule says for one target.
    pub(super) async fn act_on_step(
        &mut self,
        target: UserHash,
        step: RendezvousStep,
        now: Instant,
    ) {
        match step {
            RendezvousStep::Send => {
                // Only the buddy leg has a rendezvous to re-emit: the server
                // leg's introduction left through the session and the
                // schedule is not armed for it, so there is no step to reach
                // this arm with.
                let Some((buddy_id, buddy_udp, offer)) =
                    self.attempts
                        .get(&target)
                        .and_then(|attempt| match attempt.coordinator {
                            AttemptCoordinator::Buddy {
                                buddy_id,
                                buddy_udp,
                            } => Some((buddy_id, buddy_udp, attempt.offer)),
                            AttemptCoordinator::Server { .. } => None,
                        })
                else {
                    return;
                };
                let send = super::rendezvous_request(buddy_udp, buddy_id, &offer);
                if self.wiring.client_udp.send(send).await.is_err() {
                    tracing::debug!("rendezvous not sent: the client-UDP send half is gone");
                    return;
                }
                self.requester.on_sent(&target, now);
                self.wiring.diagnostics.count_natt_rendezvous_emitted();
            }
            RendezvousStep::Retired(reason, _until) => {
                self.retire_attempt(target, AttemptRetirement::Schedule(reason), now)
                    .await;
            }
            // The grant is spent and nothing is scheduled: the run is over
            // and the source's clock stops (ADR-0091). The
            // ledger keeps its failure count — that is what carries the cap
            // across runs — but this front forgets what to re-emit, because
            // only a fresh trigger can grant another attempt, and a fresh
            // trigger brings its own offer.
            RendezvousStep::Idle => {
                self.end_attempt(&target);
            }
            // Scheduled, or awaiting an outcome: the tick polls the ledger
            // again.
            RendezvousStep::Wait(_) | RendezvousStep::InFlight => {}
        }
    }

    /// The front's coarse clock: due re-dials, hints that never came, and
    /// paths that have gone quiet.
    async fn on_tick(&mut self, now: Instant) {
        // A dial is short because a lost opener is never re-sent; what recovers
        // one is another dial, while the attempt's budget lasts.
        for order in self.dials.due(now) {
            self.enact_dial(order, now).await;
        }
        self.expectations.prune(now);
        self.requester.prune(now);
        // Silence is the dialect's only failure signal: fifteen seconds with
        // no hint spends one of the target's five attempts.
        for target in self.requester.overdue(now) {
            let step = self.requester.on_failure(
                &target,
                RendezvousFailure::Silence,
                now,
                os_punch_jitter(),
            );
            if let Some(step) = step {
                self.act_on_step(target, step, now).await;
            }
        }
        // A retry the schedule granted is due on a later tick, so every live
        // attempt is re-polled. A target this front has already retired is no
        // longer in `attempts`, which is what keeps one retirement from being
        // reported once a second forever.
        for (target, step) in self.requester.poll(now) {
            if self.attempts.contains(&target) {
                self.act_on_step(target, step, now).await;
            }
        }
        // The attempt's own backstop: every state has a deadline.
        // The buddy leg's schedule and a dial's budget each end an attempt
        // themselves; one that neither holds — a server introduction that
        // named us the responder, and no peer ever dialed — would otherwise
        // wait forever, and its claimant with it.
        for target in self.attempts.past_run(now) {
            if !self.dials.holds(target) {
                self.retire_attempt(
                    target,
                    AttemptRetirement::Schedule(rmule_peer::natt::RetireReason::TimedOut),
                    now,
                )
                .await;
            }
        }
        for peer in self.paths.due_keepalives(now) {
            self.send_punch(peer).await;
        }
        self.drive_predictions(now);
    }

    /// Record one **Punch Expectation**, counting what the per-address bound
    /// pushed out.
    fn record_expectation(
        &mut self,
        peer: UserHash,
        nominal: Ipv4Endpoint,
        side: PunchSide,
        now: Instant,
    ) {
        if self.expectations.record(peer, nominal, side, now) {
            self.wiring.diagnostics.count_natt_expectation_evicted();
            tracing::debug!(
                %nominal,
                "an address is carrying more NAT traversals than its expectation set holds; \
                 the oldest was forgotten"
            );
        }
    }

    /// Six empty punches at the endpoint, then the ±16-port sweep.
    ///
    /// Stamps the destination limiter on the way: the coordinator paths' bursts
    /// *are* the traversal and are never refused here, but they are what a
    /// cadence re-dial's burst must not double.
    async fn fire_burst(&mut self, target: Ipv4Endpoint, now: Instant) {
        let _ = self.bursts.admit(AccountingKey::of(target.ip.into()), now);
        self.fire_burst_only(target).await;
    }

    /// The burst itself, for a caller that has already consulted the limiter.
    pub(super) async fn fire_burst_only(&self, target: Ipv4Endpoint) {
        for endpoint in punch_burst(target) {
            if self
                .wiring
                .client_udp
                .send(ClientUdpSend::plaintext(
                    PeerEndpoint::V4(endpoint),
                    holepunch_datagram(),
                ))
                .await
                .is_err()
            {
                return;
            }
        }
    }

    /// One empty `OP_HOLEPUNCH` — the keepalive an idle punched path lives on.
    async fn send_punch(&self, peer: Ipv4Endpoint) {
        let send = ClientUdpSend::plaintext(PeerEndpoint::V4(peer), holepunch_datagram());
        let _ = self.wiring.client_udp.send(send).await;
    }
}
