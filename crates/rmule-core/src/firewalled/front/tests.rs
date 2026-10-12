//! The firewalled front through its interface: the commands the running node
//! sends, the dials and dial-backs it asks of a scripted [`Dialer`], the
//! events a scripted buddy link delivers, and what the front publishes, counts
//! and enacts.
//!
//! No socket carries the buddy link or a dial-back, and nothing is polled. A
//! leg runs on a paused clock and settles the front by sleeping: the runtime
//! lets a sleep pass only once every task is idle, so what the front does with
//! an input is done when the sleep returns. What the real dial-back then does
//! on the wire is the admit seam's to prove (`serve_runtime::accept`'s legs).
//!
//! **The requester a relay names is a public address, on purpose.**
//! `is_public_punch_address` refuses loopback and the self-punch guard refuses
//! our own interfaces (ADR-0091), and neither is weakened here: a rendezvous
//! naming `127.0.0.1` *must* resolve to nothing. So the injected endpoint is
//! `45.55.200.7:5000`, and what these legs assert is the verdict and the
//! command it produced — never that a datagram arrived anywhere.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use rmule_net::peer::ConnectOptions;
use rmule_peer::natt::{NattConnectOptions, RendezvousBody};
use rmule_peer::{Callback, ConnectionEvent, PeerHandshakeContext, ReaskCallbackTcp};
use rmule_primitives::{FileHash, Ipv4Endpoint, PacketProtocol, UserHash};
use tokio::sync::oneshot;

use super::dialer::Dialed;
use super::*;
use crate::adapters::tests::held_buddy::{a_buddy, a_buddy_stating};
use crate::firewalled::link::BuddyState;
use crate::firewalled::recruit::RecruitStatus;
use crate::natt::front::NattCommand;
use crate::service::DialFailure;
use rmule_peer::{PeerCommand, SideCommand, SideEvent};

mod held_buddy;
mod inlets;

/// Our Kad ID, and the `~ourKadID` every answer for it echoes.
const OUR_KAD_ID: u8 = 0xAA;
const BUDDY_ID: u8 = 0x55;

/// The buddy's user hash — what the front checks the dialed link's identity
/// against before it holds anything.
fn buddy_hash() -> UserHash {
    a_buddy().hash
}

/// The requester a relay names. Publicly routable, so the ADR-0091 target
/// rule can resolve it; see the module doc.
fn requester() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 5000)
}

/// The `0x99` check field addressed to `id`: its bit-inverse — aMule's own
/// `TAG_BUDDYHASH` spelling, and the buddy-ID a `0x5A` for `id` echoes.
fn addressed_to(id: [u8; 16]) -> [u8; 16] {
    id.map(|b| !b)
}

/// Let every task run until it waits: on a paused clock, the sleep passes
/// only when the runtime has nothing left to do.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

/// Let the front's clock beat once, and the front act on it.
async fn tick() {
    tokio::time::sleep(TICK).await;
    settle().await;
}

/// `poll`'s value, or a failure naming `what` — a bound on a hang, never a
/// pace: on a paused clock the budget passes only while everything waits.
async fn within<T>(what: &str, poll: impl std::future::Future<Output = Option<T>>) -> T {
    tokio::time::timeout(Duration::from_secs(10), poll)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .unwrap_or_else(|| panic!("{what} never arrived"))
}

/// One dial the front asked of the scripted dialer, waiting for the leg to
/// say how it went.
struct DialRequest {
    peer: PeerEndpoint,
    hello: PeerHandshakeContext,
    options: ConnectOptions,
    answer: oneshot::Sender<Result<Dialed<ScriptedLink>, BuddyDialFailure>>,
}

impl DialRequest {
    /// The dial comes up and its hello proves `hash`, claiming `ipv6`: the
    /// buddy's side of the link is handed back.
    fn answer_as(self, hash: UserHash, ipv6: Option<Ipv6Addr>) -> BuddySide {
        let (link, side) = scripted_link(self.peer);
        let _ = self.answer.send(Ok(Dialed {
            link,
            user_hash: hash,
            claimed_ipv6: ipv6,
        }));
        side
    }

    /// The dial fails for `cause`.
    fn fail(self, cause: BuddyDialFailure) {
        let _ = self.answer.send(Err(cause));
    }
}

/// One callback dial-back the front asked for: whom, and under which key.
#[derive(Debug, PartialEq, Eq)]
struct DialBack {
    requester: PeerEndpoint,
    obfuscate_toward: Option<UserHash>,
}

/// The dialer a leg scripts: every dial is handed to the leg to answer, and
/// every dial-back is recorded for the leg to read.
struct ScriptedDialer {
    dials: mpsc::UnboundedSender<DialRequest>,
    dial_backs: mpsc::UnboundedSender<DialBack>,
}

impl Dialer for ScriptedDialer {
    type Link = ScriptedLink;

    async fn dial(
        &self,
        peer: PeerEndpoint,
        hello: PeerHandshakeContext,
        options: ConnectOptions,
    ) -> Result<Dialed<ScriptedLink>, BuddyDialFailure> {
        let (answer, answered) = oneshot::channel();
        let _ = self.dials.send(DialRequest {
            peer,
            hello,
            options,
            answer,
        });
        answered.await.unwrap_or(Err(BuddyDialFailure::Dial {
            cause: DialFailure::DriverEnded,
        }))
    }

    fn dial_back(&self, requester: PeerEndpoint, obfuscate_toward: Option<UserHash>) {
        let _ = self.dial_backs.send(DialBack {
            requester,
            obfuscate_toward,
        });
    }
}

/// The front's half of a scripted buddy link.
struct ScriptedLink {
    remote: PeerEndpoint,
    commands: mpsc::Sender<PeerCommand>,
    events: mpsc::Receiver<PeerEvent>,
    shut: oneshot::Sender<()>,
}

impl BuddyLink for ScriptedLink {
    fn remote(&self) -> PeerEndpoint {
        self.remote
    }

    fn commands(&self) -> mpsc::Sender<PeerCommand> {
        self.commands.clone()
    }

    async fn next_event(&mut self) -> Option<PeerEvent> {
        self.events.recv().await
    }

    async fn shutdown(self) {
        let _ = self.shut.send(());
    }
}

/// The buddy's half: what it sends down the link, what the front sends up
/// it, and whether the front shut it.
struct BuddySide {
    events: mpsc::Sender<PeerEvent>,
    commands: mpsc::Receiver<PeerCommand>,
    shut: oneshot::Receiver<()>,
}

impl BuddySide {
    /// Send `event` down the link, as the buddy's driver would surface it.
    async fn send(&self, event: PeerEvent) {
        self.events
            .send(event)
            .await
            .expect("the front holds the link");
    }

    /// Whether the front has shut its half.
    fn is_shut(&mut self) -> bool {
        self.shut.try_recv().is_ok()
    }
}

fn scripted_link(remote: PeerEndpoint) -> (ScriptedLink, BuddySide) {
    let (events_tx, events) = mpsc::channel(8);
    let (commands, commands_rx) = mpsc::channel(8);
    let (shut_tx, shut) = oneshot::channel();
    (
        ScriptedLink {
            remote,
            commands,
            events,
            shut: shut_tx,
        },
        BuddySide {
            events: events_tx,
            commands: commands_rx,
            shut,
        },
    )
}

/// What the front is driven with, and what the leg watches.
struct Harness {
    front: mpsc::Sender<FirewalledCommand>,
    /// The front's shared face, where the Kad pump publishes its Recruit
    /// Status.
    shared: SharedFirewalledFront,
    /// The buddy level, as every reader reads it.
    buddy: BuddyView,
    /// The dials the front asks for.
    dials: mpsc::UnboundedReceiver<DialRequest>,
    /// The Kad pump's verdict inbox, and its strong half — the front answers
    /// on a weak one, as it does a running pump.
    verdicts: mpsc::Receiver<AdoptVerdict>,
    verdicts_tx: mpsc::Sender<AdoptVerdict>,
    natt: mpsc::Receiver<NattCommand>,
    reask: mpsc::Receiver<crate::client_udp::ClientUdpDatagram>,
    /// The strong half of the reask inbox, kept alive so the front's weak
    /// sender upgrades — exactly as the client-UDP front's own does.
    _reask_tx: mpsc::Sender<crate::client_udp::ClientUdpDatagram>,
    diagnostics: crate::diagnostics::DiagnosticsState,
    /// The file-known predicate — empty by default, exactly as a fresh
    /// session shares and downloads nothing.
    file_known: crate::known_files::SharedFileKnown,
    /// Every callback dial-back the front asked the dialer for.
    dial_backs: mpsc::UnboundedReceiver<DialBack>,
    /// **Kad Presence**'s lease, held from construction — a leg stops Kad by
    /// `drop`ping it. `None` only under [`kad_down_harness`]: Kad never ran.
    kad_lease: Option<crate::adapters::KadPresenceLease>,
    /// The Kad family of **Self Reach** the front reads: a leg opens the TCP
    /// verdict here, as the pump would publish it.
    kad: crate::reachability::SharedKadVerdicts,
    /// The Hello Adverts read the front was wired with.
    hello: crate::adapters::HelloAdverts,
    /// The core events the front reports.
    events: mpsc::Receiver<crate::CoreEvent>,
    /// The strong half, so the front's weak sender upgrades.
    _events_tx: mpsc::Sender<crate::CoreEvent>,
}

impl Harness {
    /// A Kad node started as `kad_id`, presenting the serverless dial
    /// identity.
    fn kad_started_as(&self, kad_id: [u8; 16]) {
        self.shared.kad_started(KadStart {
            hello: crate::server_session::HelloSource::Fixed(
                rmule_testkit::peer_session::serverless_ctx(),
            ),
            kad_id: rmule_kad::KadId::from_bytes(kad_id),
        });
    }

    /// [`kad_started_as`](Self::kad_started_as) our usual Kad ID.
    fn kad_started(&self) {
        self.kad_started_as([OUR_KAD_ID; 16]);
    }

    /// Put `buddy` to the front as the Kad pump does on a verified `0x5A`
    /// for a node of `kad_id`, without waiting for the verdict.
    async fn ask_adopt_for(&self, buddy: RecruitedBuddy, kad_id: [u8; 16]) {
        self.front
            .send(FirewalledCommand::AdoptBuddy {
                // The walk target echoed back, not the buddy's own Kad ID.
                answer: FindBuddyRes {
                    buddy_id: rmule_kad::KadId::from_bytes(addressed_to(kad_id)),
                    buddy_endpoint: buddy.udp,
                },
                buddy,
                verdict: self.verdicts_tx.downgrade(),
            })
            .await
            .expect("front running");
    }

    /// Put `buddy` to the front for our usual Kad ID and take its verdict.
    async fn adopt(&mut self, buddy: RecruitedBuddy) -> AdoptVerdict {
        self.ask_adopt_for(buddy, [OUR_KAD_ID; 16]).await;
        within("the adopt verdict", self.verdicts.recv()).await
    }

    /// The next dial the front asks for.
    async fn next_dial(&mut self) -> DialRequest {
        within("the buddy dial", self.dials.recv()).await
    }

    /// Start a node, adopt [`a_buddy`], answer its dial as the buddy, and
    /// wait for the link to be held.
    async fn hold(&mut self) -> BuddySide {
        self.kad_started();
        assert_eq!(self.adopt(a_buddy()).await.outcome, AdoptOutcome::Adopted);
        let side = self.next_dial().await.answer_as(buddy_hash(), None);
        settle().await;
        assert_eq!(self.buddy.snapshot().state, BuddyState::Held);
        side
    }

    /// The next callback dial-back the front asked for.
    async fn next_dial_back(&mut self) -> DialBack {
        within("the dial-back", self.dial_backs.recv()).await
    }

    /// Whether the front asked for any dial-back the leg has not read.
    fn no_dial_back(&mut self) -> bool {
        self.dial_backs.try_recv().is_err()
    }
}

/// A front with every seam observable: a NAT-T front that only records, a
/// dialer that records every dial-back, a reask inbox the leg drains, and an
/// empty file-known cell a leg populates when it wants a `0x99` to prove a
/// file.
fn harness() -> Harness {
    crypt_harness(None)
}

/// A front whose clock never ticks inside a leg: an hour-long period, first
/// tick one period out. For a leg whose slot must move only on its own
/// events.
fn quiet_harness() -> Harness {
    ticking_harness(adverts(None), Duration::from_secs(3600), true)
}

/// [`quiet_harness`] on a node whose Kad never started: no lease was ever
/// taken, so Kad Presence has no change for the front to act on.
fn kad_down_harness() -> Harness {
    ticking_harness(adverts(None), Duration::from_secs(3600), false)
}

/// The same front under a chosen obfuscation policy — our side of a buddy's
/// crypt rule, and what a `0x95` dial-back reads before it decides whether to
/// dial obfuscated, plaintext or at all.
fn crypt_harness(crypt: Option<rmule_net::peer::ObfuscationPolicy>) -> Harness {
    ticking_harness(adverts(crypt), TICK, true)
}

/// The same front on a node whose every advert is live: a served reask
/// port, a running Kad node, a Known IPv6, crypt supported.
fn live_harness() -> Harness {
    ticking_harness(
        crate::adapters::tests::hello_wire::live_adverts(BuddyView::default()),
        TICK,
        true,
    )
}

/// Hello Adverts that state nothing but `crypt`.
fn adverts(crypt: Option<rmule_net::peer::ObfuscationPolicy>) -> crate::adapters::HelloAdverts {
    crate::adapters::HelloAdverts {
        obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy::new(crypt),
        ..crate::adapters::HelloAdverts::default()
    }
}

fn ticking_harness(hello: crate::adapters::HelloAdverts, tick: Duration, kad_up: bool) -> Harness {
    let (natt_tx, natt_rx) = mpsc::channel(8);
    let natt = crate::natt::front::SharedNattFront::default();
    natt.install(natt_tx);
    let (reask_tx, reask_rx) = mpsc::channel(8);
    let diagnostics = crate::diagnostics::DiagnosticsState::default();
    let file_known = crate::known_files::SharedFileKnown::default();
    let kad_presence = crate::adapters::KadPresenceView::default();
    let kad_lease = kad_up.then(|| {
        kad_presence.lease(rmule_kad::KadId::from_bytes(
            [OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN],
        ))
    });
    let kad = crate::reachability::SharedKadVerdicts::default();
    let (events_tx, events) = mpsc::channel(8);
    let (dials_tx, dials) = mpsc::unbounded_channel();
    let (dial_backs_tx, dial_backs) = mpsc::unbounded_channel();
    let (verdicts_tx, verdicts) = mpsc::channel(8);
    let shared = SharedFirewalledFront::default();
    let front = super::spawn_with(
        &shared,
        FirewalledWiring {
            hello: hello.clone(),
            reach: crate::reachability::SharedSelfReach::new(
                crate::KadReachLevel::published(kad.clone()),
                crate::own_identity::SharedOwnIdentity::default(),
                natt.clone(),
            ),
            natt,
            reask_ping: reask_tx.downgrade(),
            addresses: crate::address_learning::SharedAddressLearning::new(),
            file_known: file_known.clone(),
            diagnostics: diagnostics.clone(),
            kad_presence,
            events: Some(events_tx.downgrade()),
        },
        ScriptedDialer {
            dials: dials_tx,
            dial_backs: dial_backs_tx,
        },
        tick,
    );
    Harness {
        front,
        buddy: shared.view(),
        shared,
        dials,
        verdicts,
        verdicts_tx,
        natt: natt_rx,
        reask: reask_rx,
        _reask_tx: reask_tx,
        diagnostics,
        file_known,
        dial_backs,
        kad_lease,
        kad,
        hello,
        events,
        _events_tx: events_tx,
    }
}
