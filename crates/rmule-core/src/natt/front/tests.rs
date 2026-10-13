//! The **NAT-T Front**'s decisions, driven with an explicit clock: a hint
//! becomes a held burst, a dial and an expectation; an unsolicited one becomes
//! silence and a count; silence on a rendezvous spends the budget until the
//! target retires; and only an idle punched path draws a keepalive.
//!
//! The front is built with [`assemble`] and its handlers are called directly,
//! so every `now` is the test's own. The loop's `select!` is driven whole only
//! where its timing is the subject (the `held` leg, on paused time); the live
//! leg (`front/live.rs`) proves it over real loopback sockets.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::task::{Context, Poll};

use crate::natt::server_punch::IntroductionFailure;
use rmule_peer::BUDDY_ID_LEN;
use rmule_peer::natt::{
    NattConnectOptions, NattTransport, RendezvousBody, RetireReason, holepunch_datagram,
};
use rmule_primitives::FileHash;

use super::dialing::{DIAL_ATTEMPT_TIMEOUT, DIAL_BUDGET, REDIAL_INTERVAL};
use super::*;
use crate::natt::RendezvousOffer;
use crate::natt::acting::ACTING_MIN_INTERVAL;
use crate::natt::requester::HINT_TIMEOUT;

mod held;
mod introduction_and_attempts;
mod lifecycle;
mod prediction;

/// A sink that goes nowhere: the front's own emissions are read off the
/// client-UDP half, and the `0xB2` frames the engines write are not this
/// file's subject.
struct NullSink;

impl NattDatagramSink for NullSink {
    async fn send_to(&self, _peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
        Ok(datagram.len())
    }

    fn try_send_to(&self, _peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
        Ok(datagram.len())
    }

    fn poll_send_to(
        &self,
        _cx: &mut Context<'_>,
        _peer: PeerEndpoint,
        datagram: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(datagram.len()))
    }

    fn local_addr(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 4672))
    }
}

fn at(last: u8, port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, last), port)
}

fn hash(fill: u8) -> UserHash {
    UserHash::from_bytes([fill; UserHash::BYTE_LEN])
}

const BUDDY_ID: [u8; BUDDY_ID_LEN] = [0xBB; BUDDY_ID_LEN];

/// The buddy's UDP endpoint: a hint is believed only from exactly this
/// address and port.
fn buddy() -> Ipv4Endpoint {
    at(2, 4672)
}

/// A candidate that names the buddy above, as a source channel would — what a
/// **Traversal Attempt** falls through to when its first coordinator fails.
fn buddy_facts() -> crate::callback::NattFacts {
    crate::callback::NattFacts {
        on_our_server: true,
        supports_natt: true,
        buddy: Some(crate::callback::BuddyContact {
            buddy_id: rmule_kad::KadId::from_bytes(BUDDY_ID),
            buddy_udp: Some(buddy()),
        }),
        advertised_udp: None,
    }
}

/// The client-UDP port our socket bound, which a `0x60` names.
const OUR_UDP_PORT: u16 = 4672;

/// What the front reads of the node around it: **Self Reach** with the
/// client-UDP half bound and a Kad node running — the position rung 1 is
/// chosen under — and a live **Server Coordinator** session over a fake
/// link, off which a leg reads the `0x60`s the front put on it.
struct Surroundings {
    reach: crate::reachability::SharedSelfReach,
    server: crate::natt::server_punch::CoordinatorSession,
    addresses: crate::address_learning::SharedAddressLearning,
    /// The client-UDP half's family, for a leg that clears it.
    client_udp: crate::reachability::ClientUdpBound,
    /// What the fake session put on its link.
    session_sent: mpsc::Receiver<rmule_ed2k::Ed2kCommand>,
    /// The session's handle.
    session: crate::server_session::ServerSessionHandle,
    /// The sender that keeps the session's link open.
    link: Option<mpsc::Sender<rmule_ed2k::Ed2kEvent>>,
    _kad: crate::adapters::KadPresenceLease,
}

impl Surroundings {
    fn new() -> Self {
        Self::over(crate::address_learning::SharedAddressLearning::default())
    }

    /// The same, over a leg's own **Address Learning** store, into which the
    /// client-UDP bind is recorded.
    fn over(addresses: crate::address_learning::SharedAddressLearning) -> Self {
        let client_udp = crate::reachability::ClientUdpBound::default();
        client_udp.set();
        let presence = crate::adapters::KadPresenceView::default();
        let kad = presence.lease(rmule_kad::KadId::from_bytes(
            [0x11; rmule_kad::KadId::BYTE_LEN],
        ));
        let punch = crate::natt::server_punch::SharedServerPunch::default();
        let (handle, events, session_sent) = crate::server_session::tests::fake_session(
            crate::server_session::tests::connected(),
            rmule_ed2k::ServerGrants::default(),
        );
        punch.go_live(&handle);
        addresses.record_bind(
            crate::address_learning::SocketRole::Udp,
            &rmule_net::family::FamilyBinds {
                bound: vec![rmule_primitives::AddressFamily::V4],
                refused: Vec::new(),
            },
            OUR_UDP_PORT,
        );
        let reach = crate::reachability::SharedSelfReach::new(
            crate::KadReachLevel::fixed(false),
            crate::own_identity::SharedOwnIdentity::default(),
            SharedNattFront::default(),
        )
        .with_kad_presence(presence)
        .with_client_udp(client_udp.clone())
        .with_server_coordinator(punch.coordinator_session());
        Self {
            reach,
            server: punch.coordinator_session(),
            addresses,
            client_udp,
            session_sent,
            session: handle,
            link: Some(events),
            _kad: kad,
        }
    }

    /// End the session — its link closes — and wait until it has.
    async fn end_session(&mut self) {
        self.link = None;
        self.session.closed().await;
    }

    /// The next `0x60` the session put on its link, as `(target, our UDP
    /// port)`.
    async fn next_introduction(&mut self) -> (ClientId, u16) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let rmule_ed2k::Ed2kCommand::RequestHolepunch {
                    target,
                    our_udp_port,
                } = self.session_sent.recv().await.expect("the link is open")
                {
                    return (target, our_udp_port);
                }
            }
        })
        .await
        .expect("a 0x60 reached the session's link")
    }
}

/// A front with nothing learned, plus the halves a test reads its decisions
/// off: the client-UDP send queue and the diagnostics level.
struct Harness {
    front: NattFront<NullSink>,
    /// The node around the front.
    around: Surroundings,
    sent: mpsc::Receiver<ClientUdpSend>,
    diagnostics: DiagnosticsState,
    /// The **Awaited Inbound** registry the front reports retirements to.
    claims: crate::adapters::AwaitedInbound,
    /// The risen-tunnel receiver, kept for a test that runs the whole loop.
    risen: mpsc::Receiver<Risen>,
}

impl Harness {
    fn new() -> Self {
        let (client_udp, sent) = mpsc::channel(256);
        let diagnostics = DiagnosticsState::default();
        let claims = crate::adapters::AwaitedInbound::default();
        let own_identity = crate::own_identity::SharedOwnIdentity::default();
        own_identity.set_user_hash(hash(0xAA));
        let around = Surroundings::new();
        let assembled = assemble(
            NullSink,
            NattIdentity {
                local: RMULE_NATT_CLAIM,
            },
            Arc::new(own_identity) as Arc<dyn NattOwnHash>,
            None,
            NattWiring {
                client_udp,
                server: around.server.clone(),
                reach: around.reach.clone(),
                addresses: around.addresses.clone(),
                admit: crate::adapters::SharedTunnelAdmit::default(),
                claims: claims.clone(),
                peer_pin: crate::adapters::SharedPeerPin::default(),
                diagnostics: diagnostics.clone(),
                events: None,
                prediction: None,
            },
        )
        .expect("the uTP engine starts");
        // The adoption half is dropped: no test here raises a tunnel, and the
        // front holds its own senders, so nothing it emits is lost.
        Self {
            front: assembled.front,
            around,
            sent,
            diagnostics,
            claims,
            risen: assembled.risen,
        }
    }

    /// Traverse toward `target` through our server, as Peer Reach hands it
    /// over: the front puts the `0x60` on the session and opens the attempt.
    /// `buddy` is what the candidate's own facts say, which is all that
    /// decides where the attempt can fall to.
    async fn asked_our_server(
        &mut self,
        target: UserHash,
        low_id: ClientId,
        buddy: Option<crate::callback::BuddyContact>,
        now: Instant,
    ) {
        self.front
            .on_command(
                NattCommand::Traverse {
                    coordinator: AttemptCoordinator::Server { low_id },
                    owner: Some(AttemptOwner {
                        target,
                        facts: crate::callback::NattFacts {
                            buddy,
                            ..buddy_facts()
                        },
                        offer: RendezvousOffer {
                            our_user_hash: hash(0xAA),
                            options: NattConnectOptions::advertise(0, true, false),
                            file_hash: None,
                            claimed_endpoint: None,
                            transport: NattTransport::Utp,
                        },
                    }),
                },
                now,
            )
            .await;
    }

    /// File a download's claim on `target` under the pending callback for
    /// `low_id`, returning its key, the retire channel it is told on, and the
    /// registration that holds the claim while it lives.
    fn claim(
        &self,
        target: UserHash,
        low_id: ClientId,
    ) -> (
        crate::adapters::CallbackKey,
        mpsc::Receiver<(crate::adapters::CallbackKey, AttemptRetirement)>,
        crate::adapters::AwaitedInboundHandle,
    ) {
        let callback = crate::adapters::CallbackKey {
            server: None,
            low_id,
            kad_port: None,
        };
        let (retire_tx, retire_rx) = mpsc::channel(4);
        let claim = self
            .claims
            .register(callback, mpsc::channel(1).0, retire_tx);
        claim.claim_tunnel(
            target,
            crate::adapters::AdoptionBrief {
                own_status: rmule_peer::PartBitmap::downloader_empty(0),
                want_sources: true,
                file: rmule_primitives::Ed2kFileLink {
                    file_hash: FileHash::from_bytes([0x22; FileHash::BYTE_LEN]),
                    size: 9_728_000,
                    name: rmule_primitives::Ed2kText::from_utf8("claimed"),
                    part_hash_set: None,
                    aich_root: None,
                    ipv6_sources: Vec::new(),
                    sources: Default::default(),
                },
            },
            false,
        );
        (callback, retire_rx, claim)
    }

    /// Everything the front has put on the client-UDP send half so far.
    fn drained(&mut self) -> Vec<ClientUdpSend> {
        std::iter::from_fn(|| self.sent.try_recv().ok()).collect()
    }

    /// Begin a rendezvous toward `target` and take the datagram it emits.
    async fn begin(&mut self, target: UserHash, now: Instant) -> Vec<ClientUdpSend> {
        self.front.on_command(rendezvous_toward(target), now).await;
        self.drained()
    }
}

/// Peer Reach's rung-1 command for `target` through the buddy above.
fn rendezvous_toward(target: UserHash) -> NattCommand {
    NattCommand::Traverse {
        coordinator: AttemptCoordinator::Buddy {
            buddy_id: BUDDY_ID,
            buddy_udp: buddy(),
        },
        owner: Some(AttemptOwner {
            target,
            facts: buddy_facts(),
            offer: RendezvousOffer {
                our_user_hash: hash(0xAA),
                options: NattConnectOptions::advertise(0, true, false),
                file_hash: Some(FileHash::from_bytes([0x22; FileHash::BYTE_LEN])),
                claimed_endpoint: None,
                transport: NattTransport::Utp,
            },
        }),
    }
}

fn hint_naming(target: UserHash, endpoint: Ipv4Endpoint) -> Vec<u8> {
    EndpointHint {
        target,
        buddy_id: BUDDY_ID,
        file_hash: None,
        target_endpoint: endpoint,
        options: NattConnectOptions::from_byte(0),
    }
    .encode_udp()
}

/// The candidate's buddy as a source channel named it — the second
/// coordinator's whole address.
fn known_buddy() -> crate::callback::BuddyContact {
    crate::callback::BuddyContact {
        buddy_id: rmule_kad::KadId::from_bytes(BUDDY_ID),
        buddy_udp: Some(buddy()),
    }
}

/// The whole requester ladder in one pass: Peer Reach's command puts a
/// readable rendezvous on the wire, the buddy's hint is believed, its burst is
/// **held** for the half round trip the exchange measured, and its release
/// fires the six punches plus the ±16 sweep at the endpoint the
/// buddy observed.
#[tokio::test]
async fn a_trusted_hint_holds_its_burst_and_then_punches_where_the_buddy_looked() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);

    let emitted = harness.begin(target, t0).await;
    assert_eq!(emitted.len(), 1, "a first attempt is not jittered");
    assert_eq!(emitted[0].to, PeerEndpoint::V4(buddy()));
    assert!(
        emitted[0].crypt_target.is_none(),
        "NAT-T signalling is never obfuscated"
    );
    let relay = rmule_peer::ReaskCallbackUdp::decode_udp(&emitted[0].datagram).expect("a 0x94");
    let body = RendezvousBody::from_forwarded(&relay.forwarded)
        .expect("marked as a rendezvous")
        .expect("well-formed");
    assert_eq!(body.requester, hash(0xAA));

    // The hint arrives 240 ms later, so the burst is held for 120 ms.
    let heard = t0 + Duration::from_millis(240);
    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(buddy()),
            hint_naming(target, at(9, 31999)),
            heard,
        )
        .await;
    assert!(
        harness.drained().is_empty(),
        "the burst is held, not fired on arrival"
    );
    harness
        .front
        .release_held(heard + Duration::from_millis(119))
        .await;
    assert!(harness.drained().is_empty(), "still inside the hold");

    harness
        .front
        .release_held(heard + Duration::from_millis(120))
        .await;
    let burst = harness.drained();
    assert_eq!(burst.len(), 6 + 32, "six at the endpoint, then the sweep");
    assert!(
        burst
            .iter()
            .all(|send| send.datagram == holepunch_datagram() && send.crypt_target.is_none())
    );
    assert!(
        burst[..6]
            .iter()
            .all(|send| send.to == PeerEndpoint::V4(at(9, 31999)))
    );
    assert!(
        harness.front.dials.in_flight(target),
        "the requester dials once its own burst has opened the mapping"
    );
}

/// A hint nobody asked for changes nothing and answers nothing — the only
/// trace it leaves is the refusal count, which is what tells a node that never
/// punches *why*.
#[tokio::test]
async fn an_unsolicited_hint_draws_nothing_and_is_counted_with_its_reason() {
    let mut harness = Harness::new();
    let now = Instant::now();
    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(buddy()),
            hint_naming(hash(0x44), at(9, 31999)),
            now,
        )
        .await;
    harness.front.on_tick(now + Duration::from_secs(1)).await;

    assert!(harness.drained().is_empty());
    assert_eq!(harness.front.dials.len(), 0);
    let session = harness.diagnostics.snapshot().session;
    assert_eq!(session.natt_hint_refusals_total, 1);
    assert_eq!(
        session.natt_last_hint_refusal,
        Some(crate::diagnostics::NattHintRefusal::NotExpected)
    );
}

/// Silence is the dialect's only failure signal, and the clock is what hears
/// it: fifteen seconds without a hint spends one attempt, and the retry the
/// trigger granted goes out on a later tick with nothing else prompting it.
///
/// A spent grant ends the run — the source goes idle with its clock stopped
/// (ADR-0091), so a later trigger meets no stale timeout while
/// the failure count carries across runs to the five-attempt cap. The fifth
/// failure retires the target with the reason diagnostics carry, and it is
/// reported **once**, not once per tick.
#[tokio::test]
async fn hint_silence_spends_each_grant_until_the_target_retires_once() {
    let mut harness = Harness::new();
    let mut now = Instant::now();
    let target = hash(0x44);

    let mut emitted = 0;
    let mut triggers = 0;
    // Re-trigger run after run, as the route tree would when the peer is
    // chosen again; the clock alone drives each run's own retry.
    while harness
        .diagnostics
        .snapshot()
        .session
        .natt_retirements_total
        == 0
    {
        if !harness.front.attempts.contains(&target) {
            emitted += harness.begin(target, now).await.len();
            triggers += 1;
            assert!(triggers < 10, "the cap must be reached in a few runs");
        }
        now += HINT_TIMEOUT;
        harness.front.on_tick(now).await;
        emitted += harness.drained().len();
    }

    let session = harness.diagnostics.snapshot().session;
    assert_eq!(session.natt_retirements_total, 1);
    assert_eq!(
        session.natt_last_retire_reason,
        Some(crate::diagnostics::NattRetirement::Schedule(
            RetireReason::AttemptsExhausted
        ))
    );
    assert_eq!(
        emitted, 5,
        "five rendezvous went out — the dialect's whole per-source budget"
    );
    assert_eq!(session.natt_rendezvous_emitted_total, 5);

    // Ticking on past the retirement reports nothing further: the front drops
    // a retired target, so the clock cannot re-report it once a second.
    for _ in 0..10 {
        now += HINT_TIMEOUT;
        harness.front.on_tick(now).await;
    }
    assert_eq!(
        harness
            .diagnostics
            .snapshot()
            .session
            .natt_retirements_total,
        1
    );
    assert!(harness.drained().is_empty());
}

/// The `0xA1` asymmetry, both halves. An introduction that named us the
/// responder records the expectation and waits — the peer dials, and a dial of
/// our own would put two uTP handshakes on one pinhole. A punch from an
/// endpoint nothing expects is dropped in silence and counted; the dialect has
/// no answer frame, and inventing one would make rmule a reflector.
#[tokio::test]
async fn a_responders_punch_only_refreshes_and_a_strangers_is_never_answered() {
    let mut harness = Harness::new();
    let now = Instant::now();
    harness
        .front
        .on_command(
            NattCommand::Introduced {
                peer_hash: hash(0x44),
                target: at(9, 31999),
                role: rmule_ed2k::HolepunchRole::Responder,
                burst: false,
                source: rmule_peer::natt::PunchTargetSource::Observed,
            },
            now,
        )
        .await;
    assert_eq!(
        harness.front.dials.len(),
        0,
        "the side the server did not name as initiator accepts"
    );

    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(at(9, 31999)),
            holepunch_datagram(),
            now + Duration::from_millis(50),
        )
        .await;
    assert_eq!(harness.front.dials.len(), 0, "a responder never dials");
    assert!(harness.drained().is_empty(), "and never answers");

    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(at(77, 4672)),
            holepunch_datagram(),
            now + Duration::from_millis(60),
        )
        .await;
    assert!(harness.drained().is_empty());
    assert_eq!(
        harness
            .diagnostics
            .snapshot()
            .session
            .natt_unexpected_holepunches_total,
        1
    );
}

/// An initiator role dials the endpoint the server observed, and a later
/// `0xA1` from a **different port on the same IP** does not open a second
/// handshake: one target, one dial in flight. The correction it carries is kept
/// for the next opener, which is the only place it can be used — a dial's
/// `ST_SYN` has already left.
#[tokio::test]
async fn an_initiator_dials_once_however_many_punches_arrive() {
    let mut harness = Harness::new();
    let now = Instant::now();
    harness
        .front
        .on_command(
            NattCommand::Introduced {
                peer_hash: hash(0x44),
                target: at(9, 31999),
                role: rmule_ed2k::HolepunchRole::Initiator,
                burst: false,
                source: rmule_peer::natt::PunchTargetSource::Observed,
            },
            now,
        )
        .await;
    assert!(harness.front.dials.in_flight(hash(0x44)));

    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(at(9, 32005)),
            holepunch_datagram(),
            now + Duration::from_millis(50),
        )
        .await;
    assert_eq!(harness.front.dials.len(), 1);
    assert_eq!(
        harness.front.dials.target(hash(0x44)),
        Some(at(9, 32005)),
        "the punch corrected the port the next opener goes to"
    );
}

/// A punched path is kept alive by an empty `OP_HOLEPUNCH` only while it is
/// **idle**: a busy Tunnel is its own keepalive, and a path that already
/// carried a frame this interval draws nothing.
#[tokio::test]
async fn only_an_idle_punched_path_draws_a_keepalive() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    harness
        .front
        .paths
        .on_path_open(at(9, 31999), 4672, None, t0);
    harness
        .front
        .paths
        .on_path_open(at(10, 31999), 4672, None, t0);

    let keepalive = t0 + rmule_peer::natt::PUNCHED_PATH_KEEPALIVE;
    // One path carried a `0xB2` frame in the meantime — the busy one.
    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(at(10, 31999)),
            vec![rmule_peer::natt::NATT_PROTOCOL, 0x7F],
            keepalive - Duration::from_millis(1),
        )
        .await;
    harness.front.on_tick(keepalive).await;

    let sent = harness.drained();
    assert_eq!(sent.len(), 1, "only the idle path is refreshed");
    assert_eq!(sent[0].to, PeerEndpoint::V4(at(9, 31999)));
    assert_eq!(sent[0].datagram, holepunch_datagram());
}

/// Two peers behind one address are two traversals. Both introductions
/// survive, both are dialed, and neither punch is read as the other's — which
/// is what a single-valued expectation table got wrong.
#[tokio::test]
async fn two_peers_behind_one_address_are_two_traversals() {
    let mut harness = Harness::new();
    let now = Instant::now();
    for (peer, port) in [(hash(0x44), 4001), (hash(0x55), 4002)] {
        harness
            .front
            .on_command(
                NattCommand::Introduced {
                    peer_hash: peer,
                    target: at(9, port),
                    role: rmule_ed2k::HolepunchRole::Initiator,
                    burst: false,
                    source: rmule_peer::natt::PunchTargetSource::Observed,
                },
                now,
            )
            .await;
    }
    assert_eq!(harness.front.dials.len(), 2, "one attempt per peer");

    // A punch from the port the second introduction named belongs to it, and
    // says nothing about the first.
    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(at(9, 4002)),
            holepunch_datagram(),
            now + Duration::from_millis(50),
        )
        .await;
    assert_eq!(harness.front.dials.target(hash(0x44)), Some(at(9, 4001)));
    assert_eq!(harness.front.dials.target(hash(0x55)), Some(at(9, 4002)));
    assert_eq!(
        harness
            .diagnostics
            .snapshot()
            .session
            .natt_unexpected_holepunches_total,
        0
    );
}

/// A `0xA1` that names none of the peers expected behind its address dials
/// **nothing**: one unauthenticated datagram may not fan out into several
/// handshakes. It still refreshes, and it is counted so a node can say why it
/// is not dialing.
#[tokio::test]
async fn a_punch_that_names_nobody_refreshes_and_dials_nothing() {
    let mut harness = Harness::new();
    let now = Instant::now();
    for (peer, port) in [(hash(0x44), 4001), (hash(0x55), 4002)] {
        harness
            .front
            .on_command(
                NattCommand::Introduced {
                    peer_hash: peer,
                    target: at(9, port),
                    role: rmule_ed2k::HolepunchRole::Initiator,
                    burst: false,
                    source: rmule_peer::natt::PunchTargetSource::Observed,
                },
                now,
            )
            .await;
    }
    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(at(9, 51515)),
            holepunch_datagram(),
            now + Duration::from_millis(50),
        )
        .await;

    assert_eq!(harness.front.dials.len(), 2, "no third traversal was armed");
    assert_eq!(harness.front.dials.target(hash(0x44)), Some(at(9, 4001)));
    assert_eq!(harness.front.dials.target(hash(0x55)), Some(at(9, 4002)));
    assert!(harness.drained().is_empty(), "and never answers");
    let session = harness.diagnostics.snapshot().session;
    assert_eq!(session.natt_ambiguous_holepunches_total, 1);
    assert_eq!(session.natt_unexpected_holepunches_total, 0);
}
