//! NAT-T transport legs (ADR-0091, Correctness Tier): two nodes wired back to
//! back over a **fake `Transport`** — no socket anywhere — so the uTP and QUIC
//! engines, the `0xB2` demux, the KEY-frame interplay and the `Tunnel` are
//! exercised end to end and deterministically.
//!
//! The headline is [`a_peer_session_runs_unchanged_inside_a_tunnel`]: a real
//! `PeerSession`, driven by the real harness, completing a real eD2k hello
//! exchange inside a uTP tunnel whose datagrams never touch a socket. That is
//! the claim the whole seam exists to make.
//!
//! Live evidence — a punch through real gateways — is the interop harness's,
//! not this file's.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rmule_net::natt::{
    Admission, NattCrypt, NattDatagramSink, NattDemux, NattDisposition, NattIdentity, NattOwnHash,
    NattSender, Tunnel, TunnelRegistry, TunnelSlot, TunnelTransport,
};
use rmule_net::peer::{ConnectOptions, Connection, PeerStreamRole};
use rmule_peer::natt::{
    CapsFrame, HelloNattClaim, NattConnectOptions, NattFrame, NattTransport, TransportVerdict,
};
use rmule_peer::{ConnectionEvent, PeerEvent, PeerHandshakeContext};
use rmule_primitives::{
    AddressFamily, ClientDecryptKeys, ClientId, ClientIdentity, DatagramNonce,
    DatagramSenderAddress, Ed2kText, FileHash, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, UserHash,
    decrypt_datagram_client, is_udp_plaintext_marker,
};
use tokio::sync::mpsc;

/// One datagram in flight on the fake wire: who sent it, who it is for, and its
/// bytes exactly as the sender framed them.
type Datagram = (PeerEndpoint, PeerEndpoint, Vec<u8>);

/// The fake **Family Pair**: a sink that records what a node emitted and hands
/// it to the router rather than to a socket.
///
/// This is the whole point of ADR-0091's "the engine never owns a socket" — the
/// seam is a trait, so a test can stand in for the wire completely.
struct FakeWire {
    me: PeerEndpoint,
    tx: mpsc::UnboundedSender<Datagram>,
    log: Arc<Mutex<Vec<Datagram>>>,
}

impl NattDatagramSink for FakeWire {
    async fn send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
        self.try_send_to(peer, datagram)
    }

    fn try_send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
        let frame = (self.me, peer, datagram.to_vec());
        self.log.lock().expect("wire log").push(frame.clone());
        let _ = self.tx.send(frame);
        Ok(datagram.len())
    }

    fn poll_send_to(
        &self,
        _cx: &mut Context<'_>,
        peer: PeerEndpoint,
        datagram: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.try_send_to(peer, datagram))
    }

    fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.me.ip(), self.me.port())
    }
}

/// Armed self-facts: a node that holds an IPv4 address and will obfuscate once
/// a **Key Frame** supplies the peer's hash.
struct ArmedCrypt {
    hash: UserHash,
    v4: [u8; 4],
}

impl NattCrypt for ArmedCrypt {
    fn armed(&self) -> bool {
        true
    }

    fn crypt_options(&self) -> u8 {
        0x01
    }

    fn own_user_hash(&self) -> UserHash {
        self.hash
    }

    fn sender_address(&self, family: AddressFamily) -> Option<DatagramSenderAddress> {
        match family {
            AddressFamily::V4 => Some(DatagramSenderAddress::V4(self.v4)),
            AddressFamily::V6 => None,
        }
    }

    fn nonce(&self) -> DatagramNonce {
        DatagramNonce {
            marker_byte: 0x40,
            random_key: 0xBEEF,
            padding: Vec::new(),
        }
    }
}

/// A settable identity source — the test-tier stand-in for
/// `SharedOwnIdentity::user_hash`, cheap to clone (an `Arc` inside) and
/// mutable after a front has already started, which is the whole point: it
/// is what lets a test prove the demux reads live rather than a value
/// captured at [`NattDemux::start`].
#[derive(Clone, Default)]
struct SettableHash(Arc<Mutex<Option<UserHash>>>);

impl SettableHash {
    fn known(hash: UserHash) -> Self {
        let cell = Self::default();
        cell.set(hash);
        cell
    }

    fn set(&self, hash: UserHash) {
        *self.0.lock().expect("settable hash") = Some(hash);
    }
}

impl NattOwnHash for SettableHash {
    fn user_hash(&self) -> Option<UserHash> {
        *self.0.lock().expect("settable hash")
    }
}

/// The sender address a receiver keys an obfuscated datagram's decrypt on: the
/// source address it observes, whose width picks the 23- or 35-byte layout.
fn sender_address_of(from: PeerEndpoint) -> DatagramSenderAddress {
    DatagramSenderAddress::from_ip(from.ip())
}

fn endpoint(last: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, last), 4672))
}

fn hash(fill: u8) -> UserHash {
    UserHash::from_bytes([fill; UserHash::BYTE_LEN])
}

/// rmule's shipped posture: uTP served, QUIC dark.
const UTP_ONLY: HelloNattClaim = HelloNattClaim {
    utp: true,
    quic: false,
};

/// The posture a build with a proven QUIC runtime would hold. Used only where a
/// test needs a QUIC engine to exist — ADR-0091 keeps this off in production
/// until a live handshake is proven.
const BOTH: HelloNattClaim = HelloNattClaim {
    utp: true,
    quic: true,
};

/// Two NAT-T fronts and the router that carries datagrams between them.
struct FakeNetwork {
    a: Arc<NattDemux<FakeWire>>,
    b: Arc<NattDemux<FakeWire>>,
    a_at: PeerEndpoint,
    b_at: PeerEndpoint,
    /// Each node's **Tunnel Registry**, shared with its demux.
    a_registry: Arc<Mutex<TunnelRegistry>>,
    b_registry: Arc<Mutex<TunnelRegistry>>,
    log: Arc<Mutex<Vec<Datagram>>>,
    router: tokio::task::JoinHandle<()>,
}

impl Drop for FakeNetwork {
    fn drop(&mut self) {
        self.router.abort();
    }
}

impl FakeNetwork {
    /// Wire two nodes together. `armed` arms both sides' obfuscation, which is
    /// what makes the **Key Frame** interplay observable.
    fn build(local: HelloNattClaim, armed: bool) -> Self {
        Self::between(local, armed, endpoint(1), endpoint(2))
    }

    /// Wire two nodes together at `a_at` and `b_at`, in either family. An
    /// armed wire is IPv4: [`ArmedCrypt`] holds only a v4 self-address.
    fn between(local: HelloNattClaim, armed: bool, a_at: PeerEndpoint, b_at: PeerEndpoint) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Datagram>();
        let log = Arc::new(Mutex::new(Vec::new()));
        let front = |me: PeerEndpoint, own: UserHash, registry: &Arc<Mutex<TunnelRegistry>>| {
            // The key is our own external address in the family the datagram
            // leaves by, and the recipient keys its decrypt on the source
            // address it observes — so on this wire the two are the same
            // value, which is the invariant ADR-0087 states.
            let crypt: Option<Box<dyn NattCrypt>> = armed.then(|| {
                let std::net::IpAddr::V4(ip) = me.ip() else {
                    unreachable!("an armed wire is IPv4")
                };
                Box::new(ArmedCrypt {
                    hash: own,
                    v4: ip.octets(),
                }) as Box<dyn NattCrypt>
            });
            let sender = Arc::new(NattSender::new(
                FakeWire {
                    me,
                    tx: tx.clone(),
                    log: Arc::clone(&log),
                },
                crypt,
            ));
            Arc::new(
                NattDemux::start(
                    NattIdentity { local },
                    Arc::new(SettableHash::known(own)) as Arc<dyn NattOwnHash>,
                    sender,
                    Arc::clone(registry),
                )
                .expect("both engines start"),
            )
        };
        let a_registry = Arc::new(Mutex::new(TunnelRegistry::new()));
        let b_registry = Arc::new(Mutex::new(TunnelRegistry::new()));
        let a = front(a_at, hash(0xAA), &a_registry);
        let b = front(b_at, hash(0xBB), &b_registry);
        let (route_a, route_b) = (Arc::clone(&a), Arc::clone(&b));
        let router = tokio::spawn(async move {
            while let Some((from, to, datagram)) = rx.recv().await {
                let (front, ours) = if to == b_at {
                    (&route_b, hash(0xBB))
                } else {
                    (&route_a, hash(0xAA))
                };
                // The receive transform the production client-UDP front runs
                // ahead of the protocol demux (ADR-0046): a plaintext-marker
                // first byte bypasses, an obfuscated datagram is dual-path
                // decrypted with our own hash and the source address we
                // observe, and a miss falls through as-is. Without this the
                // demux would see a random crypt marker and drop the frame —
                // which is exactly what happened the first time this wire was
                // built without it, and it stalled the uTP handshake the
                // moment each side learned a key.
                let plain = decrypt_datagram_client(
                    &datagram,
                    &ClientDecryptKeys {
                        user_hash: Some(&ours),
                        sender: sender_address_of(from),
                        ..Default::default()
                    },
                )
                .map_or(datagram, |decrypted| decrypted.payload);
                front.on_datagram(from, &plain, &any_source, Instant::now()).await;
            }
        });
        Self {
            a,
            b,
            a_at,
            b_at,
            a_registry,
            b_registry,
            log,
            router,
        }
    }

    /// Every datagram either node has emitted, in order.
    fn wire(&self) -> Vec<Datagram> {
        self.log.lock().expect("wire log").clone()
    }
}

/// Every source expected: these legs are about what a tunnel does once its
/// opener is admitted, not about who may open one.
fn any_source(_: std::net::IpAddr) -> bool {
    true
}

fn ctx(user_hash: UserHash, nickname: &str) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(user_hash, Ed2kText::from_utf8(nickname), 4662, 0x3C),
        client_id: ClientId::from_u32(0x1000_0001),
        ed2k_client_id: ClientId::from_u32(0x1000_0001),
        public_ip: None,
        connected_server: None,
    }
}

async fn identify(conn: &mut Connection) -> UserHash {
    loop {
        match conn.next_event().await {
            Some(PeerEvent::Connection(ConnectionEvent::Identified { identity })) => {
                return identity.user_hash();
            }
            Some(PeerEvent::Connection(ConnectionEvent::Disconnected { reason })) => {
                panic!("tunnel session closed: {reason:?}")
            }
            Some(_) => continue,
            None => panic!("the driver ended before the peer identified"),
        }
    }
}

/// **The claim the seam exists to make.** A real `PeerSession`, driven by the
/// real `spawn_connection` harness, completing a real eD2k hello exchange
/// inside a uTP `Tunnel` whose datagrams never reach a socket.
///
/// Nothing in `rmule-peer` and nothing in `driver` was changed for this: the
/// tunnel is an `AsyncRead + AsyncWrite`, which is the bound the harness
/// already took. If this passes, a peer behind two NATs runs the identical
/// session a peer on the open internet does.
#[tokio::test]
async fn a_peer_session_runs_unchanged_inside_a_tunnel() {
    let net = FakeNetwork::build(UTP_ONLY, true);
    let (dialed, accepted) = tokio::join!(net.a.utp().connect(net.b_at), net.b.utp().accept());
    let dialed: Tunnel = dialed.expect("the uTP dial completed over the fake wire");
    let accepted: Tunnel = accepted.expect("the responder accepted it");

    assert_eq!(dialed.transport(), TunnelTransport::Utp);
    assert_eq!(dialed.peer(), net.b_at);
    assert_eq!(accepted.peer(), net.a_at);
    assert_eq!(dialed.role(), PeerStreamRole::Dialer);
    assert_eq!(accepted.role(), PeerStreamRole::Responder);

    let options = ConnectOptions {
        hello_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let mut initiator = Connection::over_stream(
        dialed,
        net.b_at,
        PeerStreamRole::Dialer,
        ctx(hash(0xAA), "rmule-punch-a"),
        options.clone(),
    );
    let mut responder = Connection::over_stream(
        accepted,
        net.a_at,
        PeerStreamRole::Responder,
        ctx(hash(0xBB), "rmule-punch-b"),
        options,
    );

    let (seen_by_a, seen_by_b) = tokio::join!(identify(&mut initiator), identify(&mut responder));
    assert_eq!(seen_by_a, hash(0xBB), "the dialer identified the responder");
    assert_eq!(seen_by_b, hash(0xAA), "the responder identified the dialer");

    // And the datagrams that carried it were NAT-T frames: a KEY frame first
    // (the opening `ST_SYN` asserted our hash), then obfuscated transport
    // frames, none of which leads with a whitelisted protocol byte.
    let wire = net.wire();
    assert!(
        wire.iter()
            .any(|(_, _, bytes)| bytes.as_slice() == NattFrame::Key(hash(0xAA)).encode()),
        "the opening SYN asserted our user hash"
    );
    assert!(
        wire.iter()
            .any(|(_, _, bytes)| !is_udp_plaintext_marker(bytes[0])),
        "once each side learned a key, transport frames went out obfuscated"
    );

    initiator.shutdown().await.expect("shutdown");
    responder.shutdown().await.expect("shutdown");
}

/// The same tunnel carries an obfuscated eD2k stream: `CryptStream` is generic
/// over what it wraps, so ADR-0042's RC4 layer composes over ADR-0091's
/// transport without either knowing about the other.
///
/// Two layers of obfuscation end up on the wire here — the per-datagram one
/// around each `0xB2` frame and the per-stream one inside it — which is exactly
/// what eMuleAI gets from attaching its uTP socket beneath `CEncryptedStreamSocket`.
#[tokio::test]
async fn a_crypt_stream_composes_over_a_tunnel() {
    use rmule_net::driver::CryptStream;
    use rmule_net::peer::PeerObfuscationTransport;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let net = FakeNetwork::build(UTP_ONLY, false);
    let (dialed, accepted) = tokio::join!(net.a.utp().connect(net.b_at), net.b.utp().accept());
    let target = hash(0xBB);

    let initiator = tokio::spawn(async move {
        let mut crypt = CryptStream::new(
            dialed.expect("dial"),
            PeerObfuscationTransport::initiator(target),
        );
        crypt.complete_handshake().await.expect("crypt handshake");
        crypt.write_all(b"inside the tunnel").await.expect("write");
        crypt.flush().await.expect("flush");
    });

    let mut crypt = CryptStream::new(
        accepted.expect("accept"),
        PeerObfuscationTransport::responder(target),
    );
    let mut got = [0u8; 17];
    crypt.read_exact(&mut got).await.expect("read");
    assert_eq!(&got, b"inside the tunnel");
    initiator.await.expect("initiator task");
}

/// An IPv6 source that completes one `ST_SYN` handshake is admitted only for
/// as long as the tunnel it raised lives. Core adopts only IPv4 paths and drops
/// any other tunnel, and the only release used to be the close notice of a path
/// it had adopted — so every distinct v6 `(address, port)` that finished a
/// handshake kept a `Held` slot, and `Inject` admission, for the process's life.
#[tokio::test]
async fn an_ipv6_tunnel_frees_its_registry_slot_when_it_is_dropped() {
    let v6 = |last: u16| {
        PeerEndpoint::V6(Ipv6Endpoint::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, last),
            4672,
        ))
    };
    let net = FakeNetwork::between(UTP_ONLY, false, v6(1), v6(2));
    let (dialed, accepted) = tokio::join!(net.a.utp().connect(net.b_at), net.b.utp().accept());
    let dialed = dialed.expect("the v6 dial completed over the fake wire");
    let accepted = accepted.expect("the responder accepted the v6 SYN");
    assert_eq!(accepted.peer(), net.a_at);
    let slot_at_b = || net.b_registry.lock().expect("registry").slot(net.a_at);
    assert_eq!(slot_at_b(), Some(TunnelSlot::Held));

    // What core's `adopt` does with a tunnel on a path no punch opened.
    drop(accepted);
    assert_eq!(slot_at_b(), None, "the declined tunnel's slot went with it");
    assert_eq!(
        net.b_registry
            .lock()
            .expect("registry")
            .admit(net.a_at, false, any_source, Instant::now()),
        Admission::Drop,
        "a late non-SYN from the closed source is a stranger's again"
    );

    drop(dialed);
    assert_eq!(
        net.a_registry.lock().expect("registry").slot(net.b_at),
        None,
        "a dialed tunnel's slot goes with it too"
    );
}

/// The demux matrix: every frame type reaches the arm that owns it, and the two
/// transport arms are gated by the registry.
#[tokio::test]
async fn the_demux_routes_every_frame_type_and_gates_the_transport_arms() {
    let net = FakeNetwork::build(UTP_ONLY, true);
    let now = Instant::now();

    // A non-opening uTP packet from a stranger is dropped before the engine —
    // aMule's A2: the alternative is an `ST_RESET` to an unverified address.
    let mut data = [0u8; 20];
    data[0] = 0x01; // ST_DATA
    assert_eq!(
        net.b
            .on_datagram(net.a_at, &NattFrame::Utp(&data).encode(), &any_source, now)
            .await,
        NattDisposition::Utp(Admission::Drop)
    );

    // An `ST_SYN` opens the endpoint, and the follow-up is then admitted.
    let mut syn = [0u8; 20];
    syn[0] = 0x41; // ST_SYN
    assert_eq!(
        net.b
            .on_datagram(net.a_at, &NattFrame::Utp(&syn).encode(), &any_source, now)
            .await,
        NattDisposition::Utp(Admission::Opened)
    );
    assert_eq!(
        net.b
            .on_datagram(net.a_at, &NattFrame::Utp(&data).encode(), &any_source, now)
            .await,
        NattDisposition::Utp(Admission::Inject)
    );

    // A QUIC frame with no QUIC runtime is dropped, not answered.
    assert_eq!(
        net.b
            .on_datagram(net.a_at, &NattFrame::Quic(&[0xC0, 0x00]).encode(), &any_source, now)
            .await,
        NattDisposition::QuicUnavailable
    );

    // A KEY frame teaches the endpoint's hash.
    assert_eq!(
        net.b
            .on_datagram(net.a_at, &NattFrame::Key(hash(0xAA)).encode(), &any_source, now)
            .await,
        NattDisposition::KeyLearned(hash(0xAA))
    );

    // Anything that does not decode is dropped in silence — no reply frame
    // exists in this dialect, so inventing one would make rmule a reflector.
    assert!(matches!(
        net.b.on_datagram(net.a_at, &[0xB2, 0x7F, 0x00], &any_source, now).await,
        NattDisposition::Malformed(_)
    ));
    assert!(matches!(
        net.b.on_datagram(net.a_at, &[0xB2], &any_source, now).await,
        NattDisposition::Malformed(_)
    ));
}

/// An `ST_SYN` from a source nobody expects opens nothing and draws nothing:
/// it never reaches the engine, so no `ST_STATE` and no KEY frame leave
/// (ADR-0091, security rule 10). The same opener from an expected source
/// opens the slot.
#[tokio::test]
async fn an_opener_from_an_unexpected_ip_is_dropped_with_no_answer() {
    let net = FakeNetwork::build(UTP_ONLY, true);
    let mut syn = [0u8; 20];
    syn[0] = 0x41; // ST_SYN
    let frame = NattFrame::Utp(&syn).encode();
    let nobody = |_: std::net::IpAddr| false;
    assert_eq!(
        net.b
            .on_datagram(net.a_at, &frame, &nobody, Instant::now())
            .await,
        NattDisposition::Utp(Admission::Drop)
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(net.wire().is_empty(), "nothing left the gated node");
    assert_eq!(net.b_registry.lock().expect("registry").slot(net.a_at), None);

    assert_eq!(
        net.b
            .on_datagram(net.a_at, &frame, &any_source, Instant::now())
            .await,
        NattDisposition::Utp(Admission::Opened)
    );
}

/// A CAPS probe is answered exactly once, with a CAPS-ACK that is never itself
/// answered — and a probe addressed to somebody else draws nothing at all.
#[tokio::test]
async fn a_caps_probe_is_answered_once_and_a_misaddressed_one_is_not() {
    let net = FakeNetwork::build(UTP_ONLY, true);
    let now = Instant::now();
    let probe = |expected: UserHash| CapsFrame {
        connect_options: NattConnectOptions::advertise(0x01, true, true),
        sender: hash(0xAA),
        expected_recipient: expected,
        file_hash: FileHash::from_bytes([0; FileHash::BYTE_LEN]),
    };

    let answered = net
        .b
        .on_datagram(net.a_at, &NattFrame::Caps(probe(hash(0xBB))).encode(), &any_source, now)
        .await;
    assert_eq!(
        answered,
        NattDisposition::CapsAnswered {
            sender: hash(0xAA),
            // The peer offers QUIC; this build serves only uTP, so the
            // exchange settles on uTP. A local veto demotes rather than
            // disqualifies.
            transport: Some(NattTransport::Utp),
        }
    );
    let answers: Vec<_> = net
        .wire()
        .into_iter()
        .filter(|(from, _, bytes)| *from == net.b_at && bytes.first() == Some(&0xB2))
        .collect();
    assert_eq!(answers.len(), 1, "exactly one CAPS-ACK");
    assert_eq!(
        answers[0].2[1], 0x03,
        "and it is an ACK, not a second probe"
    );

    // An ACK is adopted and not answered.
    let adopted = net
        .b
        .on_datagram(
            net.a_at,
            &NattFrame::CapsAck(probe(hash(0xBB))).encode(),
            &any_source,
            now,
        )
        .await;
    assert!(matches!(adopted, NattDisposition::CapsAckAdopted { .. }));
    assert_eq!(
        net.wire()
            .iter()
            .filter(|(from, _, _)| *from == net.b_at)
            .count(),
        1,
        "the ACK drew no further frame"
    );

    // A probe naming another node draws nothing: answering would confirm an
    // identity to whoever misrouted it.
    let not_ours = net
        .b
        .on_datagram(net.a_at, &NattFrame::Caps(probe(hash(0x77))).encode(), &any_source, now)
        .await;
    assert_eq!(not_ours, NattDisposition::CapsNotOurs);
    assert_eq!(
        net.wire()
            .iter()
            .filter(|(from, _, _)| *from == net.b_at)
            .count(),
        1
    );
}

/// The identity source is read per CAPS frame, not captured at
/// `NattDemux::start`: a front begun before its own hash exists answers
/// nothing, and the very same probe is answered once the cell is set — with
/// the acquired hash as the CAPS-ACK's sender, never a captured or
/// zero-filled one. A probe naming some other hash is `CapsNotOurs` once
/// identity exists, same as ever.
#[tokio::test]
async fn a_caps_probe_is_silent_before_identity_and_answered_once_it_arrives() {
    let (tx, _rx) = mpsc::unbounded_channel::<Datagram>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let me = endpoint(1);
    let peer = endpoint(2);
    let sender = Arc::new(NattSender::new(
        FakeWire {
            me,
            tx,
            log: Arc::clone(&log),
        },
        None,
    ));
    let own_hash = SettableHash::default();
    let demux = NattDemux::start(
        NattIdentity { local: UTP_ONLY },
        Arc::new(own_hash.clone()) as Arc<dyn NattOwnHash>,
        sender,
        Arc::new(Mutex::new(TunnelRegistry::new())),
    )
    .expect("the uTP engine starts");

    let acquired = hash(0x77);
    let probe = |expected: UserHash| CapsFrame {
        connect_options: NattConnectOptions::advertise(0x01, true, false),
        sender: hash(0xAA),
        expected_recipient: expected,
        file_hash: FileHash::from_bytes([0; FileHash::BYTE_LEN]),
    };
    let now = Instant::now();

    let before = demux
        .on_datagram(peer, &NattFrame::Caps(probe(acquired)).encode(), &any_source, now)
        .await;
    assert_eq!(before, NattDisposition::CapsBeforeIdentity);
    assert!(
        log.lock().expect("wire log").is_empty(),
        "no answer while identity is unknown"
    );

    own_hash.set(acquired);

    let answered = demux
        .on_datagram(peer, &NattFrame::Caps(probe(acquired)).encode(), &any_source, now)
        .await;
    assert_eq!(
        answered,
        NattDisposition::CapsAnswered {
            sender: hash(0xAA),
            transport: Some(NattTransport::Utp),
        }
    );
    let answers = log.lock().expect("wire log").clone();
    assert_eq!(answers.len(), 1, "exactly one CAPS-ACK");
    let decoded = match NattFrame::decode(&answers[0].2).expect("our own frame decodes") {
        NattFrame::CapsAck(caps) => caps,
        other => panic!("expected a CAPS-ACK, got {other:?}"),
    };
    assert_eq!(
        decoded.sender, acquired,
        "the CAPS-ACK carries the hash acquired after start, not a captured one"
    );

    // Identity now exists, but this frame does not name it.
    let not_ours = demux
        .on_datagram(peer, &NattFrame::Caps(probe(hash(0x11))).encode(), &any_source, now)
        .await;
    assert_eq!(not_ours, NattDisposition::CapsNotOurs);
}

/// The 1500 ms legacy fallback, end to end through the demux: a peer that
/// claimed uTP and not QUIC never stalls, and one that claimed QUIC is waited
/// on for exactly the window.
#[tokio::test]
async fn the_caps_probe_window_gates_only_a_quic_claiming_peer() {
    let net = FakeNetwork::build(UTP_ONLY, false);
    let now = Instant::now();

    net.a.probe_sent(net.b_at, UTP_ONLY, now);
    assert_eq!(
        net.a.verdict(net.b_at, UTP_ONLY, now),
        TransportVerdict::Ready(NattTransport::Utp)
    );

    let quic_claimer = endpoint(9);
    net.a.probe_sent(quic_claimer, BOTH, now);
    assert_eq!(
        net.a.verdict(quic_claimer, BOTH, now),
        TransportVerdict::AwaitingCaps
    );
    assert_eq!(
        net.a
            .verdict(quic_claimer, BOTH, now + Duration::from_millis(1500)),
        TransportVerdict::Ready(NattTransport::Utp)
    );
}

/// A QUIC failure blacklists the endpoint for two minutes, and the CAPS frame
/// rmule then sends that endpoint has `0x40` cleared — the endpoint is told
/// "no QUIC" for this exchange while the local capability is untouched.
#[tokio::test]
async fn a_quic_failure_clears_the_quic_bit_for_that_endpoint_only() {
    let net = FakeNetwork::build(BOTH, false);
    let now = Instant::now();
    let probe = CapsFrame {
        connect_options: NattConnectOptions::advertise(0, true, true),
        sender: hash(0xAA),
        expected_recipient: hash(0xBB),
        file_hash: FileHash::from_bytes([0; FileHash::BYTE_LEN]),
    };

    net.b.quic_failed(net.a_at, now);
    net.b
        .on_datagram(net.a_at, &NattFrame::Caps(probe).encode(), &any_source, now)
        .await;
    let answer = net
        .wire()
        .into_iter()
        .find(|(from, _, _)| *from == net.b_at)
        .expect("a CAPS-ACK went out");
    let decoded = match NattFrame::decode(&answer.2).expect("our own frame decodes") {
        NattFrame::CapsAck(caps) => caps,
        other => panic!("expected a CAPS-ACK, got {other:?}"),
    };
    assert!(
        !decoded.connect_options.supports_quic(),
        "a blacklisted endpoint is told no QUIC"
    );
    assert!(
        decoded.connect_options.supports_utp(),
        "and uTP is still offered"
    );

    // A different endpoint is unaffected: the blacklist is a fact about one
    // mapping, not about this build.
    net.b
        .on_datagram(endpoint(9), &NattFrame::Caps(probe).encode(), &any_source, now)
        .await;
    let other = net
        .wire()
        .into_iter()
        .rfind(|(from, _, _)| *from == net.b_at)
        .expect("a second CAPS-ACK");
    let decoded = match NattFrame::decode(&other.2).expect("our own frame decodes") {
        NattFrame::CapsAck(caps) => caps,
        other => panic!("expected a CAPS-ACK, got {other:?}"),
    };
    assert!(decoded.connect_options.supports_quic());
}

/// The QUIC engine, end to end over the fake wire: eMuleAI's pinned TLS
/// parameters, the `EAQN1` proof gate, and a `Tunnel` that carries application
/// bytes only after the proof is accepted.
///
/// This proves rmule agrees with **rmule**. No two implementations have ever
/// completed a QUIC NAT-T handshake — eMuleAI's own author says so — which is
/// exactly why `CT_MOD_MISCOPTIONS` bit 4 stays dark until a live one is seen.
#[tokio::test]
async fn a_quic_tunnel_rises_and_carries_a_peer_session() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let net = FakeNetwork::build(BOTH, true);
    let responder = Arc::clone(&net.b);
    let accepting = tokio::spawn(async move {
        responder
            .quic()
            .expect("a QUIC-serving build has an engine")
            .accept()
            .await
            .expect("the endpoint is open")
    });
    let dialed = net
        .a
        .quic()
        .expect("a QUIC-serving build has an engine")
        .connect(net.b_at, Some(hash(0xBB)), None, false)
        .await
        .expect("the QUIC handshake and the EAQN1 proof both completed");
    let mut accepted = accepting
        .await
        .expect("accept task")
        .expect("the responder raised its side");

    assert_eq!(dialed.transport(), TunnelTransport::Quic);
    assert_eq!(accepted.transport(), TunnelTransport::Quic);

    let mut dialed = dialed;
    dialed.write_all(b"eD2k inside QUIC").await.expect("write");
    dialed.flush().await.expect("flush");
    let mut got = [0u8; 16];
    accepted.read_exact(&mut got).await.expect("read");
    assert_eq!(&got, b"eD2k inside QUIC");
}

/// A QUIC proof naming a third node is refused and no tunnel rises — the gate
/// is before the data, not beside it.
#[tokio::test]
async fn a_quic_proof_for_another_node_raises_no_tunnel() {
    let net = FakeNetwork::build(BOTH, false);
    let responder = Arc::clone(&net.b);
    let accepting = tokio::spawn(async move {
        responder
            .quic()
            .expect("engine")
            .accept()
            .await
            .expect("the endpoint is open")
    });
    let refused = net
        .a
        .quic()
        .expect("engine")
        .connect(net.b_at, Some(hash(0x77)), None, false)
        .await;
    assert!(
        refused.is_err(),
        "a proof addressed to 0x77 must not raise a tunnel to 0xBB"
    );
    assert!(accepting.await.expect("accept task").is_err());
}
