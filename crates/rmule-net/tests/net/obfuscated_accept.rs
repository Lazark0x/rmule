//! Inbound obfuscated-accept tracer (ADR-0042): a `PeerListener` with
//! an obfuscation policy accepts an RC4-obfuscated dialer, runs the handshake
//! below the session, and identifies the peer hello that flowed through the
//! crypt layer. Plus the adversarial `Required`-refuses-plaintext path, and
//! its one exception: a plain dial from an address a reachability test is
//! awaited from is admitted as a Test Connection (ADR-0046).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::fixture::{RESPONDER_HASH, flow_r_dialback};
use rmule_net::driver::CryptStream;
use rmule_net::peer::{
    Admitted, AwaitedTesters, ConnectOptions, ObfuscationConfig, ObfuscationPolicy, PeerListener,
    PeerNetError, PeerObfuscationTransport,
};
use rmule_peer::{ConnectionEvent, PeerEvent, PeerHandshakeContext, PeerOpcode, SideEvent};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, Packet, UserHash};
use rmule_testkit::wire;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn responder_ctx() -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes(RESPONDER_HASH),
            Ed2kText::from_utf8("rmule-responder"),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0x1000_0001),
        ed2k_client_id: ClientId::from_u32(0x1000_0001),
        public_ip: None,
        connected_server: Some(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661)),
    }
}

#[tokio::test]
async fn accepts_obfuscated_inbound_and_identifies_peer() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let dialer_hash = UserHash::from_bytes([0xBE; 16]);

    // Transport Probe (ADR-0040/0042): a raw CryptStream dialer exercising the
    // RC4 obfuscation transport, which testkit fakes don't speak — so it stays
    // a hand-rolled socket. The dialer obfuscates toward the responder, keyed on
    // the responder's user hash (as it would be from a source row).
    let dialer = tokio::spawn(async move {
        let tcp = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();
        let transport = PeerObfuscationTransport::initiator(UserHash::from_bytes(RESPONDER_HASH));
        let mut crypt = CryptStream::new(tcp, transport);
        crypt
            .write_all(&wire::hello_bytes(dialer_hash, "obf-dialer"))
            .await
            .unwrap();
        crypt.flush().await.unwrap();
        // The reply must arrive decrypted and frame as OP_HELLOANSWER.
        let mut buf = vec![0u8; 4096];
        let n = crypt.read(&mut buf).await.unwrap();
        assert!(n > 0, "reply bytes through the crypt layer");
        let (packet, _) = Packet::decode(&buf[..n]).expect("decode reply frame");
        assert_eq!(packet.opcode(), PeerOpcode::HelloAnswer.as_u8());
        let mut sink = [0u8; 64];
        let _ = crypt.read(&mut sink).await;
    });

    let options = ConnectOptions {
        obfuscation: Some(ObfuscationConfig {
            policy: ObfuscationPolicy::Supported,
        }),
        ..Default::default()
    };
    let mut conn = listener
        .accept(responder_ctx(), options)
        .await
        .expect("accept");

    let mut identity = None;
    while let Some(event) = conn.next_event().await {
        match event {
            PeerEvent::Connection(ConnectionEvent::Identified { identity: id }) => {
                identity = Some(id);
                break;
            }
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. }) => break,
            _ => {}
        }
    }
    let identity = identity.expect("Identified arrived through the crypt layer");
    assert_eq!(identity.user_hash(), dialer_hash);

    conn.shutdown().await.expect("shutdown");
    let _ = dialer.await;
}

#[tokio::test]
async fn required_policy_refuses_a_plaintext_peer() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());

    // Transport Probe (ADR-0040): a raw plaintext dialer asserting the
    // `Required` policy refuses a plaintext opener (no reply, so FakeDialer's
    // hello-answer assertion cannot stand in) — stays a hand-rolled socket.
    let dialer = tokio::spawn(async move {
        let mut tcp = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();
        // A plaintext hello: its first byte is a known protocol marker.
        let _ = tcp
            .write_all(&wire::hello_bytes(
                UserHash::from_bytes([0x33; 16]),
                "plain",
            ))
            .await;
        let mut sink = [0u8; 64];
        let _ = tcp.read(&mut sink).await;
    });

    let options = ConnectOptions {
        obfuscation: Some(ObfuscationConfig {
            policy: ObfuscationPolicy::Required,
        }),
        ..Default::default()
    };
    match listener.accept(responder_ctx(), options).await {
        Err(PeerNetError::PlaintextRefused { .. }) => {}
        Err(other) => panic!("expected PlaintextRefused, got {other:?}"),
        Ok(_) => panic!("expected PlaintextRefused, got an accepted connection"),
    }
    let _ = dialer.await;
}

/// A test-dialer set awaiting exactly one address.
struct Awaiting(IpAddr);

impl AwaitedTesters for Awaiting {
    fn awaits_test_from(&self, ip: IpAddr) -> bool {
        ip == self.0
    }
}

fn options_under(policy: ObfuscationPolicy) -> ConnectOptions {
    ConnectOptions {
        obfuscation: Some(ObfuscationConfig { policy }),
        ..Default::default()
    }
}

/// Dial `bound` in plaintext, send a hello, and return the first frame's
/// protocol byte and opcode the listener answers with (`None` if it closed).
async fn plain_hello_answer(bound: SocketAddrV4) -> Option<(u8, u8)> {
    let mut tcp = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();
    tcp.write_all(&wire::hello_bytes(
        UserHash::from_bytes([0x33; 16]),
        "tester",
    ))
    .await
    .unwrap();
    let mut head = [0u8; 6];
    tcp.read_exact(&mut head).await.ok()?;
    Some((head[0], head[5]))
}

/// A server's High-ID test and a Kad helper's TCP check dial plain; under
/// `Required` the awaited one is admitted — marked, so core can serve it
/// nothing — and its hello is answered, which is all the test needs.
#[tokio::test]
async fn required_admits_a_plain_dial_it_awaits_a_test_from_as_a_test_connection() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let dialer = tokio::spawn(plain_hello_answer(bound));

    let awaited = Awaiting(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let admitted = listener
        .accept_with(
            || (responder_ctx(), options_under(ObfuscationPolicy::Required)),
            &awaited,
        )
        .await
        .expect("an awaited test is admitted");
    let Admitted::TestConnection(mut conn) = admitted else {
        panic!("a plain dial under Required is a Test Connection, never a peer");
    };
    assert!(matches!(
        conn.next_event().await,
        Some(PeerEvent::Connection(ConnectionEvent::Identified { .. }))
    ));
    assert_eq!(
        dialer.await.expect("dialer"),
        Some((0xE3, PeerOpcode::HelloAnswer.as_u8())),
        "the tester's hello is answered in plaintext"
    );
}

#[tokio::test]
async fn required_refuses_a_plain_dial_from_an_address_it_awaits_no_test_from() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let dialer = tokio::spawn(plain_hello_answer(bound));

    let elsewhere = Awaiting(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let refused = listener
        .accept_with(
            || (responder_ctx(), options_under(ObfuscationPolicy::Required)),
            &elsewhere,
        )
        .await;
    let Err(PeerNetError::PlaintextRefused { peer }) = refused else {
        panic!("a plain dial from an address no test is awaited from is refused");
    };
    assert_eq!(
        peer.ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "the refusal names the dialer it refused"
    );
    assert_eq!(
        dialer.await.expect("dialer"),
        None,
        "no answer, only a close"
    );
}

/// Below `Required` a plain dial was always a peer; being awaited as a tester
/// changes nothing about it.
#[tokio::test]
async fn below_required_an_awaited_plain_dial_is_an_ordinary_peer() {
    for policy in [ObfuscationPolicy::Supported, ObfuscationPolicy::Requested] {
        let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
        let dialer = tokio::spawn(plain_hello_answer(bound));
        let awaited = Awaiting(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let admitted = listener
            .accept_with(|| (responder_ctx(), options_under(policy)), &awaited)
            .await
            .expect("accepted");
        let Admitted::Peer(mut conn) = admitted else {
            panic!("{policy:?}: a plain dial is a peer");
        };
        assert!(matches!(
            conn.next_event().await,
            Some(PeerEvent::Connection(ConnectionEvent::Identified { .. }))
        ));
        assert!(dialer.await.expect("dialer").is_some());
    }
}

/// rmule's User Hash in bench flow R's runs: sixteen distinct bytes, so
/// a word-order fault in the `0x53` hash field changes the key a helper uses.
const FLOW_R_USER_HASH: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

/// Replay a captured helper stream at a `Required` listener that answers as
/// flow R's rmule, and collect what its session saw.
async fn replay_flow_r_dialback(stream: Vec<u8>) -> Vec<PeerEvent> {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let helper = tokio::spawn(async move {
        let mut tcp = TcpStream::connect(SocketAddr::V4(bound)).await.unwrap();
        tcp.write_all(&stream).await.unwrap();
        let mut sink = vec![0u8; 4096];
        while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
    });
    let mut ctx = responder_ctx();
    ctx.identity = ClientIdentity::new(
        UserHash::from_bytes(FLOW_R_USER_HASH),
        Ed2kText::from_utf8("rmule-flow-r"),
        4663,
        0x3C,
    );
    let options = ConnectOptions {
        obfuscation: Some(ObfuscationConfig {
            policy: ObfuscationPolicy::Required,
        }),
        ..Default::default()
    };
    let mut conn = listener.accept(ctx, options).await.expect("accept");
    let mut seen = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while let Some(event) = conn.next_event().await {
            let end = matches!(
                event,
                PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
                    | PeerEvent::Side(SideEvent::KadFirewallCheckAck)
            );
            seen.push(event);
            if end {
                break;
            }
        }
    })
    .await;
    helper.abort();
    seen
}

/// The dial-back a helper makes once the `0x53` names our user hash in
/// aMule's `WriteUInt128` word order: our responder authenticates it, the
/// helper's genuine hello (its hash carries the aMule markers `[5] = 14`,
/// `[14] = 111`) reads through the crypt layer, and its
/// `OP_KAD_FWTCPCHECK_ACK` follows.
#[tokio::test]
async fn a_captured_required_dialback_keyed_on_our_hash_is_accepted_and_acks() {
    let seen =
        replay_flow_r_dialback(flow_r_dialback("dialback_keyed_on_write_uint128_hash.bin")).await;
    let identity = seen
        .iter()
        .find_map(|event| match event {
            PeerEvent::Connection(ConnectionEvent::Identified { identity }) => {
                Some(identity.user_hash())
            }
            _ => None,
        })
        .expect("the helper's hello reads through the crypt layer");
    assert_eq!((identity.as_bytes()[5], identity.as_bytes()[14]), (14, 111));
    assert!(
        seen.iter()
            .any(|event| matches!(event, PeerEvent::Side(SideEvent::KadFirewallCheckAck))),
        "the helper's OP_KAD_FWTCPCHECK_ACK arrives: {seen:?}"
    );
}

/// The dial-back the same helper made while rmule's `0x53` carried the hash
/// in raw MD4 order: keyed on a word-swapped hash, it never authenticates —
/// the live `Io(InvalidData)`.
#[tokio::test]
async fn a_captured_required_dialback_keyed_on_a_word_swapped_hash_fails_the_handshake() {
    let seen =
        replay_flow_r_dialback(flow_r_dialback("dialback_keyed_on_raw_order_hash.bin")).await;
    assert!(
        !seen.iter().any(|event| matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Identified { .. })
        )),
        "no hello reads through a handshake keyed on another hash: {seen:?}"
    );
    assert!(
        seen.iter().any(|event| matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Disconnected { reason: rmule_peer::PeerCloseReason::Io(kind) })
                if *kind == std::io::ErrorKind::InvalidData
        )),
        "the link ends Io(InvalidData), as it did live: {seen:?}"
    );
}
