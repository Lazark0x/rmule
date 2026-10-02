//! Dial-side tests: the TCP dial-back enactment, the identity a dialed worker
//! reports (plain, proving, and verified), and the ban / IP-filter refusals.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rmule_net::peer::{
    ConnectOptions as PeerConnectOptions, ObfuscationConfig, ObfuscationPolicy, PeerListener,
};
use rmule_peer::{PeerEvent, PeerHandshakeContext, SecureIdentConfig};
use rmule_primitives::{
    ClientId, ClientIdentity, CryptStance, Ed2kFileLink, Ed2kText, FileHash, Ipv4Endpoint,
    PeerEndpoint, SecureIdentKey, UserHash,
};
use tokio::time::timeout;

use crate::adapters::tests::held_buddy::{BuddyTags, hold};
use crate::adapters::tests::hello_wire::{
    assert_states_live_adverts, live_adverts, read_hello_body,
};
use crate::adapters::tests::{dialed_serve_ctx, loopback_blocking_ip_filter};
use crate::ban_store::SharedBanStore;
use crate::firewalled::link::{FirewalledSlot, SharedFirewalledSlot};
use crate::ip_filter::SharedIpFilter;

use super::*;
mod refusals_and_shutdown;
mod source_ask;

/// ADR-0058 responder **enactment**, the plaintext leg (a legacy `0x50`
/// states no crypt side, so its requester reads as `PeerCrypt::unknown`, met
/// here by a node with the layer off): the core dial-back connects back to a firewalled
/// requester's TCP port over the reusable peer-TCP dial surface, completes the
/// eD2k hello, and delivers the `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) — the
/// connect-back a self-checking peer counts to flip itself open. Proven
/// against a testkit `FakePeer` standing in for the firewalled requester; the
/// live-aMule capture is a later orchestrator step.
#[tokio::test]
async fn the_dial_back_enactment_connects_and_delivers_the_firewall_ack() {
    use rmule_testkit::{FakePeer, PeerScript};

    let requester = FakePeer::bind().await;
    let endpoint = Ipv4Endpoint::new(*requester.addr().ip(), requester.addr().port());
    let requester_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);
    let requester_task =
        requester.spawn(PeerScript::hello_only(requester_hash, "fw-check-requester"));

    let ctx = PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("rmule"),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0),
        connected_server: None,
    };

    // Kad is serverless, so the dial-back is a plain outbound hello + the ack;
    // the enactment is the whole responder connect-back leg. `FakePeer`'s
    // script speaks plain eD2k framing, so it doubles as the plaintext-only
    // 0x53 leg: a `FakePeer` could not complete an obfuscated
    // handshake at all, so its ack landing proves the dial went out plain.
    enact_tcp_dial_back(
        endpoint,
        PeerCrypt::unknown(),
        &HelloAdverts::default(),
        ctx,
    )
    .await;

    let stats = timeout(Duration::from_secs(2), requester_task)
        .await
        .expect("the requester script finished within 2s")
        .expect("requester task");
    assert!(
        stats.kad_fw_tcp_check_ack,
        "the self-checking requester must receive the dial-back's OP_KAD_FWTCPCHECK_ACK",
    );
}

/// The firewall-check dial-back sends the one outbound
/// hello every dial sends (aMule `OnConnect` → `SendHelloPacket`,
/// `ClientTCPSocket.cpp:2036`), so it states our ports, Kad version, IPv6 and
/// crypt support like any other, and a firewalled node answering a check
/// while it holds a buddy names that buddy there too.
#[tokio::test]
async fn a_firewalled_node_s_dial_back_hello_states_every_advert_and_names_its_buddy() {
    let requester = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the requester");
    let port = requester.local_addr().expect("bound").port();
    let slot: SharedFirewalledSlot = Arc::new(FirewalledSlot::new(rmule_kad::KadId::from_bytes(
        [0xAA; rmule_kad::KadId::BYTE_LEN],
    )));
    // Firewalled: Self Reach with no High ID and Kad unproven.
    slot.install_reach(crate::reachability::SharedSelfReach::new(
        crate::KadReachLevel::fixed(false),
        crate::own_identity::SharedOwnIdentity::default(),
        crate::natt::front::SharedNattFront::default(),
    ));
    let _link = hold(&slot, None);
    let adverts = live_adverts(slot);

    let dial = tokio::spawn(async move {
        let endpoint = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port);
        enact_tcp_dial_back(endpoint, PeerCrypt::unknown(), &adverts, dialed_serve_ctx()).await;
    });
    let (mut stream, _) = timeout(Duration::from_secs(2), requester.accept())
        .await
        .expect("the dial-back arrives within 2s")
        .expect("accept");
    let hello = timeout(Duration::from_secs(2), read_hello_body(&mut stream))
        .await
        .expect("the hello arrives within 2s");
    assert_states_live_adverts(&hello);
    assert_eq!(BuddyTags::of(&hello), BuddyTags::naming_a_buddy(None));
    drop(stream);
    dial.await
        .expect("the dial-back ends once the requester hangs up");
}

/// A download dial's hello starts from the same Hello Adverts read
/// as every other — our ports, Kad version, IPv6, crypt support and, while we
/// are firewalled behind a held link, our buddy.
#[tokio::test]
async fn a_download_dial_s_hello_states_every_advert() {
    let source = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the source");
    let port = source.local_addr().expect("bound").port();
    let slot: SharedFirewalledSlot = Arc::new(FirewalledSlot::new(rmule_kad::KadId::from_bytes(
        [0xAA; rmule_kad::KadId::BYTE_LEN],
    )));
    // Firewalled: Self Reach with no High ID and Kad unproven.
    slot.install_reach(crate::reachability::SharedSelfReach::new(
        crate::KadReachLevel::fixed(false),
        crate::own_identity::SharedOwnIdentity::default(),
        crate::natt::front::SharedNattFront::default(),
    ));
    let _link = hold(&slot, None);
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
        .with_hello_adverts(live_adverts(slot));
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port));
    let _worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), a_file())
        .await
        .expect("the worker starts");

    let (mut stream, _) = timeout(Duration::from_secs(2), source.accept())
        .await
        .expect("the dial arrives within 2s")
        .expect("accept");
    let hello = timeout(Duration::from_secs(2), read_hello_body(&mut stream))
        .await
        .expect("the hello arrives within 2s");
    assert_states_live_adverts(&hello);
    assert_eq!(BuddyTags::of(&hello), BuddyTags::naming_a_buddy(None));
}

/// A download adapter whose Hello Adverts hold `key`, as `Core::builder`
/// loads it.
fn proving_with(key: Arc<SecureIdentKey>) -> RuntimePeerTransferService {
    let adverts = HelloAdverts {
        secure_ident: Some(key),
        ..HelloAdverts::default()
    };
    RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT).with_hello_adverts(adverts)
}

/// A file to dial for; its content is never reached.
fn a_file() -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash: FileHash::from_bytes([0xAB; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// ADR-0058 responder **enactment**, the obfuscated leg (the two-reading rule's `Obfuscated`
/// verdict): a `0x53` whose connect-options
/// require the crypt layer draws a dial-back that runs the handshake as the
/// initiator, keyed on the requester's own User Hash — exactly the transport
/// seam `dial_back_loopback.rs`'s callback tests pin
/// (`crates/rmule-net/tests/net/dial_back_loopback.rs`), reused here one layer
/// up: a real `PeerListener` responder that *requires* obfuscation still
/// receives the firewall-check ack, over the crypt layer rather than plain.
#[tokio::test]
async fn an_obfuscated_dial_back_reaches_a_responder_that_requires_it() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the requester");
    let endpoint = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let requester_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);

    let requester = tokio::spawn(async move {
        let requester_ctx = PeerHandshakeContext {
            identity: ClientIdentity::new(
                requester_hash,
                Ed2kText::from_utf8("fw-check-requester"),
                4662,
                0x3C,
            ),
            client_id: ClientId::from_u32(0),
            connected_server: None,
        };
        let opts = PeerConnectOptions {
            obfuscation: Some(ObfuscationConfig {
                policy: ObfuscationPolicy::Required,
            }),
            ..PeerConnectOptions::default()
        };
        let mut conn = listener
            .accept(requester_ctx, opts)
            .await
            .expect("the dial-back arrives obfuscated");
        loop {
            match conn.next_event().await {
                Some(PeerEvent::KadFirewallCheckAck) => return true,
                Some(PeerEvent::Disconnected { .. }) | None => return false,
                Some(_) => {}
            }
        }
    });

    let ctx = PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("rmule"),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0),
        connected_server: None,
    };
    // The verdict carries the requester's own stance (its `0x53` options
    // 0x07: supports + requests + requires) and hash; met by our `Supported`
    // policy the dial obfuscates as a must, keyed on the requester's hash —
    // the initiator always keys on the target's hash, never ours.
    let requester_crypt = PeerCrypt::new(CryptStance::new(true, true, true), Some(requester_hash));
    let ours = HelloAdverts {
        crypt_policy: Some(ObfuscationPolicy::Supported),
        ..HelloAdverts::default()
    };
    enact_tcp_dial_back(endpoint, requester_crypt, &ours, ctx).await;

    let got_ack = timeout(Duration::from_secs(2), requester)
        .await
        .expect("the requester task finished within 2s")
        .expect("requester task");
    assert!(
        got_ack,
        "an obfuscated dial-back must still deliver OP_KAD_FWTCPCHECK_ACK over the crypt layer",
    );
}

/// ADR-0058 responder **enactment**, the refused leg: a
/// requester whose check stated it *requires* the crypt layer, met by a node
/// whose layer is off, is never dialed — the enactment reads the requester's
/// own stance by `PeerCrypt::outbound` and refuses before any socket, rather
/// than trusting a stance invented for the dial. The broker already refuses
/// this pair as `DialBackRefusal::CryptIncompatible`; the enactment holds the
/// same line on its own.
#[tokio::test]
async fn a_dial_back_toward_a_requester_that_requires_crypt_opens_no_socket_while_ours_is_off() {
    let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the requester");
    let port = listener.local_addr().expect("local addr").port();
    let endpoint = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port);
    let requester_crypt = PeerCrypt::new(
        CryptStance::new(true, true, true),
        Some(UserHash::from_bytes([0xBE; UserHash::BYTE_LEN])),
    );

    // A dial that went out would sit in its hello wait (the listener never
    // speaks), so returning at once is the refusal itself.
    timeout(
        Duration::from_secs(2),
        enact_tcp_dial_back(
            endpoint,
            requester_crypt,
            &HelloAdverts::default(),
            dialed_serve_ctx(),
        ),
    )
    .await
    .expect("the enactment refuses before any socket, so it returns at once");
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "no connection may reach a requester this node cannot meet",
    );
}

/// A worker reports the dialed peer's `UserHash` (from its hello) as an
/// `Identified` event, before `Connected` — the credit accounting key.
#[tokio::test]
async fn dialed_worker_reports_the_peer_user_hash_before_connected() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let mock = tokio::spawn(async move {
        // Accept and stay alive so our worker completes its handshake.
        let mut conn = listener
            .accept(dialed_serve_ctx(), PeerConnectOptions::default())
            .await
            .unwrap();
        while let Some(event) = conn.next_event().await {
            if matches!(event, PeerEvent::Disconnected { .. }) {
                break;
            }
        }
    });

    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash: FileHash::from_bytes([0xAB; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();

    // `dialed_serve_ctx` identifies with user_hash 0x09. The router hands up
    // the hello's source-exchange facts on its own, so they may come first.
    let first = loop {
        let event = timeout(Duration::from_secs(5), worker.next_event())
            .await
            .expect("identified within 5s");
        if !matches!(event, Some(PeerWorkerEvent::SourceExchange { .. })) {
            break event;
        }
    };
    let Some(PeerWorkerEvent::Identified {
        user_hash,
        crypt,
        software,
    }) = first
    else {
        panic!("the first worker event of its own is Identified");
    };
    assert_eq!(user_hash, UserHash::from_bytes([0x09; UserHash::BYTE_LEN]));
    // The loopback peer's hello carries no crypt policy, so the stance it
    // advertises — and this worker reports — is empty.
    assert_eq!(crypt, Some(CryptStance::disabled()));
    // The loopback peer is rmule: its hello carries aMule 2.3.3's
    // CT_EMULE_VERSION word (ADR-0047) and rmule's own mod name,
    // which is what names it — read off that hello.
    assert_eq!(software.family(), rmule_peer::ClientFamily::Rmule);
    assert!(
        software.version().is_some(),
        "its own version, from the mod name"
    );
    assert_eq!(worker.next_event().await, Some(PeerWorkerEvent::Connected));
    drop(worker);
    let _ = mock.await;
}

/// A download dial proves rmule's identity with the Secure User
/// Identification keypair the Hello Adverts hold (ADR-0041) — the
/// one every other hello proves with, never a key of the download's own: the
/// accept side — a distinct keypair and user hash — challenges the dial and
/// observes `PeerIdentityVerified` carrying the *dialer's* hash and the
/// published public key. Asymmetric on purpose: a flipped signing direction
/// would fail this assert, while a symmetric rmule↔rmule check would not.
#[tokio::test]
async fn a_download_dial_proves_with_the_published_sui_key() {
    let key_a = Arc::new(SecureIdentKey::generate().unwrap()); // dialer (rmule)
    let key_b = Arc::new(SecureIdentKey::generate().unwrap()); // accept side
    let key_a_public = key_a.public_key_der();

    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let mock = tokio::spawn(async move {
        let ctx = PeerHandshakeContext {
            identity: ClientIdentity::new(
                UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]),
                Ed2kText::from_utf8("mock-sui-peer"),
                4662,
                60,
            ),
            client_id: ClientId::from_u32(0x0100_007F),
            connected_server: None,
        };
        let options = PeerConnectOptions {
            secure_ident: Some(SecureIdentConfig {
                key: key_b,
                challenge: 0xB00B_0001,
            }),
            ..PeerConnectOptions::default()
        };
        let mut conn = listener.accept(ctx, options).await.unwrap();
        while let Some(event) = conn.next_event().await {
            match event {
                PeerEvent::PeerIdentityVerified {
                    user_hash,
                    public_key,
                } => return Some((user_hash, public_key)),
                PeerEvent::Disconnected { .. } => return None,
                _ => {}
            }
        }
        None
    });

    let mut transfer = proving_with(key_a);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let file = a_file();
    let _worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();

    let verified = timeout(Duration::from_secs(5), mock)
        .await
        .expect("accept side finished within 5s")
        .unwrap()
        .expect("accept side verified the dialer's identity");
    // `dialed_serve_ctx` identifies with user_hash 0x09; the proof must
    // carry the dialer's hash and the dialer's key — not the accept side's.
    assert_eq!(verified.0, UserHash::from_bytes([0x09; UserHash::BYTE_LEN]));
    assert_eq!(verified.1, key_a_public);
}

/// The dial side of the same SUI exchange surfaces the *peer's* verified
/// identity as a worker event, even while the worker idles between
/// commands — that event is what the runner binds credit from (ADR-0041).
/// Asymmetric asserts again: the accept side's hash and exact key DER.
#[tokio::test]
async fn a_dialed_worker_reports_the_peers_verified_identity() {
    let key_a = Arc::new(SecureIdentKey::generate().unwrap()); // dialer (rmule)
    let key_b = Arc::new(SecureIdentKey::generate().unwrap()); // accept side
    let key_b_public = key_b.public_key_der();

    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let mock = tokio::spawn(async move {
        let ctx = PeerHandshakeContext {
            identity: ClientIdentity::new(
                UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]),
                Ed2kText::from_utf8("mock-sui-peer"),
                4662,
                60,
            ),
            client_id: ClientId::from_u32(0x0100_007F),
            connected_server: None,
        };
        let options = PeerConnectOptions {
            secure_ident: Some(SecureIdentConfig {
                key: key_b,
                challenge: 0xB00B_0002,
            }),
            ..PeerConnectOptions::default()
        };
        let mut conn = listener.accept(ctx, options).await.unwrap();
        // Stay alive so the dial side's exchange completes.
        while let Some(event) = conn.next_event().await {
            if matches!(event, PeerEvent::Disconnected { .. }) {
                break;
            }
        }
    });

    let mut transfer = proving_with(key_a);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let file = a_file();
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();

    let verified = timeout(Duration::from_secs(5), async {
        while let Some(event) = worker.next_event().await {
            if let PeerWorkerEvent::IdentityVerified {
                user_hash,
                public_key,
            } = event
            {
                return Some((user_hash, public_key));
            }
        }
        None
    })
    .await
    .expect("worker events flowed within 5s")
    .expect("the worker surfaced IdentityVerified");
    assert_eq!(verified.0, UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]));
    assert_eq!(verified.1, key_b_public);
    drop(worker);
    let _ = mock.await;
}
