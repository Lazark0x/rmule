//! Inbound-path tests: a recruited buddy's relays riding the held link, and
//! the slot freeing when either a recruited or an adopted link closes.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_net::peer::{ConnectOptions as PeerConnectOptions, PeerListener};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{ClientId, Ed2kFileLink, Ed2kText, FileHash, Ipv4Endpoint, UserHash};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::adapters::dialed_serve::SharedDialedServeSink;
use crate::adapters::kad_runtime::SharedKadBootstrap;
use crate::adapters::peer_transfer::PeerWorkerCommand;
use crate::adapters::serve_runtime::{ServeConnCommand, ServeConnEvent};
use crate::buddy::{BuddyIdentity, BuddyServePosture, FindBuddyOutcome, FindBuddyReq};
use crate::buddy_link::{RelayDisposition, SharedBuddySlot};

use super::*;

/// The socket-unification harness: rmule's real inbound accept surface
/// (`PeerListener` + the production `triage_inbound_connection` router) with
/// a recruited buddy slot, and a `FakeBuddy` — the firewalled client — that
/// dials in and holds the connection, exactly as aMule's buddy does after
/// `0x5A`. Returns everything a leg assertion needs; `_cmd_tx` must stay
/// alive so the serve bridge keeps running.
async fn held_buddy_link(
    buddy_id: rmule_kad::KadId,
    buddy_hash: UserHash,
) -> (
    SharedBuddySlot,
    rmule_testkit::FakeBuddy,
    mpsc::Sender<ServeConnCommand>,
    mpsc::Receiver<ServeConnEvent>,
    crate::diagnostics::DiagnosticsState,
) {
    dial_a_buddy(buddy_id, buddy_hash, buddy_hash).await
}

/// [`held_buddy_link`] with the dialer's *hello* identity separated from the
/// hash the slot was recruited on, so a leg can drive the two apart.
async fn dial_a_buddy(
    buddy_id: rmule_kad::KadId,
    recruited_hash: UserHash,
    dialer_hash: UserHash,
) -> (
    SharedBuddySlot,
    rmule_testkit::FakeBuddy,
    mpsc::Sender<ServeConnCommand>,
    mpsc::Receiver<ServeConnEvent>,
    crate::diagnostics::DiagnosticsState,
) {
    use rmule_testkit::FakeBuddy;

    let buddy_hash = recruited_hash;
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the inbound listener");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());

    // The Kad-side recruit (0x51 accepted): the slot registers the buddy's
    // id, hash, and advertised TCP endpoint.
    let slot = SharedBuddySlot::default();
    let diagnostics = crate::diagnostics::DiagnosticsState::default();
    slot.install_diagnostics(diagnostics.clone());
    let outcome = slot.consider_findbuddy(
        &FindBuddyReq {
            buddy_id,
            requester_hash: buddy_hash,
            requester: Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4662),
            requester_udp: Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4662),
            requester_known: false,
            check_collision: false,
            is_self: false,
        },
        &BuddyServePosture {
            tcp_reachable: true,
            udp: crate::buddy::BuddyUdpPosture::Open,
        },
        BuddyIdentity {
            our_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            our_tcp_port: 4662,
        },
        Instant::now(),
    );
    assert!(
        matches!(outcome, FindBuddyOutcome::Accept(_)),
        "the recruit fills the slot"
    );

    // The firewalled buddy dials us and completes the hello while the
    // listener accepts — the persistent buddy link.
    let ctx = PeerHandshakeContext {
        identity: rmule_testkit::test_identity(0x11, "rmule", 4662),
        client_id: ClientId::from_u32(0),
        connected_server: None,
    };
    let (accepted, buddy) = tokio::join!(
        listener.accept(ctx, PeerConnectOptions::default()),
        FakeBuddy::dial(bound, dialer_hash, "firewalled-buddy"),
    );
    let conn = accepted.expect("accept the buddy's dial");

    // Route the accepted connection through the REAL production accept
    // router; identifying the buddy attaches its connection as the held link.
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    tokio::spawn(triage_inbound_connection(
        conn,
        None,
        cmd_rx,
        evt_tx,
        SharedCallbackTable::default(),
        SharedTunnelClaims::default(),
        InboundPeerDeps {
            slot_wait_timeout: Duration::from_secs(5),
            dialed_serve_sink: SharedDialedServeSink::default(),
            kad_bootstrap: SharedKadBootstrap::default(),
            kad_pump: crate::adapters::SharedKadPump::default(),
            buddy_slot: Arc::clone(&slot),
            addresses: crate::address_learning::SharedAddressLearning::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            kad_presence: crate::adapters::KadPresenceView::default(),
            file_known: crate::known_files::SharedFileKnown::default(),
            tunnel_admit: crate::adapters::SharedTunnelAdmit::default(),
            hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
        },
    ));
    loop {
        match timeout(Duration::from_secs(2), evt_rx.recv())
            .await
            .expect("the buddy identifies within 2s")
        {
            Some(ServeConnEvent::Identified { user_hash, .. }) => {
                assert_eq!(user_hash, dialer_hash, "the dialer identified as itself");
                break;
            }
            Some(_) => continue,
            None => panic!("the accept router ended before the buddy identified"),
        }
    }
    (slot, buddy, cmd_tx, evt_rx, diagnostics)
}

/// **Socket unification, proven end-to-end:** every buddy leg — the Kad
/// `0x52`→`OP_CALLBACK` (`0x99`) relay, the peer-UDP `0x94`→
/// `OP_REASKCALLBACKTCP` (`0x9A`) relay, and the `OP_BUDDYPING`→
/// `OP_BUDDYPONG` keepalive — rides the ONE persistent connection the
/// firewalled buddy dialed to us (aMule's `buddy->GetSocket()`), never a
/// fresh dial: the fake buddy listens nowhere, so nothing dialed could
/// reach it, and every frame is read off its own held socket.
#[tokio::test]
async fn buddy_relays_and_pong_ride_the_held_inbound_link_not_a_fresh_dial() {
    let buddy_id = rmule_kad::KadId::from_bytes([0x7A; 16]);
    let buddy_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);
    let (slot, mut buddy, _cmd_tx, _evt_rx, diagnostics) =
        held_buddy_link(buddy_id, buddy_hash).await;
    assert_eq!(
        diagnostics.snapshot().session.served_buddy_links_held_total,
        1,
        "the attach is what the open-node diagnostics report"
    );

    // Leg 1 — the Kad pump's 0x52 relay: framed 0x99 on the held link.
    let file_hash = FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]);
    let requester = Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662);
    assert_eq!(
        slot.relay_kad_callback(buddy_id, requester, file_hash),
        RelayDisposition::Sent,
        "the relay must ride the held link, not report a missing socket"
    );
    let payload = timeout(Duration::from_secs(2), buddy.expect_emule(0x99))
        .await
        .expect("the 0x99 relay arrived on the held link within 2s");
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x7A; 16]);
    expected.extend_from_slice(file_hash.as_bytes());
    // The Kad listener's host-order address through `WriteUInt32`: octets
    // reversed, as aMule's own relay writes them (bench run `1790152605`).
    expected.extend_from_slice(&[5, 113, 0, 203]);
    expected.extend_from_slice(&4662u16.to_le_bytes());
    assert_eq!(
        payload, expected,
        "0x99 body: <buddyID 16><fileHash 16><reqIP 4 host-order LE><reqTCP 2 LE>"
    );

    // Leg 2 — the client-UDP front's 0x94 relay: framed 0x9A on the SAME
    // held link, the datagram's UDP source injected ahead of the tail.
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 5099);
    let forwarded = vec![0x90, 0xAA, 0xBB];
    assert_eq!(
        slot.relay_reask(buddy_id, udp_src, forwarded.clone()),
        RelayDisposition::Sent
    );
    let payload = timeout(Duration::from_secs(2), buddy.expect_emule(0x9A))
        .await
        .expect("the 0x9A relay arrived on the held link within 2s");
    let mut expected = Vec::new();
    expected.extend_from_slice(&[198, 51, 100, 9]);
    expected.extend_from_slice(&5099u16.to_le_bytes());
    expected.extend_from_slice(&forwarded);
    assert_eq!(
        payload, expected,
        "0x9A body: <reqIP 4><reqUDP 2 LE><forwarded…>"
    );

    // Leg 3 — the keepalive: the buddy's ping up the held link pongs back
    // down the same link (the serve bridge routed it through the slot).
    buddy.send_buddy_ping().await;
    let pong = timeout(Duration::from_secs(2), buddy.expect_emule(0xA0))
        .await
        .expect("the OP_BUDDYPONG arrived on the held link within 2s");
    assert!(pong.is_empty(), "OP_BUDDYPONG carries no body");
    let session = diagnostics.snapshot().session;
    assert_eq!(session.served_buddy_pings_answered_total, 1);
    assert_eq!(session.served_buddy_pings_refused_total, 0);
}

/// The buddy relay accepts the served buddy's ID in either
/// `TAG_BUDDYHASH` spelling — the requester's `0x52` names it word-swapped,
/// the eMule 0.70b / eMuleAI reading — and relays it **unchanged**, exactly
/// as aMule does, over the real held link; counted apart from the ordinary
/// correct-spelling relay (`buddy_relays_swapped_spelling_total`).
#[tokio::test]
async fn a_swapped_spelling_0x52_relays_unchanged_and_is_counted_apart() {
    let buddy_id = rmule_kad::KadId::from_bytes([
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF,
    ]);
    let buddy_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);
    let (slot, mut buddy, _cmd_tx, _evt_rx, diagnostics) =
        held_buddy_link(buddy_id, buddy_hash).await;

    let file_hash = FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]);
    let requester = Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662);

    // The correct spelling first: relayed, and the swapped-spelling counter
    // stays at zero.
    assert_eq!(
        slot.relay_kad_callback(buddy_id, requester, file_hash),
        RelayDisposition::Sent
    );
    timeout(Duration::from_secs(2), buddy.expect_emule(0x99))
        .await
        .expect("the correct-spelling 0x99 arrived within 2s");
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .buddy_hash_spelling
            .buddy_relays_swapped_spelling_total,
        0
    );

    // The requester's 0x52 names the served buddy's ID word-swapped: still
    // relayed — rmule's own check accepts the swapped spelling of the buddy
    // it serves — and relayed **verbatim**, in the spelling the requester
    // claimed, never corrected.
    assert_eq!(
        slot.relay_kad_callback(buddy_id.word_swapped(), requester, file_hash),
        RelayDisposition::Sent
    );
    let payload = timeout(Duration::from_secs(2), buddy.expect_emule(0x99))
        .await
        .expect("the swapped-spelling 0x99 arrived within 2s");
    assert_eq!(
        &payload[..16],
        buddy_id.word_swapped().as_bytes(),
        "relayed unchanged, in the spelling the requester claimed"
    );
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .buddy_hash_spelling
            .buddy_relays_swapped_spelling_total,
        1
    );
}

/// The **hello decides**, on the open-node side as on every other adoption
/// road: a connection dialed in from the recruited buddy's
/// own address, but whose `OP_HELLO` reports somebody else's user hash, is
/// served as an ordinary inbound peer — never attached as the held buddy link.
/// Its `OP_BUDDYPING` gets no pong (aMule's `GetBuddy() != client` drop), and
/// the slot stays empty for the buddy that may still dial.
#[tokio::test]
async fn a_dialer_whose_hello_is_not_the_recruits_is_served_not_attached() {
    let buddy_id = rmule_kad::KadId::from_bytes([0x7A; 16]);
    let recruited = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);
    let stranger = UserHash::from_bytes([0x5E; UserHash::BYTE_LEN]);
    let (slot, mut dialer, _cmd_tx, _evt_rx, diagnostics) =
        dial_a_buddy(buddy_id, recruited, stranger).await;

    // Recruited, but nothing is held: the relay finds no socket rather than
    // riding a stranger's.
    assert_eq!(
        slot.relay_kad_callback(
            buddy_id,
            Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662),
            FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
        ),
        RelayDisposition::NoHeldLink,
        "a mismatched hello attaches nothing"
    );

    // The stranger's ping is refused silently — and because the serve bridge
    // is still driving its connection, a packet it *would* answer proves the
    // connection was served rather than dropped.
    dialer.send_buddy_ping().await;
    timeout(Duration::from_millis(400), dialer.expect_emule(0xA0))
        .await
        .expect_err("a stranger's OP_BUDDYPING is never ponged");
    let session = diagnostics.snapshot().session;
    assert_eq!(session.served_buddy_links_held_total, 0);
    assert_eq!(session.served_buddy_pings_refused_total, 1);
    assert_eq!(session.served_buddy_pings_answered_total, 0);
}

/// Held-link lifecycle: the held link closing frees the buddy slot at once
/// (aMule frees `m_pBuddy` when the buddy's socket dies) — a later relay
/// finds no buddy, and the slot is free for a fresh recruit.
#[tokio::test]
async fn the_held_links_close_frees_the_buddy_slot() {
    let buddy_id = rmule_kad::KadId::from_bytes([0x7A; 16]);
    let buddy_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);
    let (slot, buddy, _cmd_tx, mut evt_rx, diagnostics) =
        held_buddy_link(buddy_id, buddy_hash).await;

    // The buddy's connection drops; the bridge surfaces the disconnect and
    // then detaches the held link. Its event sender drops only after the
    // detach, so draining the stream to its close is the happens-after
    // signal that the detach ran.
    drop(buddy);
    while timeout(Duration::from_secs(2), evt_rx.recv())
        .await
        .expect("the disconnect surfaced within 2s")
        .is_some()
    {}
    assert_eq!(
        slot.relay_kad_callback(
            buddy_id,
            Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662),
            FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
        ),
        RelayDisposition::Rejected(crate::buddy::RelayReject::NoBuddy),
        "the close released the buddy slot, not just the socket"
    );
    let session = diagnostics.snapshot().session;
    assert_eq!(session.served_buddy_links_held_total, 1);
    assert_eq!(
        session.served_buddy_links_lost_total, 1,
        "held and lost balance, so the pair reads as 'no link right now'"
    );
}

/// Held-link lifecycle, adopt arm: the recruited buddy that is ALSO a pending
/// callback source is routed to an **adopted download worker** rather than
/// the serve bridge — the attach runs before that split, so the held link
/// still carries relays (proven by leg 1) — and when the adopted worker's
/// connection dies, the slot must free exactly as the serve arm's close
/// does. A wedged slot would refuse every future recruit until a Kad
/// restart.
#[tokio::test]
async fn the_adopted_buddy_links_close_frees_the_buddy_slot() {
    use rmule_testkit::FakeBuddy;

    let buddy_id = rmule_kad::KadId::from_bytes([0x7A; 16]);
    let buddy_hash = UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]);

    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the inbound listener");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());

    // The Kad-side recruit (0x51 accepted) fills the slot, as in
    // `held_buddy_link`.
    let slot = SharedBuddySlot::default();
    let outcome = slot.consider_findbuddy(
        &FindBuddyReq {
            buddy_id,
            requester_hash: buddy_hash,
            requester: Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4662),
            requester_udp: Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4662),
            requester_known: false,
            check_collision: false,
            is_self: false,
        },
        &BuddyServePosture {
            tcp_reachable: true,
            udp: crate::buddy::BuddyUdpPosture::Open,
        },
        BuddyIdentity {
            our_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            our_tcp_port: 4662,
        },
        Instant::now(),
    );
    assert!(
        matches!(outcome, FindBuddyOutcome::Accept(_)),
        "the recruit fills the slot"
    );

    // The same client is a pending-callback source: register the entry the
    // triage will match. The testkit hello reports server `0.0.0.0:0` (→
    // `None`) and client id `0x2000_0002`, so that pair is the key.
    let callbacks = SharedCallbackTable::default();
    let (adopt_tx, mut adopt_rx) = mpsc::channel(1);
    callbacks.lock().await.register(
        CallbackKey {
            server: None,
            low_id: ClientId::from_u32(0x2000_0002),
        },
        PendingCallbackEntry {
            own_status: rmule_peer::PartBitmap::downloader_empty(0),
            want_sources: true,
            file: Ed2kFileLink {
                name: Ed2kText::from_utf8("adopted"),
                size: 4096,
                file_hash: FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
                part_hash_set: None,
                aich_root: None,
                ipv6_sources: Vec::new(),
                sources: Default::default(),
            },
            adopt_tx,
        },
    );

    let ctx = PeerHandshakeContext {
        identity: rmule_testkit::test_identity(0x11, "rmule", 4662),
        client_id: ClientId::from_u32(0),
        connected_server: None,
    };
    let (accepted, mut buddy) = tokio::join!(
        listener.accept(ctx, PeerConnectOptions::default()),
        FakeBuddy::dial(bound, buddy_hash, "adopted-buddy"),
    );
    let conn = accepted.expect("accept the buddy's dial");

    let (_cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, _evt_rx) = mpsc::channel(16);
    tokio::spawn(triage_inbound_connection(
        conn,
        None,
        cmd_rx,
        evt_tx,
        Arc::clone(&callbacks),
        SharedTunnelClaims::default(),
        InboundPeerDeps {
            slot_wait_timeout: Duration::from_secs(5),
            dialed_serve_sink: SharedDialedServeSink::default(),
            kad_bootstrap: SharedKadBootstrap::default(),
            kad_pump: crate::adapters::SharedKadPump::default(),
            buddy_slot: Arc::clone(&slot),
            addresses: crate::address_learning::SharedAddressLearning::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            kad_presence: crate::adapters::KadPresenceView::default(),
            file_known: crate::known_files::SharedFileKnown::default(),
            tunnel_admit: crate::adapters::SharedTunnelAdmit::default(),
            hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
        },
    ));
    let (_key, mut worker) = timeout(Duration::from_secs(2), adopt_rx.recv())
        .await
        .expect("the callback match adopted the connection within 2s")
        .expect("the adopt channel stayed open");

    // Leg 1 — the attach ran before the adopt/serve split: a relay rides
    // the adopted connection.
    assert_eq!(
        slot.relay_kad_callback(
            buddy_id,
            Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662),
            FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
        ),
        RelayDisposition::Sent,
        "the adopted buddy's link still carries relays"
    );
    timeout(Duration::from_secs(2), buddy.expect_emule(0x99))
        .await
        .expect("the 0x99 relay arrived on the adopted link within 2s");

    // Leg 2 — the buddy's socket dies and the runner winds the adopted
    // worker down (its normal reaction to a dead source). The event
    // stream's close is the happens-after signal that the drive returned.
    drop(buddy);
    worker
        .send(PeerWorkerCommand::Shutdown { cancel: false })
        .await
        .expect("the drive still reads commands");
    while timeout(Duration::from_secs(2), worker.next_event())
        .await
        .expect("the adopted worker wound down within 2s")
        .is_some()
    {}
    assert_eq!(
        slot.relay_kad_callback(
            buddy_id,
            Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662),
            FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
        ),
        RelayDisposition::Rejected(crate::buddy::RelayReject::NoBuddy),
        "the adopted link's close released the buddy slot, not just the socket"
    );
}
