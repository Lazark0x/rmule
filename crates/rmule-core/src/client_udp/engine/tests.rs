//! Demux-front unit tests: the accepted protocol table, opcode routing to the
//! serve and downloader inboxes with wind-down, the verified `0x94` buddy
//! relay (spoofed IDs dropped), the armed dual-path crypt receive —
//! decrypt-and-re-demux for our hash, plaintext bypass, and the wrong-key /
//! flipped-byte / garbage drops — and the **family ruling**: an IPv6 datagram
//! reaching the crypt layer under the 35-byte layout, and the one opcode
//! (`0x94`) whose relay cannot name an IPv6 requester dropping and counting.
//!
//! The Kad arms are the socket unification's (ADR-0057): the declared
//! `0xE4`/`0xE5` and the unclaimed byte that may be obfuscated Kad both reach
//! the installed inlet, an IPv6 Kad datagram drops and counts, and a full or
//! absent inlet costs its own datagrams and nothing else.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use rmule_peer::{ReaskFilePing, file_not_found_datagram, queue_full_datagram};
use rmule_primitives::{FileHash, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, UserHash};

use super::super::tests::{
    a_nonce, a_reask_ping, armed_requesting, armed_requesting_dual_stack, supporting_target,
};
use super::super::{ClientUdpSend, PeerUdpCryptTarget, encrypt_client_udp_send};
use super::*;
use crate::firewalled::front::FirewalledCommand;

mod family_and_natt;
mod kad;

#[test]
fn the_demux_table_accepts_only_the_client_udp_protocol_set() {
    // Accepted: 0xC5 peer-UDP, 0xE4 Kad, 0xE5 packed-Kad.
    assert_eq!(demux_protocol(&[0xC5, 0x90]), ClientUdpRoute::PeerUdp);
    assert_eq!(demux_protocol(&[0xE4, 0x00]), ClientUdpRoute::Kad);
    assert_eq!(demux_protocol(&[0xE5, 0x00]), ClientUdpRoute::KadPacked);
    // Unclaimed: the server-UDP 0xE3 (the disjoint set), the packed-ed2k TCP
    // 0xD4, and arbitrary junk. None of them is a client-UDP protocol — but
    // an obfuscated Kad datagram opens with a random marker byte and is
    // indistinguishable from all three here, so the verdict names what is
    // known ("no protocol claims this") and the Kad node's key families are
    // what decide (ADR-0046/0057).
    assert_eq!(demux_protocol(&[0xE3, 0x90]), ClientUdpRoute::Unclaimed);
    assert_eq!(demux_protocol(&[0xD4, 0x00]), ClientUdpRoute::Unclaimed);
    assert_eq!(demux_protocol(&[0x00, 0x00]), ClientUdpRoute::Unclaimed);
    // Dropped outright: shorter than the two-byte header, so no protocol and
    // no crypt header either.
    assert_eq!(demux_protocol(&[0xC5]), ClientUdpRoute::Undersized);
    assert_eq!(demux_protocol(&[]), ClientUdpRoute::Undersized);
}

/// A transport preloaded with a datagram script; `recv` drains it in order,
/// then reports the transport closed.
struct ScriptedTransport {
    script: tokio::sync::Mutex<mpsc::Receiver<ClientUdpDatagram>>,
}

fn scripted(datagrams: Vec<ClientUdpDatagram>) -> ScriptedTransport {
    let (tx, rx) = mpsc::channel(datagrams.len().max(1));
    for datagram in datagrams {
        tx.try_send(datagram).expect("script fits the channel");
    }
    ScriptedTransport {
        script: tokio::sync::Mutex::new(rx),
    }
}

impl ClientUdpTransport for ScriptedTransport {
    async fn recv(&self) -> Option<ClientUdpDatagram> {
        self.script.lock().await.recv().await
    }
}

/// A front with **no Kad node running** — the posture every leg below but the
/// Kad ones wants, and the honest default: the inlet is empty until an
/// `EnableKad` installs one, so a Kad datagram is traced and dropped.
fn front_without_kad<T: ClientUdpTransport>(
    transport: T,
    crypt: Option<PeerUdpCrypt>,
    buddy_slot: SharedBuddySlot,
    diagnostics: DiagnosticsState,
    send_tx: mpsc::Sender<ClientUdpSend>,
) -> (ClientUdpEngine<T>, ClientUdpInboxes) {
    // And no firewalled front either: an empty cell is what the demux reads
    // as "nothing to hand a `0x95`/`0xA0` to", which is the posture every leg
    // below but the firewalled ones wants.
    let firewalled = SharedFirewalledFront::default();
    ClientUdpEngine::new(
        transport,
        crypt,
        buddy_slot,
        firewalled,
        diagnostics,
        send_tx,
        SharedKadInlet::default(),
    )
}

/// A front with a Kad node installed, plus the inlet's receiving end.
fn front_with_kad<T: ClientUdpTransport>(
    transport: T,
    crypt: Option<PeerUdpCrypt>,
    diagnostics: DiagnosticsState,
    capacity: usize,
) -> (
    ClientUdpEngine<T>,
    ClientUdpInboxes,
    mpsc::Receiver<rmule_net::kad::KadDatagram>,
) {
    let (kad_tx, kad_rx) = mpsc::channel(capacity);
    let inlet: SharedKadInlet = SharedKadInlet::default();
    *inlet.lock().expect("kad inlet mutex") = Some(kad_tx);
    let (engine, inboxes) = ClientUdpEngine::new(
        transport,
        crypt,
        SharedBuddySlot::default(),
        SharedFirewalledFront::default(),
        diagnostics,
        mpsc::channel(4).0,
        inlet,
    );
    (engine, inboxes, kad_rx)
}

#[tokio::test]
async fn the_front_routes_pings_to_serve_replies_to_the_downloader_and_drops_the_rest() {
    let src = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 5000));
    let ping = ReaskFilePing {
        file_hash: FileHash::from_bytes([0x11; FileHash::BYTE_LEN]),
        part_status: None,
        complete_sources: None,
    }
    .encode_udp();
    // The two downloader-consumed reask replies (0x93 queue-full first, then
    // 0x91 ack) and, before them, a truncated callback (0x94) that is *not*
    // routed to either inbox (it belongs to the buddy relay).
    let queue_full = queue_full_datagram();
    let ack = vec![0xC5, 0x91, 0x00, 0x00];
    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![
            // Kad + packed-Kad with no node running: recognized and dropped.
            (src, vec![0xE4, 0x00, 0x01]),
            (src, vec![0xE5, 0x00, 0x01]),
            // A server-UDP 0xE3 datagram: the disjoint set rejects it.
            (src, vec![0xE3, 0x9B, 0x01]),
            // Shorter than the header.
            (src, vec![0xC5]),
            // A truncated callback (0x94): dropped by its decode, routed to
            // neither inbox.
            (src, vec![0xC5, 0x94]),
            // The two reask replies the downloader consumes, in order.
            (src, queue_full.clone()),
            (src, ack.clone()),
            // The reask ping the uploader side consumes.
            (src, ping.clone()),
        ]),
        None,
        SharedBuddySlot::default(),
        DiagnosticsState::default(),
        mpsc::channel(4).0,
    );
    let engine_task = tokio::spawn(engine.run());

    // The reask ping reaches the serve inbox.
    let routed_ping = tokio::time::timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
        .await
        .expect("the reask ping routed within 2s");
    assert_eq!(routed_ping, Some((src, ping)));

    // Both reask replies reach the downloader inbox, in order — receiving
    // exactly these two proves the 0x94 callback and every foreign byte were
    // demuxed away rather than misrouted here.
    let first_reply = tokio::time::timeout(Duration::from_secs(2), inboxes.reask_reply.recv())
        .await
        .expect("the first reask reply routed within 2s");
    assert_eq!(first_reply, Some((src, queue_full)));
    let second_reply = tokio::time::timeout(Duration::from_secs(2), inboxes.reask_reply.recv())
        .await
        .expect("the second reask reply routed within 2s");
    assert_eq!(second_reply, Some((src, ack)));

    // The exhausted script closes the transport; the front ends and its
    // dropped senders wind both inboxes down.
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
            .await
            .expect("the ping inbox closed within 2s"),
        None
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), inboxes.reask_reply.recv())
            .await
            .expect("the reply inbox closed within 2s"),
        None
    );
    engine_task.await.expect("the front task ended cleanly");

    // The empty-body reply datagram is two bytes (used above as a seam).
    assert_eq!(file_not_found_datagram().len(), 2);
}

/// Socket unification, the client-UDP half: an inbound `0x94`
/// (`OP_REASKCALLBACKUDP`) is verified against the registered buddy and
/// relayed as the framed `OP_REASKCALLBACKTCP` (`0x9A`) session command on
/// the HELD buddy link — the datagram's UDP source injected as the answer
/// endpoint — while a spoofed buddy-ID's `0x94` is dropped (the ADR-0061
/// tightening). This is the front's own relay (aMule
/// `CClientUDPSocket::OnPacketReceived`), not the Kad pump's.
#[tokio::test]
async fn an_inbound_0x94_relays_as_0x9a_over_the_held_buddy_link() {
    use std::sync::Arc;
    use std::time::Instant;

    use rmule_kad::KadId;
    use rmule_peer::{PeerCommand, ReaskCallbackTcp};

    use crate::buddy::{
        BuddyIdentity, BuddyServePosture, BuddyUdpPosture, FindBuddyOutcome, FindBuddyReq,
    };

    // A recruited buddy whose inbound TCP connection has attached as the
    // held link (the channel stands in for the connection's driver).
    let slot = SharedBuddySlot::default();
    let buddy_id = KadId::from_bytes([0x11; KadId::BYTE_LEN]);
    let buddy_hash = UserHash::from_bytes([0x11; UserHash::BYTE_LEN]);
    let outcome = slot.consider_findbuddy(
        &FindBuddyReq {
            buddy_id,
            requester_hash: buddy_hash,
            requester: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 1), 4662),
            requester_udp: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 1), 4662),
            requester_known: false,
            check_collision: false,
            is_self: false,
        },
        &BuddyServePosture {
            tcp_reachable: true,
            udp: BuddyUdpPosture::Open,
        },
        BuddyIdentity {
            our_hash: UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
            our_tcp_port: 4662,
        },
        Instant::now(),
    );
    assert!(matches!(outcome, FindBuddyOutcome::Accept(_)));
    let (link_tx, mut link_rx) = mpsc::channel(4);
    assert!(slot.try_attach(
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 1), 61234)),
        buddy_hash,
        link_tx,
    ));

    // A spoofed 0x94 (wrong buddy-ID) then the genuine relay, both arriving
    // from the requesting downloader's UDP source.
    let requester = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 5099);
    let requester_src = PeerEndpoint::V4(requester);
    let forwarded = vec![0x90, 0xAA, 0xBB, 0xCC];
    let spoofed = ReaskCallbackUdp {
        buddy_id: [0x22; 16],
        forwarded: forwarded.clone(),
    }
    .encode_udp();
    let genuine = ReaskCallbackUdp {
        buddy_id: *buddy_id.as_bytes(),
        forwarded: forwarded.clone(),
    }
    .encode_udp();
    let (engine, _inboxes) = front_without_kad(
        scripted(vec![(requester_src, spoofed), (requester_src, genuine)]),
        None,
        Arc::clone(&slot),
        DiagnosticsState::default(),
        mpsc::channel(4).0,
    );
    engine.run().await;

    // Exactly one relay rode the held link — the verified one — framed as
    // the 0x9A command with the datagram's UDP source injected and the
    // reask tail forwarded verbatim; the spoofed 0x94 sent nothing.
    assert_eq!(
        link_rx.try_recv().expect("the verified 0x94 relayed"),
        PeerCommand::SendReaskCallbackTcp(ReaskCallbackTcp {
            requester: PeerEndpoint::V4(requester),
            forwarded,
        })
    );
    assert!(
        link_rx.try_recv().is_err(),
        "the spoofed buddy-ID's 0x94 must not relay"
    );
}

/// ADR-0091, rmule as the target's serving buddy. An embedded rendezvous is
/// forwarded on the held link byte for byte as a reask would be — the target
/// reads the marker itself — with the requester's **observed** source
/// injected; and because the requester asked, it is answered with an endpoint
/// hint naming the target's UDP mapping *as recruited*, never the requester's
/// claim about anything. A second rendezvous inside the per-source window is
/// refused by the relay service's own admission: nothing forwarded, no hint,
/// and the refusal counted.
#[tokio::test]
async fn an_embedded_rendezvous_is_relayed_admitted_and_answered_with_a_hint() {
    use std::sync::Arc;
    use std::time::Instant;

    use rmule_kad::KadId;
    use rmule_peer::natt::{EndpointHint, NattConnectOptions, NattTransport, RendezvousBody};
    use rmule_peer::{PeerCommand, ReaskCallbackTcp};

    use crate::buddy::{
        BuddyIdentity, BuddyServePosture, BuddyUdpPosture, FindBuddyOutcome, FindBuddyReq,
    };

    let slot = SharedBuddySlot::default();
    let buddy_id = KadId::from_bytes([0x11; KadId::BYTE_LEN]);
    let target_hash = UserHash::from_bytes([0x44; UserHash::BYTE_LEN]);
    // The target's TCP port is what it advertised; its UDP mapping is what
    // the `0x51` was *seen* coming from — a different port, as behind a NAT.
    let target_udp_seen = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 31999);
    let outcome = slot.consider_findbuddy(
        &FindBuddyReq {
            buddy_id,
            requester_hash: target_hash,
            requester: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4662),
            requester_udp: target_udp_seen,
            requester_known: false,
            check_collision: false,
            is_self: false,
        },
        &BuddyServePosture {
            tcp_reachable: true,
            udp: BuddyUdpPosture::Open,
        },
        BuddyIdentity {
            our_hash: UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
            our_tcp_port: 4662,
        },
        Instant::now(),
    );
    assert!(matches!(outcome, FindBuddyOutcome::Accept(_)));
    let (link_tx, mut link_rx) = mpsc::channel(4);
    assert!(slot.try_attach(
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 61234)),
        target_hash,
        link_tx,
    ));

    let requester = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 5099);
    let rendezvous = RendezvousBody {
        requester: UserHash::from_bytes([0x77; UserHash::BYTE_LEN]),
        options: NattConnectOptions::advertise(0, true, false),
        file_hash: Some(FileHash::from_bytes([0x22; FileHash::BYTE_LEN])),
        // A claim that disagrees with the source the datagram arrives from.
        claimed_endpoint: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 66), 1)),
        transport_hint: Some(NattTransport::Utp),
    }
    .embed(*buddy_id.as_bytes());
    let datagram = rendezvous.encode_udp();

    let diagnostics = DiagnosticsState::default();
    let (send_tx, mut send_rx) = mpsc::channel(4);
    let (engine, _inboxes) = front_without_kad(
        scripted(vec![
            (PeerEndpoint::V4(requester), datagram.clone()),
            (PeerEndpoint::V4(requester), datagram),
        ]),
        None,
        Arc::clone(&slot),
        diagnostics.clone(),
        send_tx,
    );
    engine.run().await;

    assert_eq!(
        link_rx.try_recv().expect("the rendezvous was forwarded"),
        PeerCommand::SendReaskCallbackTcp(ReaskCallbackTcp {
            requester: PeerEndpoint::V4(requester),
            forwarded: rendezvous.forwarded,
        })
    );
    assert!(link_rx.try_recv().is_err(), "the second was not admitted");

    let hint = send_rx.try_recv().expect("the requester asked for a hint");
    assert_eq!(hint.to, PeerEndpoint::V4(requester));
    assert!(
        hint.crypt_target.is_none(),
        "NAT-T signalling is never obfuscated"
    );
    assert_eq!(
        EndpointHint::decode_udp(&hint.datagram),
        Ok(EndpointHint {
            target: target_hash,
            buddy_id: *buddy_id.as_bytes(),
            file_hash: Some(FileHash::from_bytes([0x22; FileHash::BYTE_LEN])),
            target_endpoint: target_udp_seen,
            options: NattConnectOptions::from_byte(0),
        })
    );
    assert!(
        send_rx.try_recv().is_err(),
        "a refused relay is owed no hint"
    );

    let session = diagnostics.snapshot().session;
    assert_eq!(session.natt_relays_forwarded_total, 1);
    assert_eq!(session.natt_relays_refused_total, 1);
}

/// Obfuscate `payload` for `target` through the production gate, asserting
/// it really was obfuscated — so no test can silently assert on plaintext.
fn sealed(crypt: &PeerUdpCrypt, target: PeerUdpCryptTarget, payload: &[u8]) -> Vec<u8> {
    sealed_to(
        crypt,
        target,
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4662)),
        payload,
    )
}

/// [`sealed`] with an explicit destination, so a test can prove the send key's
/// layout follows the family the datagram leaves by (ADR-0087).
fn sealed_to(
    crypt: &PeerUdpCrypt,
    target: PeerUdpCryptTarget,
    to: PeerEndpoint,
    payload: &[u8],
) -> Vec<u8> {
    let (_, datagram) = encrypt_client_udp_send(
        Some(crypt),
        ClientUdpSend::to_peer(to, payload.to_vec(), Some(target)),
        a_nonce,
    );
    assert_ne!(datagram, payload, "the gate must have obfuscated this");
    datagram
}

#[tokio::test]
async fn an_armed_front_decrypts_peer_crypt_datagrams_and_still_bypasses_plaintext() {
    // Two peers on the ed2k family: we receive; `them` at `their_ep` sends.
    let our_hash = UserHash::from_bytes([0x11; 16]);
    let their_ip = [198u8, 51, 100, 7];
    let their_ep = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::from(their_ip), 4662));

    // `them` encrypts a reask ping (0xC5 0x90 …) and a queue-full reply
    // (0xC5 0x93) *for us* — keyed on our hash + their own sender IP — via
    // the send gate; our armed front must decrypt both to the exact
    // plaintext and re-demux each by its recovered inner opcode.
    let their_crypt = armed_requesting(UserHash::from_bytes([0x99; 16]), their_ip);
    let plain_ping = a_reask_ping(0x11);
    let plain_reply = queue_full_datagram();
    let crypt_ping = sealed(&their_crypt, supporting_target(our_hash), &plain_ping);
    let crypt_reply = sealed(&their_crypt, supporting_target(our_hash), &plain_reply);
    // A crypt datagram must not masquerade as a plaintext protocol byte.
    assert_ne!(crypt_ping[0], 0xC5);

    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![
            (their_ep, crypt_ping),
            // A legacy plaintext ping the armed front must still bypass.
            (their_ep, plain_ping.clone()),
            (their_ep, crypt_reply),
        ]),
        Some(armed_requesting(our_hash, [203, 0, 113, 9])),
        SharedBuddySlot::default(),
        DiagnosticsState::default(),
        mpsc::channel(4).0,
    );
    let engine_task = tokio::spawn(engine.run());

    // Both pings reach the serve inbox — the decrypted one recovered to the
    // exact plaintext, then the plaintext one bypassed — proving the dual
    // path routes crypt and plain alike.
    let first = tokio::time::timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
        .await
        .expect("the decrypted ping routed within 2s");
    assert_eq!(first, Some((their_ep, plain_ping.clone())));
    let second = tokio::time::timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
        .await
        .expect("the plaintext ping routed within 2s");
    assert_eq!(second, Some((their_ep, plain_ping)));

    // The decrypted reply re-demuxes by its inner 0x93 opcode to the
    // downloader — proving the recovered plaintext walks the opcode demux.
    let reply = tokio::time::timeout(Duration::from_secs(2), inboxes.reask_reply.recv())
        .await
        .expect("the decrypted reply routed within 2s");
    assert_eq!(reply, Some((their_ep, plain_reply)));

    engine_task.await.expect("the front task ended cleanly");
}

#[tokio::test]
async fn an_armed_front_drops_crypt_for_another_hash_garbage_and_flipped_bytes() {
    let our_hash = UserHash::from_bytes([0x11; 16]);
    let their_ip = [198u8, 51, 100, 7];
    let their_ep = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::from(their_ip), 4662));
    let their_crypt = armed_requesting(UserHash::from_bytes([0x99; 16]), their_ip);

    // A crypt datagram keyed on a DIFFERENT recipient hash (not ours): our
    // ed2k key cannot validate its sync word — the wrong-key trap. It must
    // not spuriously route as though it decrypted.
    let not_our_hash = UserHash::from_bytes([0x22; 16]);
    let crypt_for_other = sealed(
        &their_crypt,
        supporting_target(not_our_hash),
        &a_reask_ping(0x11),
    );
    // The vacuity guard: a genuine datagram FOR US with one ciphertext byte
    // flipped. Left alone it decrypts and routes (the test above proves
    // that), so only the sync-word check can reject it — the receive path
    // must validate, not accept whatever it is handed. The flip lands inside
    // the encrypted region, past the 3-byte cleartext marker + key seed.
    let mut flipped = sealed(
        &their_crypt,
        supporting_target(our_hash),
        &a_reask_ping(0x11),
    );
    flipped[4] ^= 0x01;
    // Full-length noise with a non-marker first byte: fails the sync outright.
    let garbage: Vec<u8> = (0u8..40)
        .map(|i| i.wrapping_mul(37).wrapping_add(3))
        .collect();
    assert!(!rmule_primitives::is_udp_plaintext_marker(garbage[0]));

    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![
            (their_ep, crypt_for_other),
            (their_ep, flipped),
            (their_ep, garbage),
        ]),
        Some(armed_requesting(our_hash, [203, 0, 113, 9])),
        SharedBuddySlot::default(),
        DiagnosticsState::default(),
        mpsc::channel(4).0,
    );
    let engine_task = tokio::spawn(engine.run());

    // None of the three routes anywhere: the exhausted transport closes the
    // front and both inboxes wind down with nothing delivered.
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
            .await
            .expect("the ping inbox closed within 2s"),
        None
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), inboxes.reask_reply.recv())
            .await
            .expect("the reply inbox closed within 2s"),
        None
    );
    engine_task.await.expect("the front task ended cleanly");
}
