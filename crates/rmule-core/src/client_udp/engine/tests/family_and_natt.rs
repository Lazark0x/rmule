//! The IPv6 family ruling (the 35-byte crypt key, the IPv4-only `0x94`) and the
//! inlets the NAT-T and firewalled fronts drive through this socket.

use super::*;
use rmule_peer::SideCommand;

/// A global-unicast IPv6 for the fixtures below — documentation range, so it
/// passes **Address Learning**'s admissibility filter exactly as a real one
/// would (ADR-0084 refuses anything that is not global unicast).
fn v6(last: u16, port: u16) -> PeerEndpoint {
    PeerEndpoint::V6(Ipv6Endpoint::new(
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, last),
        port,
    ))
}

/// **The 35-byte key on the wire, not only in a KAT** (ADR-0087).
///
/// An IPv6 peer obfuscates a `0x90` for us keyed on its own 128-bit sender
/// address — the 35-byte layout, magic at offset 32 — and sends it to the v6
/// half of our client-UDP Family Pair. The front must select that layout from
/// the family the datagram arrived in, recover the exact plaintext, re-demux
/// it by its inner opcode, and hand the serve inbox the **IPv6** source it
/// came from. Before this, the transport narrowed every datagram to IPv4 and
/// the layout could only ever be exercised against the primitive.
///
/// The vacuity guard is the second datagram: the *same* ciphertext replayed as
/// though it had arrived from an IPv4 source. Its address bytes key a 23-byte
/// layout, the sync word fails, and nothing routes — so the first datagram's
/// success is the family selection working and not the receive path accepting
/// whatever it is handed.
#[tokio::test]
async fn an_ipv6_datagram_reaches_the_crypt_layer_with_the_35_byte_key() {
    let our_hash = UserHash::from_bytes([0x11; 16]);
    let their_v6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x7);
    let their_ep = PeerEndpoint::V6(Ipv6Endpoint::new(their_v6, 4662));

    // `them` is dual-stack, so nothing about *its* state forces the v6 layout:
    // the only thing that selects it is that the datagram goes to a v6
    // destination — our own v6 half — and comes back from a v6 source.
    let their_crypt = armed_requesting_dual_stack(
        UserHash::from_bytes([0x99; 16]),
        [198, 51, 100, 7],
        their_v6,
    );
    let plain_ping = a_reask_ping(0x11);
    let crypt_ping = sealed_to(
        &their_crypt,
        supporting_target(our_hash),
        v6(0x1, 4662),
        &plain_ping,
    );
    // The key mixed in sixteen address bytes, not four: the ciphertext is the
    // 35-byte layout's, and the layout is what the magic's offset rides on.
    assert_ne!(
        crypt_ping,
        sealed(&their_crypt, supporting_target(our_hash), &plain_ping),
        "the v6 destination must key a different layout than the v4 one",
    );

    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![
            (their_ep, crypt_ping.clone()),
            // The same bytes, claimed to have arrived over IPv4: the 23-byte
            // layout keys on four address bytes and recovers nothing.
            (
                PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::from([198, 51, 100, 7]), 4662)),
                crypt_ping,
            ),
        ]),
        Some(armed_requesting(our_hash, [203, 0, 113, 9])),
        SharedBuddySlot::default(),
        DiagnosticsState::default(),
        mpsc::channel(4).0,
    );
    let engine_task = tokio::spawn(engine.run());

    let routed = tokio::time::timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
        .await
        .expect("the decrypted IPv6 ping routed within 2s");
    assert_eq!(
        routed,
        Some((their_ep, plain_ping)),
        "the v6 source reaches the serve inbox carrying its own family",
    );

    // Nothing else routed: the v4-claimed replay never decrypted.
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), inboxes.reask_ping.recv())
            .await
            .expect("the ping inbox closed within 2s"),
        None
    );
    engine_task.await.expect("the front task ended cleanly");
}

/// The `0x94` ruling (ADR-0087, the module doc's table): the relay a verified
/// `0x94` becomes — `OP_REASKCALLBACKTCP` (`0x9A`) — injects the requester as
/// `WriteUInt32(ip)`, which an IPv6 requester has no form in. So the front
/// drops it and **counts** it, rather than relaying a firewalled client toward
/// an address that is not the requester's; the identical `0x94` from an IPv4
/// requester relays as it always did.
#[tokio::test]
async fn an_ipv6_0x94_is_dropped_and_counted_while_its_ipv4_twin_relays() {
    use std::sync::Arc;
    use std::time::Instant;

    use rmule_kad::KadId;
    use rmule_peer::{PeerCommand, ReaskCallbackTcp};

    use crate::buddy::{
        BuddyIdentity, BuddyServePosture, BuddyUdpPosture, FindBuddyOutcome, FindBuddyReq,
    };

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

    // One genuine, verifiable `0x94`, delivered twice: once from an IPv6
    // requester and once from an IPv4 one. Only the buddy-ID is verified, so
    // the *only* difference between the two outcomes is the family.
    let forwarded = vec![0x90, 0xAA, 0xBB, 0xCC];
    let genuine = ReaskCallbackUdp {
        buddy_id: *buddy_id.as_bytes(),
        forwarded: forwarded.clone(),
    }
    .encode_udp();
    let v4_requester = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 5099);
    let diagnostics = DiagnosticsState::default();
    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![
            (v6(0x9, 5099), genuine.clone()),
            (PeerEndpoint::V4(v4_requester), genuine),
            // The other IPv6 arms, so the count is provably about `0x94` and
            // not about the family: a `0x95` direct callback (no address in
            // its body, so it passes) and a reask reply (the quartet passes
            // and routes). The Kad arm's own family ruling has its own leg
            // below — it is counted too, and mixing the two here would make
            // this assertion unable to say which drop it saw.
            (v6(0xA, 5099), vec![0xC5, 0x95, 0x00, 0x00]),
            (v6(0xB, 5099), queue_full_datagram()),
            // And a *malformed* IPv6 `0x94`: dropped in either family, so it
            // is a decode drop and never a family one.
            (v6(0xD, 5099), vec![0xC5, 0x94]),
        ]),
        None,
        Arc::clone(&slot),
        diagnostics.clone(),
        mpsc::channel(4).0,
    );
    engine.run().await;

    // The v6 reask reply routed: the quartet is family-generic.
    assert_eq!(
        inboxes.reask_reply.try_recv(),
        Ok((v6(0xB, 5099), queue_full_datagram())),
    );

    // Exactly one relay rode the held link — the IPv4 one.
    assert_eq!(
        link_rx.try_recv().expect("the IPv4 0x94 relayed"),
        PeerCommand::Side(SideCommand::SendReaskCallbackTcp(ReaskCallbackTcp {
            requester: PeerEndpoint::V4(v4_requester),
            forwarded,
        }))
    );
    assert!(
        link_rx.try_recv().is_err(),
        "the IPv6 0x94 must not relay: the 0x9A it becomes cannot name its requester",
    );
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .unanswerable_family_datagrams_total,
        1,
        "exactly the dropped IPv6 0x94 is counted — never silent, and never the rest",
    );
}

/// ADR-0091's inlet: everything the **NAT-T Front** drives reaches one inbox.
/// The `0xB2` transport frames pass in **both** families (no `0xB2` body names
/// an address, ADR-0046's amendment) and so does the empty `0xA1`
/// trigger, whose sender *is* its source. `0xAA` is the second opcode on this
/// front ruled IPv4-only: its acceptance rule compares the observed source
/// against the buddy's `Ipv4Endpoint`, so an IPv6 one is dropped and counted
/// exactly as an IPv6 `0x94` is. The standalone `0xA0` goes to the firewalled
/// front instead, which holds the buddy slot its carrier is gated against — so
/// it never reaches this inbox, and with no front running it is dropped.
#[tokio::test]
async fn the_natt_inbox_takes_the_transport_frames_and_the_signalling_it_can_attribute() {
    use rmule_peer::natt::{EndpointHint, NattConnectOptions, NattFrame, holepunch_datagram};

    let v4_src = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672));
    let utp_frame = NattFrame::Key(UserHash::from_bytes([0xAA; 16])).encode();
    let hint = EndpointHint {
        target: UserHash::from_bytes([0x44; 16]),
        buddy_id: [0xBB; 16],
        file_hash: None,
        target_endpoint: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 31999),
        options: NattConnectOptions::from_byte(0),
    }
    .encode_udp();
    let diagnostics = DiagnosticsState::default();
    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![
            (v4_src, utp_frame.clone()),
            (v6(0x1, 4672), utp_frame.clone()),
            (v4_src, holepunch_datagram()),
            (v6(0x2, 4672), holepunch_datagram()),
            (v4_src, hint.clone()),
            // The IPv6 hint: well-formed, unattributable, dropped and counted.
            (v6(0x3, 4672), hint.clone()),
            // A malformed IPv6 hint: a decode drop in either family, so it
            // must not read as a dialect gap.
            (v6(0x4, 4672), vec![0xC5, 0xAA, 0x01]),
            // The standalone relay form: the firewalled front's inlet, not
            // this one's — and no front runs here, so it is dropped.
            (v4_src, vec![0xC5, 0xA0, 0x00]),
        ]),
        None,
        SharedBuddySlot::default(),
        diagnostics.clone(),
        mpsc::channel(4).0,
    );
    engine.run().await;

    let routed: Vec<_> = std::iter::from_fn(|| inboxes.natt.try_recv().ok()).collect();
    assert_eq!(
        routed,
        vec![
            (v4_src, utp_frame.clone()),
            (v6(0x1, 4672), utp_frame),
            (v4_src, holepunch_datagram()),
            (v6(0x2, 4672), holepunch_datagram()),
            (v4_src, hint),
        ],
        "both families for 0xB2 and 0xA1, IPv4 only for 0xAA, and no 0xA0",
    );
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .unanswerable_family_datagrams_total,
        1,
        "exactly the well-formed IPv6 hint is counted",
    );
}

/// The dual-path receive runs **ahead** of the protocol demux:
/// an obfuscated NAT-T frame leads with a random crypt marker, not `0xB2`, so
/// a demux that ran first would drop every frame the moment a KEY frame armed
/// the peer's obfuscation.
#[tokio::test]
async fn an_obfuscated_natt_frame_is_recovered_before_the_protocol_demux() {
    use rmule_peer::natt::NattFrame;

    let our_hash = UserHash::from_bytes([0x11; 16]);
    let their_ip = [198u8, 51, 100, 7];
    let their_ep = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::from(their_ip), 4672));
    let their_crypt = armed_requesting(UserHash::from_bytes([0x99; 16]), their_ip);
    let frame = NattFrame::Key(our_hash).encode();
    let sealed_frame = sealed(&their_crypt, supporting_target(our_hash), &frame);
    assert_ne!(
        sealed_frame[0],
        rmule_peer::natt::NATT_PROTOCOL,
        "an obfuscated frame is not recognisable as NAT-T until it is decrypted",
    );

    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![(their_ep, sealed_frame)]),
        Some(armed_requesting(our_hash, [203, 0, 113, 9])),
        SharedBuddySlot::default(),
        DiagnosticsState::default(),
        mpsc::channel(4).0,
    );
    engine.run().await;

    assert_eq!(inboxes.natt.try_recv(), Ok((their_ep, frame)));
}

/// A datagram queue never back-pressures the socket it shares: the NAT-T inbox
/// drops and counts rather than stalling the front, so a slow tunnel cannot
/// cost every reask behind it. The reask ping queued *after* the overflow is
/// the proof — it arrives.
#[tokio::test]
async fn a_full_natt_inbox_drops_without_stalling_the_reask_path() {
    use rmule_peer::natt::holepunch_datagram;

    let src = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672));
    let ping = a_reask_ping(0x11);
    let overflow = NATT_INBOX_CAPACITY + 8;
    let mut script: Vec<_> = std::iter::repeat_n((src, holepunch_datagram()), overflow).collect();
    script.push((src, ping.clone()));

    let diagnostics = DiagnosticsState::default();
    let (engine, mut inboxes) = front_without_kad(
        scripted(script),
        None,
        SharedBuddySlot::default(),
        diagnostics.clone(),
        mpsc::channel(4).0,
    );
    // Nothing drains the NAT-T inbox: the front must still finish its script.
    engine.run().await;

    assert_eq!(inboxes.reask_ping.try_recv(), Ok((src, ping)));
    assert_eq!(
        diagnostics.snapshot().session.natt_inbox_drops_total,
        overflow as u64 - NATT_INBOX_CAPACITY as u64,
    );
}

/// The firewalled front's two inlets on this socket (ADR-0061/0091):
/// a standalone `0xC5 0xA0` rendezvous and an inbound `0x95` direct
/// callback. Both are handed on rather than decided here — the gates they meet
/// read the buddy slot the front owns — and both pass in **either** family:
/// the rendezvous because its carrier gate compares whole endpoints (an IPv6
/// source simply never matches an IPv4 buddy, which is a refusal the gate
/// states), the `0x95` because its body names no address, so the requester is
/// its source and rung 0 dials an IPv6 one where it stands.
#[tokio::test]
async fn the_firewalled_front_takes_the_standalone_rendezvous_and_the_direct_callback() {
    use rmule_peer::natt::{NattConnectOptions, RendezvousBody};

    let v4_src = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672));
    let rendezvous = RendezvousBody {
        requester: UserHash::from_bytes([0x11; 16]),
        options: NattConnectOptions::from_byte(0x80),
        file_hash: None,
        claimed_endpoint: None,
        transport_hint: None,
    }
    .encode_standalone();
    let direct = rmule_peer::DirectCallbackReq {
        our_tcp_port: 4662,
        our_user_hash: UserHash::from_bytes([0x77; 16]),
        connect_options: 0x03,
    }
    .encode_udp();

    let front = SharedFirewalledFront::default();
    let (front_tx, mut front_rx) = mpsc::channel(8);
    front.install(front_tx);
    let diagnostics = DiagnosticsState::default();
    let (engine, _inboxes) = ClientUdpEngine::new(
        scripted(vec![
            (v4_src, rendezvous.clone()),
            (v6(0x5, 4672), direct.clone()),
            (v4_src, direct),
            // Malformed in either family: a decode drop, never a dialect gap.
            (v4_src, vec![0xC5, 0xA0, 0x01]),
            (v4_src, vec![0xC5, 0x95, 0x00]),
        ]),
        PeerUdpCrypt::disarmed(),
        SharedBuddySlot::default(),
        front.clone(),
        diagnostics.clone(),
        mpsc::channel(4).0,
        SharedKadInlet::default(),
    );
    engine.run().await;

    let taken: Vec<_> = std::iter::from_fn(|| front_rx.try_recv().ok()).collect();
    assert!(
        matches!(
            taken.as_slice(),
            [
                FirewalledCommand::StandaloneRendezvous { from, .. },
                FirewalledCommand::DirectCallback(v6_req),
                FirewalledCommand::DirectCallback(v4_req),
            ] if *from == v4_src
                && v6_req.requester == v6(0x5, 4662)
                && v4_req.requester == PeerEndpoint::V4(Ipv4Endpoint::new(
                    Ipv4Addr::new(45, 55, 200, 2),
                    4662,
                ))
        ),
        "the front saw exactly the three well-formed datagrams: {taken:?}"
    );
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .unanswerable_family_datagrams_total,
        0,
        "neither opcode is family-ruled, so nothing here is a dialect gap"
    );
}
