//! Session-level dispatch for the human-layer catalog (ADR-0068,
//! Private-Citizen Parity): golden emits, silence assertions on every drop
//! row, the pre-`Identified` guard, and a mid-transfer volley proving the
//! catalog never disturbs an unrelated active slot.

use std::net::Ipv4Addr;

use crate::fixture::identified_session;
use rmule_peer::{
    ChangeClientIpV6, ConnectionCommand, ConnectionEvent, IdentityChange, NoticeEvent, PartRanges,
    PeerCommand, PeerEvent, PeerSession, RequesterCommand, RequesterEvent, SideEvent,
    SlotReleaseReason,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Ipv4Endpoint, Packet, PacketProtocol, PartHash,
};
use rmule_testkit::peer_session::{ctx, events, file_hash, peer_at, writes};

// --- Wire helpers -----------------------------------------------

fn ask_shared_files() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x4A, Vec::new()).encode()
}

fn ask_shared_dirs() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x5D, Vec::new()).encode()
}

fn ask_shared_files_dir() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x5E, b"incoming".to_vec()).encode()
}

fn ask_shared_files_answer() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x4B, vec![0u8; 4]).encode()
}

fn ask_shared_dirs_ans() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x5F, vec![0u8; 4]).encode()
}

fn ask_shared_files_dir_ans() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x60, vec![0u8; 4]).encode()
}

fn ask_shared_denied_ans() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x61, Vec::new()).encode()
}

fn public_ip_req() -> Vec<u8> {
    Packet::new(PacketProtocol::Emule, 0x97, Vec::new()).encode()
}

fn public_ip_answer(ip: Ipv4Addr) -> Vec<u8> {
    Packet::new(PacketProtocol::Emule, 0x98, ip.octets().to_vec()).encode()
}

fn message(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut payload = (bytes.len() as u16).to_le_bytes().to_vec();
    payload.extend_from_slice(bytes);
    Packet::new(PacketProtocol::Edonkey, 0x4E, payload).encode()
}

fn filedesc(rating: u8, comment: &str) -> Vec<u8> {
    let bytes = comment.as_bytes();
    let mut payload = vec![rating];
    payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(bytes);
    Packet::new(PacketProtocol::Emule, 0x61, payload).encode()
}

fn change_client_id(new_id: u32, new_server_ip: Ipv4Addr) -> Vec<u8> {
    let mut payload = new_id.to_le_bytes().to_vec();
    payload.extend_from_slice(&new_server_ip.octets());
    Packet::new(PacketProtocol::Edonkey, 0x4D, payload).encode()
}

fn chat_captcha_req() -> Vec<u8> {
    Packet::new(PacketProtocol::Emule, 0xA5, vec![0u8; 16]).encode()
}

fn chat_captcha_res() -> Vec<u8> {
    Packet::new(PacketProtocol::Emule, 0xA6, vec![0u8; 4]).encode()
}

fn reqfilename_answer(hash: FileHash, name: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(name_bytes);
    Packet::new(PacketProtocol::Edonkey, 0x59, payload).encode()
}

fn file_status(hash: FileHash, part_count: u16, bitmap: &[u8]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&part_count.to_le_bytes());
    payload.extend_from_slice(bitmap);
    Packet::new(PacketProtocol::Edonkey, 0x50, payload).encode()
}

fn hashset_answer(hash: FileHash, part_hashes: &[PartHash]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&(part_hashes.len() as u16).to_le_bytes());
    for h in part_hashes {
        payload.extend_from_slice(h.as_bytes());
    }
    Packet::new(PacketProtocol::Edonkey, 0x52, payload).encode()
}

fn acceptuploadreq() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x55, Vec::new()).encode()
}

fn sendingpart(hash: FileHash, start: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&(start + data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    Packet::new(PacketProtocol::Edonkey, 0x46, payload).encode()
}

// --- Respond-by-parity: browse requests --------------------------

#[test]
fn every_browse_request_is_denied_and_counted() {
    for wire in [
        ask_shared_files(),
        ask_shared_dirs(),
        ask_shared_files_dir(),
    ] {
        let mut session = identified_session();
        session.handle_bytes(&wire);
        let out = drain(|| session.poll_output());

        let writes = writes(&out);
        assert_eq!(writes.len(), 1, "exactly one reply, got {writes:?}");
        assert_eq!(writes[0].protocol(), PacketProtocol::Edonkey);
        assert_eq!(writes[0].opcode(), 0x61);
        assert!(writes[0].payload().is_empty());

        assert!(
            events(&out)
                .iter()
                .any(|e| matches!(e, PeerEvent::Notice(NoticeEvent::BrowseDenied))),
            "expected BrowseDenied, got {out:?}"
        );
    }
}

// --- Respond-by-parity: publicip ----------------------------------

#[test]
fn public_ip_req_is_answered_with_the_peers_own_observed_ip() {
    let mut session = identified_session();
    session.handle_bytes(&public_ip_req());
    let out = drain(|| session.poll_output());

    let writes = writes(&out);
    assert_eq!(writes.len(), 1, "exactly one reply, got {writes:?}");
    assert_eq!(writes[0].protocol(), PacketProtocol::Emule);
    assert_eq!(writes[0].opcode(), 0x98);
    assert_eq!(writes[0].payload(), &[203, 0, 113, 55]);

    assert!(
        events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::Side(SideEvent::PublicIpAnswered))),
        "expected PublicIpAnswered, got {out:?}"
    );
}

// --- Drop-with-counter: silence assertions ------------------------

#[test]
fn unsolicited_browse_answers_are_silently_dropped() {
    for wire in [
        ask_shared_files_answer(),
        ask_shared_dirs_ans(),
        ask_shared_files_dir_ans(),
        ask_shared_denied_ans(),
    ] {
        let mut session = identified_session();
        session.handle_bytes(&wire);
        let out = drain(|| session.poll_output());

        assert!(writes(&out).is_empty(), "no reply expected, got {out:?}");
        assert!(
            events(&out).iter().any(|e| matches!(
                e,
                PeerEvent::Notice(NoticeEvent::UnsolicitedBrowseAnswerDropped)
            )),
            "expected UnsolicitedBrowseAnswerDropped, got {out:?}"
        );
    }
}

#[test]
fn unsolicited_public_ip_answer_is_silently_dropped() {
    let mut session = identified_session();
    session.handle_bytes(&public_ip_answer(Ipv4Addr::new(198, 51, 100, 9)));
    let out = drain(|| session.poll_output());

    assert!(writes(&out).is_empty(), "no reply expected, got {out:?}");
    assert!(
        events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Notice(NoticeEvent::UnsolicitedPublicIpAnswerDropped)
        )),
        "expected UnsolicitedPublicIpAnswerDropped, got {out:?}"
    );
}

#[test]
fn chat_captcha_challenge_and_answer_are_silently_dropped() {
    for wire in [chat_captcha_req(), chat_captcha_res()] {
        let mut session = identified_session();
        session.handle_bytes(&wire);
        let out = drain(|| session.poll_output());

        assert!(writes(&out).is_empty(), "no reply expected, got {out:?}");
        assert!(
            events(&out)
                .iter()
                .any(|e| matches!(e, PeerEvent::Notice(NoticeEvent::ChatCaptchaDropped))),
            "expected ChatCaptchaDropped, got {out:?}"
        );
    }
}

// --- Surface-as-event: wire-silent, payload up the spine ----------

#[test]
fn chat_message_is_surfaced_with_no_reply() {
    let mut session = identified_session();
    session.handle_bytes(&message("hello there"));
    let out = drain(|| session.poll_output());

    assert!(writes(&out).is_empty(), "no reply expected, got {out:?}");
    assert!(
        events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Notice(NoticeEvent::ChatMessageReceived { text }) if text == &Ed2kText::from_utf8("hello there")
        )),
        "expected ChatMessageReceived, got {out:?}"
    );
}

#[test]
fn oversize_chat_message_is_surfaced_capped_at_450_not_dropped() {
    let text = "z".repeat(500);
    let mut session = identified_session();
    session.handle_bytes(&message(&text));
    let out = drain(|| session.poll_output());

    assert!(writes(&out).is_empty(), "no reply expected, got {out:?}");
    assert!(
        events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Notice(NoticeEvent::ChatMessageReceived { text }) if text.as_bytes().len() == 450
        )),
        "expected a 450-byte-capped ChatMessageReceived, got {out:?}"
    );
}

#[test]
fn file_comment_is_surfaced_with_no_reply() {
    let mut session = identified_session();
    session.handle_bytes(&filedesc(4, "nice rip"));
    let out = drain(|| session.poll_output());

    assert!(writes(&out).is_empty(), "no reply expected, got {out:?}");
    assert!(
        events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::FileCommentReceived { rating, comment })
                if *rating == 4 && comment == &Ed2kText::from_utf8("nice rip")
        )),
        "expected FileCommentReceived, got {out:?}"
    );
}

/// `OP_CHANGE_CLIENT_ID` is offered to core, with no reply: a High ID that
/// is the address the peer connected from, and any Low ID, are offered with
/// the server named beside them, and a High ID that is some other address is
/// dropped (aMule `ClientTCPSocket.cpp:773-787`). Nothing moves until core
/// answers.
#[test]
fn a_changed_client_id_is_offered_to_core() {
    let server = Ipv4Addr::new(198, 51, 100, 200);
    let mut session = identified_session();
    let own = u32::from_le_bytes(peer_at(55).as_v4().expect("v4 peer").ip.octets());

    let offers = |session: &mut PeerSession, id: u32| {
        session.handle_bytes(&change_client_id(id, server));
        let out = drain(|| session.poll_output());
        assert!(writes(&out).is_empty(), "no reply expected, got {out:?}");
        assert!(
            !events(&out).iter().any(|e| matches!(
                e,
                PeerEvent::Connection(ConnectionEvent::IdentityRevised { .. })
            )),
            "nothing moves before core answers: {out:?}"
        );
        events(&out)
            .into_iter()
            .filter_map(|e| match e {
                PeerEvent::Connection(ConnectionEvent::ClientIdOffered { client_id, server }) => {
                    Some((client_id.as_u32(), *server))
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    assert!(offers(&mut session, 0x0102_0304).is_empty());
    assert_eq!(offers(&mut session, own), vec![(own, server)]);
    assert_eq!(offers(&mut session, 77), vec![(77, server)]);
}

/// Core's answer moves the identity: a Low ID only with the known server it
/// names, which then stands as the server the peer is on — the "on our
/// server" claim reads it — and a High ID only when it is the peer's own
/// address, whatever core says.
#[test]
fn a_taken_client_id_revises_the_identity_and_its_server() {
    let ours = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 200), 4661);
    let own = u32::from_le_bytes(peer_at(55).as_v4().expect("v4 peer").ip.octets());
    let mut session = identified_session();
    let take = |session: &mut PeerSession, id: u32, server: Option<Ipv4Endpoint>| {
        session.handle_command(PeerCommand::Connection(ConnectionCommand::TakeClientId {
            client_id: ClientId::from_u32(id),
            server,
        }));
        let out = drain(|| session.poll_output());
        events(&out).into_iter().find_map(|e| match e {
            PeerEvent::Connection(ConnectionEvent::IdentityRevised { identity, what }) => {
                assert_eq!(*what, IdentityChange::ClientId);
                Some(identity.clone())
            }
            _ => None,
        })
    };

    assert!(
        take(&mut session, 77, None).is_none(),
        "no server, no Low ID"
    );
    assert!(take(&mut session, 0x0102_0304, Some(ours)).is_none());
    let identity = take(&mut session, 77, Some(ours)).expect("the revision is reported");
    assert_eq!(identity.client_id().as_u32(), 77);
    assert!(identity.is_on_server(ours));
    assert!(!identity.is_on_server(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 201), 4661)));
    let identity = take(&mut session, own, None).expect("its own address is its High ID");
    assert!(
        identity.is_on_server(ours),
        "an unknown server leaves the one it was on"
    );
}

/// `OP_CHANGE_CLIENT_IP` moves the identity the session keeps: the one
/// revision it reports carries the whole identity with the new IPv6, and a
/// restatement of the address it already holds says nothing.
#[test]
fn a_changed_ipv6_revises_the_identity_once() {
    let address: std::net::Ipv6Addr = "2001:db8::7".parse().expect("an address");
    let change = ChangeClientIpV6::new(address).expect("a usable address");
    let mut session = identified_session();

    session.handle_bytes(&change.encode_packet().encode());
    let out = drain(|| session.poll_output());
    let revisions: Vec<_> = events(&out)
        .into_iter()
        .filter_map(|e| match e {
            PeerEvent::Connection(ConnectionEvent::IdentityRevised { identity, what }) => {
                Some((*what, identity.peer_ipv6()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(revisions, vec![(IdentityChange::Ipv6, Some(address))]);

    session.handle_bytes(&change.encode_packet().encode());
    let out = drain(|| session.poll_output());
    assert!(events(&out).is_empty(), "{out:?}");
}

/// A dialer whose hello named `named`, answered by a peer whose hello claims
/// `MODMISC_IPV6` when `capable`. Returns the session still awaiting that
/// answer, and the answer's bytes.
fn dialing_with_ipv6(named: std::net::Ipv6Addr, capable: bool) -> (PeerSession, Vec<u8>) {
    let mut session = PeerSession::new_outbound(peer_at(55), ctx()).with_ipv6_advertisement(named);
    session.start();
    let _ = drain(|| session.poll_output());
    let mut tags =
        crate::fixture::plain_hello_body(rmule_primitives::UserHash::from_bytes([0x99; 16])).tags;
    if capable {
        tags.push(rmule_peer::ModMiscOptions::rmule_claim().to_tag());
    }
    let answer = rmule_peer::HelloAnswer::new(crate::fixture::hello_body(
        rmule_primitives::UserHash::from_bytes([0x99; 16]),
        0x20000002,
        tags,
    ))
    .encode_packet()
    .encode();
    (session, answer)
}

fn announced(out: &[rmule_peer::PeerOutput]) -> Vec<std::net::Ipv6Addr> {
    writes(out)
        .iter()
        .filter(|packet| packet.opcode() == 0xAC)
        .filter_map(|packet| ChangeClientIpV6::decode_packet(packet).ok())
        .map(ChangeClientIpV6::address)
        .collect()
}

fn announce(address: std::net::Ipv6Addr) -> PeerCommand {
    PeerCommand::Connection(rmule_peer::ConnectionCommand::AnnounceIpv6Change(address))
}

/// ADR-0087: a move of our Advertised IPv6 reaches an IPv6-capable peer once,
/// and a restatement of what it was told says nothing.
#[test]
fn an_ipv6_move_is_announced_once_to_a_capable_peer() {
    let named: std::net::Ipv6Addr = "2001:db8::1".parse().expect("an address");
    let moved: std::net::Ipv6Addr = "2001:db8::2".parse().expect("an address");
    let (mut session, answer) = dialing_with_ipv6(named, true);
    session.handle_bytes(&answer);
    let _ = drain(|| session.poll_output());

    session.handle_command(announce(named));
    assert!(
        announced(&drain(|| session.poll_output())).is_empty(),
        "the hello named it"
    );
    session.handle_command(announce(moved));
    assert_eq!(announced(&drain(|| session.poll_output())), vec![moved]);
    session.handle_command(announce(moved));
    assert!(
        announced(&drain(|| session.poll_output())).is_empty(),
        "told once"
    );
}

/// A peer whose hello claims no IPv6 is never sent `0xAC`, and the command is
/// no error.
#[test]
fn a_legacy_peer_is_never_sent_an_ipv6_move() {
    let named: std::net::Ipv6Addr = "2001:db8::1".parse().expect("an address");
    let (mut session, answer) = dialing_with_ipv6(named, false);
    session.handle_bytes(&answer);
    let _ = drain(|| session.poll_output());
    session.handle_command(announce("2001:db8::2".parse().expect("an address")));
    let out = drain(|| session.poll_output());
    assert!(writes(&out).is_empty(), "{out:?}");
    assert!(events(&out).is_empty(), "{out:?}");
}

/// A move while our hello was already out and its answer not yet in is owed:
/// it follows the answer.
#[test]
fn an_ipv6_move_during_the_handshake_follows_the_answer() {
    let named: std::net::Ipv6Addr = "2001:db8::1".parse().expect("an address");
    let moved: std::net::Ipv6Addr = "2001:db8::2".parse().expect("an address");
    let (mut session, answer) = dialing_with_ipv6(named, true);
    session.handle_command(announce(moved));
    let out = drain(|| session.poll_output());
    assert!(
        writes(&out).is_empty() && events(&out).is_empty(),
        "{out:?}"
    );
    session.handle_bytes(&answer);
    assert_eq!(announced(&drain(|| session.poll_output())), vec![moved]);
}

// --- Pre-Identified guard ------------------------------------------

#[test]
fn human_layer_packets_before_identified_are_unknown_not_acted_on() {
    let mut session = PeerSession::new_inbound(peer_at(55), ctx());
    for wire in [ask_shared_files(), public_ip_req(), message("too soon")] {
        session.handle_bytes(&wire);
        let out = drain(|| session.poll_output());
        assert!(
            writes(&out).is_empty(),
            "no reply before the hello exchange, got {out:?}"
        );
        assert!(
            events(&out)
                .iter()
                .any(|e| matches!(e, PeerEvent::Notice(NoticeEvent::UnknownPacket { .. }))),
            "expected UnknownPacket pre-Identified, got {out:?}"
        );
        assert!(
            !events(&out).iter().any(|e| matches!(
                e,
                PeerEvent::Notice(NoticeEvent::BrowseDenied)
                    | PeerEvent::Side(SideEvent::PublicIpAnswered)
                    | PeerEvent::Notice(NoticeEvent::ChatMessageReceived { .. })
            )),
            "a human-layer classification must not fire before Identified, got {out:?}"
        );
    }
}

// --- Session no-break volley ---------------------------------------

#[test]
fn the_full_human_layer_volley_mid_transfer_leaves_the_active_slot_unbroken() {
    let h = file_hash(0x77);
    let mut session = identified_session();

    // Open a real requester-capability transfer: request parts, satisfy the
    // probe + hash-set gate, get the slot granted.
    let ranges = PartRanges::new([(0, 16), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    }));
    session.handle_bytes(&reqfilename_answer(h, "volley.bin"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    session.handle_bytes(&acceptuploadreq());
    let setup = drain(|| session.poll_output());
    assert!(
        events(&setup)
            .iter()
            .any(|e| matches!(e, PeerEvent::Requester(RequesterEvent::SlotGranted { file_hash }) if *file_hash == h)),
        "setup must reach a granted slot, got {setup:?}"
    );

    // Fire the entire human-layer catalog on the same connection, mid-slot.
    let volley: Vec<Vec<u8>> = vec![
        ask_shared_files(),
        ask_shared_dirs(),
        ask_shared_files_dir(),
        ask_shared_files_answer(),
        ask_shared_dirs_ans(),
        ask_shared_files_dir_ans(),
        ask_shared_denied_ans(),
        public_ip_req(),
        public_ip_answer(Ipv4Addr::new(203, 0, 113, 200)),
        message("mid-transfer hello"),
        filedesc(3, "still going"),
        change_client_id(0x0203_0405, Ipv4Addr::new(198, 51, 100, 1)),
        chat_captcha_req(),
        chat_captcha_res(),
    ];
    for wire in &volley {
        session.handle_bytes(wire);
    }
    let volley_out = drain(|| session.poll_output());
    // No protocol violation: the connection must still be open afterward.
    assert!(
        !events(&volley_out).iter().any(|e| matches!(
            e,
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
        )),
        "the volley must not close the session, got {volley_out:?}"
    );
    // The active slot must not have been touched by any of it.
    assert!(
        !events(&volley_out)
            .iter()
            .any(|e| matches!(e, PeerEvent::Requester(RequesterEvent::SlotReleased { .. }))),
        "the volley must not release the active slot, got {volley_out:?}"
    );

    // The transfer proceeds unbroken: the requested bytes still arrive and
    // the worker can still release the slot normally.
    let data: Vec<u8> = (0..16u8).collect();
    session.handle_bytes(&sendingpart(h, 0, &data));
    let part_out = drain(|| session.poll_output());
    assert!(
        events(&part_out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::PartReceived { file_hash, offset: 0, bytes }) if *file_hash == h && bytes == &data
        )),
        "expected PartReceived after the volley, got {part_out:?}"
    );

    session.handle_command(PeerCommand::Requester(RequesterCommand::ReleaseSlot {
        file_hash: h,
    }));
    let released = drain(|| session.poll_output());
    assert!(
        events(&released).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::SlotReleased { file_hash, reason: SlotReleaseReason::DownloadComplete }) if *file_hash == h
        )),
        "expected a normal DownloadComplete release after the volley, got {released:?}"
    );
}
