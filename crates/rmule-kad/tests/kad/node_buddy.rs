//! Buddy recruitment: the `0x51` this node sends, the tracked-packet and XOR
//! guards a `0x5A` answer must pass, and the events an inbound findbuddy or
//! callback request surfaces to the core.

use rmule_kad::{Kad2Message, KadCommand, KadEvent, KadNode, KadNodeDiagnostic};
use rmule_primitives::Ipv4Endpoint;
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{
    T0, datagrams, deliver, diagnostics, endpoint, events, host_ip, id, info, node,
};

/// Assemble a plain (`0xE4`) `0x5A KADEMLIA_FINDBUDDY_RES` wire datagram:
/// `<buddyID 16><responderHash 16><tcpport 2 LE>[connectopts 1]`.
fn findbuddy_res_bytes(buddy_id: u8, hash: u8, tcp: u16, connect_options: Option<u8>) -> Vec<u8> {
    let mut bytes = vec![0xE4, 0x5A];
    bytes.extend_from_slice(&[buddy_id; 16]);
    bytes.extend_from_slice(&[hash; 16]);
    bytes.extend_from_slice(&tcp.to_le_bytes());
    if let Some(opts) = connect_options {
        bytes.push(opts);
    }
    bytes
}

#[test]
fn buddy_recruit_emits_0x51_toward_the_inverse_target_and_a_verified_0x5a_fills_the_slot() {
    // ADR-0061 firewalled-node recruitment: rmule (Kad ID 0xAA…) asks
    // a converged contact to be its buddy. The `0x51` carries the recruitment
    // target `~0xAA == 0x55…`, our user hash (0xEE…), and our TCP port (4662).
    let mut node = node();
    let buddy = endpoint(1, 4701);
    node.recruit_buddy(T0, buddy);

    let mut expected = vec![0xE4, 0x51];
    expected.extend_from_slice(&[0x55; 16]);
    expected.extend_from_slice(&[0xEE; 16]);
    expected.extend_from_slice(&[0x36, 0x12]); // 4662 little-endian
    assert_eq!(
        datagrams(&drain(|| node.poll_output())),
        vec![(buddy, expected)]
    );

    // A `0x5A` from that tracked target, echoing the inverse target so it
    // XOR-verifies (`~0x55 == 0xAA`), fills the slot — with the responder's hash,
    // TCP port (6752), and the v7+ connect-options byte.
    node.handle_datagram(
        T0,
        buddy,
        &findbuddy_res_bytes(0x55, 0xBB, 6752, Some(0x03)),
    );
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![
            KadEvent::HadContact { from: buddy },
            KadEvent::BuddyFound {
                buddy: Ipv4Endpoint::new(host_ip(1), 4701),
                buddy_id: id(0x55),
                buddy_hash: rmule_kad::UserHash::from_bytes([0xBB; 16]),
                buddy_tcp_port: 6752,
                connect_options: Some(0x03),
            }
        ]
    );
}

/// A contact ID inside aMule's `SEARCHTOLERANCE` of `id(0x55)`: the XOR
/// distance's top word (bytes 0..4 read little-endian) is `0x0100_0000`.
fn id_within_tolerance_of_0x55() -> rmule_kad::KadId {
    let mut bytes = [0x55; 16];
    bytes[3] ^= 0x01;
    rmule_kad::KadId::from_bytes(bytes)
}

/// Drive a FINDBUDDY walk toward `id(0x55)` whose only responders are
/// `contacts`, to convergence, returning its outputs.
fn converged_findbuddy_walk(
    contacts: &[(rmule_kad::KadId, rmule_kad::KadNodeEndpoint)],
) -> Vec<rmule_kad::KadOutput> {
    let mut node = node();
    for (contact_id, at) in contacts {
        let hello = rmule_kad::Kad2NodeInfo {
            id: *contact_id,
            ..info(0x50, None)
        };
        deliver(&mut node, T0, *at, &Kad2Message::HelloReq(hello));
    }
    drain(|| node.poll_output());
    node.handle_command(T0, KadCommand::FindBuddyWalk { target: id(0x55) });
    drain(|| node.poll_output());
    for (_, at) in contacts {
        deliver(
            &mut node,
            T0,
            *at,
            &Kad2Message::LookupRes {
                target: id(0x55),
                contacts: Vec::new(),
            },
        );
    }
    drain(|| node.poll_output())
}

/// aMule's `StorePacket` sends a FINDBUDDY only to a contact inside
/// `SEARCHTOLERANCE` of the target, or on a LAN (`Search.cpp:624-628`),
/// the same gate the Callback Walk applies when it looks for that buddy
/// again. A walk whose closest responder is outside it and on the WAN asks
/// nobody and says so.
#[test]
fn a_findbuddy_walk_asks_nobody_outside_the_store_tolerance() {
    let far = endpoint(0x50, 4750);
    let outputs = converged_findbuddy_walk(&[(id(0x50), far)]);
    assert!(
        datagrams(&outputs)
            .iter()
            .all(|(_, bytes)| bytes[1] != 0x51),
        "no 0x51 to a contact a callback could never reach"
    );
    assert!(
        events(&outputs).contains(&KadEvent::BuddyWalkEnded { asked: false }),
        "{:?}",
        events(&outputs)
    );
}

#[test]
fn the_findbuddy_walk_asks_the_contact_closest_to_the_inverse_target() {
    // ADR-0061's FINDBUDDY walk (aMule `Search.cpp#L784`): the firewalled node
    // walks toward `~ourKadID` and, at convergence, asks the *closest* responded
    // contact to be its buddy. Two contacts answer our `KADEMLIA2_REQ`; only the
    // one nearer `0x55…` (and inside `SEARCHTOLERANCE`) is sent a `0x51`.
    let mut node = node();
    let near = endpoint(0x50, 4750);
    let far = endpoint(0x90, 4790);
    for (contact_id, at) in [(id_within_tolerance_of_0x55(), near), (id(0x90), far)] {
        let hello = rmule_kad::Kad2NodeInfo {
            id: contact_id,
            ..info(0x50, None)
        };
        deliver(&mut node, T0, at, &Kad2Message::HelloReq(hello));
    }
    drain(|| node.poll_output());

    node.handle_command(
        T0,
        KadCommand::FindBuddyWalk {
            target: id(0x55), // `~0xAA`, what `recruitment_target` derives.
        },
    );
    // The walk's own α queries go out first; nothing is asked to buddy yet.
    assert!(
        datagrams(&drain(|| node.poll_output()))
            .iter()
            .all(|(_, bytes)| bytes[1] != 0x51),
        "the walk queries before it recruits"
    );

    // Both answer with no closer candidate, so the walk converges.
    for at in [near, far] {
        deliver(
            &mut node,
            T0,
            at,
            &Kad2Message::LookupRes {
                target: id(0x55),
                contacts: Vec::new(),
            },
        );
    }
    let outputs = drain(|| node.poll_output());
    let recruits: Vec<_> = datagrams(&outputs)
        .into_iter()
        .filter(|(_, bytes)| bytes[1] == 0x51)
        .collect();
    let mut expected = vec![0xE4, 0x51];
    expected.extend_from_slice(&[0x55; 16]);
    expected.extend_from_slice(&[0xEE; 16]);
    expected.extend_from_slice(&[0x36, 0x12]); // 4662 little-endian
    assert_eq!(
        recruits,
        vec![(near, expected)],
        "only the closest responded contact is asked"
    );
    assert!(
        events(&outputs).contains(&KadEvent::BuddyWalkEnded { asked: true }),
        "the walk reports that it asked somebody: {:?}",
        events(&outputs)
    );
}

/// A second `FindBuddyWalk` toward a target already being walked is kept
/// out, and says so: the walk in flight answers for both.
#[test]
fn a_second_findbuddy_walk_toward_the_same_target_is_diagnosed() {
    let mut node = node();
    let at = endpoint(0x50, 4750);
    deliver(&mut node, T0, at, &Kad2Message::HelloReq(info(0x50, None)));
    drain(|| node.poll_output());

    node.handle_command(T0, KadCommand::FindBuddyWalk { target: id(0x55) });
    let first = drain(|| node.poll_output());
    assert!(diagnostics(&first).is_empty(), "{:?}", diagnostics(&first));

    node.handle_command(T0, KadCommand::FindBuddyWalk { target: id(0x55) });
    let second = drain(|| node.poll_output());
    assert_eq!(
        diagnostics(&second),
        vec![KadNodeDiagnostic::DuplicateFindBuddyWalk { target: id(0x55) }]
    );
    assert!(datagrams(&second).is_empty(), "no second walk goes out");
}

#[test]
fn a_findbuddy_walk_with_nothing_to_ask_ends_saying_so() {
    // An empty routing table cannot seed a walk, so the walk converges at once
    // with nobody to ask. Core re-arms on the event rather than waiting out the
    // 20-minute FindBuddy tick for a walk that never left the house.
    let mut node = node();
    node.handle_command(T0, KadCommand::FindBuddyWalk { target: id(0x55) });
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        events(&outputs),
        vec![KadEvent::BuddyWalkEnded { asked: false }]
    );
    assert!(
        datagrams(&outputs).is_empty(),
        "nothing to query, nothing to recruit"
    );
}

#[test]
fn an_unanswered_buddy_recruit_expires_at_its_window_and_stops_waking_the_node() {
    // The recruit tracker holds `(ip, deadline)` per `0x51`; an unanswered
    // recruit must not pin its entry forever. Its deadline joins the wake set
    // so an otherwise-idle node actually ticks the prune, and after the window
    // a late `0x5A` from the target is untracked again.
    let mut node = node();
    let buddy = endpoint(1, 4701);
    assert_eq!(node.next_wake(), None, "an idle node starts quiescent");

    node.recruit_buddy(T0, buddy);
    drain(|| node.poll_output());
    assert_eq!(
        node.next_wake(),
        Some(T0 + KadNode::FIREWALL_CHECK_WINDOW),
        "the tracked recruit's expiry drives the wake"
    );

    node.tick(T0 + KadNode::FIREWALL_CHECK_WINDOW);
    assert_eq!(
        node.next_wake(),
        None,
        "the expired recruit is pruned and the node re-quiesces"
    );

    // The pruned target's (correctly XOR-echoing) late answer is untracked.
    node.handle_datagram(
        T0 + KadNode::FIREWALL_CHECK_WINDOW,
        buddy,
        &findbuddy_res_bytes(0x55, 0xBB, 6752, None),
    );
    assert!(matches!(
        diagnostics(&drain(|| node.poll_output())).as_slice(),
        [KadNodeDiagnostic::UnrequestedBuddyResponse { .. }]
    ));
}

#[test]
fn a_findbuddy_response_that_is_untracked_or_fails_the_xor_guard_is_dropped() {
    let mut node = node();
    // Untracked: no `0x51` was ever sent to this endpoint.
    node.handle_datagram(
        T0,
        endpoint(2, 4702),
        &findbuddy_res_bytes(0x55, 0xBB, 6752, None),
    );
    assert!(matches!(
        diagnostics(&drain(|| node.poll_output())).as_slice(),
        [KadNodeDiagnostic::UnrequestedBuddyResponse { .. }]
    ));

    // Tracked, but the echoed buddyID is not `~ourKadID` (0x11 ≠ 0x55): the
    // XOR-inversion guard rejects it, exactly as aMule's `GetKadID() == check`.
    node.recruit_buddy(T0, endpoint(1, 4701));
    drain(|| node.poll_output());
    node.handle_datagram(
        T0,
        endpoint(1, 4701),
        &findbuddy_res_bytes(0x11, 0xBB, 6752, None),
    );
    assert!(matches!(
        diagnostics(&drain(|| node.poll_output())).as_slice(),
        [KadNodeDiagnostic::UnrequestedBuddyResponse { .. }]
    ));
}

#[test]
fn inbound_findbuddy_and_callback_requests_surface_as_core_decided_events() {
    // The open-node consume side: the node decodes `0x51`/`0x52` and surfaces the
    // typed event; the buddy-slot accept and the relay decision are core-side.
    let mut node = node();
    let from = endpoint(5, 4705);

    // 0x51 FINDBUDDY_REQ: <buddyID 16><requesterHash 16><tcpport 2>.
    let mut req = vec![0xE4, 0x51];
    req.extend_from_slice(&[0x33; 16]);
    req.extend_from_slice(&[0x44; 16]);
    req.extend_from_slice(&[0x38, 0x12]); // 4664
    node.handle_datagram(T0, from, &req);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![
            KadEvent::HadContact { from },
            KadEvent::FindBuddyRequested {
                requester: Ipv4Endpoint::new(host_ip(5), 4705),
                buddy_id: id(0x33),
                requester_hash: rmule_kad::UserHash::from_bytes([0x44; 16]),
                requester_tcp_port: 4664,
            }
        ]
    );

    // 0x52 CALLBACK_REQ: <buddyID 16><fileHash 16><tcpport 2>.
    let mut cb = vec![0xE4, 0x52];
    cb.extend_from_slice(&[0x7A; 16]);
    cb.extend_from_slice(&[0xCD; 16]);
    cb.extend_from_slice(&[0x88, 0x13]); // 5000
    node.handle_datagram(T0, from, &cb);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::CallbackRelayRequested {
            requester: Ipv4Endpoint::new(host_ip(5), 4705),
            buddy_id: id(0x7A),
            file_hash: rmule_kad::FileHash::from_bytes([0xCD; 16]),
            requester_tcp_port: 5000,
        }]
    );
}

#[test]
fn answer_findbuddy_emits_the_0x5a_accept_echoing_the_target_with_our_identity() {
    // The open-node accept enactment (ADR-0061): once core's single-slot buddy
    // service accepts a `0x51` recruit, it commands the `0x5A` answer. The node
    // echoes the requester's proposed `buddy_id` verbatim and fills in *our*
    // responder identity from config — client hash (0xEE…) and advertised TCP
    // port (4662) — so the firewalled requester can address our buddy TCP link.
    let mut node = node();
    let requester = endpoint(5, 4705);

    // Plain form: no sender key on the request → no v7+ connect-options byte.
    node.handle_command(
        T0,
        KadCommand::AnswerFindBuddy {
            requester,
            buddy_id: id(0x33),
            connect_options: None,
        },
    );
    assert_eq!(
        datagrams(&drain(|| node.poll_output())),
        vec![(requester, findbuddy_res_bytes(0x33, 0xEE, 4662, None))]
    );

    // v7+ form: the crypt connect-options byte rides along after the TCP port.
    node.handle_command(
        T0,
        KadCommand::AnswerFindBuddy {
            requester,
            buddy_id: id(0x33),
            connect_options: Some(0x03),
        },
    );
    assert_eq!(
        datagrams(&drain(|| node.poll_output())),
        vec![(requester, findbuddy_res_bytes(0x33, 0xEE, 4662, Some(0x03)))]
    );
}
