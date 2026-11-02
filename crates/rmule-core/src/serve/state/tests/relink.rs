//! A waiter is a client, not a link: the hello of a new link that names a
//! client already waiting takes that client's place (aMule attaches the new
//! socket to the client it knows, `ClientList.cpp:371-412`, and a client
//! already on the queue keeps its place, `UploadQueue.cpp:395-431`).

use super::*;

/// The rank `p`'s slot ask for `file` is answered with.
fn rank_of(state: &mut ServeState, p: PeerEndpoint, file: FileHash, t: Instant) -> Option<u16> {
    slot_request(state, p, file, t)
        .into_iter()
        .find_map(|decision| match decision {
            ServeDecision::Emit(ServeEvent::PeerQueued { rank, .. }) => Some(rank),
            _ => None,
        })
}

/// A one-slot state whose slot `peer(1)` holds and whose wait list holds
/// `waiter`, identified as `user(0x0B)`.
fn waiting(file: FileHash, waiter: PeerEndpoint, t: Instant) -> ServeState {
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let _ = slot_request(&mut state, peer(1), file, t);
    identify(&mut state, waiter, user(0x0B), t);
    assert_eq!(rank_of(&mut state, waiter, file, t), Some(1));
    state
}

fn hello_of(state: &mut ServeState, p: PeerEndpoint, user_hash: UserHash) -> Vec<ServeDecision> {
    let identified = hello_facts(user_hash, 0, 0, 2).identified();
    state.on_conn_event(Instant::now(), p, identified, &no_modifiers())
}

#[test]
fn a_waiter_back_on_a_new_link_keeps_its_place() {
    let file = hash(0x31);
    let t = Instant::now();
    let (first, second) = (
        peer_at([172, 19, 0, 5], 51318),
        peer_at([172, 19, 0, 5], 50288),
    );
    let mut state = waiting(file, first, t);
    let _ = state.on_conn_event(t, first, disconnected(), &no_modifiers());

    assert_eq!(
        hello_of(&mut state, second, user(0x0B)),
        [ServeDecision::Emit(ServeEvent::WaiterRelinked {
            from: first,
            to: second,
        })]
    );
    assert_eq!(rank_of(&mut state, second, file, t), Some(1));
    assert_eq!(state.queue.waiting_len(), 1, "no stale entry behind it");
}

#[test]
fn a_new_link_takes_a_place_only_from_its_own_client() {
    let file = hash(0x32);
    let t = Instant::now();
    let first = peer_at([172, 19, 0, 5], 51318);

    // Another user from the same address is another client.
    let mut state = waiting(file, first, t);
    let _ = state.on_conn_event(t, first, disconnected(), &no_modifiers());
    let neighbour = peer_at([172, 19, 0, 5], 50288);
    assert_eq!(hello_of(&mut state, neighbour, user(0x0C)), []);
    assert_eq!(rank_of(&mut state, neighbour, file, t), Some(2));

    // The same user on a second link while its first is still up from
    // another address is not attached (`ClientList.cpp:384-398`).
    let mut state = waiting(file, first, t);
    let elsewhere = peer_at([198, 51, 100, 7], 40000);
    assert_eq!(hello_of(&mut state, elsewhere, user(0x0B)), []);
    assert_eq!(rank_of(&mut state, first, file, t), Some(1));
}

#[test]
fn a_new_link_from_where_the_live_one_is_replaces_it() {
    // aMule drops the socket it held and keeps the client on the new one
    // (`ClientList.cpp:400-403`).
    let file = hash(0x33);
    let t = Instant::now();
    let (first, second) = (
        peer_at([172, 19, 0, 5], 51318),
        peer_at([172, 19, 0, 5], 50288),
    );
    let mut state = waiting(file, first, t);

    assert_eq!(
        hello_of(&mut state, second, user(0x0B)),
        [
            ServeDecision::Emit(ServeEvent::WaiterRelinked {
                from: first,
                to: second,
            }),
            ServeDecision::Disconnect { peer: first },
        ]
    );
    assert_eq!(rank_of(&mut state, second, file, t), Some(1));
    // The replaced link's close moves nobody.
    assert_eq!(
        state.on_conn_event(t, first, disconnected(), &no_modifiers()),
        []
    );
    assert_eq!(state.queue.waiting_len(), 1);
}

#[test]
fn a_link_rmule_dialed_takes_no_client_from_its_live_link() {
    // aMule moves a client to a new socket only at the hello of one the peer
    // opened (`ClientTCPSocket.cpp:391`); the hello answer on a socket it
    // dialed finishes that client's own.
    let file = hash(0x34);
    let t = Instant::now();
    let first = peer_at([172, 19, 0, 5], 51318);
    let mut state = waiting(file, first, t);
    let dialed = peer_at([172, 19, 0, 5], 4662);
    state.on_link_dialed(dialed, crate::adapters::FarEnd::new());

    assert_eq!(hello_of(&mut state, dialed, user(0x0B)), []);
    assert_eq!(rank_of(&mut state, first, file, t), Some(1));
}

/// Prove `p`'s hello hash by Secure User Identification, the link binding
/// it.
fn bind(state: &mut ServeState, p: PeerEndpoint, user_hash: UserHash) {
    let bound = ServeInput::IdentityBound { user_hash };
    let _ = state.on_conn_event(Instant::now(), p, bound, &no_modifiers());
}

#[test]
fn a_second_link_naming_an_identified_linked_clients_hash_is_banned() {
    // aMule: "Banreason: Userhash invalid" (`ClientList.cpp:384-392`).
    let file = hash(0x35);
    let t = Instant::now();
    let held = peer_at([172, 19, 0, 5], 51318);
    let mut state = waiting(file, held, t);
    let elsewhere = peer_at([198, 51, 100, 7], 40000);
    bind(&mut state, held, user(0x0B));

    assert_eq!(
        hello_of(&mut state, elsewhere, user(0x0B)),
        [
            ServeDecision::Ban { peer: elsewhere },
            ServeDecision::Disconnect { peer: elsewhere },
        ]
    );
    // Once the identified client's link is gone the same hash is welcome.
    let _ = state.on_conn_event(t, held, disconnected(), &no_modifiers());
    assert_eq!(
        hello_of(&mut state, elsewhere, user(0x0B)),
        [ServeDecision::Emit(ServeEvent::WaiterRelinked {
            from: held,
            to: elsewhere,
        })]
    );
}

#[test]
fn a_hash_clash_drops_the_unidentified_waiter_and_answers_an_unidentified_asker_nothing() {
    // aMule `UploadQueue.cpp:432-458`.
    let file = hash(0x36);
    let t = Instant::now();
    let held = peer_at([172, 19, 0, 5], 51318);
    let clash = peer_at([198, 51, 100, 7], 40000);

    let mut state = waiting(file, held, t);
    let _ = hello_of(&mut state, clash, user(0x0B));
    assert_eq!(
        slot_request(&mut state, clash, file, t),
        [ServeDecision::Emit(ServeEvent::WaiterLeft {
            peer: held,
            cause: WaiterLeaveCause::UserHashClash,
        })],
        "neither is identified: the waiter leaves and the asker hears nothing"
    );
    assert_eq!(state.queue.waiting_len(), 0);

    // An identified asker takes its place in the queue as the unidentified
    // waiter leaves.
    let mut state = waiting(file, held, t);
    let _ = hello_of(&mut state, clash, user(0x0B));
    bind(&mut state, clash, user(0x0B));
    let decisions = slot_request(&mut state, clash, file, t);
    assert!(
        decisions.contains(&ServeDecision::Emit(ServeEvent::WaiterLeft {
            peer: held,
            cause: WaiterLeaveCause::UserHashClash,
        }))
    );
    assert!(decisions.contains(&send(clash, ServerCommand::SetQueueRank { rank: 1 })));
}

// --- One client on two addresses (ADR-0107) ---

/// The address the client of run `1793356626` dials from over IPv4.
const CLIENT_V4: [u8; 4] = [45, 55, 200, 3];

/// A hello naming `user(0x0B)`, claiming the High ID that is `CLIENT_V4`.
fn claiming_v4() -> HelloFacts {
    HelloFacts {
        client_id: rmule_primitives::ClientId::from_u32(u32::from_le_bytes(CLIENT_V4)),
        ..hello_facts(user(0x0B), 0, 0, 2)
    }
}

/// One client's two links, one address, two ephemeral ports.
fn two_links() -> (PeerEndpoint, PeerEndpoint) {
    (
        peer_at([172, 19, 0, 5], 51318),
        peer_at([172, 19, 0, 5], 50288),
    )
}

/// Leaving a slot tracks the client, proof or none (`UploadQueue.cpp:525`), so
/// it comes back under another hash into the ban
/// (`BaseClient.cpp:686-689`).
#[test]
fn a_slot_holder_back_under_another_hash_is_banned_with_no_proof() {
    let file = hash(0x31);
    let t = Instant::now();
    let (first, second) = two_links();
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    identify(&mut state, first, user(0x0B), t);
    let _ = slot_request(&mut state, first, file, t);
    let _ = state.on_conn_event(t, first, disconnected(), &no_modifiers());

    let back = hello_of(&mut state, second, user(0x0C));
    assert!(
        back.contains(&ServeDecision::Ban { peer: second }),
        "{back:?}"
    );
}

/// A waiter that never held a slot or proved a key is tracked by nothing, in
/// stock as here: a new hash is a new client.
#[test]
fn a_waiter_back_under_another_hash_is_a_new_client() {
    let file = hash(0x31);
    let t = Instant::now();
    let (first, second) = two_links();
    let mut state = waiting(file, first, t);
    let _ = state.on_conn_event(t, first, disconnected(), &no_modifiers());

    let back = hello_of(&mut state, second, user(0x0C));
    assert!(
        !back.contains(&ServeDecision::Ban { peer: second }),
        "{back:?}"
    );
}

/// A hello naming `user(0x0B)` and `v6_peer(3, _)`'s address as its IPv6.
fn naming_v6() -> HelloFacts {
    HelloFacts {
        ipv6: Some(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 3)),
        ..hello_facts(user(0x0B), 0, 0, 2)
    }
}

/// A one-slot state whose slot `peer(1)` holds, and whose wait list holds
/// `held`, linked and proved, on the hello `facts`.
fn verified_waiter(file: FileHash, held: PeerEndpoint, facts: HelloFacts) -> ServeState {
    let t = Instant::now();
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let _ = slot_request(&mut state, peer(1), file, t);
    let _ = state.on_conn_event(t, held, facts.identified(), &no_modifiers());
    assert_eq!(rank_of(&mut state, held, file, t), Some(1));
    bind(&mut state, held, user(0x0B));
    state
}

fn hello_on(state: &mut ServeState, p: PeerEndpoint, facts: HelloFacts) -> Vec<ServeDecision> {
    state.on_conn_event(Instant::now(), p, facts.identified(), &no_modifiers())
}

/// The shape of run `1793356626`: the client's IPv6 link, proved, claims the
/// IPv4 its second link comes from 51 ms later. It is banned today.
#[test]
fn a_clients_ipv4_named_by_its_proved_ipv6_link_is_its_second_link() {
    let file = hash(0x36);
    let t = Instant::now();
    let held = v6_peer(3, 58334);
    let mut state = verified_waiter(file, held, claiming_v4());
    let second = peer_at(CLIENT_V4, 52354);

    assert_eq!(hello_on(&mut state, second, claiming_v4()), []);
    assert_eq!(
        slot_request(&mut state, second, file, t),
        [send(second, ServerCommand::SetQueueRank { rank: 1 })],
        "answered with the rank the client holds, and no second place"
    );
    assert_eq!(state.queue.waiting_len(), 1);
    assert_eq!(rank_of(&mut state, held, file, t), Some(1));
}

#[test]
fn a_clients_ipv6_named_by_its_proved_ipv4_link_is_its_second_link() {
    let file = hash(0x37);
    let t = Instant::now();
    let held = peer_at(CLIENT_V4, 52354);
    let mut state = verified_waiter(file, held, naming_v6());
    let second = v6_peer(3, 58334);

    assert_eq!(hello_on(&mut state, second, naming_v6()), []);
    assert_eq!(
        slot_request(&mut state, second, file, t),
        [send(second, ServerCommand::SetQueueRank { rank: 1 })],
    );
    assert_eq!(state.queue.waiting_len(), 1);
}

/// A client holding a slot on one family asks on the other: one client, one
/// slot.
#[test]
fn a_second_link_of_a_client_holding_a_slot_takes_no_second_slot() {
    let file = hash(0x38);
    let t = Instant::now();
    let held = v6_peer(3, 58334);
    let mut state = serving_state(2, vec![entry(file, 4096, "served.bin")]);
    let _ = state.on_conn_event(t, held, claiming_v4().identified(), &no_modifiers());
    let _ = slot_request(&mut state, held, file, t);
    bind(&mut state, held, user(0x0B));
    assert!(state.queue.is_granted(held));
    let second = peer_at(CLIENT_V4, 52354);

    assert_eq!(hello_on(&mut state, second, claiming_v4()), []);
    assert_eq!(
        slot_request(&mut state, second, file, t),
        [send(second, ServerCommand::SetQueueRank { rank: 1 })],
    );
    assert!(!state.queue.is_granted(second));
}

/// The newcomer's own claim proves nothing: it is a stranger on another
/// family, never banned at first sight, and it gets no place.
#[test]
fn a_link_on_another_family_its_client_never_named_is_unproved_and_not_banned() {
    let file = hash(0x39);
    let t = Instant::now();
    let held = v6_peer(3, 58334);
    let mut state = verified_waiter(file, held, hello_facts(user(0x0B), 0, 0, 2));
    let stranger = peer_at(CLIENT_V4, 52354);

    assert_eq!(hello_on(&mut state, stranger, claiming_v4()), []);
    assert_eq!(slot_request(&mut state, stranger, file, t), []);
    assert_eq!(state.queue.waiting_len(), 1);
    assert_eq!(rank_of(&mut state, held, file, t), Some(1));
}

/// An IPv6 host holds several addresses at once.
#[test]
fn a_second_ipv6_address_of_a_proved_hash_is_not_banned() {
    let file = hash(0x3A);
    let t = Instant::now();
    let held = v6_peer(3, 58334);
    let mut state = verified_waiter(file, held, hello_facts(user(0x0B), 0, 0, 2));
    let other = v6_peer(4, 58400);

    assert_eq!(hello_of(&mut state, other, user(0x0B)), []);
    assert_eq!(slot_request(&mut state, other, file, t), []);
    assert_eq!(state.queue.waiting_len(), 1);
}

/// Neither link proved, nobody named: an ask from the other family cannot
/// knock the first out of the queue, and earns nothing itself.
#[test]
fn an_unproved_ask_from_another_family_evicts_nobody() {
    let file = hash(0x3B);
    let t = Instant::now();
    let held = v6_peer(3, 58334);
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let _ = slot_request(&mut state, peer(1), file, t);
    identify(&mut state, held, user(0x0B), t);
    assert_eq!(rank_of(&mut state, held, file, t), Some(1));
    let other = peer_at(CLIENT_V4, 52354);
    let _ = hello_of(&mut state, other, user(0x0B));

    assert_eq!(slot_request(&mut state, other, file, t), []);
    assert_eq!(rank_of(&mut state, held, file, t), Some(1));
}

/// The unproved link proves the key on its own link: one client from then
/// on, in any family.
#[test]
fn an_unproved_link_that_proves_the_key_is_the_clients_second_link() {
    let file = hash(0x3C);
    let t = Instant::now();
    let held = v6_peer(3, 58334);
    let mut state = verified_waiter(file, held, hello_facts(user(0x0B), 0, 0, 2));
    let second = peer_at(CLIENT_V4, 52354);
    let _ = hello_of(&mut state, second, user(0x0B));
    bind(&mut state, second, user(0x0B));

    assert_eq!(
        slot_request(&mut state, second, file, t),
        [send(second, ServerCommand::SetQueueRank { rank: 1 })],
    );
    assert_eq!(state.queue.waiting_len(), 1);
}

/// aMule's rule runs at the `OP_HELLO` of a socket the peer opened
/// (`ClientTCPSocket.cpp:391`): where rmule dials, the hello answer is no
/// newcomer, even between two IPv4 addresses.
#[test]
fn a_link_rmule_dialed_is_never_banned() {
    let file = hash(0x3D);
    let held = peer_at([172, 19, 0, 5], 51318);
    let mut state = verified_waiter(file, held, hello_facts(user(0x0B), 0, 0, 2));
    let dialed = peer_at([198, 51, 100, 7], 4662);
    state.on_link_dialed(dialed, crate::adapters::FarEnd::new());

    assert_eq!(hello_of(&mut state, dialed, user(0x0B)), []);
}

/// The slot of a proved client whose link ends rides on on its second link,
/// and never on an unproved one.
#[test]
fn a_slot_moves_to_a_proved_second_link_and_never_to_an_unproved_one() {
    let file = hash(0x3E);
    let t = Instant::now();
    let slotted = |facts: HelloFacts| {
        let held = v6_peer(3, 58334);
        let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
        let _ = state.on_conn_event(t, held, facts.identified(), &no_modifiers());
        let _ = slot_request(&mut state, held, file, t);
        bind(&mut state, held, user(0x0B));
        (state, held)
    };
    let second = peer_at(CLIENT_V4, 52354);

    let (mut proved, held) = slotted(claiming_v4());
    let _ = hello_on(&mut proved, second, claiming_v4());
    let _ = proved.on_conn_event(t, held, disconnected(), &no_modifiers());
    assert!(proved.queue.is_granted(second));

    let (mut unproved, held) = slotted(hello_facts(user(0x0B), 0, 0, 2));
    let _ = hello_of(&mut unproved, second, user(0x0B));
    let _ = unproved.on_conn_event(t, held, disconnected(), &no_modifiers());
    assert!(!unproved.queue.is_granted(second));
}

/// The client's first link ended with its place: the next ask of its second
/// link takes the place, as a standing whose link has ended moves to any
/// link.
#[test]
fn a_place_whose_link_ended_moves_to_the_clients_second_link_at_its_ask() {
    let file = hash(0x3F);
    let t = Instant::now();
    let held = v6_peer(3, 58334);
    let mut state = verified_waiter(file, held, claiming_v4());
    let second = peer_at(CLIENT_V4, 52354);
    let _ = hello_on(&mut state, second, claiming_v4());
    let _ = state.on_conn_event(t, held, disconnected(), &no_modifiers());

    let decisions = slot_request(&mut state, second, file, t);
    assert!(
        decisions.contains(&ServeDecision::Emit(ServeEvent::WaiterRelinked {
            from: held,
            to: second,
        }))
    );
    assert!(decisions.contains(&send(second, ServerCommand::SetQueueRank { rank: 1 })));
    assert_eq!(state.queue.waiting_len(), 1);
}

/// One client holds one key: a proof of another under the hash, while the
/// client that holds the bound one is linked, is the thief, and now it is
/// banned, on proof.
#[test]
fn a_link_that_proves_another_key_under_a_linked_clients_hash_is_banned() {
    let file = hash(0x40);
    let t = Instant::now();
    let held = v6_peer(3, 58334);
    let mut state = verified_waiter(file, held, hello_facts(user(0x0B), 0, 0, 2));
    let thief = peer_at(CLIENT_V4, 52354);
    let _ = hello_of(&mut state, thief, user(0x0B));
    let mismatch = ServeInput::KeyMismatch {
        user_hash: user(0x0B),
    };

    assert_eq!(
        state.on_conn_event(t, thief, mismatch.clone(), &no_modifiers()),
        [
            ServeDecision::Ban { peer: thief },
            ServeDecision::Disconnect { peer: thief },
        ]
    );
    // With no holder linked the proof is the ledger's to raise, and no ban's.
    let _ = state.on_conn_event(t, held, disconnected(), &no_modifiers());
    assert_eq!(state.on_conn_event(t, thief, mismatch, &no_modifiers()), []);
}
