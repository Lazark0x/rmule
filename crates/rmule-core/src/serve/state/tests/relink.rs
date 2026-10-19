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
    state.on_link_dialed(dialed);

    assert_eq!(hello_of(&mut state, dialed, user(0x0B)), []);
    assert_eq!(rank_of(&mut state, first, file, t), Some(1));
}

/// Prove `p`'s hello hash by Secure User Identification, the ledger binding
/// it.
fn bind(state: &mut ServeState, p: PeerEndpoint, user_hash: UserHash) {
    state.on_identity_bound(p, user_hash, true);
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
