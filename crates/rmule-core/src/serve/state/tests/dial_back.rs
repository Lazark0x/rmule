//! The **Dial-Back Grant** (ADR-0057): a freed slot reaches the waiter it
//! promotes — on a link it holds, on the link rmule dials back to it, or on
//! the one it comes back on — and a dial that fails hands the slot on, as
//! aMule's `AddUpNextClient` (`UploadQueue.cpp:202-222`) and
//! `ConnectionEstablished` (`BaseClient.cpp:1707-1716`) do. A Low-ID waiter is
//! passed over and granted at its next connection (`UploadQueue.cpp:126-149`,
//! `:410-425`).

use rmule_primitives::PeerCrypt;

use super::*;
use crate::service::{DialBackEnd, DialEnd, GrantRoad};

/// The slot `holder` holds, and `waiter` — identified as `user_hash`, a High
/// ID listening on 4662 — queued behind it and hung up.
fn hung_up_behind(
    file: FileHash,
    holder: PeerEndpoint,
    waiter: PeerEndpoint,
    user_hash: UserHash,
    t: Instant,
) -> ServeState {
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let _ = slot_request(&mut state, holder, file, t);
    identify(&mut state, waiter, user_hash, t);
    let _ = slot_request(&mut state, waiter, file, t);
    let _ = state.on_conn_event(t, waiter, disconnected(), &no_modifiers());
    state
}

/// The dial-back to `waiter`: its address at its hello's listen port, toward
/// its hello's crypt stance and User Hash.
fn dial_of(waiter: PeerEndpoint, user_hash: UserHash) -> ServeDecision {
    ServeDecision::DialBack(crate::adapters::DialBack {
        waiter,
        at: waiter.with_port(4662),
        crypt: PeerCrypt::new(crypt_advert(), Some(user_hash)),
    })
}

fn granted(peer: PeerEndpoint, file_hash: FileHash, road: GrantRoad) -> [ServeDecision; 2] {
    [
        send(peer, ServerCommand::GrantSlot { file_hash }),
        ServeDecision::Emit(ServeEvent::UploadSlotGranted {
            peer,
            file_hash,
            software: Some(nameless_software()),
            road,
        }),
    ]
}

#[test]
fn a_promoted_waiter_with_no_link_is_dialed_and_granted_after_the_hellos() {
    let file = hash(0x41);
    let t = Instant::now();
    let (holder, waiter) = (peer_at([10, 0, 0, 1], 51000), peer_at([10, 0, 0, 2], 51318));
    let mut state = hung_up_behind(file, holder, waiter, user(0x0A), t);

    assert_eq!(
        state.on_conn_event(t, holder, disconnected(), &no_modifiers()),
        [
            dial_of(waiter, user(0x0A)),
            ServeDecision::Emit(ServeEvent::UploadDialBack {
                peer: waiter,
                file_hash: file,
                software: Some(nameless_software()),
            }),
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: holder }),
        ]
    );

    // The dialed link's hello names the waiter: the held slot goes on it.
    let link = waiter.with_port(4662);
    let hello = hello_facts(user(0x0A), 0, 0, 2).identity();
    let [grant, said] = granted(link, file, GrantRoad::DialedBack);
    assert_eq!(
        state.on_dial_back_linked(t, waiter, link, hello, &no_modifiers()),
        [
            ServeDecision::Emit(ServeEvent::WaiterRelinked {
                from: waiter,
                to: link,
            }),
            grant,
            said,
        ]
    );
    assert!(state.queue.is_granted(link));
}

#[test]
fn a_promoted_waiter_with_a_live_link_is_granted_on_it() {
    // The client's second link from elsewhere stays its own while the first
    // lives (`ClientList.cpp:384-398`); once the first hangs up, the
    // promotion finds the second and grants there, dialing nothing.
    let file = hash(0x42);
    let t = Instant::now();
    let (holder, waiter) = (peer_at([10, 0, 0, 1], 51000), peer_at([10, 0, 0, 2], 51318));
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let _ = slot_request(&mut state, holder, file, t);
    identify(&mut state, waiter, user(0x0A), t);
    let _ = slot_request(&mut state, waiter, file, t);
    let elsewhere = peer_at([198, 51, 100, 7], 40000);
    identify(&mut state, elsewhere, user(0x0A), t);
    let _ = state.on_conn_event(t, waiter, disconnected(), &no_modifiers());

    let [grant, said] = granted(elsewhere, file, GrantRoad::Linked);
    assert_eq!(
        state.on_conn_event(t, holder, disconnected(), &no_modifiers()),
        [
            ServeDecision::Emit(ServeEvent::WaiterRelinked {
                from: waiter,
                to: elsewhere,
            }),
            grant,
            said,
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: holder }),
        ]
    );
}

#[test]
fn a_waiter_back_while_its_slot_is_held_is_granted_on_the_link_it_came_back_on() {
    // aMule grants a client it promoted unconnected on whichever link its
    // hellos finish first, inbound included (`ClientTCPSocket.cpp:417`,
    // `BaseClient.cpp:1707-1716`) — not at its next ask.
    let file = hash(0x43);
    let t = Instant::now();
    let (holder, waiter) = (peer_at([10, 0, 0, 1], 51000), peer_at([10, 0, 0, 2], 51318));
    let mut state = hung_up_behind(file, holder, waiter, user(0x0A), t);
    let _ = state.on_conn_event(t, holder, disconnected(), &no_modifiers());

    let back = peer_at([10, 0, 0, 2], 50288);
    let hello = hello_facts(user(0x0A), 0, 0, 2).identified();
    let [grant, said] = granted(back, file, GrantRoad::CameBack);
    assert_eq!(
        state.on_conn_event(t, back, hello, &no_modifiers()),
        [
            ServeDecision::Emit(ServeEvent::WaiterRelinked {
                from: waiter,
                to: back,
            }),
            grant,
            said,
        ]
    );
    // The dial that was in flight comes up after: nothing of the grant is
    // left for it, so its link is let go.
    let link = waiter.with_port(4662);
    let dialed = hello_facts(user(0x0A), 0, 0, 2).identity();
    assert_eq!(
        state.on_dial_back_linked(t, waiter, link, dialed, &no_modifiers()),
        [ServeDecision::Disconnect { peer: link }]
    );
    assert!(state.queue.is_granted(back));
}

#[test]
fn a_failed_dial_back_frees_the_slot_for_the_next_waiter() {
    let file = hash(0x44);
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(60);
    let (holder, first) = (peer_at([10, 0, 0, 1], 51000), peer_at([10, 0, 0, 2], 51318));
    let mut state = hung_up_behind(file, holder, first, user(0x0A), t0);
    let second = peer_at([10, 0, 0, 3], 52000);
    identify(&mut state, second, user(0x0B), t1);
    let _ = slot_request(&mut state, second, file, t1);
    let promoted = state.on_conn_event(t1, holder, disconnected(), &no_modifiers());
    assert_eq!(promoted[0], dial_of(first, user(0x0A)), "{promoted:?}");

    let [grant, said] = granted(second, file, GrantRoad::Linked);
    assert_eq!(
        state.on_dial_back_failed(t1, first, DialEnd::ConnectionRefused, &no_modifiers()),
        [
            ServeDecision::Emit(ServeEvent::UploadDialBackFailed {
                peer: first,
                cause: DialBackEnd::Dial(DialEnd::ConnectionRefused),
            }),
            grant,
            said,
        ]
    );
    // aMule deletes a client whose upload connect failed
    // (`BaseClient.cpp:1333-1337`): the waiter's place went with the grant.
    assert!(!state.queue.contains(first));
}

#[test]
fn a_dialed_hello_naming_another_client_ends_the_grant() {
    let file = hash(0x45);
    let t = Instant::now();
    let (holder, waiter) = (peer_at([10, 0, 0, 1], 51000), peer_at([10, 0, 0, 2], 51318));
    let mut state = hung_up_behind(file, holder, waiter, user(0x0A), t);
    let _ = state.on_conn_event(t, holder, disconnected(), &no_modifiers());

    let link = waiter.with_port(4662);
    let stranger = hello_facts(user(0x0C), 0, 0, 2).identity();
    assert_eq!(
        state.on_dial_back_linked(t, waiter, link, stranger, &no_modifiers()),
        [
            ServeDecision::Emit(ServeEvent::UploadDialBackFailed {
                peer: waiter,
                cause: DialBackEnd::AnotherClient,
            }),
            ServeDecision::Disconnect { peer: link },
        ]
    );
    assert!(!state.queue.contains(waiter));
}

#[test]
fn a_low_id_waiter_is_passed_over_and_granted_when_it_next_connects() {
    let file = hash(0x46);
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(60);
    let holder = peer_at([10, 0, 0, 1], 51000);
    let (low, high) = (peer_at([10, 0, 0, 2], 51318), peer_at([10, 0, 0, 3], 52000));
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let _ = slot_request(&mut state, holder, file, t0);
    let low_id = || HelloFacts {
        client_id: ClientId::from_u32(5),
        ..hello_facts(user(0x0A), 0, 0, 2)
    };
    let _ = state.on_conn_event(t0, low, low_id().identified(), &no_modifiers());
    let _ = slot_request(&mut state, low, file, t0);
    identify(&mut state, high, user(0x0B), t1);
    let _ = slot_request(&mut state, high, file, t1);
    let _ = state.on_conn_event(t1, low, disconnected(), &no_modifiers());

    // The Low ID ranks first but nothing can dial it: the High ID behind it
    // takes the slot, and the Low ID is marked for its next connection.
    let [grant, said] = granted(high, file, GrantRoad::Linked);
    assert_eq!(
        state.on_conn_event(t1, holder, disconnected(), &no_modifiers()),
        [
            grant,
            said,
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: holder }),
        ]
    );

    // Back on a new link, its slot ask takes a slot one over the budget.
    let back = peer_at([10, 0, 0, 2], 50288);
    let _ = state.on_conn_event(t1, back, low_id().identified(), &no_modifiers());
    let [grant, said] = granted(back, file, GrantRoad::NextConnection);
    assert_eq!(slot_request(&mut state, back, file, t1), [grant, said]);
}
