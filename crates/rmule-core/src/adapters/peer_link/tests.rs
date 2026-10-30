//! The Peer Links' names and turns (ADR-0107, "One peer, one link"): what a
//! link is found by, which link holds a name two links prove, and who rides
//! next.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_primitives::Ipv6Endpoint;

use super::*;
use crate::hello_facts::HelloFacts;

fn user(seed: u8) -> UserHash {
    UserHash::from_bytes([seed; UserHash::BYTE_LEN])
}

fn v4(ip: [u8; 4], port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::from(ip), port))
}

fn server() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4661)
}

#[test]
fn a_low_id_asker_is_found_by_its_callback_and_an_ipv6_asker_by_its_own_address() {
    let low_id = ClientId::from_u32(0x0000_1234);
    let lowid_asker = HelloFacts {
        client_id: low_id,
        connected_server: Some(server()),
        tcp_port: 4662,
        ..HelloFacts::of(user(0x11))
    }
    .identity();
    let names = LinkName::of(v4([203, 0, 113, 9], 51_000), &lowid_asker);
    assert!(names.contains(&LinkName::Callback {
        server: server(),
        low_id,
    }));
    assert!(names.contains(&LinkName::User(user(0x11))));

    // An IPv6 asker claiming a High ID: the claim names nothing; the link's
    // own address with the listen port is where it is a source.
    let claimed = ClientId::from_u32(u32::from_le_bytes([192, 0, 2, 44]));
    let v6_asker = HelloFacts {
        client_id: claimed,
        tcp_port: 4662,
        ..HelloFacts::of(user(0x12))
    }
    .identity();
    let address = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x44);
    let names = LinkName::of(
        PeerEndpoint::V6(Ipv6Endpoint::new(address, 50_123)),
        &v6_asker,
    );
    assert_eq!(
        names,
        [
            LinkName::Endpoint(PeerEndpoint::V6(Ipv6Endpoint::new(address, 4662))),
            LinkName::User(user(0x12)),
        ]
    );
}

#[test]
fn a_newer_link_takes_a_name_and_the_older_one_ending_leaves_it_there() {
    let links = SharedPeerLinks::default();
    let shared = LinkName::User(user(0x21));
    let (older_at, newer_at) = (v4([203, 0, 113, 1], 4662), v4([203, 0, 113, 1], 50_288));
    let (older, _older_joins, _) = links.file(older_at, vec![LinkName::Endpoint(older_at), shared]);
    let (newer, _newer_joins, _) = links.file(newer_at, vec![shared]);

    assert_eq!(
        links.find(&[shared]).map(|found| found.remote),
        Some(newer_at)
    );
    drop(older);
    assert_eq!(
        links.find(&[shared]).map(|found| found.remote),
        Some(newer_at)
    );
    assert!(links.find(&[LinkName::Endpoint(older_at)]).is_none());
    drop(newer);
    assert!(links.find(&[shared]).is_none());
}

#[test]
fn the_link_the_peer_opened_during_a_dial_keeps_every_name_past_the_dials_hello() {
    // aMule attaches a socket to a client it knows only at the hello of a
    // socket the peer opened, replacing the one it was connecting
    // (`ClientTCPSocket.cpp:391`, `ClientList.cpp:400-403`): the dial's own
    // hello later takes nothing back, and its end leaves the names filed.
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 3], 4662);
    let looked_up = [LinkName::Endpoint(at), LinkName::User(user(0x23))];
    let Reach::Dial(dial) = links.reach(at, &looked_up) else {
        panic!("nothing is filed yet: the look-up files the dial");
    };
    let came_back = v4([203, 0, 113, 3], 50_288);
    let low_id = LinkName::Callback {
        server: server(),
        low_id: ClientId::from_u32(0x0000_1234),
    };
    let proven = vec![looked_up[0], looked_up[1], low_id];
    let (_inbound, _inbound_joins, _) = links.file(came_back, proven.clone());

    let (mut dialed, _dialed_joins) = dial.into_parts();
    dialed.refile(proven.clone());
    for name in &proven {
        assert_eq!(
            links.find(&[*name]).map(|found| found.remote),
            Some(came_back),
            "{name:?} stays with the link the peer opened"
        );
    }
    drop(dialed);
    for name in &proven {
        assert_eq!(
            links.find(&[*name]).map(|found| found.remote),
            Some(came_back),
            "{name:?} outlives the dial"
        );
    }
}

#[test]
fn a_dial_overtaken_while_its_socket_came_up_sends_no_hello() {
    // The far side keeps the socket it reads our hello on
    // (`ClientList.cpp:400-403`): a download's dial the peer's own link
    // overtook before its hello went out gives way, socket up or not, and
    // one that claimed its hello first is not overtaken.
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 4], 4662);
    let names = [LinkName::Endpoint(at), LinkName::User(user(0x24))];
    let Reach::Dial(mut overtaken) = links.reach(at, &names) else {
        panic!("nothing is filed yet: the look-up files the dial");
    };
    let came_back = v4([203, 0, 113, 4], 50_289);
    let (_inbound, _joins, moving) = links.file(came_back, names.to_vec());
    assert!(moving.coming(), "the dial's downloads move over");
    let Err(link) = overtaken.claim_hello() else {
        panic!("an overtaken dial claims no hello");
    };
    assert_eq!(link.remote, came_back);

    let other = v4([203, 0, 113, 5], 4662);
    let names = [LinkName::Endpoint(other), LinkName::User(user(0x25))];
    let Reach::Dial(mut claimed) = links.reach(other, &names) else {
        panic!("nothing is filed yet: the look-up files the dial");
    };
    assert!(claimed.claim_hello().is_ok());
    let (_inbound, _joins, moving) = links.file(v4([203, 0, 113, 5], 50_290), names.to_vec());
    assert!(
        !moving.coming(),
        "a dial whose hello went out is not overtaken"
    );
}

fn half() -> (DownloadHalf, mpsc::Sender<PeerCommand>) {
    let (peer_cmd_tx, peer_cmd_rx) = mpsc::channel(1);
    let half = DownloadHalf {
        requester_tx: mpsc::channel(1).0,
        worker_evt_tx: mpsc::channel(1).0,
        peer_cmd_rx,
    };
    (half, peer_cmd_tx)
}

fn join() -> (LinkJoin, oneshot::Receiver<()>, oneshot::Receiver<Seat>) {
    let (waiting, told) = oneshot::channel();
    let (seated, turn) = oneshot::channel();
    let join = LinkJoin {
        half: half().0,
        waiting,
        seated,
    };
    (join, told, turn)
}

#[test]
fn the_oldest_waiter_still_running_takes_the_link_when_the_rider_leaves() {
    let identity = HelloFacts::of(user(0x31)).identity();
    let (rider, _rider_cmd) = half();
    let mut riders = Riders::seated(rider);
    let (gone, mut gone_told, gone_turn) = join();
    let (next, mut next_told, mut next_turn) = join();
    let (last, mut last_told, mut last_turn) = join();
    riders.take(gone, Some(&identity));
    riders.take(next, Some(&identity));
    riders.take(last, Some(&identity));
    for told in [&mut gone_told, &mut next_told, &mut last_told] {
        assert_eq!(told.try_recv(), Ok(()), "a waiter is told it waits");
    }
    drop(gone_turn);

    riders.rider_left(Some(&identity));
    assert!(
        matches!(next_turn.try_recv(), Ok(Seat::Riding(_))),
        "the oldest live waiter rides"
    );
    assert!(last_turn.try_recv().is_err(), "the last still waits");
    assert!(!riders.is_empty());
}

/// Two downloads of one peer that start together (ADR-0107 invariant 11):
/// the first finds nothing and its dial is filed in the same step, the second
/// finds that dial and waits on it, and the dial failing before the hello
/// retires the waiter with the dial's cause and leaves nothing filed.
#[test]
fn a_dial_in_flight_is_found_by_the_next_download_and_its_failure_retires_the_waiter() {
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 7], 4662);
    let names = [LinkName::Endpoint(at), LinkName::User(user(0x41))];
    let Reach::Dial(dial) = links.reach(at, &names) else {
        panic!("nothing is filed: the first download dials");
    };
    let Reach::Found(found) = links.reach(at, &names) else {
        panic!("the second download finds the first one's dial");
    };
    assert_eq!(found.remote, at);
    let (waiter, _told, mut turn) = join();
    assert!(
        found.join_tx.try_send(waiter).is_ok(),
        "the dial takes the join"
    );

    dial.failed(DialEnd::ConnectionRefused);
    assert!(matches!(
        turn.try_recv(),
        Ok(Seat::DialEnded(DialEnd::ConnectionRefused))
    ));
    assert!(links.find(&names).is_none(), "a failed dial is unfiled");
}

/// A link that closes before its hello retires the downloads waiting on it,
/// and one whose hello came seats the oldest of them when nobody rides it.
#[test]
fn waiters_before_the_hello_take_the_dials_outcome() {
    let identity = HelloFacts::of(user(0x51)).identity();
    let (rider, _rider_cmd) = half();
    let mut riders = Riders::seated(rider);
    let (early, mut early_told, mut early_turn) = join();
    riders.take(early, None);
    assert_eq!(
        early_told.try_recv(),
        Ok(()),
        "a join before the hello waits"
    );
    riders.dial_ended(DialEnd::NoHelloInTime);
    assert!(matches!(
        early_turn.try_recv(),
        Ok(Seat::DialEnded(DialEnd::NoHelloInTime))
    ));

    let (rider, _rider_cmd) = half();
    let mut riders = Riders::seated(rider);
    let (waiter, _told, mut turn) = join();
    riders.take(waiter, None);
    riders.rider_left(None);
    assert!(
        turn.try_recv().is_err(),
        "nobody is seated before the hello"
    );
    riders.identified(&identity);
    assert!(matches!(turn.try_recv(), Ok(Seat::Riding(_))));
}

#[test]
fn a_changed_low_id_stands_only_on_a_server_the_list_holds() {
    use crate::server_list::{ManagedServer, ServerListStore};

    let list = crate::DurableAppConfig::new(rmule_testkit::memory_store());
    let listed = rmule_primitives::ServerEndpoint::new("198.51.100.7", 4661).expect("endpoint");
    list.merge_server(ManagedServer::listed(listed))
        .expect("the list takes it");
    let links = SharedPeerLinks::knowing(std::sync::Arc::new(list));
    let low_id = ClientId::from_u32(0x0000_1234);

    assert_eq!(
        links.take_client_id(low_id, Ipv4Addr::new(198, 51, 100, 7)),
        Some(ConnectionCommand::TakeClientId {
            client_id: low_id,
            server: Some(server()),
        })
    );
    assert_eq!(
        links.take_client_id(low_id, Ipv4Addr::new(198, 51, 100, 9)),
        None,
        "a Low ID on a server the node does not know moves nothing"
    );
    let high_id = ClientId::from_u32(u32::from_le_bytes([203, 0, 113, 9]));
    assert_eq!(
        links.take_client_id(high_id, Ipv4Addr::new(198, 51, 100, 9)),
        Some(ConnectionCommand::TakeClientId {
            client_id: high_id,
            server: None,
        })
    );
}

/// An unasked grant goes to the download holding the peer's Queue Standing
/// though another filed first, found by the User Hash from wherever the peer
/// came back; a grant on the standing calls the other download to the link
/// (ADR-0107).
#[test]
fn an_unasked_grant_goes_to_the_standing_holder_and_the_waiter_is_called() {
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 9], 4662);
    let names = vec![LinkName::Endpoint(at), LinkName::User(user(0x61))];
    let (waiter_tx, mut waiter_rx) = mpsc::channel(4);
    let (holder_tx, mut holder_rx) = mpsc::channel(4);
    let _waiter = links.await_grant(at, names.clone(), false, waiter_tx);
    let holder = links.await_grant(at, names.clone(), true, holder_tx);

    let moved = v4([203, 0, 113, 99], 4662);
    assert!(links.offer_grant(&[LinkName::Endpoint(moved), LinkName::User(user(0x61))]));
    assert_eq!(holder_rx.try_recv(), Ok(LinkOffer::Grant(at)));
    assert!(
        waiter_rx.try_recv().is_err(),
        "the waiter does not take the holder's grant"
    );

    drop(holder);
    links.call_waiters(&names);
    assert_eq!(waiter_rx.try_recv(), Ok(LinkOffer::Call(at)));
}

/// A dial filed under `names` at `at`, with its hello out.
fn dial_past_its_hello(
    links: &SharedPeerLinks,
    at: PeerEndpoint,
    names: &[LinkName],
) -> (Filing, tokio::sync::mpsc::Receiver<LinkJoin>) {
    let Reach::Dial(dial) = links.reach(at, names) else {
        panic!("nothing is filed yet");
    };
    dial.into_parts()
}

fn meet(links: &SharedPeerLinks, names: &[LinkName]) -> Meeting {
    let came_back = v4([203, 0, 113, 3], 50_288);
    links.meet(came_back, names.to_vec(), Some(user(0x80)))
}

#[tokio::test]
async fn a_hello_meeting_a_dial_past_its_hello_is_held_until_the_far_end_shows_which_link_it_kept()
{
    let within = std::time::Duration::from_secs(5);
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 3], 4662);
    let names = [LinkName::Endpoint(at), LinkName::User(user(0x23))];

    // The far end stayed on its own link: filed, it overtakes the dial.
    let (mut refused, _joins) = dial_past_its_hello(&links, at, &names);
    let Meeting::Crossed(mut crossed) = meet(&links, &names) else {
        panic!("the dial's hello is out: this hello waits");
    };
    assert_eq!(links.find(&names).map(|found| found.remote), Some(at));
    let verdict = tokio::spawn(async move { refused.heard_answer().await });
    assert_eq!(crossed.settled().await, DialSettled::Answered);
    let Meeting::Clear(_filed) = meet(&links, &names) else {
        panic!("an answered dial holds no hello up");
    };
    drop(crossed);
    let AnswerHeard::GaveWay(link) = tokio::time::timeout(within, verdict)
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("the dial gives way to the peer's own link");
    };
    assert_eq!(link.remote, v4([203, 0, 113, 3], 50_288));

    // The far end closed its own link: the dial stands, and owes the answer.
    let links = SharedPeerLinks::default();
    let (mut kept, _joins) = dial_past_its_hello(&links, at, &names);
    let Meeting::Crossed(mut crossed) = meet(&links, &names) else {
        panic!("the dial's hello is out: this hello waits");
    };
    let verdict = tokio::spawn(async move { kept.heard_answer().await });
    assert_eq!(crossed.settled().await, DialSettled::Answered);
    drop(crossed);
    assert!(matches!(
        tokio::time::timeout(within, verdict)
            .await
            .unwrap()
            .unwrap(),
        AnswerHeard::Kept
    ));

    // It closed it ahead of its answer, as stock aMule does: the same.
    let links = SharedPeerLinks::default();
    let (mut kept, _joins) = dial_past_its_hello(&links, at, &names);
    drop(meet(&links, &names));
    assert!(matches!(kept.heard_answer().await, AnswerHeard::Kept));

    // The dial ended: the hello is met again.
    let links = SharedPeerLinks::default();
    let (ended, _joins) = dial_past_its_hello(&links, at, &names);
    let Meeting::Crossed(mut crossed) = meet(&links, &names) else {
        panic!("the dial's hello is out: this hello waits");
    };
    drop(ended);
    assert_eq!(crossed.settled().await, DialSettled::Ended);
    assert!(matches!(meet(&links, &names), Meeting::Clear(_)));
}

#[tokio::test]
async fn a_dial_answered_with_no_hello_held_stands_at_once() {
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 3], 4662);
    let names = [LinkName::Endpoint(at), LinkName::User(user(0x23))];
    let (mut dial, _joins) = dial_past_its_hello(&links, at, &names);
    assert!(matches!(dial.heard_answer().await, AnswerHeard::Stands));
    assert!(
        matches!(meet(&links, &names), Meeting::Clear(_)),
        "an answered dial holds no hello up: the far end closes one of the two"
    );
}

#[tokio::test]
async fn a_dial_given_up_at_the_bound_hears_it_and_the_hello_is_filed() {
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 3], 4662);
    let names = [LinkName::Endpoint(at), LinkName::User(user(0x23))];
    let (mut dial, _joins) = dial_past_its_hello(&links, at, &names);
    let Meeting::Crossed(crossed) = meet(&links, &names) else {
        panic!("the dial's hello is out: this hello waits");
    };

    crossed.give_up();

    tokio::time::timeout(std::time::Duration::from_secs(5), dial.given_up())
        .await
        .expect("the dial hears it was given up");
    assert!(matches!(meet(&links, &names), Meeting::Clear(_)));
}

#[test]
fn of_two_rmules_crossing_the_higher_hash_gives_its_dial_up_first() {
    // Each holds the other's hello, and only the bound settles that.
    let at = v4([203, 0, 113, 3], 4662);
    let came_back = v4([203, 0, 113, 3], 50_288);
    let hold = |own: u8, peer: u8| {
        let links = SharedPeerLinks::default();
        let names = [LinkName::User(user(peer))];
        let (_dial, _joins) = dial_past_its_hello(&links, at, &names);
        let Meeting::Crossed(crossed) = links.meet(came_back, names.to_vec(), Some(user(own)))
        else {
            panic!("the dial's hello is out: this hello waits");
        };
        crossed.hold()
    };
    assert!(hold(0x90, 0x10) < hold(0x10, 0x90));
    assert!(
        hold(0x10, 0x90) + super::crossing::CLOSE_BOUND < std::time::Duration::from_secs(40),
        "inside the peer's clock on the link it waits on (`ClientTCPSocket.cpp:201-229`)"
    );
}

#[test]
fn a_hello_meeting_a_dial_before_its_hello_overtakes_it() {
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 3], 4662);
    let names = [LinkName::Endpoint(at), LinkName::User(user(0x23))];
    let Reach::Dial(mut dial) = links.reach(at, &names) else {
        panic!("nothing is filed yet");
    };
    assert!(matches!(meet(&links, &names), Meeting::Clear(_)));
    assert!(
        dial.claim_hello().is_err(),
        "no byte of the dial's hello may follow the answer"
    );
}

#[tokio::test]
async fn the_peers_own_link_lets_a_dial_dead_at_the_far_end_go_and_spares_a_live_one() {
    // A rider's dial the far end dropped would carry it to the dial's end,
    // with the peer's own link up beside it (`ClientList.cpp:400-403`).
    let within = std::time::Duration::from_millis(200);
    let silent = std::time::Duration::from_secs(41);
    let at = v4([203, 0, 113, 3], 4662);
    let names = [LinkName::Endpoint(at), LinkName::User(user(0x23))];
    for (far_end, dead) in [(FarEnd::silent_for(silent), true), (FarEnd::new(), false)] {
        let links = SharedPeerLinks::default();
        let (mut dial, _joins) = dial_past_its_hello(&links, at, &names);
        assert!(matches!(dial.heard_answer().await, AnswerHeard::Stands));
        dial.read_through(Some(&far_end));

        let Meeting::Clear(mut accepted) = meet(&links, &names) else {
            panic!("an answered dial holds no hello up");
        };
        accepted.moving.let_dead_dials_go();

        let let_go = tokio::time::timeout(within, let_go_of(Some(&far_end))).await;
        assert_eq!(let_go.is_ok(), dead);
    }
}

/// A client's second address, or a thief's, attaches to nothing while the link
/// that holds the hash stands: a download looking the peer up by its hash
/// rides that link, as aMule's client stays on its socket
/// (`ClientList.cpp:384-398`), and the name passes on when that link ends.
#[test]
fn a_link_from_another_address_takes_no_user_hash_from_the_link_that_stands() {
    let links = SharedPeerLinks::default();
    let (first, second) = (v4([203, 0, 113, 3], 4662), v4([198, 51, 100, 9], 4662));
    let hash = LinkName::User(user(0x24));
    let (held, _joins, _moving) = links.file(first, vec![LinkName::Endpoint(first), hash]);

    let (_newcomer, _joins, _moving) = links.file(second, vec![LinkName::Endpoint(second), hash]);

    let found = |names: &[LinkName]| links.find(names).map(|link| link.remote);
    assert_eq!(found(&[hash]), Some(first));
    assert_eq!(found(&[LinkName::Endpoint(second)]), Some(second));
    drop(held);
    assert_eq!(found(&[hash]), Some(second));
}

/// A hello proves no name, so one from anywhere but the address dialed takes
/// nothing from a dial before its hello: it stays filed, and it passes the
/// hash on at its end (ADR-0107, "What a link proves to take a dial").
#[tokio::test]
async fn a_link_from_another_address_does_not_overtake_a_dial_before_its_hello() {
    let links = SharedPeerLinks::default();
    let (dialed, came_in) = (v4([203, 0, 113, 3], 4662), v4([198, 51, 100, 9], 4662));
    let hash = LinkName::User(user(0x25));
    let Reach::Dial(mut dial) = links.reach(dialed, &[LinkName::Endpoint(dialed), hash]) else {
        panic!("nothing is linked yet: the look-up files a dial");
    };

    let (_link, _joins, _moving) = links.file(came_in, vec![LinkName::Endpoint(came_in), hash]);

    let overtaken = tokio::time::timeout(std::time::Duration::from_millis(50), dial.overtaken());
    assert!(overtaken.await.is_err(), "the dial is told nothing");
    assert_eq!(links.find(&[hash]).map(|link| link.remote), Some(dialed));
    drop(dial);
    assert_eq!(links.find(&[hash]).map(|link| link.remote), Some(came_in));
}

/// The sender of a hello from another address can hold its socket open past
/// the answer all it likes: nothing waits on it, so the close bound never
/// hands it the dial (ADR-0107, "What a link proves to take a dial").
#[tokio::test]
async fn a_hello_from_another_address_meets_no_dial_past_its_hello() {
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 3], 4662);
    let hash = LinkName::User(user(0x26));
    let (mut dial, _joins) = dial_past_its_hello(&links, at, &[LinkName::Endpoint(at), hash]);

    let sender = v4([198, 51, 100, 9], 50_288);
    let met = links.meet(sender, vec![LinkName::Endpoint(sender), hash], None);

    assert!(
        matches!(met, Meeting::Clear(_)),
        "a hello from elsewhere is not held on the dial"
    );
    assert_eq!(links.find(&[hash]).map(|link| link.remote), Some(at));
    assert!(matches!(dial.heard_answer().await, AnswerHeard::Stands));
    assert_eq!(links.find(&[hash]).map(|link| link.remote), Some(at));
}

/// The address is the proof, the port no part of it: the peer's own connect
/// comes from an ephemeral port and may name a listen port the source record
/// does not.
#[test]
fn a_hello_from_the_address_dialed_is_held_whatever_its_port() {
    let links = SharedPeerLinks::default();
    let at = v4([203, 0, 113, 3], 4662);
    let hash = LinkName::User(user(0x27));
    let (_dial, _joins) = dial_past_its_hello(&links, at, &[LinkName::Endpoint(at), hash]);

    let came_back = v4([203, 0, 113, 3], 50_288);
    let elsewhere = LinkName::Endpoint(came_back.with_port(4711));

    assert!(matches!(
        links.meet(came_back, vec![elsewhere, hash], None),
        Meeting::Crossed(_)
    ));
}
