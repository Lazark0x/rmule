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
    let (older_at, newer_at) = (v4([203, 0, 113, 1], 4662), v4([203, 0, 113, 2], 4662));
    let (older, _older_joins) = links.file(older_at, vec![LinkName::Endpoint(older_at), shared]);
    let (newer, _newer_joins) = links.file(newer_at, vec![shared]);

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

fn half() -> (DownloadHalf, mpsc::Sender<PeerCommand>) {
    let (peer_cmd_tx, peer_cmd_rx) = mpsc::channel(1);
    let half = DownloadHalf {
        requester_tx: mpsc::channel(1).0,
        worker_evt_tx: mpsc::channel(1).0,
        peer_cmd_rx,
    };
    (half, peer_cmd_tx)
}

fn join() -> (
    LinkJoin,
    oneshot::Receiver<()>,
    oneshot::Receiver<PeerIdentity>,
) {
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
    riders.take(gone, &identity);
    riders.take(next, &identity);
    riders.take(last, &identity);
    for told in [&mut gone_told, &mut next_told, &mut last_told] {
        assert_eq!(told.try_recv(), Ok(()), "a waiter is told it waits");
    }
    drop(gone_turn);

    riders.rider_left(Some(&identity));
    assert!(next_turn.try_recv().is_ok(), "the oldest live waiter rides");
    assert!(last_turn.try_recv().is_err(), "the last still waits");
    assert!(!riders.is_empty());
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
