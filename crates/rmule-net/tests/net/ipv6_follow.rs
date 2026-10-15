//! A live peer link follows our Advertised IPv6 (ADR-0087): a move after the
//! hellos reaches the peer as one `OP_CHANGE_CLIENT_IP`, which its session
//! reads as a revision of who we are.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule_net::peer::{ConnectOptions, Connection, Ipv6Follow, PeerStreamRole};
use rmule_peer::{ConnectionEvent, IdentityChange, PeerEvent, PeerHandshakeContext};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::sync::watch;

fn ctx(fill: u8) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([fill; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("follow"),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0x1000_0001),
        ed2k_client_id: ClientId::from_u32(0x1000_0001),
        public_ip: None,
        connected_server: None,
    }
}

fn at(last: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), 4662))
}

async fn identified(conn: &mut Connection) {
    loop {
        match conn.next_event().await {
            Some(PeerEvent::Connection(ConnectionEvent::Identified { .. })) => return,
            Some(PeerEvent::Connection(ConnectionEvent::Disconnected { reason })) => {
                panic!("the link closed: {reason:?}")
            }
            Some(_) => continue,
            None => panic!("the driver ended before the peer identified"),
        }
    }
}

#[tokio::test]
async fn a_move_of_our_ipv6_reaches_the_identified_peer() {
    let named: Ipv6Addr = "2001:db8::1".parse().expect("an address");
    let moved: Ipv6Addr = "2001:db8::2".parse().expect("an address");
    let current = Arc::new(Mutex::new(named));
    let (wake, changed) = watch::channel(0u64);
    let read = {
        let current = Arc::clone(&current);
        Arc::new(move || Some(*current.lock().expect("the address cell")))
    };
    let (ours_io, theirs_io) = tokio::io::duplex(64 * 1024);
    let mut ours = Connection::over_stream(
        ours_io,
        at(2),
        PeerStreamRole::Dialer,
        ctx(0xAA),
        ConnectOptions {
            ipv6: Some(named),
            ipv6_follow: Some(Ipv6Follow { changed, read }),
            ..ConnectOptions::default()
        },
    );
    let mut theirs = Connection::over_stream(
        theirs_io,
        at(1),
        PeerStreamRole::Responder,
        ctx(0xBB),
        ConnectOptions::default(),
    );
    tokio::join!(identified(&mut ours), identified(&mut theirs));

    *current.lock().expect("the address cell") = moved;
    wake.send_replace(1);
    let revised = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match theirs.next_event().await {
                Some(PeerEvent::Connection(ConnectionEvent::IdentityRevised {
                    what: IdentityChange::Ipv6,
                    identity,
                })) => return identity.peer_ipv6(),
                Some(_) => continue,
                None => panic!("the link ended before the move arrived"),
            }
        }
    })
    .await
    .expect("the move arrives within 5 s");
    assert_eq!(revised, Some(moved));
    drop(ours);
}
