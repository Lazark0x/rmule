//! Live integration test for the peer-transfer slice. Env-gated on
//! both `RMULE_LIVE_TRANSFER_PEER` (ipv4:port) and
//! `RMULE_LIVE_TRANSFER_FILE` (ed2k file link); when either is unset
//! the test is `#[ignore]` and the default `cargo test` run skips it.
//!
//! Asserts only through `HashSetReceived` per ADR-0025 / the slice's
//! live test policy: slot grant is unbounded in eMule reality, so
//! deeper assertions would make the test brittle. Operators wanting
//! end-to-end live evidence use `rmule-tools ed2k peer transfer
//! capture` or the `download_one_part` example.

use std::time::Duration;

use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::{
    ConnectionEvent, PartRanges, PeerCommand, PeerEvent, PeerHandshakeContext, RequesterCommand,
    RequesterEvent,
};
use rmule_primitives::{
    ClientId, ClientIdentity, ED2K_PART_SIZE, Ed2kLink, Ed2kText, Ipv4Endpoint, PeerEndpoint,
    UserHash,
};

#[tokio::test]
#[ignore = "requires RMULE_LIVE_TRANSFER_PEER and RMULE_LIVE_TRANSFER_FILE"]
async fn live_transfer_reaches_hash_set_received() {
    let Ok(peer_str) = std::env::var("RMULE_LIVE_TRANSFER_PEER") else {
        return;
    };
    let Ok(link_str) = std::env::var("RMULE_LIVE_TRANSFER_FILE") else {
        return;
    };

    let addr: std::net::SocketAddr = peer_str.parse().expect("parse peer addr");
    let std::net::IpAddr::V4(ip) = addr.ip() else {
        panic!("peer must be ipv4");
    };
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(ip, addr.port()));
    let link = Ed2kLink::parse(&link_str).expect("parse ed2k link");
    let file = match link {
        Ed2kLink::File(f) => f,
        _ => panic!("RMULE_LIVE_TRANSFER_FILE must be a file link"),
    };

    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x42; 16]),
        Ed2kText::from_utf8("rmule-live-test"),
        4662,
        60,
    );
    let ctx = PeerHandshakeContext {
        identity,
        client_id: ClientId::from_u32(0x10000001),
        ed2k_client_id: ClientId::from_u32(0x10000001),
        public_ip: None,
        connected_server: None,
    };
    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(10),
        hello_timeout: Duration::from_secs(20),
        ..Default::default()
    };
    let mut conn = Connection::connect(peer, ctx, options)
        .await
        .expect("connect");
    let ranges = PartRanges::new([
        (0, std::cmp::min(file.size, ED2K_PART_SIZE)),
        (0, 0),
        (0, 0),
    ])
    .expect("ranges");

    let mut identified = false;
    let mut probed = false;
    let mut hash_set = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    while !hash_set && tokio::time::Instant::now() < deadline {
        let Some(evt) = tokio::time::timeout(Duration::from_secs(1), conn.next_event())
            .await
            .ok()
            .flatten()
        else {
            continue;
        };
        match evt {
            PeerEvent::Connection(ConnectionEvent::Identified { .. }) => {
                identified = true;
                conn.send(PeerCommand::Requester(RequesterCommand::RequestHashSet {
                    file_hash: file.file_hash,
                }))
                .await
                .ok();
                conn.send(PeerCommand::Requester(RequesterCommand::RequestParts {
                    file_hash: file.file_hash,
                    file_size: file.size,
                    ranges,
                }))
                .await
                .ok();
            }
            PeerEvent::Requester(RequesterEvent::FileProbed { .. }) => probed = true,
            PeerEvent::Requester(RequesterEvent::HashSetReceived { .. }) => hash_set = true,
            PeerEvent::Connection(ConnectionEvent::Disconnected { reason }) => {
                panic!("peer disconnected: {reason:?}");
            }
            _ => {}
        }
    }
    let _ = conn.shutdown().await;

    assert!(identified, "Identified arrived");
    assert!(probed, "FileProbed arrived");
    assert!(hash_set, "HashSetReceived arrived within 30s");
}
