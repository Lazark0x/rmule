//! Protocol-level transfer flow against the testkit `FakePeer` (Correctness
//! Tier, ADR-0040): a real `rmule_net::peer::Connection` runs the full probe →
//! queue-ranking → slot → parts flow and the consumer releases the held slot
//! (ADR-0025, amended) once the requested range is complete. The CLI-boundary
//! variant of this scenario lives in `peer_transfer_cli.rs`.

use std::time::Duration;

use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::{
    ConnectionEvent, PartRanges, PeerCommand, PeerEvent, RequesterCommand, RequesterEvent,
    SlotReleaseReason,
};
use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint};
use rmule_testkit::peer_session::loopback_ctx;
use rmule_testkit::{FakePeer, PeerScript, SlotPolicy};

use crate::fixture::FILE_HASH;

#[tokio::test]
async fn full_transfer_flow_replays_against_real_connection() {
    let part_data: Vec<u8> = (0..40u8).collect();
    let file_hash = FileHash::from_bytes(FILE_HASH);

    let fake = FakePeer::bind().await;
    let bound = fake.addr();
    // Rank 5 then 3 (improvement), then accept and serve the requested range.
    let mock = fake.spawn(PeerScript {
        file_name: "replay.bin".into(),
        slot: SlotPolicy::QueueThenGrant(vec![5, 3]),
        ..PeerScript::serving(file_hash, part_data.clone())
    });

    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(2),
        hello_timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let mut conn = Connection::connect(peer, loopback_ctx(), options)
        .await
        .unwrap();

    let file_size = part_data.len() as u64;
    let ranges = PartRanges::new([(0, file_size), (0, 0), (0, 0)]).unwrap();

    let mut events = Vec::new();
    let mut accumulated: Vec<u8> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut released = false;

    while std::time::Instant::now() < deadline && !released {
        let evt = match tokio::time::timeout(Duration::from_millis(500), conn.next_event()).await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => continue,
        };
        match &evt {
            PeerEvent::Connection(ConnectionEvent::Identified { .. }) => {
                // Sub-part RequestParts auto-pipelines probe + startupload.
                conn.send(PeerCommand::Requester(RequesterCommand::RequestParts {
                    file_hash,
                    file_size,
                    ranges,
                }))
                .await
                .unwrap();
            }
            PeerEvent::Requester(RequesterEvent::FileProbed { .. }) => {
                // Auto-pipelined via RequestParts; no extra work here.
            }
            PeerEvent::Requester(RequesterEvent::PartReceived { bytes, .. }) => {
                accumulated.extend_from_slice(bytes);
                // Held slot (ADR-0025, amended): the consumer is the
                // completion authority and releases the slot once it has
                // the whole requested range, rather than relying on a
                // per-request auto-release.
                if accumulated.len() as u64 >= file_size {
                    conn.send(PeerCommand::Requester(RequesterCommand::ReleaseSlot {
                        file_hash,
                    }))
                    .await
                    .unwrap();
                }
            }
            PeerEvent::Requester(RequesterEvent::SlotReleased { reason, .. }) => {
                assert_eq!(*reason, SlotReleaseReason::DownloadComplete);
                released = true;
            }
            _ => {}
        }
        events.push(evt);
    }

    let _ = conn.shutdown().await;
    let _ = mock.await;

    assert!(released, "SlotReleased(DownloadComplete) emitted");
    assert_eq!(accumulated, part_data, "accumulated bytes match part data");

    // Event order spot-checks: QueueProgress fires for rank 5 → 3.
    let progressed = events.iter().any(|e| {
        matches!(
            e,
            PeerEvent::Requester(RequesterEvent::QueueProgress {
                previous_rank: 5,
                new_rank: 3,
                ..
            })
        )
    });
    assert!(progressed, "QueueProgress(5→3) observed");

    // Identified strictly precedes the first FileProbed.
    let identified_idx = events
        .iter()
        .position(|e| matches!(e, PeerEvent::Connection(ConnectionEvent::Identified { .. })))
        .unwrap();
    let probed_idx = events
        .iter()
        .position(|e| matches!(e, PeerEvent::Requester(RequesterEvent::FileProbed { .. })))
        .unwrap();
    assert!(identified_idx < probed_idx);
}
