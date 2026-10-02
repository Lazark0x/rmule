//! Same-socket serve test: a peer rmule dialed asks for a file back over that
//! very connection and is served from it.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rmule_net::peer::{ConnectOptions as PeerConnectOptions, PeerListener};
use rmule_peer::{PartBitmap, PartRanges, PeerCommand, PeerEvent};
use rmule_primitives::{Ed2kFileLink, Ed2kText, Ipv4Endpoint, PeerEndpoint, UserHash};
use rmule_primitives::{FileHashSummary, part_count};
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;

use crate::adapters::peer_transfer::{PeerTransferService, RuntimePeerTransferService};
use crate::adapters::serve_runtime::{ServeConnCommand, ServeConnEvent};
use crate::adapters::tests::dialed_serve_ctx;

use super::*;

/// A connection rmule *dialed* (to download) also serves the peer's pull on
/// the same socket: the worker produces a serve half, and a file the peer
/// requests is streamed back over that one connection.
#[tokio::test]
async fn a_dialed_connection_serves_the_peer_it_dialed_on_the_same_socket() {
    // A sub-part shared file: one block, one SendBlock, empty hash set.
    let bytes = vec![0xAB_u8; 4096];
    let summary = FileHashSummary::digest_bytes(&bytes);
    let file_hash = summary.file_hash();

    // Mock peer: bind a listener, accept OUR worker's dial, then pull the
    // shared file from us and collect the streamed bytes. Our requester
    // auto-issues the filename / hash-set / slot steps before the parts.
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let mock = tokio::spawn(async move {
        let mut conn = listener
            .accept(dialed_serve_ctx(), PeerConnectOptions::default())
            .await
            .unwrap();
        loop {
            match conn.next_event().await {
                Some(PeerEvent::PeerIdentified { .. }) => break,
                Some(PeerEvent::Disconnected { .. }) | None => return Vec::new(),
                _ => {}
            }
        }
        let ranges = PartRanges::new([(0, 4096), (0, 0), (0, 0)]).unwrap();
        let _ = conn
            .send(PeerCommand::RequestParts {
                file_hash,
                file_size: 4096,
                ranges,
            })
            .await;
        let mut got = Vec::new();
        while let Some(event) = conn.next_event().await {
            if let PeerEvent::PartReceived { bytes, .. } = event {
                got.extend_from_slice(&bytes);
                if got.len() >= 4096 {
                    break;
                }
            }
        }
        got
    });

    // Our side: a peer-transfer adapter whose dialed connections serve.
    let (dialed_tx, mut dialed_rx) = mpsc::channel(4);
    let sink: SharedDialedServeSink = Arc::new(Mutex::new(Some(dialed_tx)));
    let mut transfer =
        RuntimePeerTransferService::with_dialed_serve_sink(crate::DEFAULT_SLOT_WAIT_TIMEOUT, sink);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    // A dummy download target: we never assign a part, so this proves the
    // *serve* direction. Download coexistence is covered by download_loopback.
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash,
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let _worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();

    // The dialed connection produced a serve half.
    let mut serve_conn = timeout(Duration::from_secs(5), dialed_rx.recv())
        .await
        .expect("serve half produced for the dialed connection")
        .expect("serve connection present");

    // Act as the serve task for the one shared file: answer each probe and
    // stream the requested block back over the dialed socket.
    timeout(Duration::from_secs(5), async {
        while let Some(event) = serve_conn.next_event().await {
            match event {
                ServeConnEvent::FileRequested { file_hash, .. } => serve_conn
                    .send(ServeConnCommand::AnswerFileName {
                        file_hash,
                        file_name: Ed2kText::from_utf8("dummy"),
                    })
                    .await
                    .unwrap(),
                ServeConnEvent::FileBundleRequested {
                    file_hash, asks, ..
                } => {
                    for ask in asks {
                        let command = match ask {
                            rmule_peer::BundledAsk::Name { .. } => {
                                ServeConnCommand::AnswerFileName {
                                    file_hash,
                                    file_name: Ed2kText::from_utf8("dummy"),
                                }
                            }
                            rmule_peer::BundledAsk::SetReqId => {
                                ServeConnCommand::AnswerFileStatus {
                                    file_hash,
                                    bitmap: PartBitmap::decode(part_count(4096), &[0xFF]).unwrap(),
                                }
                            }
                            _ => continue,
                        };
                        serve_conn.send(command).await.unwrap();
                    }
                }
                ServeConnEvent::FileIdSet { file_hash } => serve_conn
                    .send(ServeConnCommand::AnswerFileStatus {
                        file_hash,
                        bitmap: PartBitmap::decode(part_count(4096), &[0xFF]).unwrap(),
                    })
                    .await
                    .unwrap(),
                ServeConnEvent::HashSetRequested { file_hash } => serve_conn
                    .send(ServeConnCommand::AnswerHashSet {
                        file_hash,
                        part_hashes: Vec::new(),
                    })
                    .await
                    .unwrap(),
                ServeConnEvent::SlotRequested { file_hash } => serve_conn
                    .send(ServeConnCommand::GrantSlot { file_hash })
                    .await
                    .unwrap(),
                ServeConnEvent::PartsRequested { file_hash, ranges } => {
                    for &(start, end) in ranges.as_array().iter().filter(|(s, e)| e > s) {
                        serve_conn
                            .send(ServeConnCommand::SendBlock {
                                file_hash,
                                start,
                                end,
                                bytes: bytes[start as usize..end as usize].to_vec(),
                            })
                            .await
                            .unwrap();
                    }
                    break;
                }
                ServeConnEvent::AichRequested { .. } => {}
                ServeConnEvent::AichFileHashRequested { .. } => {}
                // Not exercised: this dialed download never asks us for sources.
                ServeConnEvent::SourcesRequested { .. } => {}
                // Not exercised: this test never cancels mid-transfer.
                ServeConnEvent::TransferCancelled { .. } => {}
                ServeConnEvent::Disconnected => break,
                // Not exercised on a dialed serve half (no callback routing).
                ServeConnEvent::Readopted => break,
                // No SUI on this test's connections.
                ServeConnEvent::IdentityVerified { .. }
                | ServeConnEvent::SoftwareRevised { .. }
                | ServeConnEvent::ReaskContactRevised { .. } => {}
                ServeConnEvent::Identified { user_hash, .. } => {
                    assert_eq!(user_hash, UserHash::from_bytes([0x09; UserHash::BYTE_LEN]));
                }
            }
        }
    })
    .await
    .expect("served the requested block within 5s");

    let served = timeout(Duration::from_secs(5), mock)
        .await
        .expect("mock peer finished within 5s")
        .unwrap();
    assert_eq!(
        served, bytes,
        "the peer rmule dialed received the file rmule serves, over the same socket"
    );
}
