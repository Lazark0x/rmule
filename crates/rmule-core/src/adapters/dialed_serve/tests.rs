//! Same-socket serve test: a peer rmule dialed asks for a file back over that
//! very connection and is served from it.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_net::peer::{ConnectOptions as PeerConnectOptions, PeerListener};
use rmule_peer::{
    ConnectionEvent, PartBitmap, PartRanges, PeerCommand, PeerEvent, RequesterCommand,
    RequesterEvent, ServerCommand, ServerEvent,
};
use rmule_primitives::{Ed2kFileLink, Ed2kText, Ipv4Endpoint, PeerEndpoint, UserHash};
use rmule_primitives::{FileHashSummary, part_count};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::adapters::peer_transfer::{PeerTransferService, RuntimePeerTransferService};
use crate::adapters::serve_runtime::{ServeInput, ServeOutput};
use crate::adapters::tests::dialed_serve_ctx;

use super::*;

mod dial_in_flight;
mod hang_up;

/// A one-part file of 4096 bytes no peer serves: a download target whose
/// probe the peer's name answer completes.
fn dummy_file(seed: u8) -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash: FileHashSummary::digest_bytes(&[seed; 4096]).file_hash(),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

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
                Some(PeerEvent::Connection(ConnectionEvent::Identified { .. })) => break,
                Some(PeerEvent::Connection(ConnectionEvent::Disconnected { .. })) | None => {
                    return Vec::new();
                }
                _ => {}
            }
        }
        let ranges = PartRanges::new([(0, 4096), (0, 0), (0, 0)]).unwrap();
        let _ = conn
            .send(PeerCommand::Requester(RequesterCommand::RequestParts {
                file_hash,
                file_size: 4096,
                ranges,
            }))
            .await;
        let mut got = Vec::new();
        while let Some(event) = conn.next_event().await {
            if let PeerEvent::Requester(RequesterEvent::PartReceived { bytes, .. }) = event {
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
    let sink = SharedDialedServeSink::default();
    sink.install_for_good(dialed_tx);
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
                ServeInput::Server(ServerEvent::FileRequested { file_hash, .. }) => serve_conn
                    .send(ServeOutput::Server(ServerCommand::AnswerFileName {
                        file_hash,
                        file_name: Ed2kText::from_utf8("dummy"),
                    }))
                    .await
                    .unwrap(),
                ServeInput::Server(ServerEvent::FileBundleRequested {
                    file_hash, asks, ..
                }) => {
                    for ask in asks {
                        let command = match ask {
                            rmule_peer::BundledAsk::Name { .. } => {
                                ServeOutput::Server(ServerCommand::AnswerFileName {
                                    file_hash,
                                    file_name: Ed2kText::from_utf8("dummy"),
                                })
                            }
                            rmule_peer::BundledAsk::SetReqId => {
                                ServeOutput::Server(ServerCommand::AnswerFileStatus {
                                    file_hash,
                                    bitmap: PartBitmap::decode(part_count(4096), &[0xFF]).unwrap(),
                                })
                            }
                            _ => continue,
                        };
                        serve_conn.send(command).await.unwrap();
                    }
                }
                ServeInput::Server(ServerEvent::FileIdSet { file_hash }) => serve_conn
                    .send(ServeOutput::Server(ServerCommand::AnswerFileStatus {
                        file_hash,
                        bitmap: PartBitmap::decode(part_count(4096), &[0xFF]).unwrap(),
                    }))
                    .await
                    .unwrap(),
                ServeInput::Server(ServerEvent::HashSetRequested { file_hash }) => serve_conn
                    .send(ServeOutput::Server(ServerCommand::AnswerHashSet {
                        file_hash,
                        part_hashes: Vec::new(),
                    }))
                    .await
                    .unwrap(),
                ServeInput::Server(ServerEvent::SlotRequested { file_hash }) => serve_conn
                    .send(ServeOutput::Server(ServerCommand::GrantSlot { file_hash }))
                    .await
                    .unwrap(),
                ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges }) => {
                    for &(start, end) in ranges.as_array().iter().filter(|(s, e)| e > s) {
                        serve_conn
                            .send(ServeOutput::Server(ServerCommand::SendBlock {
                                file_hash,
                                start,
                                end,
                                bytes: bytes[start as usize..end as usize].to_vec(),
                            }))
                            .await
                            .unwrap();
                    }
                    break;
                }
                ServeInput::Server(ServerEvent::AichRequested { .. }) => {}
                ServeInput::Server(ServerEvent::AichFileHashRequested { .. }) => {}
                // Not exercised: this dialed download never asks us for sources.
                ServeInput::Server(
                    ServerEvent::SourcesRequested { .. } | ServerEvent::SourcesAnswered { .. },
                ) => {}
                // Not exercised: this test never cancels mid-transfer.
                ServeInput::Server(ServerEvent::TransferCancelled { .. }) => {}
                ServeInput::Connection(ConnectionEvent::Disconnected { .. }) => break,
                // Not exercised on a dialed serve half (no callback routing).
                ServeInput::Readopted => break,
                // No part ask without a slot from this mock.
                ServeInput::Server(ServerEvent::PartsWithoutSlot { .. }) => {}
                ServeInput::Connection(ConnectionEvent::Identified { identity }) => {
                    assert_eq!(
                        identity.user_hash(),
                        UserHash::from_bytes([0x09; UserHash::BYTE_LEN])
                    );
                }
                // No SUI, no revisions on this test's connections.
                ServeInput::Connection(_) => {}
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

/// aMule's `OP_KAD_FWTCPCHECK_ACK` handler (`ClientTCPSocket.cpp:1950-1962`)
/// runs on whichever socket the frame arrives on, so an ack read on a link
/// rmule dialed reaches the Kad node as an accepted link's does.
#[tokio::test]
async fn a_side_frame_read_on_a_dialed_link_reaches_the_node_wide_service() {
    use crate::adapters::AdapterCells;
    use crate::adapters::kad_runtime::KadPumpCommand;
    use rmule_peer::SideCommand;

    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let mock = tokio::spawn(async move {
        let mut conn = listener
            .accept(dialed_serve_ctx(), PeerConnectOptions::default())
            .await
            .unwrap();
        while let Some(event) = conn.next_event().await {
            if let PeerEvent::Connection(ConnectionEvent::Identified { .. }) = event {
                conn.send(PeerCommand::Side(SideCommand::SendKadFirewallAck))
                    .await
                    .unwrap();
                break;
            }
        }
        // Keep the link open until the test has read its fact.
        std::future::pending::<()>().await;
    });

    let (pump_tx, mut pump_rx) = mpsc::channel(4);
    let cells = AdapterCells::detached();
    cells.kad_pump.install_for_good(pump_tx);
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    transfer.adopt_cells(&cells);
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash: FileHashSummary::digest_bytes(&[0xAB; 4096]).file_hash(),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let _worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();
    let command = timeout(Duration::from_secs(5), pump_rx.recv())
        .await
        .expect("the ack reaches the Kad node within 5s")
        .expect("the pump is open");
    assert!(matches!(command, KadPumpCommand::TcpFirewallAck(ip) if ip == *bound.ip()));
    mock.abort();
}

/// Two downloads of one peer rmule dialed: the second waits on the first's
/// link and rides it at its turn (ADR-0107, "One peer, one link") — the peer
/// is dialed once, and the second file request reaches it on that same
/// connection once the first download let go. A second dial would make aMule
/// drop the first link (`ClientList.cpp:400-403`).
#[tokio::test]
async fn a_second_download_of_a_dialed_peer_waits_and_rides_the_same_link() {
    use crate::adapters::PeerWorkerEvent;
    use crate::service::LinkTurn;

    let (first_file, second_file) = (dummy_file(0xA1), dummy_file(0xA2));
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let (asked_tx, mut asked_rx) = mpsc::channel(8);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let first_hash = first_file.file_hash;
    // The peer: every link it accepts reports the files asked on it, tagged
    // with the link's number, and the first file is refused once the test
    // says so.
    let mock = tokio::spawn(async move {
        let mut release = Some(release_rx);
        let mut link = 0_u32;
        loop {
            let mut conn = listener
                .accept(dialed_serve_ctx(), PeerConnectOptions::default())
                .await
                .unwrap();
            link += 1;
            let asked_tx = asked_tx.clone();
            let release = release.take();
            tokio::spawn(async move {
                let mut release = release;
                while let Some(event) = conn.next_event().await {
                    let asked = match event {
                        PeerEvent::Server(
                            ServerEvent::FileRequested { file_hash, .. }
                            | ServerEvent::FileBundleRequested { file_hash, .. },
                        ) => file_hash,
                        _ => continue,
                    };
                    let _ = asked_tx.send((link, asked)).await;
                    if asked == first_hash
                        && let Some(release) = release.take()
                    {
                        let _ = release.await;
                        let _ = conn
                            .send(PeerCommand::Server(ServerCommand::AnswerFileNotFound {
                                file_hash: asked,
                            }))
                            .await;
                    }
                }
            });
        }
    });

    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let _first = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), first_file.clone())
        .await
        .unwrap();
    let asked = timeout(Duration::from_secs(5), asked_rx.recv()).await;
    assert_eq!(asked.ok().flatten(), Some((1, first_file.file_hash)));

    let mut second = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), second_file.clone())
        .await
        .unwrap();
    let waiting = timeout(Duration::from_secs(5), second.next_event()).await;
    assert!(matches!(
        waiting,
        Ok(Some(PeerWorkerEvent::LinkShared {
            turn: LinkTurn::Waiting
        }))
    ));
    release_tx.send(()).unwrap();
    let asked = timeout(Duration::from_secs(5), asked_rx.recv()).await;
    assert_eq!(
        asked.ok().flatten(),
        Some((1, second_file.file_hash)),
        "the second file is asked on the first link"
    );
    assert!(matches!(
        second.next_event().await,
        Some(PeerWorkerEvent::LinkShared {
            turn: LinkTurn::Riding
        })
    ));
    mock.abort();
}
