//! A block's packets on their way to core: gathered to the block, handed over
//! within their wait, and never behind what the peer said after them.

use std::time::Duration;

use rmule_peer::{PeerEvent, RequesterEvent};
use tokio::sync::mpsc;

use super::super::{Pipeline, WorkerLink};
use super::{DRAINED, block, drained, streamed};
use crate::adapters::peer_transfer::PeerWorkerEvent;

/// Run [`stream_blocks`] over half of `bytes`, then `next`, and return the
/// worker events it reported.
async fn events_after_partial(bytes: &[u8], next: PeerEvent) -> Vec<PeerWorkerEvent> {
    let file = rmule_testkit::file_link("partial.bin", bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, worker_events) = mpsc::channel(8);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    let half = bytes.len() / 2;
    events_tx
        .send(PeerEvent::Requester(RequesterEvent::PartReceived {
            file_hash: file.file_hash,
            offset: 0,
            bytes: bytes[..half].to_vec(),
        }))
        .await
        .unwrap();
    events_tx.send(next).await.unwrap();
    let mut link = WorkerLink::new(
        &mut events,
        &cmd_tx,
        &event_tx,
        &mut worker_cmd_rx,
        Duration::from_secs(5),
    );
    let handed = [block(0, bytes.len() as u64)];
    let budget = Duration::from_secs(5);
    streamed(&mut link, &mut Pipeline::new(), &file, &handed, budget).await;
    drop(link);
    drop(event_tx);
    drained(worker_events).await
}

/// A block arrives in its uploader's packets and core hears one event: a turn
/// of the download's brain per block, not per packet.
#[tokio::test]
async fn a_block_framed_in_packets_reaches_core_as_one() {
    const BLOCK: usize = rmule_peer::EMBLOCKSIZE as usize;
    let bytes = vec![0x5A; BLOCK];
    let file = rmule_testkit::file_link("framed.bin", &bytes);
    let (events_tx, mut events) = mpsc::channel(32);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, worker_events) = mpsc::channel(8);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    for (index, packet) in bytes.chunks(10_240).enumerate() {
        events_tx
            .send(PeerEvent::Requester(RequesterEvent::PartReceived {
                file_hash: file.file_hash,
                offset: (index * 10_240) as u64,
                bytes: packet.to_vec(),
            }))
            .await
            .unwrap();
    }
    let mut link = WorkerLink::new(
        &mut events,
        &cmd_tx,
        &event_tx,
        &mut worker_cmd_rx,
        Duration::from_secs(5),
    );
    let handed = [block(0, BLOCK as u64)];
    let budget = Duration::from_secs(5);
    streamed(&mut link, &mut Pipeline::new(), &file, &handed, budget).await;
    drop(link);
    drop(event_tx);
    let reported = drained(worker_events).await;
    assert_eq!(
        reported
            .iter()
            .filter(|event| matches!(event, PeerWorkerEvent::BlockReceived { .. }))
            .collect::<Vec<_>>(),
        vec![&PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: 0,
            bytes,
        }]
    );
    assert_eq!(reported.last(), Some(&DRAINED));
}

/// What arrived of a block a slow uploader is still sending reaches core
/// within the gather wait, so the rate shows and the bytes are counted.
#[tokio::test(start_paused = true)]
async fn the_start_of_a_slow_block_reaches_core_within_its_wait() {
    let bytes = vec![0x5A; 20_480];
    let file = rmule_testkit::file_link("slow.bin", &bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, mut worker_events) = mpsc::channel(8);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    events_tx
        .send(PeerEvent::Requester(RequesterEvent::PartReceived {
            file_hash: file.file_hash,
            offset: 0,
            bytes: bytes[..10_240].to_vec(),
        }))
        .await
        .unwrap();
    let streaming = async {
        let mut link = WorkerLink::new(
            &mut events,
            &cmd_tx,
            &event_tx,
            &mut worker_cmd_rx,
            Duration::from_secs(5),
        );
        let handed = [block(0, 20_480)];
        let budget = Duration::from_secs(5);
        streamed(&mut link, &mut Pipeline::new(), &file, &handed, budget).await;
    };
    let started = tokio::time::Instant::now();
    let hearing = async {
        loop {
            let heard = worker_events.recv().await.expect("the stream runs");
            if let PeerWorkerEvent::BlockReceived { bytes, .. } = heard {
                return bytes.len();
            }
        }
    };
    tokio::select! {
        () = streaming => panic!("the block never finished"),
        heard = hearing => assert_eq!(heard, 10_240),
    }
    assert_eq!(started.elapsed(), Duration::from_millis(100));
}

/// A link's end follows the bytes that came before it: core counts them and
/// keeps their part's Arrived Ranges.
#[tokio::test]
async fn gathered_bytes_reach_core_ahead_of_the_links_end() {
    let bytes = vec![0x5A; 20_480];
    let reported = events_after_partial(
        &bytes,
        PeerEvent::Connection(rmule_peer::ConnectionEvent::Disconnected {
            reason: rmule_peer::PeerCloseReason::PeerClosed,
        }),
    )
    .await;
    let blocks = reported
        .iter()
        .filter(|event| matches!(event, PeerWorkerEvent::BlockReceived { bytes, .. } if bytes.len() == 10_240));
    assert_eq!(blocks.count(), 1);
    assert_eq!(reported.last(), Some(&PeerWorkerEvent::Disconnected));
}
