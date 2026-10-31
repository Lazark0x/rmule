//! The Outbox's rules, read off the stream a reader sees.

use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};

use super::*;
use crate::service::{DownloadEvent, DownloadId, ServeEvent};

fn peer(port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new([1, 2, 3, 4].into(), port))
}

fn rank(port: u16, rank: u16) -> CoreEvent {
    CoreEvent::Download(DownloadEvent::PeerQueued {
        download_id: DownloadId::from_u64(1),
        peer: peer(port),
        rank,
    })
}

fn paused(id: u64) -> CoreEvent {
    CoreEvent::Download(DownloadEvent::DownloadPaused {
        download_id: DownloadId::from_u64(id),
    })
}

fn note(port: u16) -> CoreEvent {
    CoreEvent::Serve(ServeEvent::UploadQueueFull { peer: peer(port) })
}

fn rank_of(event: &CoreEvent) -> Option<u16> {
    match event {
        CoreEvent::Download(DownloadEvent::PeerQueued { rank, .. }) => Some(*rank),
        _ => None,
    }
}

fn drain(stream: &mut EventStream) -> Vec<CoreEvent> {
    std::iter::from_fn(|| stream.try_recv().ok()).collect()
}

#[test]
fn a_new_level_replaces_the_old_and_keeps_core_s_order() {
    let (outbox, mut stream) = outbox(LevelHandle::default());
    outbox.send(rank(1, 9));
    outbox.send(paused(7));
    outbox.send(rank(1, 8));
    outbox.send(rank(2, 5));
    outbox.send(rank(1, 7));

    let read = drain(&mut stream);
    assert_eq!(read.len(), 3, "{read:?}");
    // The Edge stays ahead of the value core said after it, so a fold never
    // sees a rank from after a change applied before that change.
    assert!(matches!(
        read[0],
        CoreEvent::Download(DownloadEvent::DownloadPaused { .. })
    ));
    assert_eq!(rank_of(&read[1]), Some(5));
    assert_eq!(rank_of(&read[2]), Some(7));
}

#[test]
fn a_read_level_is_not_superseded_afterwards() {
    let (outbox, mut stream) = outbox(LevelHandle::default());
    outbox.send(rank(1, 9));
    assert_eq!(rank_of(&stream.try_recv().expect("queued")), Some(9));
    outbox.send(rank(1, 8));
    assert_eq!(rank_of(&stream.try_recv().expect("queued")), Some(8));
}

#[test]
fn past_the_room_notes_and_levels_shed_and_every_edge_stays() {
    let (outbox, mut stream) = outbox_with_room(LevelHandle::default(), 8);
    outbox.send(paused(1));
    outbox.send(rank(1, 9));
    for port in 0..6 {
        outbox.send(note(port));
    }
    // The queue is at its room: this send sheds, then joins behind the count.
    outbox.send(paused(2));

    let read = drain(&mut stream);
    assert_eq!(read.len(), 3, "{read:?}");
    assert!(matches!(read[0], CoreEvent::Download(_)));
    assert!(matches!(read[1], CoreEvent::EventsShed { count: 7 }));
    assert!(matches!(read[2], CoreEvent::Download(_)));
}

#[test]
fn edges_alone_past_the_room_are_all_kept() {
    let (outbox, mut stream) = outbox_with_room(LevelHandle::default(), 4);
    for id in 0..32 {
        outbox.send(paused(id));
    }
    let read = drain(&mut stream);
    let edges = read
        .iter()
        .filter(|event| matches!(event, CoreEvent::Download(_)))
        .count();
    assert_eq!(edges, 32, "{read:?}");
}

#[test]
fn peer_traffic_with_no_reader_stays_inside_the_room() {
    let (outbox, stream) = outbox_with_room(LevelHandle::default(), 64);
    for round in 0..100_000_u32 {
        outbox.send(note(u16::try_from(round % 1000).expect("small")));
    }
    let held = stream.shared.lock().slots.len();
    assert!(held <= 64, "{held} held");
}

#[tokio::test]
async fn the_stream_ends_with_the_last_outbox_after_what_it_held() {
    let (outbox, mut stream) = outbox(LevelHandle::default());
    let weak = outbox.downgrade();
    let second = outbox.clone();
    outbox.send(paused(1));
    drop(outbox);
    assert!(weak.upgrade().is_some());
    drop(second);

    assert!(stream.recv().await.is_some());
    assert!(stream.recv().await.is_none(), "every door is gone");
    assert!(weak.upgrade().is_none(), "a weak door holds nothing open");
}

#[tokio::test]
async fn a_waiting_reader_wakes_on_the_next_send() {
    let (outbox, mut stream) = outbox(LevelHandle::default());
    let reader = tokio::spawn(async move { stream.recv().await });
    tokio::task::yield_now().await;
    outbox.send(paused(1));
    let read = reader.await.expect("reader");
    assert!(read.is_some());
}

#[test]
fn a_dropped_reader_keeps_nothing() {
    let (outbox, stream) = outbox(LevelHandle::default());
    let shared = Arc::clone(&stream.shared);
    outbox.send(paused(1));
    drop(stream);
    outbox.send(paused(2));
    assert!(shared.lock().slots.is_empty());
}
