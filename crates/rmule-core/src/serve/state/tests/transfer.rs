//! Serving data out: part asks reading only unserved ranges, credit accruing on
//! every served block, and a failed read ending the file's offer with an
//! honest answer.

use super::*;
use rmule_peer::{ServerCommand, ServerEvent};

#[test]
fn parts_requests_read_only_unserved_ranges_and_serve_blocks_with_credit() {
    let file_hash = hash(0x44);
    let mut state = serving_state(1, vec![entry(file_hash, 512, "served.bin")]);
    let t = Instant::now();
    let p = peer(1);
    identify(&mut state, p, user(0x0A), t);

    let read = |start: u64, end: u64| ServeDecision::ReadRange {
        peer: p,
        path: "/shared/served.bin".into(),
        block: BlockRead {
            file_hash,
            start,
            end,
        },
        check: None,
    };
    let parts_requested =
        |ranges| ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges });
    let slot = ServeInput::Server(ServerEvent::SlotRequested { file_hash });
    let _ = state.on_conn_event(t, p, slot.clone(), &no_modifiers());

    let first = PartRanges::new([(0, 100), (100, 200), (200, 300)]);
    assert_eq!(
        state.on_conn_event(t, p, parts_requested(first), &no_modifiers()),
        vec![read(0, 100), read(100, 200), read(200, 300)],
    );

    // The read result closes the round trip: credit first, then the block.
    let bytes = vec![0xEE_u8; 100];
    assert_eq!(
        state.on_read_result(
            p,
            BlockRead {
                file_hash,
                start: 0,
                end: 100,
            },
            bytes.clone(),
        ),
        vec![
            ServeDecision::RecordCredit {
                user_hash: user(0x0A),
                bytes: 100,
            },
            send(
                p,
                ServerCommand::SendBlock {
                    file_hash,
                    start: 0,
                    end: 100,
                    bytes,
                }
            ),
        ],
    );

    // A re-request overlapping already-served ranges reads only the tail.
    let overlapping = PartRanges::new([(100, 200), (200, 300), (300, 400)]);
    assert_eq!(
        state.on_conn_event(t, p, parts_requested(overlapping), &no_modifiers()),
        vec![read(300, 400)],
    );

    // A request for a file we do not share is dropped.
    let unshared = PartRanges::new([(0, 100), (0, 0), (0, 0)]);
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::PartsRequested {
                file_hash: hash(0x99),
                ranges: unshared,
            }),
            &no_modifiers(),
        ),
        Vec::new(),
    );

    // Disconnecting wipes the flow: on a new slot the same range reads again,
    // and the forgotten identity earns no credit.
    let _ = state.on_conn_event(t, p, disconnected(), &no_modifiers());
    let _ = state.on_conn_event(t, p, slot, &no_modifiers());
    let again = PartRanges::new([(0, 100), (0, 0), (0, 0)]);
    assert_eq!(
        state.on_conn_event(t, p, parts_requested(again), &no_modifiers()),
        vec![read(0, 100)],
    );
    assert_eq!(
        state.on_read_result(
            p,
            BlockRead {
                file_hash,
                start: 0,
                end: 100,
            },
            vec![0xEE_u8; 100],
        ),
        vec![send(
            p,
            ServerCommand::SendBlock {
                file_hash,
                start: 0,
                end: 100,
                bytes: vec![0xEE_u8; 100],
            }
        )],
    );
}

#[test]
fn a_failed_block_read_stops_serving_the_file_and_tells_its_peers() {
    let (file_hash, other) = (hash(0x55), hash(0x56));
    let mut state = serving_state(
        1,
        vec![
            entry(file_hash, 512, "served.bin"),
            entry(other, 512, "other.bin"),
        ],
    );
    let t = Instant::now();
    let slot = |file_hash| ServeInput::Server(ServerEvent::SlotRequested { file_hash });
    let _ = state.on_conn_event(t, peer(1), slot(file_hash), &no_modifiers());
    let _ = state.on_conn_event(t, peer(2), slot(file_hash), &no_modifiers());
    let _ = state.on_conn_event(t, peer(3), slot(other), &no_modifiers());

    let decisions = state.on_read_failed(t, peer(1), file_hash, &no_modifiers());
    let not_found = |port| send(peer(port), ServerCommand::AnswerFileNotFound { file_hash });
    assert_eq!(
        decisions,
        vec![
            not_found(2),
            ServeDecision::Emit(ServeEvent::WaiterLeft {
                peer: peer(2),
                cause: WaiterLeaveCause::Purged,
            }),
            not_found(1),
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: peer(1) }),
            send(peer(3), ServerCommand::GrantSlot { file_hash: other }),
            ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: peer(3),
                file_hash: other,
                software: None,
                road: crate::GrantRoad::Linked,
            }),
            ServeDecision::ReadFailed(file_hash),
        ],
        "no disconnect: the asker is told the file is not here, its slot \
         goes to a waiter for another file"
    );
    // Every later ask for the file is answered honestly too.
    assert_eq!(
        state.on_conn_event(
            t,
            peer(4),
            ServeInput::Server(ServerEvent::FileIdSet { file_hash }),
            &no_modifiers(),
        ),
        vec![not_found(4)],
    );
}

#[test]
fn a_file_that_leaves_the_offer_releases_the_slot_holding_it() {
    let (file_hash, kept) = (hash(0x58), hash(0x59));
    let mut state = serving_state(
        1,
        vec![
            entry(file_hash, 512, "gone.bin"),
            entry(kept, 512, "kept.bin"),
        ],
    );
    let t = Instant::now();
    let _ = state.on_conn_event(
        t,
        peer(1),
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );
    let decisions = state.on_share_set(vec![entry(kept, 512, "kept.bin")], t, &no_modifiers());
    assert_eq!(
        &decisions[..2],
        &[
            send(peer(1), ServerCommand::AnswerFileNotFound { file_hash }),
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: peer(1) }),
        ],
    );
    assert!(matches!(decisions.last(), Some(ServeDecision::Announce(files)) if files.len() == 1));
}

/// One ask queues three reads; the first fails and ends the offer. The reads
/// still in flight land on a file rmule has just said it does not have, for a
/// peer whose slot is gone: nothing is sent and no credit accrues.
#[test]
fn a_read_that_lands_after_the_offer_ended_sends_nothing() {
    let file_hash = hash(0x5A);
    let mut state = serving_state(1, vec![entry(file_hash, 2 * EMBLOCKSIZE, "gone.bin")]);
    let t = Instant::now();
    let p = peer(3);
    identify(&mut state, p, user(0x3C), t);
    let _ = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );
    let ranges = PartRanges::new([(0, 100), (100, 250), (250, 300)]);
    let reads = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges }),
        &no_modifiers(),
    );
    assert_eq!(reads.len(), 3);
    let block = |start, end| BlockRead {
        file_hash,
        start,
        end,
    };

    let _ = state.on_read_failed(t, p, file_hash, &no_modifiers());

    assert_eq!(
        state.on_read_result(p, block(100, 250), vec![0x5E; 150]),
        Vec::new()
    );
}

/// A slot that ends for any reason ends the blocks queued under it, as aMule
/// drops a block request from a client it is not uploading to
/// (`UploadClient.cpp:497-500`).
#[test]
fn a_read_that_lands_after_the_slot_ended_sends_nothing() {
    let file_hash = hash(0x5B);
    let mut state = serving_state(1, vec![entry(file_hash, 512, "kept.bin")]);
    let t = Instant::now();
    let p = peer(4);
    let _ = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::SlotRequested { file_hash }),
        &no_modifiers(),
    );
    let ranges = PartRanges::new([(0, 100), (0, 0), (0, 0)]);
    let _ = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges }),
        &no_modifiers(),
    );
    let _ = state.on_conn_event(t, p, disconnected(), &no_modifiers());

    let block = BlockRead {
        file_hash,
        start: 0,
        end: 100,
    };
    assert_eq!(state.on_read_result(p, block, vec![0x4D; 100]), Vec::new());
}

/// A waiter for a withdrawn file leaves the queue, and the waiter behind it
/// moves up: it is told its new rank at once, not at the next unrelated move.
#[test]
fn a_withdrawn_files_waiters_leaving_move_the_rest_up_at_once() {
    let (gone, kept) = (hash(0x5C), hash(0x5D));
    let mut state = serving_state(
        1,
        vec![entry(gone, 512, "gone.bin"), entry(kept, 512, "kept.bin")],
    );
    let t = Instant::now();
    let slot = |file_hash| ServeInput::Server(ServerEvent::SlotRequested { file_hash });
    let _ = state.on_conn_event(t, peer(1), slot(kept), &no_modifiers());
    let _ = state.on_conn_event(t, peer(2), slot(gone), &no_modifiers());
    let later = t + Duration::from_secs(5);
    let _ = state.on_conn_event(later, peer(3), slot(kept), &no_modifiers());

    let decisions = state.on_share_set(
        vec![entry(kept, 512, "kept.bin")],
        later + Duration::from_secs(1),
        &no_modifiers(),
    );
    assert!(
        decisions.contains(&send(peer(3), ServerCommand::SetQueueRank { rank: 1 })),
        "{decisions:?}"
    );
    assert!(decisions.iter().any(|d| matches!(
        d,
        ServeDecision::Emit(ServeEvent::PeerQueued { peer: queued, rank: 1, .. })
            if *queued == peer(3)
    )));
}

/// aMule never compresses an archive's block (`UploadClient.cpp:252`): core
/// marks it plain by the name the file is offered under, and any other
/// block may cross compressed (ADR-0031).
/// A block goes to its deflate only when the file may be compressed and the
/// peer inflates; no pass is spent otherwise (ADR-0031).
#[test]
fn only_a_block_a_peer_can_inflate_of_a_non_archive_goes_to_its_deflate() {
    for (name, inflates, deflated) in [
        ("backup.rar", 1, false),
        ("sources.tar.gz", 1, false),
        ("ubuntu.iso", 1, true),
        ("film.mkv", 1, true),
        ("README", 1, true),
        ("README", 0, false),
    ] {
        let file_hash = hash(0x5E);
        let mut state = serving_state(1, vec![entry(file_hash, 512, name)]);
        let p = peer(5);
        let t = Instant::now();
        let hello = HelloFacts {
            data_compression_version: inflates,
            ..HelloFacts::of(user(0x05))
        };
        let _ = state.on_conn_event(t, p, hello.identified(), &no_modifiers());
        let _ = slot_request(&mut state, p, file_hash, t);
        let block = BlockRead {
            file_hash,
            start: 0,
            end: 100,
        };

        let decisions = state.on_read_result(p, block, vec![0; 100]);
        assert_eq!(
            matches!(decisions.last(), Some(ServeDecision::DeflateBlock { .. })),
            deflated,
            "{name}, {inflates}: {decisions:?}"
        );
    }
}
