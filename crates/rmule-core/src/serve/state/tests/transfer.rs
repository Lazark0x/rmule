//! Serving data out: part asks reading only unserved ranges, credit accruing on
//! every served block, a failed read ending the file's offer with an honest
//! answer, and the AICH hash tree built once then answered from the cache.

use super::*;
use rmule_peer::{ServerCommand, ServerEvent};

#[test]
fn parts_requests_read_only_unserved_ranges_and_serve_blocks_with_credit() {
    let file_hash = hash(0x44);
    let mut state = serving_state(1, vec![entry(file_hash, 512, "served.bin")]);
    let t = Instant::now();
    let p = peer(1);
    identify(&mut state, p, user(0x0A), t);

    let read = |offset: u64, end: u64| ServeDecision::ReadRange {
        peer: p,
        path: "/shared/served.bin".into(),
        offset,
        len: end - offset,
        purpose: ReadPurpose::Block {
            file_hash,
            start: offset,
            end,
        },
    };
    let parts_requested =
        |ranges| ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges });
    let slot = ServeInput::Server(ServerEvent::SlotRequested { file_hash });
    let _ = state.on_conn_event(t, p, slot.clone(), &no_modifiers());

    let first = PartRanges::new([(0, 100), (100, 200), (200, 300)]).unwrap();
    assert_eq!(
        state.on_conn_event(t, p, parts_requested(first), &no_modifiers()),
        vec![read(0, 100), read(100, 200), read(200, 300)],
    );

    // The read result closes the round trip: credit first, then the block.
    let bytes = vec![0xEE_u8; 100];
    assert_eq!(
        state.on_read_result(
            p,
            ReadPurpose::Block {
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
    let overlapping = PartRanges::new([(100, 200), (200, 300), (300, 400)]).unwrap();
    assert_eq!(
        state.on_conn_event(t, p, parts_requested(overlapping), &no_modifiers()),
        vec![read(300, 400)],
    );

    // A request for a file we do not share is dropped.
    let unshared = PartRanges::new([(0, 100), (0, 0), (0, 0)]).unwrap();
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
    let again = PartRanges::new([(0, 100), (0, 0), (0, 0)]).unwrap();
    assert_eq!(
        state.on_conn_event(t, p, parts_requested(again), &no_modifiers()),
        vec![read(0, 100)],
    );
    assert_eq!(
        state.on_read_result(
            p,
            ReadPurpose::Block {
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

    let decisions = state.on_read_failed(
        t,
        peer(1),
        ReadPurpose::Block {
            file_hash,
            start: 0,
            end: 100,
        },
        &no_modifiers(),
    );
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
fn a_failed_aich_build_stops_serving_the_file_for_a_peer_holding_no_slot() {
    let file_hash = hash(0x57);
    let mut state = serving_state(1, vec![entry(file_hash, 2 * EMBLOCKSIZE, "a.bin")]);
    let decisions = state.on_read_failed(
        Instant::now(),
        peer(7),
        ReadPurpose::AichMasterRoot { file_hash },
        &no_modifiers(),
    );
    assert_eq!(
        decisions,
        vec![
            send(peer(7), ServerCommand::AnswerFileNotFound { file_hash }),
            ServeDecision::ReadFailed(file_hash),
        ],
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

/// Converted from the inline serve-task AICH test (ADR-0038 serve side):
/// an `OP_AICHREQUEST` for a shared file round-trips one whole-file read,
/// builds the tree, and answers recovery data that verifies against our
/// master root — and the second request answers from the cache with no
/// second `ReadRange`.
#[test]
fn aich_recovery_builds_the_tree_once_and_answers_from_the_cache() {
    let file_size = 3 * EMBLOCKSIZE; // 3 AICH blocks, one part
    let bytes: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
    let true_root = AichHashSet::from_bytes(&bytes).master_root();
    let file_hash = hash(0x66);
    let mut state = serving_state(1, vec![entry(file_hash, file_size, "shared.bin")]);
    let t = Instant::now();
    let p = peer(1);
    let request = ServeInput::Server(ServerEvent::AichRequested {
        file_hash,
        part: 0,
        root: true_root,
    });

    // Not shared: silent, the requester falls back.
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::AichRequested {
                file_hash: hash(0x99),
                part: 0,
                root: true_root,
            }),
            &no_modifiers(),
        ),
        Vec::new(),
    );

    assert_eq!(
        state.on_conn_event(t, p, request.clone(), &no_modifiers()),
        vec![ServeDecision::ReadRange {
            peer: p,
            path: "/shared/shared.bin".into(),
            offset: 0,
            len: file_size,
            purpose: ReadPurpose::AichRecovery { file_hash, part: 0 },
        }],
    );

    let answered = state.on_read_result(
        p,
        ReadPurpose::AichRecovery { file_hash, part: 0 },
        bytes.clone(),
    );
    let [
        ServeDecision::Send {
            command:
                ServerCommand::AnswerAich {
                    file_hash: answered_hash,
                    part,
                    root,
                    recovery_data,
                },
            ..
        },
    ] = answered.as_slice()
    else {
        panic!("expected one AnswerAich, got {answered:?}");
    };
    assert_eq!(*answered_hash, file_hash);
    assert_eq!(*part, 0);
    assert_eq!(*root, true_root);
    // Our served recovery data verifies against the true root and reports
    // the on-disk part as intact.
    let bad = AichHashSet::verify_part(file_size, 0, &bytes, recovery_data, true_root).unwrap();
    assert!(
        bad.is_empty(),
        "served recovery data verifies the intact part"
    );

    // Cache hit: the same request answers directly, no second read.
    let cached = state.on_conn_event(t, p, request, &no_modifiers());
    assert!(
        cached
            .iter()
            .all(|d| !matches!(d, ServeDecision::ReadRange { .. })),
        "a cache hit must not re-read the file: {cached:?}"
    );
    assert!(matches!(
        cached.as_slice(),
        [ServeDecision::Send {
            command: ServerCommand::AnswerAich { .. },
            ..
        }]
    ));

    // The master-root path shares the same cache.
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::AichFileHashRequested { file_hash }),
            &no_modifiers(),
        ),
        vec![send(
            p,
            ServerCommand::AnswerAichFileHash { root: true_root }
        )],
    );
}

#[test]
fn aich_master_root_answers_share_the_cache() {
    // Above one block: a single-block file has no AICH recovery data
    // (aMule `create_part_recovery_data` returns `None`), so the shared
    // cache could not answer the recovery request below.
    let file_size = 2 * EMBLOCKSIZE;
    let bytes: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
    let true_root = AichHashSet::from_bytes(&bytes).master_root();
    let file_hash = hash(0x77);
    let mut state = serving_state(1, vec![entry(file_hash, file_size, "shared.bin")]);
    let t = Instant::now();
    let p = peer(1);
    let request = ServeInput::Server(ServerEvent::AichFileHashRequested { file_hash });
    let expected_read = ServeDecision::ReadRange {
        peer: p,
        path: "/shared/shared.bin".into(),
        offset: 0,
        len: file_size,
        purpose: ReadPurpose::AichMasterRoot { file_hash },
    };

    assert_eq!(
        state.on_conn_event(t, p, request.clone(), &no_modifiers()),
        vec![expected_read.clone()],
    );
    // A second ask before the tree is built reads again.
    assert_eq!(
        state.on_conn_event(t, p, request.clone(), &no_modifiers()),
        vec![expected_read],
    );
    assert_eq!(
        state.on_read_result(p, ReadPurpose::AichMasterRoot { file_hash }, bytes),
        vec![send(
            p,
            ServerCommand::AnswerAichFileHash { root: true_root }
        )],
    );
    // The recovery path shares the tree built for the master root.
    let cached = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::AichRequested {
            file_hash,
            part: 0,
            root: true_root,
        }),
        &no_modifiers(),
    );
    assert!(matches!(
        cached.as_slice(),
        [ServeDecision::Send {
            command: ServerCommand::AnswerAich { .. },
            ..
        }]
    ));
}

/// One ask queues three reads; the first fails and ends the offer. The reads
/// still in flight land on a file rmule has just said it does not have, for a
/// peer whose slot is gone: nothing is sent, no credit accrues, and a late
/// AICH tree does not come back into the cache.
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
    let ranges = PartRanges::new([(0, 100), (100, 250), (250, 300)]).unwrap();
    let reads = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges }),
        &no_modifiers(),
    );
    assert_eq!(reads.len(), 3);
    let block = |start, end| ReadPurpose::Block {
        file_hash,
        start,
        end,
    };

    let _ = state.on_read_failed(t, p, block(0, 100), &no_modifiers());

    assert_eq!(
        state.on_read_result(p, block(100, 250), vec![0x5E; 150]),
        Vec::new()
    );
    assert_eq!(
        state.on_read_result(
            p,
            ReadPurpose::AichMasterRoot { file_hash },
            (0..2 * EMBLOCKSIZE).map(|i| (i % 253) as u8).collect(),
        ),
        Vec::new(),
    );
    assert!(!state.aich_cache.contains_key(&file_hash));
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
    let ranges = PartRanges::new([(0, 100), (0, 0), (0, 0)]).unwrap();
    let _ = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges }),
        &no_modifiers(),
    );
    let _ = state.on_conn_event(t, p, disconnected(), &no_modifiers());

    let block = ReadPurpose::Block {
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
