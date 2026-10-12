//! What the share set answers: a probe against the live snapshot, the announce
//! list derived from it, the eD2k part count at an exact multiple, and the
//! not-found a refreshed-away file starts returning.

use super::*;
use rmule_peer::{ServerCommand, ServerEvent};

/// aMule `CKnownFile::SetFileSize` sets `m_iED2KPartCount = size / PARTSIZE +
/// 1` (KnownFile.cpp), so a file whose size is an exact multiple of the
/// 9.28 MB part size carries a trailing zero-length part — three parts for a
/// two-part-sized file. A serving peer's `OP_FILESTATUS` must report that
/// count: `CUpDownClient::ProcessFileStatus` (DownloadClient.cpp) throws
/// "wrong part number" and drops the source when the received count differs.
/// A plain `ceil` (the old `part_count`) under-counts this boundary to two,
/// so a live aMule tears the reverse download down (flow C). This
/// also keeps `OP_FILESTATUS` consistent with the `OP_HASHSETANSWER` count
/// (`PartHashSet::expected_hash_count`), which already adds the trailing part.
#[test]
fn file_status_reports_amule_ed2k_part_count_at_an_exact_part_multiple() {
    let exact_two_parts = ED2K_PART_SIZE * 2;
    let mut state = serving_state(1, vec![entry(hash(0x21), exact_two_parts, "exact.bin")]);
    let status = state.on_conn_event(
        Instant::now(),
        peer(1),
        ServeInput::Server(ServerEvent::FileIdSet {
            file_hash: hash(0x21),
        }),
        &no_modifiers(),
    );
    let [
        ServeDecision::Send {
            command: ServerCommand::AnswerFileStatus { bitmap, .. },
            ..
        },
    ] = status.as_slice()
    else {
        panic!("expected one AnswerFileStatus, got {status:?}");
    };
    assert_eq!(
        bitmap.part_count(),
        3,
        "OP_FILESTATUS must carry aMule's ED2K part count (size / PARTSIZE + 1)",
    );
    assert!((0..3).all(|i| bitmap.has(PartIndex::new(i))));
}

#[test]
fn the_share_snapshot_answers_probes_and_derives_the_announce_list() {
    let two_parts = ED2K_PART_SIZE + 1;
    let mut state = ServeState::new(UploadSlotQueue::new(1, 8));

    let announce = state.on_share_set(
        vec![entry(hash(0x11), two_parts, "served.bin")],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    assert_eq!(
        announce,
        vec![ServeDecision::Announce(vec![OfferedFile::new(
            hash(0x11),
            two_parts,
            Ed2kText::from_utf8("served.bin"),
        )])],
    );

    let t = Instant::now();
    let p = peer(1);
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::FileRequested {
                file_hash: hash(0x11),
                status: PartStatusTail::default(),
            }),
            &no_modifiers(),
        ),
        vec![send(
            p,
            ServerCommand::AnswerFileName {
                file_hash: hash(0x11),
                file_name: Ed2kText::from_utf8("served.bin"),
            }
        )],
    );

    // A complete shared file reports every part present.
    let status = state.on_conn_event(
        t,
        p,
        ServeInput::Server(ServerEvent::FileIdSet {
            file_hash: hash(0x11),
        }),
        &no_modifiers(),
    );
    let [
        ServeDecision::Send {
            command: ServerCommand::AnswerFileStatus { bitmap, .. },
            ..
        },
    ] = status.as_slice()
    else {
        panic!("expected one AnswerFileStatus, got {status:?}");
    };
    assert_eq!(bitmap.part_count(), 2);
    assert!((0..2).all(|i| bitmap.has(PartIndex::new(i))));
}

/// aMule leaves a standalone name ask for a file it does
/// not share unanswered and the connection up (stock 2.3.3 `4e8f2b3c`
/// `ClientTCPSocket.cpp:442-447`), while a bundle for it gets exactly one
/// `OP_FILEREQANSNOFIL` however many asks it holds (`:1061-1085`, before the
/// sub-opcode loop). ADR-0055 §Name-ask surface.
#[test]
fn an_unshared_file_draws_silence_standalone_and_one_not_found_per_bundle() {
    let mut state = serving_state(1, vec![entry(hash(0x11), 4096, "served.bin")]);
    let t = Instant::now();
    let p = peer(1);
    let standalone = ServeInput::Server(ServerEvent::FileRequested {
        file_hash: hash(0x99),
        status: PartStatusTail::default(),
    });
    assert_eq!(
        state.on_conn_event(t, p, standalone, &no_modifiers()),
        Vec::new()
    );
    let bundle = ServeInput::Server(ServerEvent::FileBundleRequested {
        file_hash: hash(0x99),
        file_size: None,
        asks: vec![
            BundledAsk::Name { part_status: None },
            BundledAsk::SetReqId,
            BundledAsk::AichRoot,
        ],
        cut: None,
    });
    assert_eq!(
        state.on_conn_event(t, p, bundle, &no_modifiers()),
        vec![send(
            p,
            ServerCommand::AnswerFileNotFound {
                file_hash: hash(0x99)
            }
        )],
    );
}

/// An `OP_MULTIPACKET_EXT` naming a size that is not the shared file's is
/// answered as if the file were not shared (`ClientTCPSocket.cpp:1075-1078`):
/// one not-found, no ask answered. The same bundle at the right size is
/// answered in full.
#[test]
fn an_ext_bundle_naming_another_size_is_answered_not_found() {
    let mut state = serving_state(1, vec![entry(hash(0x11), 4096, "served.bin")]);
    let t = Instant::now();
    let p = peer(1);
    let bundle = |file_size| {
        ServeInput::Server(ServerEvent::FileBundleRequested {
            file_hash: hash(0x11),
            file_size: Some(file_size),
            asks: vec![BundledAsk::Name { part_status: None }, BundledAsk::SetReqId],
            cut: None,
        })
    };
    assert_eq!(
        state.on_conn_event(t, p, bundle(4097), &no_modifiers()),
        vec![send(
            p,
            ServerCommand::AnswerFileNotFound {
                file_hash: hash(0x11)
            }
        )],
    );
    let answered = state.on_conn_event(t, p, bundle(4096), &no_modifiers());
    assert!(
        matches!(
            answered.as_slice(),
            [
                ServeDecision::Send {
                    command: ServerCommand::AnswerFileName { .. },
                    ..
                },
                ServeDecision::Send {
                    command: ServerCommand::AnswerFileStatus { .. },
                    ..
                },
            ]
        ),
        "{answered:?}"
    );
}

/// Unsharing mid-probe answers "no such file" instead of silently
/// dropping the request (design §5): the snapshot refresh is what flips
/// the answer.
#[test]
fn an_unshared_file_answers_not_found_after_the_snapshot_refresh() {
    let part_hashes = vec![PartHash::from_bytes([0xAB; PartHash::BYTE_LEN]); 2];
    let mut shared = entry(hash(0x22), 2 * ED2K_PART_SIZE, "hashed.bin");
    shared.part_hashes = part_hashes.clone();
    let mut state = serving_state(1, vec![shared]);

    let t = Instant::now();
    let p = peer(1);
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::HashSetRequested {
                file_hash: hash(0x22)
            }),
            &no_modifiers(),
        ),
        vec![send(
            p,
            ServerCommand::AnswerHashSet {
                file_hash: hash(0x22),
                part_hashes,
            }
        )],
    );

    let _ = state.on_share_set(
        Vec::new(),
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            ServeInput::Server(ServerEvent::HashSetRequested {
                file_hash: hash(0x22)
            }),
            &no_modifiers(),
        ),
        vec![send(
            p,
            ServerCommand::AnswerFileNotFound {
                file_hash: hash(0x22)
            }
        )],
    );
}
