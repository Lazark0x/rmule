//! The AICH leg (ADR-0038): recovery repairing the corrupt blocks' part and
//! retiring only their peer, the trusted-root vote committing once enough
//! distinct IPs agree, and the provisional hash-set authority a set that is
//! not the file's own is refused against.

use super::*;

#[test]
fn aich_recovery_retires_only_the_corrupt_blocks_peer_and_hands_only_that_block() {
    // A 6-block file with a trusted AICH root. peer 1 is handed blocks 0-2
    // and delivers block 1 corrupt; peer 2 is handed blocks 3-5 and completes
    // the part. MD4 fails — but AICH localizes block 1, so only its writer
    // (peer 1) is retired and only block 1 is handed again (ADR-0038, ADR-0117).
    let emb = EMBLOCKSIZE as usize;
    let file_size = 6 * EMBLOCKSIZE;
    let true_bytes: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
    let tree = AichHashSet::from_bytes(&true_bytes);
    let root = tree.master_root();
    let recovery = tree.create_part_recovery_data(0).expect("recovery data");

    let mut state = aich_state(file_size, root, vec![peer(1), peer(2)], 2);
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, t0(), peer(2));

    let mut corrupt_block1 = true_bytes[emb..2 * emb].to_vec();
    corrupt_block1[0] ^= 0xFF;
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: 0,
            bytes: true_bytes[..emb].to_vec(),
        },
    );
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: EMBLOCKSIZE,
            bytes: corrupt_block1,
        },
    );
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: 2 * EMBLOCKSIZE,
            bytes: true_bytes[2 * emb..3 * emb].to_vec(),
        },
    );
    let completing = state.on_worker_event(
        t0(),
        peer(2),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: 3 * EMBLOCKSIZE,
            bytes: true_bytes[3 * emb..].to_vec(),
        },
    );
    assert!(
        completing
            .iter()
            .any(|d| matches!(d, Decision::PersistPart { part_index: 0, .. })),
        "the completed prefix round-trips through PersistPart: {completing:?}"
    );

    // MD4 fails: with a trusted root, ask the completing peer for AICH
    // recovery data rather than retiring everyone up front.
    let failed = state.on_persist_result(
        t0(),
        0,
        peer(2),
        Err(DownloadFailure::PartVerificationFailed),
    );
    assert!(
        failed.iter().any(|d| matches!(
            d,
            Decision::Send { peer: p, command: PeerWorkerCommand::RequestAich { part: 0, root: r } }
                if *p == peer(2) && *r == root
        )),
        "an MD4 failure with a trusted root requests AICH recovery: {failed:?}"
    );
    assert!(
        !failed
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::PeerRetired { .. }))),
        "no peer is retired before the AICH answer arrives: {failed:?}"
    );

    // The peer answers; AICH localizes block 1 → retire only its writer
    // (peer 1), keeping every good block.
    let repaired = state.on_worker_event(
        t0(),
        peer(2),
        PeerWorkerEvent::AichAnswerReceived {
            part: 0,
            recovery_data: recovery,
        },
    );
    assert!(
        repaired.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired { peer: p, .. }) if *p == peer(1)
        )),
        "the corrupt block's deliverer (peer 1) is retired: {repaired:?}"
    );
    assert!(
        !repaired.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired { peer: p, .. }) if *p == peer(2)
        )),
        "peer 2 (delivered only a good block) is NOT retired: {repaired:?}"
    );
    // peer 2 has room again: it is handed the corrupt block alone.
    let handed = state.on_worker_event(
        t0(),
        peer(2),
        PeerWorkerEvent::BlocksWanted {
            room: 3,
            drained: true,
        },
    );
    assert_eq!(
        sent(&handed),
        vec![(
            peer(2),
            PeerWorkerCommand::RequestBlocks {
                blocks: vec![crate::BlockPlan {
                    part_index: 0,
                    start: EMBLOCKSIZE,
                    end: 2 * EMBLOCKSIZE,
                }],
            }
        )],
        "only the corrupt block is fetched again: {handed:?}"
    );
}
#[test]
fn trusted_set_commits_a_root_once_enough_distinct_ips_agree() {
    // A rootless download collects AICH master-hash proposals; the root is
    // committed (turning on recovery) only after >= 10 distinct IPs agree
    // (ADR-0038 secure AICH). peer(1..=10) have distinct masked IPs
    // (10.0.0.n & 0x00F0FFFF == n).
    let root = AichRootHash::from_bytes([0xA7; AichRootHash::BYTE_LEN]);
    let mut state = file_hash_only_state(Vec::new(), 1);
    assert_eq!(state.trusted_aich_root(), None);

    for n in 1..=9 {
        let _ = state.on_worker_event(
            t0(),
            peer(n),
            PeerWorkerEvent::AichFileHashReceived { root },
        );
    }
    assert_eq!(
        state.trusted_aich_root(),
        None,
        "9 agreeing IPs is below the 10-IP trust threshold"
    );

    let _ = state.on_worker_event(
        t0(),
        peer(10),
        PeerWorkerEvent::AichFileHashReceived { root },
    );
    assert_eq!(
        state.trusted_aich_root(),
        Some(root),
        "the 10th distinct agreeing IP commits the trusted root"
    );
}

/// The AICH recovery pins a corrupt block on its sender: that sender —
/// and only it, not the part's other contributor — is distrusted, durably.
#[test]
fn an_aich_attributed_corrupt_block_distrusts_only_its_sender() {
    const CORRUPTER: UserHash = UserHash::from_bytes([0xC0; UserHash::BYTE_LEN]);
    const HONEST: UserHash = UserHash::from_bytes([0x40; UserHash::BYTE_LEN]);
    let emb = EMBLOCKSIZE as usize;
    // Four blocks: the first grant takes three, the second the last.
    let file_size = 4 * EMBLOCKSIZE;
    let true_bytes: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
    let tree = AichHashSet::from_bytes(&true_bytes);
    let recovery = tree.create_part_recovery_data(0).expect("recovery data");
    let mut state = aich_state(file_size, tree.master_root(), vec![peer(1), peer(2)], 2);
    let _ = state.start(t0());
    for (at, user_hash) in [(peer(1), CORRUPTER), (peer(2), HONEST)] {
        let _ = state.on_worker_event(t0(), at, identified(user_hash));
        let _ = connect(&mut state, t0(), at);
    }
    let mut corrupt_block0 = true_bytes[..emb].to_vec();
    corrupt_block0[0] ^= 0xFF;
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: 0,
            bytes: corrupt_block0,
        },
    );
    let _ = state.on_worker_event(
        t0(),
        peer(2),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: EMBLOCKSIZE,
            bytes: true_bytes[emb..].to_vec(),
        },
    );
    let _ = state.on_persist_result(
        t0(),
        0,
        peer(2),
        Err(DownloadFailure::PartVerificationFailed),
    );

    let repaired = state.on_worker_event(
        t0(),
        peer(2),
        PeerWorkerEvent::AichAnswerReceived {
            part: 0,
            recovery_data: recovery,
        },
    );

    let distrusted: Vec<UserHash> = repaired
        .iter()
        .filter_map(|d| match d {
            Decision::DistrustPeer { user_hash } => Some(*user_hash),
            _ => None,
        })
        .collect();
    assert_eq!(distrusted, vec![CORRUPTER], "{repaired:?}");
}

#[test]
fn a_first_peer_hash_set_is_adopted_as_the_provisional_authority() {
    let file = two_part_file();
    let mut state = two_part_state(&file);
    let hashes = file.part_hash_set().expect("two parts").hashes().to_vec();

    // With no link hash set, the first peer set — the file's own — becomes
    // the provisional PeerHashSet authority and is persisted (ADR-0027).
    let out = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::HashSetReceived {
            part_hashes: hashes.clone(),
        },
    );
    assert!(
        out.iter().any(|d| matches!(
            d,
            Decision::PersistProvisionalHashes(h) if *h == hashes
        )),
        "the adopted set is persisted as provisional: {out:?}"
    );
    assert!(
        out.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::HashSetReceived {
                authority: VerificationAuthority::PeerHashSet,
                ..
            })
        )),
        "the new authority is announced: {out:?}"
    );
}

/// A part hash set whose MD4 is not the file hash is proven wrong by the file
/// hash alone (aMule `CKnownFile::LoadHashsetFromFile`): it is refused,
/// never adopted, and its sender is retired and distrusted — whether or not a
/// truthful set arrived first.
#[test]
fn a_hash_set_that_is_not_the_files_own_is_refused_and_its_sender_distrusted() {
    const FORGER: UserHash = UserHash::from_bytes([0xF0; UserHash::BYTE_LEN]);
    let file = two_part_file();
    let mut state = two_part_state(&file);
    let _ = state.on_worker_event(t0(), peer(2), identified(FORGER));
    let _ = connect(&mut state, t0(), peer(2));
    let mut forged = file.part_hash_set().expect("two parts").hashes().to_vec();
    forged[0] = PartHash::from_bytes([0x22; 16]);

    let out = state.on_worker_event(
        t0(),
        peer(2),
        PeerWorkerEvent::HashSetReceived {
            part_hashes: forged,
        },
    );

    assert!(
        out.iter()
            .any(|d| matches!(d, Decision::DistrustPeer { user_hash } if *user_hash == FORGER)),
        "the forger is distrusted: {out:?}"
    );
    assert!(
        out.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::VerificationAuthorityMismatch,
                ..
            }) if *p == peer(2)
        )),
        "the forger is retired: {out:?}"
    );
    assert!(
        !out.iter()
            .any(|d| matches!(d, Decision::PersistProvisionalHashes(_))),
        "the forged set is never adopted: {out:?}"
    );
}

/// A part verified while no part hash set was held is outside the Verified
/// Range until a set arrives (ADR-0113 rule 2): the status the run sends
/// leaves it out, so it never names a part the serve side refuses, and names
/// it once the file's own set is adopted.
#[test]
fn a_part_verified_before_the_set_is_named_only_once_the_set_arrives() {
    let file = two_part_file();
    let mut state = pooled_state(
        ContentFacts {
            file_hash: file.file_hash(),
            verified_parts: vec![0],
            ..file_hash_only_content(file.file_size())
        },
        &[peer(1)],
        QUIET_POSTURE,
        1,
    );
    let _ = state.start(t0());
    let none = PartBitmap::downloader(file.file_size(), |_| false);
    assert_eq!(state.our_part_status(), none);

    let _ = connect(&mut state, t0(), peer(1));
    let hashes = file.part_hash_set().expect("two parts").hashes().to_vec();
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::HashSetReceived {
            part_hashes: hashes,
        },
    );
    assert!(state.our_part_status().has(rmule_peer::PartIndex::new(0)));
}
