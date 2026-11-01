//! The AICH leg (ADR-0038): recovery repairing the corrupt blocks' part and
//! retiring only their peer, the trusted-root vote committing once enough
//! distinct IPs agree, and the provisional hash-set authority a set that is
//! not the file's own is refused against.

use super::super::aich::{AichVote, AichVoter, MAX_VOTERS, masked_ip};
use super::*;

/// `peer` states `root` as the file's AICH master hash.
fn states_root(state: &mut DownloadState, peer: PeerEndpoint, root: AichRootHash) {
    let _ = state.on_worker_event(t0(), peer, PeerWorkerEvent::AichFileHashReceived { root });
}

/// A four-block file with a trusted root, `peer(1)` and `peer(2)` granted at
/// `t0` and `granted_two`, whose only part `peer(2)` completes unverified.
fn part_awaiting_recovery(granted_two: Instant) -> (DownloadState, AichRootHash) {
    let file_size = 4 * EMBLOCKSIZE;
    let bytes = vec![0x5A_u8; file_size as usize];
    let root = AichHashSet::from_bytes(&bytes).master_root();
    let mut state = aich_state(file_size, root, vec![peer(1), peer(2)], 2);
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, granted_two, peer(2));
    for (at, offset) in [
        (peer(1), 0),
        (peer(1), EMBLOCKSIZE),
        (peer(1), 2 * EMBLOCKSIZE),
        (peer(2), 3 * EMBLOCKSIZE),
    ] {
        let _ = state.on_worker_event(
            granted_two,
            at,
            PeerWorkerEvent::BlockReceived {
                part_index: 0,
                offset,
                bytes: vec![0_u8; EMBLOCKSIZE as usize],
            },
        );
    }
    (state, root)
}

fn recovery_asked(decisions: &[Decision]) -> Vec<PeerEndpoint> {
    sent(decisions)
        .into_iter()
        .filter(|(_, command)| matches!(command, PeerWorkerCommand::RequestAich { .. }))
        .map(|(to, _)| to)
        .collect()
}

fn part_fails(state: &mut DownloadState, now: Instant) -> Vec<Decision> {
    state.on_persist_result(
        now,
        0,
        peer(2),
        Err(DownloadFailure::PartVerificationFailed),
    )
}

/// `OP_AICHREQUEST` is scored at 3.1.0 and kno (`ClientTCPSocket.cpp:1768`):
/// inside the peer's clock nothing is asked, and the part takes its refetch.
#[test]
fn a_recovery_ask_inside_the_peers_clock_leaves_nothing() {
    let (mut state, root) = part_awaiting_recovery(t0());
    states_root(&mut state, peer(2), root);
    let failed = part_fails(&mut state, t0() + Duration::from_secs(60));
    assert!(recovery_asked(&failed).is_empty(), "{failed:?}");
}

/// A recovery ask goes only to a peer stating the trusted root, which need
/// not be the one that completed the part (3.1.0 `PartFile.cpp:3994-4047`).
#[test]
fn a_recovery_ask_goes_to_a_peer_stating_the_trusted_root() {
    let (mut state, root) = part_awaiting_recovery(t0());
    states_root(&mut state, peer(1), root);
    let failed = part_fails(&mut state, t0() + MIN_REQUEST_TIME);
    assert_eq!(recovery_asked(&failed), vec![peer(1)], "{failed:?}");
}

/// Asks spread among the peers stating the root: the one asked longest ago
/// goes first, so a corrupting swarm does not spend one innocent peer's clock.
#[test]
fn recovery_asks_spread_to_the_peer_asked_longest_ago() {
    let later = t0() + Duration::from_secs(100);
    let (mut state, root) = part_awaiting_recovery(later);
    states_root(&mut state, peer(1), root);
    states_root(&mut state, peer(2), root);
    let failed = part_fails(&mut state, later + MIN_REQUEST_TIME);
    assert_eq!(recovery_asked(&failed), vec![peer(1)], "{failed:?}");
}

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
    states_root(&mut state, peer(2), root);

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
        t0() + MIN_REQUEST_TIME,
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
            handout: 1,
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
                handout: 2,
            }
        )],
        "only the corrupt block is fetched again: {handed:?}"
    );
}
#[test]
fn trusted_set_commits_a_root_once_enough_distinct_ips_agree() {
    // A rootless download collects AICH master-hash proposals; the root is
    // committed (turning on recovery) only after >= 10 distinct voters agree
    // (ADR-0038 secure AICH).
    let root = AichRootHash::from_bytes([0xA7; AichRootHash::BYTE_LEN]);
    let mut state = file_hash_only_state(Vec::new(), 1);
    assert_eq!(state.trusted_aich_root(), None);

    for n in 1..=9 {
        let _ = state.on_worker_event(
            t0(),
            voter(n),
            PeerWorkerEvent::AichFileHashReceived { root },
        );
    }
    assert_eq!(
        state.trusted_aich_root(),
        None,
        "9 agreeing voters is below the 10-voter trust threshold"
    );

    let _ = state.on_worker_event(
        t0(),
        voter(10),
        PeerWorkerEvent::AichFileHashReceived { root },
    );
    assert_eq!(
        state.trusted_aich_root(),
        Some(root),
        "the 10th distinct agreeing voter commits the trusted root"
    );
}

/// Stock keeps the top 20 bits (`SHAHashSet.cpp:451`, a network-order word on
/// a little-endian host), so one subnet is one voter however many hosts it has.
#[test]
fn ten_addresses_of_one_subnet_are_one_voter() {
    let root = AichRootHash::from_bytes([0xA7; AichRootHash::BYTE_LEN]);
    let mut state = file_hash_only_state(Vec::new(), 1);

    for n in 1..=10 {
        states_root(&mut state, peer(n), root);
    }

    assert_eq!(state.trusted_aich_root(), None);
}

#[test]
fn a_voter_is_the_top_twenty_bits_of_its_address() {
    let at = |a, b, c, d| {
        masked_ip(PeerEndpoint::V4(Ipv4Endpoint::new(
            Ipv4Addr::new(a, b, c, d),
            4662,
        )))
    };

    assert_eq!(at(10, 20, 0x30, 1), at(10, 20, 0x3F, 254));
    assert_ne!(at(10, 20, 0x30, 1), at(10, 20, 0x40, 1));
    assert_ne!(at(10, 20, 0x30, 1), at(11, 20, 0x30, 1));
}

/// One peer posting root after root neither grows the tally nor drags the
/// total past the 92 % line, so ten honest voters still reach trust.
#[test]
fn a_peer_posting_many_roots_holds_one_vote() {
    let root = AichRootHash::from_bytes([0xA7; AichRootHash::BYTE_LEN]);
    let mut state = file_hash_only_state(Vec::new(), 1);
    for n in 0..=255 {
        states_root(
            &mut state,
            voter(200),
            AichRootHash::from_bytes([n; AichRootHash::BYTE_LEN]),
        );
    }

    for n in 1..=9 {
        states_root(&mut state, voter(n), root);
    }
    states_root(&mut state, voter(200), root);
    assert_eq!(
        state.trusted_aich_root(),
        Some(root),
        "its vote moved with it: ten of ten"
    );
}

#[test]
fn a_restated_vote_leaves_the_root_it_held() {
    let (first, second) = (
        AichRootHash::from_bytes([0xA7; AichRootHash::BYTE_LEN]),
        AichRootHash::from_bytes([0xB8; AichRootHash::BYTE_LEN]),
    );
    let mut state = file_hash_only_state(Vec::new(), 1);
    for n in 1..=9 {
        states_root(&mut state, voter(n), first);
    }
    states_root(&mut state, voter(9), second);

    states_root(&mut state, voter(10), first);

    assert_eq!(state.trusted_aich_root(), None, "nine hold it, not ten");
}

#[test]
fn past_its_size_the_vote_counts_no_new_voter_and_a_held_one_may_restate() {
    let (root, other) = (
        AichRootHash::from_bytes([0xA7; AichRootHash::BYTE_LEN]),
        AichRootHash::from_bytes([0xB8; AichRootHash::BYTE_LEN]),
    );
    let v6 = |n: u64| AichVoter::V6(n);
    let mut vote = AichVote::default();
    for n in 0..MAX_VOTERS as u64 {
        vote.cast(v6(n), other);
    }

    assert!(!vote.cast(v6(MAX_VOTERS as u64), root));
    assert_eq!(vote.ballots.len(), MAX_VOTERS);
    assert_eq!(vote.tally.get(&root), None);

    vote.cast(v6(0), root);
    assert_eq!(vote.tally.get(&root), Some(&1));
    assert_eq!(vote.tally.get(&other), Some(&(MAX_VOTERS - 1)));
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
    states_root(&mut state, peer(2), tree.master_root());
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
        t0() + MIN_REQUEST_TIME,
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
