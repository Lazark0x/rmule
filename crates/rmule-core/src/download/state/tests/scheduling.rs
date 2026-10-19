//! Slot occupancy and block scheduling: one worker per candidate up to the
//! concurrency, a refilled pool taking a free slot, two workers sharing one
//! part's blocks, a freed block handed from its first missing byte, backfill
//! on retirement, and what a stop does to the blocks still in flight.

use super::*;

/// A one-part file of five blocks, two workers' worth: the first grant takes
/// three blocks and the second the other two.
const FIVE_BLOCKS: u64 = 4 * rmule_primitives::EMBLOCKSIZE + 100;

/// A started two-peer download of [`FIVE_BLOCKS`] whose workers both took
/// their blocks at their grants.
fn shared_part_state() -> DownloadState {
    let mut state = pooled_state(
        file_hash_only_content(FIVE_BLOCKS),
        &[peer(1), peer(2)],
        QUIET_POSTURE,
        2,
    );
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, t0(), peer(2));
    state
}

#[test]
fn start_spawns_one_worker_per_candidate_up_to_concurrency() {
    let mut state = file_hash_only_state(vec![peer(1), peer(2), peer(3)], 2);
    let spawns: Vec<_> = state
        .start(t0())
        .into_iter()
        .filter_map(|d| match d {
            Decision::Spawn { peer, slot, .. } => Some((peer, slot)),
            _ => None,
        })
        .collect();
    // Concurrency caps the fleet at two; the third candidate stays pooled
    // for backfill. Slots are claimed in order from the free set.
    assert_eq!(spawns, vec![(peer(1), slot(0)), (peer(2), slot(1))]);
}

#[test]
fn sources_received_refills_the_pool_and_fills_a_free_slot() {
    use rmule_primitives::{ClientId, PeerSource};
    // One initial candidate, concurrency 2 → one worker spawns, one free slot.
    let mut state = file_hash_only_state(vec![peer(1)], 2);
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));

    // A worker exchanges two sources: a new High-ID peer(2) and a dup of the
    // already-working peer(1). `peer(n)` is IP 10.0.0.n; its High-ID client
    // id is that IP as a little-endian u32 (ADR-0055 backfill).
    let src = |n: u8| {
        rmule_primitives::SourceSighting::plain(
            PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, n])), 4662),
            Informant::Own,
        )
    };
    let decisions = via_exchange(&mut state, peer(1), vec![src(2), src(1)]);

    // The new source refills the pool and fills the free slot → Spawn for
    // peer(2); the dup (already a worker) is not re-spawned.
    let spawns: Vec<_> = decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Spawn { peer, .. } => Some(*peer),
            _ => None,
        })
        .collect();
    assert_eq!(spawns, vec![peer(2)]);
}

#[test]
fn an_exchanged_source_records_the_crypt_side_its_dial_meets() {
    use rmule_primitives::{ClientId, PeerCrypt, PeerSource, SourceCryptOptions};
    use rmule_primitives::{Informant, SourceSighting};
    let mut state = file_hash_only_state(vec![peer(1)], 4);
    let _ = state.start(t0());

    let high_id = |n: u8| ClientId::from_u32(u32::from_le_bytes([10, 0, 0, n]));
    let dial_hash = UserHash::from_bytes([0x42; 16]);
    // peer(2): a v4 source carrying a hash + crypt support → obfuscate-dialable.
    let crypt_capable = SourceSighting::new(
        PeerSource::new(high_id(2), 4662),
        Some(dial_hash),
        Some(SourceCryptOptions::from_byte(0x01)),
        Informant::Own,
    );
    // peer(3): a v4 source that carries a hash but does NOT support crypt.
    let no_crypt = SourceSighting::new(
        PeerSource::new(high_id(3), 4662),
        Some(UserHash::from_bytes([0x99; 16])),
        Some(SourceCryptOptions::from_byte(0x00)),
        Informant::Own,
    );
    // peer(4): a plain (v1) source, no hash at all.
    let plain = SourceSighting::plain(PeerSource::new(high_id(4), 4662), Informant::Own);

    let _ = via_exchange(&mut state, peer(1), vec![crypt_capable, no_crypt, plain]);

    assert_eq!(
        state.peer_crypt(peer(2)),
        crypt_capable.peer_crypt(),
        "a crypt-capable source's stance and hash reach its dial"
    );
    assert_eq!(
        state.peer_crypt(peer(3)),
        no_crypt.peer_crypt(),
        "a source stating no crypt support reaches its dial as such"
    );
    assert_eq!(
        state.peer_crypt(peer(4)),
        PeerCrypt::unknown(),
        "a plain (v1) source stated nothing"
    );
}

/// A worker's slot ask waits for its probe's answer (ADR-0112) and its part
/// for the grant (ADR-0026): the handshake alone asks nothing while the file
/// is asked, a release meanwhile passes the worker over, its Advertised Parts
/// ask its slot whether or not a part is free, and the grant that answers the
/// ask hands it the part — each step on its slot's phase (ADR-0028). A rank
/// instead hangs it up (`asking.rs`).
#[test]
fn a_worker_asks_its_slot_at_its_probe_answer_and_is_handed_its_part_at_the_grant() {
    let mut state = two_peer_state();
    let connected = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    assert!(
        !connected.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { .. })
                | Decision::Send {
                    command: PeerWorkerCommand::AskSlot
                        | PeerWorkerCommand::RequestHashSet
                        | PeerWorkerCommand::RequestBlocks { .. },
                    ..
                }
        )),
        "{connected:?}"
    );
    assert_eq!(phases(&connected), vec![WorkerPhase::AskingFile]);

    let _ = connect(&mut state, t0(), peer(2));
    let _ = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::Disconnected);
    assert!(
        !state.is_working(peer(1)),
        "the released part waits for a worker whose slot is granted"
    );

    let answered = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::every_part(ONE_PART));
    assert_eq!(sent(&answered), vec![(peer(1), PeerWorkerCommand::AskSlot)]);
    assert_eq!(
        phases(&answered),
        vec![WorkerPhase::WaitingForSlot { rank: None }]
    );
    assert!(!state.is_working(peer(1)), "a queued worker holds no part");

    let granted = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotGranted);
    assert!(
        granted.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { part_index: 0, peer: p, .. }) if *p == peer(1)
        )),
        "{granted:?}"
    );
    assert_eq!(
        phases(&granted),
        vec![WorkerPhase::RequestingPart { part_index: 0 }]
    );
}

/// A Streaming Priority download takes its head and its tail first — the
/// Preview Band — then the rest; any other fills in index order (ADR-0112).
/// One worker reporting room for a whole part at a time opens the parts in
/// rank order.
#[test]
fn a_streaming_priority_download_fetches_its_head_and_tail_first() {
    let size = 2 * rmule_primitives::ED2K_PART_SIZE + rmule_primitives::ED2K_PART_SIZE / 2;
    let part_blocks = rmule_primitives::ED2K_PART_SIZE.div_ceil(rmule_primitives::EMBLOCKSIZE);
    for (streaming_priority, order) in [(true, vec![0, 2, 1]), (false, vec![0, 1, 2])] {
        let content = ContentFacts {
            order: PartOrder::of(streaming_priority, 4),
            ..file_hash_only_content(size)
        };
        let mut state = pooled_state(content, &[peer(1)], QUIET_POSTURE, 1);
        let _ = state.start(t0());
        let mut decisions = connect(&mut state, t0(), peer(1));
        // The rest of part 0, then two parts' worth.
        for (handout, room) in [(1, part_blocks - 3), (2, 2 * part_blocks)] {
            decisions.extend(state.on_worker_event(
                t0(),
                peer(1),
                PeerWorkerEvent::BlocksWanted {
                    room: room as u32,
                    drained: false,
                    handout,
                },
            ));
        }
        let assigned: Vec<u32> = decisions
            .into_iter()
            .filter_map(|d| match d {
                Decision::Emit(DownloadEvent::PartAssigned { part_index, .. }) => Some(part_index),
                _ => None,
            })
            .collect();
        assert_eq!(assigned, order, "streaming priority {streaming_priority}");
    }
}

/// A grant that finds every block claimed and no slower worker to duplicate
/// gives its slot back (ADR-0117, ADR-0056); the worker holding the block
/// completes the part and the download finalizes.
#[test]
fn a_grant_with_nothing_unclaimed_gives_its_slot_back() {
    let mut state = two_peer_state();
    let _ = connect(&mut state, t0(), peer(1));
    let second = connect(&mut state, t0(), peer(2));
    assert!(
        second.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::NoFreePart,
                ..
            }) if *p == peer(2)
        )),
        "the one block is claimed: {second:?}"
    );
    assert!(second.iter().any(|d| matches!(
        d,
        Decision::EndWorker { peer: p, cancel: true } if *p == peer(2)
    )));

    let part = crate::planning::part_plan(ONE_PART, 0);
    let completing = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: part.offset,
            bytes: vec![0u8; part.len as usize],
        },
    );
    assert!(
        completing.iter().any(|d| matches!(
            d,
            Decision::PersistPart { part_index: 0, peer: p, .. } if *p == peer(1)
        )),
        "a whole part round-trips through PersistPart: {completing:?}"
    );
    let resumed = state.on_persist_result(t0(), 0, peer(1), Ok(()));
    assert!(
        resumed.iter().any(|d| matches!(d, Decision::Finalize)),
        "the last verified part finalizes the download: {resumed:?}"
    );
}

/// A block whose worker left after part of it arrived is handed again from
/// its first missing byte, not its first byte (ADR-0117).
#[test]
fn a_freed_block_is_handed_from_its_first_missing_byte() {
    let mut state = two_peer_state();
    let _ = connect(&mut state, t0(), peer(1));
    let part = crate::planning::part_plan(ONE_PART, 0);
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: part.offset,
            bytes: vec![0u8; 400],
        },
    );
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    let handed = connect(&mut state, t0(), peer(2));
    assert_eq!(handed_blocks(&handed, peer(2)), vec![(0, 400, ONE_PART)]);
}

#[test]
fn a_retired_worker_frees_its_slot_and_backfills_a_pooled_candidate() {
    // Three candidates, room for two: peer 3 waits in the pool.
    let mut state = pooled_state(
        file_hash_only_content(FIVE_BLOCKS),
        &[peer(1), peer(2), peer(3)],
        QUIET_POSTURE,
        2,
    );
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, t0(), peer(2));

    // peer 1 drops while peer 2 still holds blocks of the part; the freed
    // slot 0 is backfilled by the pooled peer 3.
    let retired = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        retired.iter().any(|d| matches!(
            d,
            Decision::Spawn { peer: p, slot: s, .. } if *p == peer(3) && *s == slot(0)
        )),
        "the retired worker's slot is reused to backfill the next candidate: {retired:?}"
    );
    assert!(!state.is_working(peer(1)), "the retired peer holds no part");
}

#[test]
fn the_last_worker_retiring_with_an_empty_pool_fails_the_download() {
    let mut state = file_hash_only_state(vec![peer(1)], 1);
    let _ = state.start(t0());
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);

    // The sole worker drops before it stands anywhere: with no candidate
    // left to backfill, the download fails (ADR-0030).
    let retired = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        retired
            .iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::NoUsableSources))),
        "an exhausted pool with no workers fails the download: {retired:?}"
    );
}

/// A granted slot that delivered no byte for the slot budget is given back
/// and its source stays one, standing without a rank, as aMule's
/// `DOWNLOADTIMEOUT` cancels and turns `DS_DOWNLOADING` into `DS_ONQUEUE`
/// (`DownloadClient.cpp:1188-1196`, ADR-0090).
#[test]
fn a_granted_slot_that_stalls_leaves_its_source_standing_queued() {
    let mut state = file_hash_only_state(vec![peer(1)], 1);
    let _ = state.start(t0());
    let _ = probed(&mut state, t0(), peer(1));
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotAsked);
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotGranted);

    let stalled = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotTimeout);
    assert!(
        stalled.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceRemoteQueued { peer: p, rank: None, .. })
                if *p == peer(1)
        )),
        "the source waits queued: {stalled:?}"
    );
    assert!(
        !stalled
            .iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::NoUsableSources))),
        "a source still stands: {stalled:?}"
    );
}

/// A source transferring on a granted slot whose link fails stays a source,
/// as aMule turns `DS_DOWNLOADING` into `DS_ONQUEUE` at a disconnect and
/// keeps the client (`BaseClient.cpp:1283-1284`): its part returns to the
/// pool, its record waits in the RemoteQueued stage with a standing dated at
/// its last ask, and the download does not fail (ADR-0090).
#[test]
fn a_transferring_source_whose_link_fails_waits_queued_rather_than_failing() {
    let mut state = file_hash_only_state(vec![peer(1)], 1);
    let _ = state.start(t0());
    let _ = probed(&mut state, t0(), peer(1));
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotAsked);
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotGranted);

    let later = t0() + Duration::from_secs(60);
    let cut = state.on_worker_event(later, peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        cut.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartReleased { part_index: 0, peer: p, .. })
                if *p == peer(1)
        )),
        "its part returns to the pool: {cut:?}"
    );
    assert!(
        cut.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceRemoteQueued { peer: p, rank: None, .. })
                if *p == peer(1)
        )),
        "the source waits queued: {cut:?}"
    );
    assert!(
        !cut.iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::NoUsableSources))),
        "a source still stands: {cut:?}"
    );
    assert_eq!(state.remote_queued().collect::<Vec<_>>(), vec![peer(1)]);
}

#[test]
fn an_armed_download_waits_instead_of_failing_when_its_pool_exhausts() {
    // Same exhaustion as above, but global discovery is armed (ADR-0051): a
    // future UDP sweep may backfill, so the download waits rather than failing.
    let mut state = discovery_armed_state(vec![peer(1)], 2);
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let retired = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        !retired
            .iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::NoUsableSources))),
        "an armed download waits for global discovery, not fails: {retired:?}"
    );
}

#[test]
fn a_verification_failure_retires_every_contributor() {
    let mut state = shared_part_state();

    // Two peers assemble the part: peer 1 the head, peer 2 the completing
    // tail.
    let part = crate::planning::part_plan(FIVE_BLOCKS, 0);
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: part.offset,
            bytes: vec![0u8; 400],
        },
    );
    let _ = state.on_worker_event(
        t0(),
        peer(2),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: part.offset + 400,
            bytes: vec![0u8; (part.len - 400) as usize],
        },
    );

    // The assembled part fails verification: with no per-block attribution
    // (no AICH), every contributor is retired (ADR-0029).
    let failed = state.on_persist_result(
        t0(),
        0,
        peer(2),
        Err(DownloadFailure::PartVerificationFailed),
    );
    for contributor in [peer(1), peer(2)] {
        assert!(
            failed.iter().any(|d| matches!(
                d,
                Decision::Emit(DownloadEvent::PeerRetired { peer: p, reason: PeerRetirementReason::PartVerificationFailed, .. })
                    if *p == contributor
            )),
            "contributor {contributor:?} is retired on verification failure: {failed:?}"
        );
        assert!(!state.is_working(contributor));
    }
}

/// Every retirement ends its worker, one path: a peer retired for bad
/// data would otherwise sit connected until the peer hung up, and a peer that
/// hung up on its own gets the same `EndWorker` — harmless on a gone worker.
#[test]
fn every_retirement_ends_its_worker() {
    let mut state = shared_part_state();
    let part = crate::planning::part_plan(FIVE_BLOCKS, 0);
    let _ = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlockReceived {
            part_index: 0,
            offset: part.offset,
            bytes: vec![0u8; part.len as usize],
        },
    );

    let failed = state.on_persist_result(
        t0(),
        0,
        peer(1),
        Err(DownloadFailure::PartVerificationFailed),
    );
    let hung_up = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::Disconnected);

    for (out, at) in [(&failed, peer(1)), (&hung_up, peer(2))] {
        assert!(
            out.iter()
                .any(|d| matches!(d, Decision::EndWorker { peer: p, .. } if *p == at)),
            "{at:?}'s retirement ends its worker: {out:?}"
        );
    }
}
#[test]
fn on_stop_releases_in_flight_parts_and_fails_with_the_reason() {
    let mut state = two_peer_state();
    let _ = connect(&mut state, t0(), peer(1));

    // A pause releases the in-flight part with the Paused reason (so it can
    // resume later) and fails the activity with Paused.
    let out = state.on_stop(DownloadFailure::Paused);
    assert!(
        out.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartReleased {
                part_index: 0,
                reason: PartReleaseReason::Paused,
                ..
            })
        )),
        "the in-flight part is released as Paused: {out:?}"
    );
    assert!(
        out.iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::Paused))),
        "the activity fails with the stop reason: {out:?}"
    );
}

/// The blocks `decisions` hand `peer`, in order.
fn handed_blocks(decisions: &[Decision], to: PeerEndpoint) -> Vec<(u32, u64, u64)> {
    sent(decisions)
        .into_iter()
        .filter(|(peer, _)| *peer == to)
        .flat_map(|(_, command)| match command {
            PeerWorkerCommand::RequestBlocks { blocks, .. } => blocks,
            _ => Vec::new(),
        })
        .map(|block| (block.part_index, block.start, block.end))
        .collect()
}

/// A part's blocks are handed to every granted worker that advertised it,
/// one worker per block (ADR-0117): the second grant takes the blocks the
/// first left unclaimed, the part assembles from both, and it verifies with
/// both named as contributors.
#[test]
fn two_workers_share_one_parts_blocks() {
    use rmule_primitives::EMBLOCKSIZE as B;
    let size = 4 * B + 100;
    let mut state = pooled_state(
        file_hash_only_content(size),
        &[peer(1), peer(2)],
        QUIET_POSTURE,
        2,
    );
    let _ = state.start(t0());
    let first = connect(&mut state, t0(), peer(1));
    let second = connect(&mut state, t0(), peer(2));
    assert_eq!(
        handed_blocks(&first, peer(1)),
        vec![(0, 0, B), (0, B, 2 * B), (0, 2 * B, 3 * B)],
        "the first grant takes the three blocks its first request may carry"
    );
    assert_eq!(
        handed_blocks(&second, peer(2)),
        vec![(0, 3 * B, 4 * B), (0, 4 * B, size)],
        "the second grant takes what the first left of the same part"
    );
    for (decisions, to) in [(&first, peer(1)), (&second, peer(2))] {
        assert!(decisions.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { peer, part_index: 0, .. }) if *peer == to
        )));
    }

    let deliver = |state: &mut DownloadState, from: PeerEndpoint, start: u64, end: u64| {
        state.on_worker_event(
            t0(),
            from,
            PeerWorkerEvent::BlockReceived {
                part_index: 0,
                offset: start,
                bytes: vec![0x5A; (end - start) as usize],
            },
        )
    };
    assert!(
        deliver(&mut state, peer(2), 3 * B, size)
            .iter()
            .all(|d| !matches!(d, Decision::PersistPart { .. }))
    );
    let last = deliver(&mut state, peer(1), 0, 3 * B);
    assert!(
        last.iter().any(|d| matches!(
            d,
            Decision::PersistPart { part_index: 0, offset: 0, bytes, .. } if bytes.len() as u64 == size
        )),
        "the part is whole once both workers' blocks are in: {last:?}"
    );
}

/// A want the worker sent before the latest handout reached it is set aside:
/// it says nothing of the blocks it has not seen, so a drained want from
/// before them never takes the slot back (ADR-0117).
#[test]
fn a_want_sent_before_the_latest_handout_is_set_aside() {
    use rmule_primitives::EMBLOCKSIZE as B;
    let mut state = pooled_state(file_hash_only_content(4 * B), &[peer(1)], QUIET_POSTURE, 1);
    let _ = state.start(t0());
    let first = connect(&mut state, t0(), peer(1));
    assert_eq!(handed_blocks(&first, peer(1)).len(), 3);
    let second = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlocksWanted {
            room: 1,
            drained: false,
            handout: 1,
        },
    );
    assert_eq!(handed_blocks(&second, peer(1)), vec![(0, 3 * B, 4 * B)]);
    for n in 0..3 {
        let _ = state.on_worker_event(
            t0(),
            peer(1),
            PeerWorkerEvent::BlockReceived {
                part_index: 0,
                offset: n * B,
                bytes: vec![0; B as usize],
            },
        );
    }
    let stale = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::BlocksWanted {
            room: 3,
            drained: true,
            handout: 1,
        },
    );
    assert!(
        !stale
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::PeerRetired { .. }))),
        "the worker has block 3 on its way: {stale:?}"
    );
    assert!(state.is_working(peer(1)));
}
