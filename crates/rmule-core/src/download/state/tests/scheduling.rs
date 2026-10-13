//! Slot occupancy and part scheduling: one worker per candidate up to the
//! concurrency, a refilled pool taking a free slot, two peers racing one part,
//! mid-part resume from a shared prefix, backfill on retirement, and what a
//! stop does to the parts still in flight.

use super::*;

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
        rmule_primitives::SourceSighting::plain(PeerSource::new(
            ClientId::from_u32(u32::from_le_bytes([10, 0, 0, n])),
            4662,
        ))
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
    use rmule_primitives::SourceSighting;
    use rmule_primitives::{ClientId, PeerCrypt, PeerSource, SourceCryptOptions};
    let mut state = file_hash_only_state(vec![peer(1)], 4);
    let _ = state.start(t0());

    let high_id = |n: u8| ClientId::from_u32(u32::from_le_bytes([10, 0, 0, n]));
    let dial_hash = UserHash::from_bytes([0x42; 16]);
    // peer(2): a v4 source carrying a hash + crypt support → obfuscate-dialable.
    let crypt_capable = SourceSighting::new(
        PeerSource::new(high_id(2), 4662),
        Some(dial_hash),
        Some(SourceCryptOptions::from_byte(0x01)),
    );
    // peer(3): a v4 source that carries a hash but does NOT support crypt.
    let no_crypt = SourceSighting::new(
        PeerSource::new(high_id(3), 4662),
        Some(UserHash::from_bytes([0x99; 16])),
        Some(SourceCryptOptions::from_byte(0x00)),
    );
    // peer(4): a plain (v1) source, no hash at all.
    let plain = SourceSighting::plain(PeerSource::new(high_id(4), 4662));

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

/// A worker's first part waits for its probe's answer (ADR-0112): the
/// handshake alone hands it nothing, a release meanwhile passes it over, and
/// its Advertised Parts assign it.
#[test]
fn a_connected_worker_is_handed_nothing_until_its_parts_are_known() {
    let mut state = two_peer_state();
    let connected = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    assert!(
        !connected.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { .. }) | Decision::Phase { .. }
        )),
        "{connected:?}"
    );

    let _ = connect(&mut state, t0(), peer(2));
    let _ = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::Disconnected);
    assert!(
        !state.is_working(peer(1)),
        "the released part waits for a worker whose parts are known"
    );

    let answered = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::every_part(ONE_PART));
    assert!(
        answered.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { part_index: 0, peer: p, .. }) if *p == peer(1)
        )),
        "{answered:?}"
    );
}

/// A Streaming Priority download takes its head and its tail first — the
/// Preview Band — then the rest; any other fills in index order (ADR-0112).
#[test]
fn a_streaming_priority_download_fetches_its_head_and_tail_first() {
    let size = 2 * rmule_primitives::ED2K_PART_SIZE + rmule_primitives::ED2K_PART_SIZE / 2;
    for (streaming_priority, order) in [(true, vec![0, 2, 1]), (false, vec![0, 1, 2])] {
        let content = ContentFacts {
            streaming_priority,
            ..file_hash_only_content(size)
        };
        let pool = [peer(1), peer(2), peer(3)];
        let mut state = pooled_state(content, &pool, QUIET_POSTURE, 3);
        let _ = state.start(t0());
        let assigned: Vec<u32> = pool
            .iter()
            .flat_map(|&at| connect(&mut state, t0(), at))
            .filter_map(|d| match d {
                Decision::Emit(DownloadEvent::PartAssigned { part_index, .. }) => Some(part_index),
                _ => None,
            })
            .collect();
        assert_eq!(assigned, order, "streaming priority {streaming_priority}");
    }
}

#[test]
fn a_raced_part_completing_clears_the_losing_racer_and_finalizes() {
    let mut state = two_peer_state();

    // peer 1 takes the only part; peer 2, idle with nothing fresh, races it.
    let _ = connect(&mut state, t0(), peer(1));
    let assigned_two = connect(&mut state, t0(), peer(2));
    assert!(
        assigned_two.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { part_index: 0, .. })
        )),
        "the surplus peer races the only in-flight part: {assigned_two:?}"
    );
    assert!(state.is_working(peer(2)), "peer 2 is racing part 0");

    // peer 1 delivers the whole part: completion hands it off to persist.
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
        "a completed prefix round-trips through PersistPart: {completing:?}"
    );

    // Persist succeeds: the part is verified, its losing racer is dropped,
    // and with the only part done the download finalizes.
    let resumed = state.on_persist_result(t0(), 0, peer(1), Ok(()));
    assert!(
        resumed.iter().any(|d| matches!(d, Decision::Finalize)),
        "the last verified part finalizes the download: {resumed:?}"
    );
    assert!(
        !state.is_working(peer(2)),
        "the losing racer is cleared when the part it raced is verified"
    );
}

#[test]
fn racing_a_partially_assembled_part_resumes_from_the_shared_prefix() {
    let mut state = two_peer_state();

    // peer 1 takes part 0 and delivers a partial prefix, then stalls.
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

    // peer 2 races the same part: it must resume from the shared prefix
    // end, not refetch from the part's first byte (ADR-0029).
    let raced = connect(&mut state, t0(), peer(2));
    let resume_offset = raced
        .iter()
        .find_map(|d| {
            if let Decision::Send {
                command: PeerWorkerCommand::RequestPart { resume_offset, .. },
                ..
            } = d
            {
                Some(*resume_offset)
            } else {
                None
            }
        })
        .expect("the racer is told to request the part");
    assert_eq!(
        resume_offset,
        part.offset + 400,
        "a racer resumes from the cross-peer shared prefix, not block 0"
    );
}

#[test]
fn a_retired_worker_frees_its_slot_and_backfills_a_pooled_candidate() {
    // Three candidates, room for two: peer 3 waits in the pool.
    let mut state = file_hash_only_state(vec![peer(1), peer(2), peer(3)], 2);
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, t0(), peer(2));

    // peer 1 drops while peer 2 still races the part, so nothing is
    // released, but the freed slot 0 is backfilled by the pooled peer 3.
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
    let _ = connect(&mut state, t0(), peer(1));

    // The sole worker drops: its part returns to the pool and, with no
    // candidate left to backfill, the download fails (ADR-0030).
    let retired = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        retired.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartReleased { part_index: 0, peer: p, .. })
                if *p == peer(1)
        )),
        "the sole holder's part returns to the pool: {retired:?}"
    );
    assert!(
        retired
            .iter()
            .any(|d| matches!(d, Decision::Fail(DownloadFailure::NoUsableSources))),
        "an exhausted pool with no workers fails the download: {retired:?}"
    );
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
    let mut state = two_peer_state();
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, t0(), peer(2));

    // Two peers assemble the part across the cross-peer prefix: peer 1 the
    // head, peer 2 the completing tail.
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
    let mut state = two_peer_state();
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, t0(), peer(2));
    let part = crate::planning::part_plan(ONE_PART, 0);
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
