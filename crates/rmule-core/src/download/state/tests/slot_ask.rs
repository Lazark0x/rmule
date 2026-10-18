//! The slot ask and the download's one hash-set ask (ADR-0026): a download
//! holding its part hash set asks no link for it, one wanting it asks one link
//! at a time while every other asks its slot at once, and the ask passes on at
//! its answer, its worker's end and the **Hash-Set Deadline**. A queued worker
//! left holding nothing we need goes without a slot to give back.

use super::*;
use crate::download::state::slot_ask::HASH_SET_DEADLINE;

/// Two parts and a byte: three hashes, so the set is wanted until held.
const THREE_PARTS: u64 = 2 * rmule_primitives::ED2K_PART_SIZE + 1;

/// A download of `content` with `peer(1)` and `peer(2)` spawned.
fn two_workers(content: ContentFacts) -> DownloadState {
    let mut state = pooled_state(content, &[peer(1), peer(2)], QUIET_POSTURE, 2);
    let _ = state.start(t0());
    state
}

/// A link carrying `p=`: the whole part hash set, final.
fn link_set_content(file_size: u64) -> ContentFacts {
    let held = set_held_content(file_size, Vec::new());
    let hashes = held.resolved.hashes.clone();
    ContentFacts {
        link_part_hash_set: Some(
            PartHashSet::from_hashes(file_size, hashes.clone()).expect("a whole set"),
        ),
        resolved: ResolvedHashSet {
            authority: VerificationAuthority::LinkPartHashSet,
            hashes,
        },
        ..held
    }
}

/// Whether `decisions` send `peer` its hash-set ask.
fn asks_hash_set(decisions: &[Decision], peer: PeerEndpoint) -> bool {
    sent(decisions).contains(&(peer, PeerWorkerCommand::RequestHashSet))
}

/// Whether `decisions` send `peer` its slot ask.
fn asks_slot(decisions: &[Decision], peer: PeerEndpoint) -> bool {
    sent(decisions).contains(&(peer, PeerWorkerCommand::AskSlot))
}

/// A link already holding the set never waits for its own answer: every
/// worker of a `p=` download asks its slot at its probe answer, and none asks
/// the set (ADR-0026).
#[test]
fn a_download_holding_its_set_asks_no_link_for_it() {
    let mut state = two_workers(link_set_content(THREE_PARTS));
    for n in [1, 2] {
        let answered = probed(&mut state, t0(), peer(n));
        assert!(asks_slot(&answered, peer(n)), "{answered:?}");
        assert!(!asks_hash_set(&answered, peer(n)), "{answered:?}");
    }
    assert_eq!(
        state.slot_asks.next_deadline(),
        None,
        "no hash-set ask is timed"
    );
}

/// A download without the set asks it of its first link alone, whose slot ask
/// waits on the answer; the second asks its slot at once (aMule
/// `IsHashSetNeeded`, `DownloadClient.cpp:467-483`). An answer that is not
/// the file's own retires its sender, and the ask passes to the link the
/// uploader granted (`DownloadClient.cpp:583`, ADR-0116).
#[test]
fn only_one_link_asks_the_set_and_a_refused_answer_passes_it_on() {
    let mut state = two_workers(file_hash_only_content(THREE_PARTS));
    let first = probed(&mut state, t0(), peer(1));
    assert!(asks_hash_set(&first, peer(1)), "{first:?}");
    assert!(!asks_slot(&first, peer(1)), "{first:?}");
    assert_eq!(
        phases(&first),
        vec![WorkerPhase::AskingFile, WorkerPhase::RequestingHashSet]
    );

    let second = probed(&mut state, t0(), peer(2));
    assert!(asks_slot(&second, peer(2)), "{second:?}");
    assert!(!asks_hash_set(&second, peer(2)), "{second:?}");
    let _ = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::SlotGranted);

    let hashes = set_held_content(THREE_PARTS, Vec::new()).resolved.hashes;
    let answered = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::HashSetReceived {
            part_hashes: hashes,
        },
    );
    assert!(
        answered.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::VerificationAuthorityMismatch,
                ..
            }) if *p == peer(1)
        )),
        "{answered:?}"
    );
    assert!(asks_hash_set(&answered, peer(2)), "{answered:?}");
}

/// The asker's proven answer holds the set: its slot ask goes out, and no
/// later link asks it again.
#[test]
fn a_proven_answer_sends_the_askers_slot_ask() {
    let file = two_part_file();
    let mut state = two_part_state(&file);
    let first = probed(&mut state, t0(), peer(1));
    assert!(asks_hash_set(&first, peer(1)), "{first:?}");

    let answered = state.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::HashSetReceived {
            part_hashes: file.part_hash_set().expect("two parts").hashes().to_vec(),
        },
    );
    assert!(asks_slot(&answered, peer(1)), "{answered:?}");
    assert_eq!(
        state.slot_asks.next_deadline(),
        None,
        "the ask's deadline ended with it"
    );

    let second = probed(&mut state, t0(), peer(2));
    assert!(asks_slot(&second, peer(2)), "{second:?}");
    assert!(!asks_hash_set(&second, peer(2)), "{second:?}");
}

/// An asker that never answers asks its slot at the **Hash-Set Deadline**
/// regardless, and the ask passes to the next transferring link; the deadline
/// is what the brain wakes for. A link the deadline passed is not asked again.
#[test]
fn the_deadline_sends_the_askers_slot_ask_and_passes_the_set_on() {
    let mut state = two_workers(file_hash_only_content(THREE_PARTS));
    let _ = probed(&mut state, t0(), peer(1));
    let _ = probed(&mut state, t0(), peer(2));
    let _ = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::SlotGranted);
    let deadline = t0() + HASH_SET_DEADLINE;
    assert_eq!(state.next_wake(), Some(deadline));
    assert!(sent(&state.on_tick(deadline - Duration::from_millis(1))).is_empty());

    let passed = state.on_tick(deadline);
    assert!(asks_slot(&passed, peer(1)), "{passed:?}");
    assert!(asks_hash_set(&passed, peer(2)), "{passed:?}");
    assert_eq!(
        state.slot_asks.next_deadline(),
        Some(deadline + HASH_SET_DEADLINE)
    );

    let again = state.on_tick(deadline + HASH_SET_DEADLINE);
    assert!(
        sent(&again).is_empty(),
        "both links were passed; the next probe answer takes the ask: {again:?}"
    );
    assert_eq!(state.slot_asks.next_deadline(), None);
}

/// The asker's link closing before an answer passes the ask to a
/// transferring link, as aMule's `Disconnected` sets the set needed again
/// (`BaseClient.cpp:1305-1306`).
#[test]
fn the_askers_end_passes_the_set_on() {
    let mut state = two_workers(file_hash_only_content(THREE_PARTS));
    let _ = probed(&mut state, t0(), peer(1));
    let _ = probed(&mut state, t0(), peer(2));
    let _ = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::SlotGranted);

    let ended = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(asks_hash_set(&ended, peer(2)), "{ended:?}");
}

/// A link only queued is never passed the ask: its rank will hang it up and
/// drop the answer in flight (ADR-0116 invariant 3). With no link
/// transferring, the next probe answer takes it.
#[test]
fn a_queued_link_is_not_passed_the_set() {
    let mut state = two_workers(file_hash_only_content(THREE_PARTS));
    let _ = probed(&mut state, t0(), peer(1));
    let _ = probed(&mut state, t0(), peer(2));

    let ended = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(!asks_hash_set(&ended, peer(2)), "{ended:?}");
    let ranked = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::Queued { rank: 4 });
    assert!(
        ranked.iter().any(|d| matches!(
            d,
            Decision::EndWorker { peer: p, cancel: false } if *p == peer(2)
        )),
        "{ranked:?}"
    );
}

/// A queued worker whose parts all verify elsewhere holds nothing we need: it
/// is retired `NoNeededParts`, with no `0x56`, since it holds no granted slot
/// (ADR-0112 §6, ADR-0056), while the verifier takes its next part.
#[test]
fn a_queued_worker_left_holding_nothing_we_lack_goes_with_no_slot_to_give_back() {
    let mut state = two_workers(set_held_content(THREE_PARTS, Vec::new()));
    let _ = connect(&mut state, t0(), peer(1));
    let _ = state.on_worker_event(t0(), peer(2), PeerWorkerEvent::Connected);
    let first = PeerWorkerEvent::PartsAdvertised {
        parts: Some(PartBitmap::decode(3, &[0b0000_0001]).expect("three parts")),
        complete: false,
    };
    let queued = state.on_worker_event(t0(), peer(2), first);
    assert!(asks_slot(&queued, peer(2)), "{queued:?}");

    let verified = deliver_verified(&mut state, peer(1), 0);
    assert!(
        verified.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::NoNeededParts,
                ..
            }) if *p == peer(2)
        )),
        "{verified:?}"
    );
    assert!(
        verified.iter().any(|d| matches!(
            d,
            Decision::EndWorker { peer: p, cancel: false } if *p == peer(2)
        )),
        "{verified:?}"
    );
    assert!(
        verified.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { part_index: 1, peer: p, .. }) if *p == peer(1)
        )),
        "{verified:?}"
    );
}

/// Two queued workers left holding nothing we lack by one verified part are
/// each retired once: the first retirement's backfill finds the second, and
/// the batch does not retire it again.
#[test]
fn workers_left_unworkable_together_are_each_retired_once() {
    let mut state = pooled_state(
        set_held_content(THREE_PARTS, Vec::new()),
        &[peer(1), peer(2), peer(3)],
        QUIET_POSTURE,
        3,
    );
    let _ = state.start(t0());
    let _ = connect(&mut state, t0(), peer(1));
    for n in [2, 3] {
        let _ = state.on_worker_event(t0(), peer(n), PeerWorkerEvent::Connected);
        let first = PeerWorkerEvent::PartsAdvertised {
            parts: Some(PartBitmap::decode(3, &[0b0000_0001]).expect("three parts")),
            complete: false,
        };
        let _ = state.on_worker_event(t0(), peer(n), first);
    }

    let verified = deliver_verified(&mut state, peer(1), 0);
    for n in [2, 3] {
        let retired = verified
            .iter()
            .filter(|d| {
                matches!(
                    d,
                    Decision::Emit(DownloadEvent::PeerRetired { peer: p, .. }) if *p == peer(n)
                )
            })
            .count();
        assert_eq!(retired, 1, "peer {n}: {verified:?}");
    }
}
