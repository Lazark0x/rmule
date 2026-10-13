//! A granted slot with no part to work goes back (ADR-0056): the worker sends
//! `OP_CANCELTRANSFER` and is retired `NoFreePart`, and its record waits in the
//! RemoteQueued stage on the ordinary cadence (ADR-0057) — the source still
//! holds a part we lack. Asked again, it asks its slot at its probe answer
//! even with every part in flight; a flow queued again by `OP_OUTOFPARTREQS`
//! is handed its part at its next grant.

use super::*;

/// Two parts, so one can be in flight elsewhere while the other verifies.
const TWO_PARTS: u64 = rmule_primitives::ED2K_PART_SIZE + 1;

/// `peer(1)` and `peer(2)` granted on a two-part download that holds its
/// set, `peer(1)` stating its client-UDP contact; part 0 on `peer(1)`,
/// part 1 on `peer(2)`.
fn both_granted(posture: SourcingPosture) -> DownloadState {
    let mut state = pooled_state(
        set_held_content(TWO_PARTS, Vec::new()),
        &[peer(1), peer(2)],
        posture,
        2,
    );
    let _ = state.start(t0());
    let identity = reaskable(SOURCE).identity();
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Identity(identity));
    let _ = connect(&mut state, t0(), peer(1));
    let _ = connect(&mut state, t0(), peer(2));
    state
}

/// Whether `decisions` retire `peer` `NoFreePart`, giving its granted slot
/// back with `OP_CANCELTRANSFER`.
fn gave_back(decisions: &[Decision], peer: PeerEndpoint) -> bool {
    let retired = decisions.iter().any(|d| {
        matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::NoFreePart,
                ..
            }) if *p == peer
        )
    });
    let cancelled = decisions
        .iter()
        .any(|d| matches!(d, Decision::EndWorker { peer: p, cancel: true } if *p == peer));
    retired && cancelled
}

/// `peer(1)` verifies part 0 while part 1 is in flight on `peer(2)`; having
/// delivered a part it may not race, so its granted slot goes back (aMule's
/// `OP_CANCELTRANSFER (no free blocks)`, `DownloadClient.cpp:641-693`) and its
/// record waits unranked, pinged before the ordinary period — never the
/// no-needed-parts doubling.
#[test]
fn a_granted_worker_with_no_part_free_gives_its_slot_back_onto_the_ordinary_cadence() {
    let mut state = both_granted(live_posture());

    let verified = deliver_verified(&mut state, peer(1), 0);
    assert!(gave_back(&verified, peer(1)), "{verified:?}");
    assert!(
        verified.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceRemoteQueued { peer: p, rank: None, .. })
                if *p == peer(1)
        )),
        "{verified:?}"
    );
    assert!(state.remote_queued().any(|at| at == peer(1)));
    assert!(!state.sources.is_spent(peer(1)));
    assert!(
        state.is_working(peer(2)),
        "the part's other source keeps it"
    );

    assert_eq!(
        pinged(&state.on_tick(t0() + udp_due())),
        vec![contact(peer(1))],
        "the ordinary cadence: a ping before the period"
    );
}

/// The source given back is asked again over TCP at `FILEREASKTIME`; its new
/// worker, which has delivered a part, asks its slot at its probe answer with
/// every part it holds that we lack in flight — no idle worker waits for a
/// part — and its grant, finding none free, gives the slot back again.
#[test]
fn a_redialled_source_that_delivered_a_part_asks_its_slot_with_every_part_in_flight() {
    let mut state = both_granted(SourcingPosture {
        client_udp: false,
        ..live_posture()
    });
    let _ = deliver_verified(&mut state, peer(1), 0);

    let asked = t0() + FILE_REASK_TIME;
    let redial = state.on_tick(asked);
    assert_eq!(asked_by_tcp(&redial), vec![peer(1)]);
    assert_eq!(spawned(&redial), vec![peer(1)]);

    let _ = state.on_worker_event(asked, peer(1), PeerWorkerEvent::Connected);
    let answered = state.on_worker_event(asked, peer(1), PeerWorkerEvent::every_part(TWO_PARTS));
    assert_eq!(sent(&answered), vec![(peer(1), PeerWorkerCommand::AskSlot)]);
    assert_eq!(
        phases(&answered),
        vec![WorkerPhase::WaitingForSlot { rank: None }],
        "queued, not idle"
    );

    let granted = state.on_worker_event(asked, peer(1), PeerWorkerEvent::SlotGranted);
    assert!(gave_back(&granted, peer(1)), "{granted:?}");
}

/// A flow `OP_OUTOFPARTREQS` queued again waits holding no part, and its next
/// grant hands it one (ADR-0026, ADR-0057).
#[test]
fn a_flow_queued_again_is_handed_its_part_at_its_next_grant() {
    let mut state = started(&[peer(1)], live_posture());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Requeued);
    assert!(!state.is_working(peer(1)));

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
