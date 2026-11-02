//! A source on its uploader's queue without a rank (ADR-0090, "How a worker
//! ends, and what its record keeps"): its upload request out, or put back by
//! `OP_OUTOFPARTREQS` on a granted slot (ADR-0057), it holds a standing that
//! the rank which follows ranks, and is reasked on the ordinary cadence.

use super::*;

/// `OP_OUTOFPARTREQS` on a granted slot puts the source back on its
/// uploader's queue (ADR-0057): the worker stays, its part goes back for
/// retry, it waits for its next grant holding none (ADR-0026), and the rank
/// that follows is its standing and hangs the worker up (ADR-0116). It
/// reasks on the ordinary cadence — a UDP ping before `FILEREASKTIME`, never
/// the no-needed-parts doubling: it holds parts we lack.
#[test]
fn a_source_put_back_on_queue_stays_queued_at_its_new_rank() {
    let mut state = started(&[peer(1)], live_posture());
    let _ = connect(&mut state, t0(), peer(1));
    let identity = HelloFacts {
        software: rmule_testkit::emule_qt(),
        ..reaskable(SOURCE)
    }
    .identity();
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Identity(identity));
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotAsked);
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Queued { rank: 5 });
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotGranted);

    let requeued = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Requeued);
    assert!(
        requeued.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartReleased {
                peer: p,
                reason: PartReleaseReason::BackOnQueue,
                ..
            }) if *p == peer(1)
        )),
        "{requeued:?}"
    );
    assert!(
        !requeued.iter().any(|d| matches!(d, Decision::Send { .. })),
        "a queued worker is handed its part at its grant: {requeued:?}"
    );
    assert_eq!(
        phases(&requeued),
        vec![WorkerPhase::WaitingForSlot { rank: None }]
    );
    assert!(
        !requeued.iter().any(|d| matches!(
            d,
            Decision::EndWorker { .. } | Decision::Emit(DownloadEvent::PeerRetired { .. })
        )),
        "the worker stays on its link: {requeued:?}"
    );

    let hung_up = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Queued { rank: 3 });
    assert!(
        hung_up.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceRemoteQueued { peer: p, rank: Some(3), .. })
                if *p == peer(1)
        )),
        "{hung_up:?}"
    );
    assert!(
        hung_up.iter().any(|d| matches!(
            d,
            Decision::EndWorker { peer: p, cancel: false } if *p == peer(1)
        )),
        "the rank ends the worker, silently: {hung_up:?}"
    );
    assert_eq!(
        pinged(&state.on_tick(t0() + udp_due())),
        vec![contact(peer(1))],
        "the ordinary cadence: a ping before the period"
    );
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![peer(1)]
    );
}

/// A worker whose upload request left is on the uploader's queue before any
/// rank (aMule `DS_ONQUEUE`, ADR-0090): when its link closes then, its record
/// keeps a standing without a rank and is reasked on schedule.
#[test]
fn a_source_asked_for_a_slot_keeps_a_standing_without_a_rank() {
    let mut state = started(&[peer(1)], live_posture());
    let _ = connect(&mut state, t0(), peer(1));
    let identity = reaskable(SOURCE).identity();
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Identity(identity));
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotAsked);

    let hung_up = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        hung_up.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceRemoteQueued { peer: p, rank: None, .. })
                if *p == peer(1)
        )),
        "{hung_up:?}"
    );
    assert_eq!(
        pinged(&state.on_tick(t0() + udp_due())),
        vec![contact(peer(1))]
    );
}
