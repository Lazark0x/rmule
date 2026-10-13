//! A source whose Advertised Parts hold nothing we lack (ADR-0112 §6): its
//! worker is retired `NoNeededParts`, and its record waits as a queued source
//! asked again over TCP at twice the period (aMule `DS_NONEEDEDPARTS`, stock
//! 2.3.3 `DownloadClient.cpp:464-466`, `PartFile.cpp:1436-1444`).

use super::*;

/// The retirement ends the worker with a cancel, so a slot it granted is
/// given back; its record earns a rank-0 standing with the mark, reported as
/// no queue rank and spent on nothing; its slot is backfilled; and the reask
/// is a TCP full ask at twice the period, never a ping, though its hello
/// stated a contact.
#[test]
fn a_worker_holding_nothing_we_lack_is_retired_no_needed_parts() {
    let mut state = pooled_state(
        file_hash_only_content(THREE_PARTS),
        &[peer(1), peer(2)],
        live_posture(),
        1,
    );
    let _ = state.start(t0());
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    let identity = reaskable(SOURCE).identity();
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Identity(identity));
    let nothing = PeerWorkerEvent::PartsAdvertised {
        parts: Some(PartBitmap::decode(3, &[0]).expect("three parts")),
        complete: false,
    };
    let retired = state.on_worker_event(t0(), peer(1), nothing);

    assert!(
        retired.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::NoNeededParts,
                ..
            }) if *p == peer(1)
        )),
        "{retired:?}"
    );
    assert!(
        retired.iter().any(|d| matches!(
            d,
            Decision::EndWorker { peer: p, cancel: true } if *p == peer(1)
        )),
        "{retired:?}"
    );
    assert!(
        !retired
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::SourceRemoteQueued { .. }))),
        "no queue rank is reported for it: {retired:?}"
    );
    assert_eq!(spawned(&retired), vec![peer(2)], "its slot is backfilled");
    assert!(state.remote_queued().any(|at| at == peer(1)));
    assert!(!state.sources.is_spent(peer(1)));

    assert!(pinged(&state.on_tick(t0() + udp_due())).is_empty());
    assert!(asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)).is_empty());
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME * NO_NEEDED_PARTS_MULTIPLIER)),
        vec![peer(1)]
    );
}
