//! A source asked again over TCP comes back through a fresh worker, its
//! record still holding the parts its earlier connection advertised: the new
//! worker is handed a part only once its own probe answers (ADR-0112 §3).

use super::*;

/// A queued source re-dialled by its full ask completes its handshake while a
/// part is in flight elsewhere; that part's release passes it over though
/// its record's earlier parts hold it, and its own answer assigns it.
#[test]
fn a_redialled_source_is_handed_nothing_before_its_own_probe_answers() {
    let mut state = started(
        &[peer(1), peer(2)],
        SourcingPosture {
            client_udp: false,
            ..live_posture()
        },
    );
    queue_and_hang_up(&mut state, peer(1), false, 5);
    let _ = connect(&mut state, t0(), peer(2));
    assert!(state.is_working(peer(2)));

    let asked = t0() + FILE_REASK_TIME;
    let redial = state.on_tick(asked);
    assert_eq!(asked_by_tcp(&redial), vec![peer(1)]);
    assert_eq!(spawned(&redial), vec![peer(1)]);
    let _ = state.on_worker_event(asked, peer(1), PeerWorkerEvent::Connected);

    let released = state.on_worker_event(asked, peer(2), PeerWorkerEvent::Disconnected);
    assert!(
        !released
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::PartAssigned { .. }))),
        "the released part waits for the re-dialled worker's answer: {released:?}"
    );
    assert!(!state.is_working(peer(1)));

    let answered = state.on_worker_event(asked, peer(1), PeerWorkerEvent::every_part(ONE_PART));
    assert!(
        answered.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { part_index: 0, peer: p, .. }) if *p == peer(1)
        )),
        "{answered:?}"
    );
}
