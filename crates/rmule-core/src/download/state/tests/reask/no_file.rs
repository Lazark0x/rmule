//! A source that says it lacks the file (`OP_FILEREQANSNOFIL`, ADR-0090) is
//! spent for this download under every name its record holds, whichever road
//! reached it, as aMule dead-lists it and removes it (stock 2.3.3
//! `ClientTCPSocket.cpp:541-563`, `DeadSourceList.cpp:63-75`).

use rmule_primitives::PeerSource;

use super::*;

/// The worker on `peer`, its hello naming [`SOURCE`], is told the peer lacks
/// the file: the decisions of its probe answer.
fn answers_no_file(state: &mut DownloadState, now: Instant, peer: PeerEndpoint) -> Vec<Decision> {
    let _ = state.on_worker_event(now, peer, PeerWorkerEvent::Connected);
    let identity = reaskable(SOURCE).identity();
    let _ = state.on_worker_event(now, peer, PeerWorkerEvent::Identity(identity));
    state.on_worker_event(
        now,
        peer,
        PeerWorkerEvent::PartsAdvertised {
            parts: None,
            complete: false,
        },
    )
}

/// Whether `decisions` retire `peer` as one lacking the file.
fn retired_lacking(decisions: &[Decision], peer: PeerEndpoint) -> bool {
    decisions.iter().any(|d| {
        matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::FileNotFound,
                ..
            }) if *p == peer
        )
    })
}

/// A queued source whose TCP full ask meets no file is retired as lacking it,
/// its standing gone: it is never asked again at the next `FILEREASKTIME`, and
/// a sighting of it is refused until two spent turns have passed.
#[test]
fn a_queued_source_whose_full_ask_meets_no_file_is_never_asked_again() {
    let mut state = started(&[peer(1)], live_posture());
    queue_and_hang_up(&mut state, peer(1), false, 5);
    let full_ask = state.on_tick(t0() + FILE_REASK_TIME);
    assert_eq!(asked_by_tcp(&full_ask), vec![peer(1)]);
    assert_eq!(spawned(&full_ask), vec![peer(1)]);

    let answered = answers_no_file(&mut state, t0() + FILE_REASK_TIME, peer(1));
    assert!(retired_lacking(&answered, peer(1)), "{answered:?}");
    assert!(
        answered
            .iter()
            .any(|d| matches!(d, Decision::EndWorker { peer: p, .. } if *p == peer(1))),
        "{answered:?}"
    );
    assert!(
        !answered
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::SourceRemoteQueued { .. }))),
        "it keeps no standing: {answered:?}"
    );
    assert_eq!(state.known_sources(), 0);

    let next_period = state.on_tick(t0() + FILE_REASK_TIME * 2);
    assert!(asked_by_tcp(&next_period).is_empty(), "{next_period:?}");
    assert!(spawned(&next_period).is_empty(), "{next_period:?}");
    assert!(
        spawned(&take(&mut state, Channel::Server, plain_sightings(&[peer(1)])).decisions)
            .is_empty(),
        "a sighting of it is refused one turn on"
    );
    let _ = state.on_tick(t0() + FILE_REASK_TIME * 3);
    assert_eq!(
        spawned(&take(&mut state, Channel::Server, plain_sightings(&[peer(1)])).decisions),
        vec![peer(1)],
        "two turns on it is a source again"
    );
}

/// A called-back Low ID that says it lacks the file does not go back to its
/// Low-ID lane to be called back again, and a later sighting of its id on the
/// server that assigned it is refused.
#[test]
fn a_called_back_source_that_lacks_the_file_is_not_called_back_again() {
    let server = source_server(9);
    let key = CallbackKey {
        server: Some(server),
        low_id: low(7),
        kad_port: None,
    };
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let _ = via_global(&mut state, server, vec![PeerSource::new(low(7), 4662)]);
    let _ = state.on_callback_connected(t0(), key, peer(9));

    let answered = answers_no_file(&mut state, t0(), peer(9));
    assert!(retired_lacking(&answered, peer(9)), "{answered:?}");
    assert!(
        !answered.iter().any(|d| matches!(
            d,
            Decision::RequestGlobalCallback { .. } | Decision::RequestCallback { .. }
        )),
        "it is not called back again: {answered:?}"
    );

    let again = via_global(&mut state, server, vec![PeerSource::new(low(7), 4662)]);
    assert!(
        !again.iter().any(
            |d| matches!(d, Decision::RequestGlobalCallback { low_id, .. } if *low_id == low(7))
        ),
        "a sighting of its id is refused: {again:?}"
    );
}
