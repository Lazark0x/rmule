//! Spent names on stock's dead-source windows (`DeadSourceList.cpp:34-35`,
//! ADR-0090): 30 minutes for a High ID, 45 for a Low ID, and the same for a
//! peer that hung up before it answered the file request.

use std::sync::Arc;

use super::*;
use crate::download::spent_names::{SharedSpentNames, SpentNames, SpentSeat};

const MINUTE: Duration = Duration::from_secs(60);

fn one_source() -> DownloadState {
    let mut state = file_hash_only_state(vec![peer(1)], 1);
    let _ = state.start(t0());
    state
}

fn sighted_at(state: &mut DownloadState, now: Instant) -> Vec<PeerEndpoint> {
    let taken = take_at(state, now, Channel::Server, plain_sightings(&[peer(1)]));
    spawned(&taken.decisions)
}

/// A dial that failed: dead for 30 minutes (`BaseClient.cpp:1340-1346`), no
/// more and no less.
#[test]
fn a_failed_dial_is_spent_for_stocks_thirty_minutes() {
    let mut state = one_source();
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    let window = MINUTE * 30;
    assert!(sighted_at(&mut state, t0() + window - MINUTE).is_empty());
    assert_eq!(sighted_at(&mut state, t0() + window), vec![peer(1)]);
}

/// A peer that answers the hello and closes before its file answer is what a
/// stock peer banning us does at its 40 s close: dead and removed, 30 minutes,
/// not dialed again at the next sighting (`BaseClient.cpp:1288-1293`).
#[test]
fn a_peer_closing_after_the_hello_is_spent_for_stocks_thirty_minutes() {
    let mut state = one_source();
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert_eq!(state.known_sources(), 0);
    let window = MINUTE * 30;
    assert!(sighted_at(&mut state, t0() + window - MINUTE).is_empty());
    assert_eq!(sighted_at(&mut state, t0() + window), vec![peer(1)]);
}

/// A queued peer asked again over TCP is `DS_CONNECTED` again
/// (`BaseClient.cpp:1700-1704`), so one that closes after the hello is dead as
/// any other: its standing goes with it and the period brings no dial.
#[test]
fn a_queued_peer_closing_after_the_hello_is_spent() {
    let mut state = started(
        &[peer(1)],
        SourcingPosture {
            client_udp: false,
            ..live_posture()
        },
    );
    queue_and_hang_up(&mut state, peer(1), false, 5);
    let asked = t0() + FILE_REASK_TIME;
    assert_eq!(spawned(&state.on_tick(asked)), vec![peer(1)]);
    let _ = state.on_worker_event(asked, peer(1), PeerWorkerEvent::Connected);
    let _ = state.on_worker_event(asked, peer(1), PeerWorkerEvent::Disconnected);

    assert_eq!(state.known_sources(), 0);
    let next = state.on_tick(asked + FILE_REASK_TIME);
    assert!(spawned(&next).is_empty(), "{next:?}");
    assert!(sighted_at(&mut state, asked + MINUTE * 29).is_empty());
    assert_eq!(sighted_at(&mut state, asked + MINUTE * 30), vec![peer(1)]);
}

/// A rank moves no download state (`DownloadClient.cpp:1213-1218`): a peer
/// that ranks us and closes before its file answer is still `DS_CONNECTED`.
#[test]
fn a_peer_closing_with_a_rank_and_no_file_answer_is_spent() {
    let mut state = one_source();
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    let rank = PeerWorkerEvent::Queued { rank: 5 };
    let _ = state.on_worker_event(t0(), peer(1), rank);
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert_eq!(state.known_sources(), 0);
    assert!(sighted_at(&mut state, t0() + MINUTE * 29).is_empty());
}

/// A worker that took a grant left the ask, and a close takes it back to the
/// queue as `DS_DOWNLOADING` (`BaseClient.cpp:1283-1284`).
#[test]
fn a_granted_peer_closing_before_its_file_answer_is_not_spent() {
    let mut state = one_source();
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotGranted);
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert_eq!(state.known_sources(), 1);
}

/// A peer that answered its file request and then closed is alive and owes
/// nothing: it never spends.
#[test]
fn a_peer_closing_after_its_file_answer_spends_nothing() {
    let mut state = one_source();
    let _ = probed(&mut state, t0(), peer(1));
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    let after_the_clock = t0() + MIN_REQUEST_TIME;
    assert_eq!(sighted_at(&mut state, after_the_clock), vec![peer(1)]);
}

/// A callback nobody answered: dead for 45 minutes, a Low ID's window
/// (`DeadSourceList.cpp:35`), so the next server answer opens no road.
#[test]
fn a_lapsed_callback_is_spent_for_stocks_forty_five_minutes() {
    let candidate = || low_candidate(7);
    let mut state = callback_state(Vec::new(), vec![candidate(), low_candidate(8)], true, 1);
    let _ = state.start(t0());
    let called_back = |decisions: &[Decision]| {
        decisions
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { low_id, .. } if *low_id == low(7)))
    };
    let _ = until_road_ends(&mut state, connected_key(low(7)));
    let _ = state.on_tick(t0() + CALLBACK_TIMEOUT * 3);

    let inside = t0() + MINUTE * 44;
    let taken = take_at(&mut state, inside, Channel::Server, [candidate()]);
    assert!(!called_back(&taken.decisions), "{:?}", taken.decisions);
    assert_eq!(taken.tally.fresh, 0);
}

/// A run of file `file` reading and writing `names`.
fn run_of(names: &SharedSpentNames, file: u8) -> DownloadState {
    pooled_state(file_hash_only_content(ONE_PART), &[], QUIET_POSTURE, 1).with_spent(
        SpentSeat::new(Arc::clone(names), FileHash::from_bytes([file; 16])),
    )
}

/// A Pause, a Cancel and a re-add end the run and keep its spent names, and a
/// dead peer is dead for every file (`ClientList.cpp:87`).
#[test]
fn a_new_run_of_any_file_keeps_a_dead_peer_spent() {
    let names = SpentNames::shared();
    let mut stopped = run_of(&names, 1);
    let _ = stopped.start(t0());
    assert_eq!(sighted_at(&mut stopped, t0()), vec![peer(1)]);
    let _ = stopped.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    drop(stopped);

    for file in [1, 2] {
        let mut run = run_of(&names, file);
        let _ = run.start(t0());
        assert!(
            sighted_at(&mut run, t0() + MINUTE).is_empty(),
            "file {file}"
        );
    }
    let mut run = run_of(&names, 1);
    let _ = run.start(t0());
    assert_eq!(sighted_at(&mut run, t0() + MINUTE * 30), vec![peer(1)]);
}

/// A peer that lacks one file is spent for that file alone, 45 minutes
/// (`ClientTCPSocket.cpp:549`), across a run's end.
#[test]
fn a_peer_lacking_the_file_is_spent_for_that_file_alone() {
    let names = SpentNames::shared();
    let mut stopped = run_of(&names, 1);
    let _ = stopped.start(t0());
    assert_eq!(sighted_at(&mut stopped, t0()), vec![peer(1)]);
    let lacks = PeerWorkerEvent::PartsAdvertised {
        parts: None,
        complete: false,
    };
    let _ = stopped.on_worker_event(t0(), peer(1), PeerWorkerEvent::Connected);
    let _ = stopped.on_worker_event(t0(), peer(1), lacks);
    drop(stopped);

    let mut same = run_of(&names, 1);
    let _ = same.start(t0());
    assert!(sighted_at(&mut same, t0() + MINUTE * 44).is_empty());
    let mut other = run_of(&names, 2);
    let _ = other.start(t0());
    assert_eq!(sighted_at(&mut other, t0() + MINUTE), vec![peer(1)]);
}
