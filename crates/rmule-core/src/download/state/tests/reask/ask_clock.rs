//! One ask clock per peer (ADR-0107 invariants 14-16): nothing is asked inside
//! `MIN_REQUESTTIME` of the peer's last ask, whatever road, download, run or
//! stop, and a run's end forgets neither the clock nor the place at the peer.

use std::sync::Arc;

use super::*;
use crate::download::queue_standings::{QueueStandings, SharedQueueStandings, StandingSeat};
use crate::service::LinkTurn;

const SAME_FILE: [u8; 16] = [0x11; 16];

/// A run with id `id` of one file, seated in `standings`, over `peer(1)`.
fn run(standings: &SharedQueueStandings, id: u64) -> DownloadState {
    of_file(standings, id, SAME_FILE)
}

fn of_file(standings: &SharedQueueStandings, id: u64, file: [u8; 16]) -> DownloadState {
    let download = DownloadId::from_u64(id);
    let mut state = DownloadState::new(
        download,
        file_hash_only_content(ONE_PART),
        no_facts(),
        tcp_only_posture(),
        CALLBACK_TIMEOUT,
        crate::download::connection_budget::BudgetSeat::ceiling(1),
    )
    .with_standings(StandingSeat::new(
        Arc::clone(standings),
        download,
        FileHash::from_bytes(file),
    ));
    take(&mut state, Channel::Server, plain_sightings(&[peer(1)]));
    state
}

/// A run asked the peer at `asked`, is ranked and hangs up, and stops.
fn left_queued(standings: &SharedQueueStandings, id: u64, asked: Instant) {
    let mut stopped = run(standings, id);
    let _ = stopped.start(asked);
    queue_and_hang_up_at(&mut stopped, peer(1), false, 3, asked);
    stopped.hold_standings();
}

/// A run asked the peer at `asked`, was granted, and stops holding the slot.
fn left_holding_a_slot(standings: &SharedQueueStandings, id: u64, asked: Instant) {
    let mut stopped = run(standings, id);
    let _ = stopped.start(asked);
    let _ = connect(&mut stopped, asked, peer(1));
    stopped.hold_standings();
}

fn asked_slot(decisions: &[Decision]) -> bool {
    decisions.iter().any(|d| {
        matches!(
            d,
            Decision::Send {
                command: PeerWorkerCommand::AskSlot,
                ..
            }
        )
    })
}

/// A Resume finds the sources stock's Pause keeps: queued, on their clock,
/// dialed by nobody until a period past the ask (stock 2.3.3
/// `PartFile.cpp:2429-2443`, `:1476-1477`). Four quick cycles would score 12
/// and ban us at every uploader (`UploadClient.cpp:795-825`).
#[test]
fn a_resume_stands_where_the_pause_left_it_and_dials_nothing() {
    let standings = QueueStandings::shared();
    let asked = t0();
    left_queued(&standings, 1, asked);

    let resumed_at = asked + Duration::from_secs(4);
    let mut resumed = run(&standings, 1);
    let started = resumed.start(resumed_at);
    resumed.hold_standings();
    assert!(spawned(&started).is_empty(), "{started:?}");
    assert_eq!(resumed.source_activity().queued, 1);

    assert!(
        asked_by_tcp(&resumed.on_tick(asked + FILE_REASK_TIME - Duration::from_secs(1))).is_empty()
    );
    assert_eq!(
        asked_by_tcp(&resumed.on_tick(asked + FILE_REASK_TIME)),
        vec![peer(1)]
    );
}

/// A re-add of one hash is a new id and the same file: it keeps what a Resume
/// keeps, where stock forgets and pays +3 (`BaseClient.cpp:2002`).
#[test]
fn a_re_add_under_a_new_id_keeps_the_clock_and_the_place() {
    let standings = QueueStandings::shared();
    let asked = t0();
    left_queued(&standings, 1, asked);

    let mut readded = run(&standings, 2);
    let started = readded.start(asked + Duration::from_secs(5));
    readded.hold_standings();
    assert!(spawned(&started).is_empty(), "{started:?}");
    assert_eq!(readded.source_activity().queued, 1);
    assert_eq!(readded.next_wake(), Some(asked + FILE_REASK_TIME));
}

/// A slot holder we told `OP_CANCELTRANSFER` left the uploader's lists
/// (`UploadQueue.cpp:527-542`): it is not queued, and it is asked at the first
/// instant nothing scores, not a period on. Stock asks it at once and pays
/// (`PartFile.cpp:2441`).
#[test]
fn a_cancelled_slot_holder_is_not_queued_and_is_asked_once_the_clock_lets_it() {
    let standings = QueueStandings::shared();
    let asked = t0();
    left_holding_a_slot(&standings, 1, asked);

    let mut resumed = run(&standings, 2);
    let started = resumed.start(asked + Duration::from_secs(5));
    resumed.hold_standings();
    assert!(spawned(&started).is_empty(), "{started:?}");
    let activity = resumed.source_activity();
    assert_eq!((activity.queued, activity.asking), (0, 1));
    assert_eq!(resumed.next_wake(), Some(asked + MIN_REQUEST_TIME));

    let due = resumed.on_tick(asked + MIN_REQUEST_TIME);
    assert_eq!(spawned(&due), vec![peer(1)], "{due:?}");
}

/// A resume past the score asks a slot holder at once, as stock's cleared
/// clock does.
#[test]
fn a_slot_holder_resumed_past_the_clock_is_dialed_at_once() {
    let standings = QueueStandings::shared();
    let asked = t0();
    left_holding_a_slot(&standings, 1, asked);
    let mut resumed = run(&standings, 1);
    assert_eq!(
        spawned(&resumed.start(asked + MIN_REQUEST_TIME)),
        vec![peer(1)]
    );
}

/// A worker that reached the peer by its own road, with the peer's clock
/// running, sends no slot ask whatever room the Ask Score has: only a Link
/// Rider has a link to lose (invariant 17).
#[test]
fn a_dialed_worker_inside_the_clock_sends_no_slot_ask_and_waits_for_the_reask() {
    let standings = QueueStandings::shared();
    let mut holder = of_file(&standings, 1, [1; 16]);
    let _ = holder.start(t0());
    let mut rider = of_file(&standings, 2, [2; 16]);
    let _ = rider.start(t0());
    let _ = connect(&mut holder, t0(), peer(1));
    holder.hold_standings();

    let turn = t0() + Duration::from_secs(60);
    let probed = probed(&mut rider, turn, peer(1));
    assert!(!asked_slot(&probed), "{probed:?}");
    assert!(
        probed.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                reason: PeerRetirementReason::OnPeersClock,
                ..
            })
        )),
        "{probed:?}"
    );
    assert!(spawned(&probed).is_empty(), "{probed:?}");
}

/// Run `id` of a file of its own, waiting on the peer's standing, is called
/// to the link and seated on it at `turn`: what its probe's answer does.
fn rider_takes_its_turn(
    standings: &SharedQueueStandings,
    id: u8,
    turn: Instant,
) -> (DownloadState, Vec<Decision>) {
    let mut rider = of_file(standings, u64::from(id), [id; 16]);
    let started = rider.start(turn);
    assert!(spawned(&started).is_empty(), "{started:?}");
    let called = rider.on_link_called(turn, peer(1));
    assert_eq!(spawned(&called), vec![peer(1)]);
    let _ = rider.on_worker_event(
        turn,
        peer(1),
        PeerWorkerEvent::LinkShared {
            turn: LinkTurn::Riding,
        },
    );
    let answered = probed(&mut rider, turn, peer(1));
    (rider, answered)
}

/// A download holding the peer's slot, its grant on the link.
fn holder(standings: &SharedQueueStandings) -> DownloadState {
    let mut holder = of_file(standings, 1, [1; 16]);
    let _ = holder.start(t0());
    let _ = connect(&mut holder, t0(), peer(1));
    holder.hold_standings();
    holder
}

/// The source gates read aMule's `GetSourceCount`, `m_SrcList` alone: a record
/// waiting on another download's standing is its A4AF list.
#[test]
fn a_record_waiting_on_another_downloads_standing_is_outside_the_gates() {
    let standings = QueueStandings::shared();
    let mut holding = of_file(&standings, 1, [1; 16]);
    let _ = holding.start(t0());
    queue_and_hang_up(&mut holding, peer(1), false, 3);
    holding.hold_standings();
    let mut waiter = of_file(&standings, 2, [2; 16]);
    let started = waiter.start(t0());
    assert!(spawned(&started).is_empty(), "{started:?}");
    assert_eq!(waiter.known_sources(), 1);
    assert_eq!(waiter.listed_sources(), 0);
}

/// Two downloads of one peer ride one link: the second's turn comes inside
/// the clock, and its ask leaves on that link, 3 points the score has room
/// for, where a refusal would cost a second link a reask away. Stock's own
/// swap waits (`DownloadClient.cpp:1498`); the score does not ask it to
/// (`UploadClient.cpp:806-818`).
#[test]
fn a_rider_with_room_in_the_score_asks_on_the_link_inside_the_clock() {
    let standings = QueueStandings::shared();
    let _holder = holder(&standings);

    let turn = t0() + Duration::from_secs(60);
    let (_, answered) = rider_takes_its_turn(&standings, 2, turn);
    assert!(asked_slot(&answered), "{answered:?}");
    assert!(
        !answered
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::PeerRetired { .. }))),
        "{answered:?}"
    );
}

/// Six small files from one peer: the first ask scores nothing, three fast
/// asks take the score to 9, and the fourth, which would make it 12 and ban us
/// at 10 (`UploadClient.cpp:806-818`), stays home, as does the one behind it.
/// The next ask leaves on the clock, polite, at 590 s past the last, and the
/// 1 it takes off is no room for a fast one.
#[test]
fn six_files_of_one_peer_stop_before_the_fourth_fast_ask_and_resume_on_the_clock() {
    let standings = QueueStandings::shared();
    let _holder = holder(&standings);

    let mut riders = Vec::new();
    let mut last_ask = t0();
    for id in 2..=4 {
        last_ask += Duration::from_secs(5);
        let (rider, answered) = rider_takes_its_turn(&standings, id, last_ask);
        assert!(asked_slot(&answered), "file {id}: {answered:?}");
        riders.push(rider);
    }
    for id in 5..=6 {
        let turn = last_ask + Duration::from_secs(5);
        let (rider, answered) = rider_takes_its_turn(&standings, id, turn);
        assert!(!asked_slot(&answered), "file {id}: {answered:?}");
        assert!(
            answered.iter().any(|d| matches!(
                d,
                Decision::Emit(DownloadEvent::PeerRetired {
                    reason: PeerRetirementReason::OnPeersClock,
                    ..
                })
            )),
            "file {id}: {answered:?}"
        );
        rider.hold_standings();
        riders.push(rider);
    }

    let (_, fast) = rider_takes_its_turn(
        &standings,
        7,
        last_ask + MIN_REQUEST_TIME - Duration::from_secs(1),
    );
    assert!(!asked_slot(&fast), "still on the clock: {fast:?}");

    let polite = last_ask + MIN_REQUEST_TIME;
    let (_, answered) = rider_takes_its_turn(&standings, 8, polite);
    assert!(asked_slot(&answered), "past the clock: {answered:?}");

    let (_, fast) = rider_takes_its_turn(&standings, 9, polite + Duration::from_secs(5));
    assert!(!asked_slot(&fast), "8 and 3 is past 9: {fast:?}");
}

/// A record refused its ride asks by TCP when the clock lets it.
#[test]
fn a_rider_past_the_score_is_asked_on_the_clock() {
    let standings = QueueStandings::shared();
    let _holder = holder(&standings);
    let turn = t0() + Duration::from_secs(5);
    let _keep: Vec<_> = (2..=4)
        .map(|id| rider_takes_its_turn(&standings, id, turn).0)
        .collect();

    let (mut refused, _) = rider_takes_its_turn(&standings, 5, turn);
    refused.hold_standings();
    assert_eq!(
        asked_by_tcp(&refused.on_tick(turn + MIN_REQUEST_TIME - Duration::from_secs(1))),
        Vec::new()
    );
    assert_eq!(
        asked_by_tcp(&refused.on_tick(turn + MIN_REQUEST_TIME)),
        vec![peer(1)]
    );
}

/// The same rider past the score asks, and its ask stamps the peer there and
/// then, so a third download reading the clock a moment later holds back.
#[test]
fn a_slot_ask_stamps_the_peer_as_it_leaves() {
    let standings = QueueStandings::shared();
    let mut first = of_file(&standings, 1, [1; 16]);
    let mut second = of_file(&standings, 2, [2; 16]);
    let _ = first.start(t0());
    let _ = second.start(t0());
    assert!(asked_slot(&probed(&mut first, t0(), peer(1))));
    assert!(!asked_slot(&probed(
        &mut second,
        t0() + Duration::from_secs(1),
        peer(1)
    )));
}

/// A source a link's end hands back when nobody ever asked the peer has no
/// place to stand on: it is not queued, and it is dialed at the next sweep
/// rather than a reask period on.
#[test]
fn a_handed_back_source_nobody_asked_is_dialed_at_the_next_sweep() {
    let standings = QueueStandings::shared();
    let mut state = run(&standings, 1);
    let _ = state.start(t0());
    let cut = t0() + Duration::from_secs(5);
    let _ = state.on_worker_event(cut, peer(1), PeerWorkerEvent::HandedBack);
    state.hold_standings();
    assert_eq!(state.source_activity().queued, 0);
    assert_eq!(state.next_wake(), Some(cut));
    assert_eq!(spawned(&state.on_tick(cut)), vec![peer(1)]);
}

/// A worker of one run that lost its link inside the clock is not dialed
/// again inside it, a same-run re-sighting included.
#[test]
fn a_same_run_re_sighting_inside_the_clock_dials_nothing() {
    let standings = QueueStandings::shared();
    let mut state = run(&standings, 1);
    let _ = state.start(t0());
    let _ = probed(&mut state, t0(), peer(1));
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    let seen = t0() + Duration::from_secs(30);
    let again = take_at(
        &mut state,
        seen,
        Channel::Server,
        plain_sightings(&[peer(1)]),
    );
    assert!(
        spawned(&again.decisions).is_empty(),
        "{:?}",
        again.decisions
    );
}
