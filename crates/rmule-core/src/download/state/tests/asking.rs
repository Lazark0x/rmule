//! Asking and transferring (ADR-0116): a rank without a grant hangs the worker
//! up and its record keeps its place, every road a fill opens waits for the
//! node's **Connection Budget**, and a grant transfers whatever the budget
//! reads.

use std::sync::Arc;

use super::*;
use crate::PeerConnections;
use crate::download::connection_budget::{
    BudgetSeat, ConnectionBudget, DIAL_WINDOW, SharedConnectionBudget,
};

/// A budget of `dials_per_window` roads per window and a Ceiling of
/// `max_connections`.
fn budget(dials_per_window: u32, max_connections: usize) -> SharedConnectionBudget {
    ConnectionBudget::shared(PeerConnections {
        dials_per_window,
        max_connections,
    })
}

/// A five-part file whose part hash set is held: four workers each take a
/// part of their own.
const FIVE_PARTS: u64 = 4 * rmule_primitives::ED2K_PART_SIZE + 1;

/// Download `id` seated in `budget`, its `pool` sighted from a server, not
/// yet started.
fn seated(budget: &SharedConnectionBudget, id: u64, pool: &[PeerEndpoint]) -> DownloadState {
    let mut state = DownloadState::new(
        DownloadId::from_u64(id),
        set_held_content(FIVE_PARTS, Vec::new()),
        no_facts(),
        QUIET_POSTURE,
        CALLBACK_TIMEOUT,
        BudgetSeat::new(Arc::clone(budget), DownloadId::from_u64(id)),
    );
    take(&mut state, Channel::Server, plain_sightings(pool));
    state
}

/// `peer`'s slot ask, answered with `rank`: the decisions of the answer.
fn ranked(state: &mut DownloadState, peer: PeerEndpoint, rank: u16) -> Vec<Decision> {
    let _ = probed(state, t0(), peer);
    state.on_worker_event(t0(), peer, PeerWorkerEvent::Queued { rank })
}

/// A rank without a grant is the ask's answer: the worker hangs up silently,
/// its record waits queued at that rank, and the connection it held goes to
/// the next source at once (ADR-0116 invariant 3).
#[test]
fn a_rank_without_a_grant_hangs_the_worker_up_and_keeps_its_place() {
    let shared = budget(u32::MAX, 1);
    let mut state = seated(&shared, 1, &[peer(1), peer(2)]);
    assert_eq!(
        spawned(&state.start(t0())),
        vec![peer(1)],
        "the Ceiling holds one"
    );

    let answered = ranked(&mut state, peer(1), 5);
    assert!(
        answered.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::Queued,
                ..
            }) if *p == peer(1)
        )),
        "{answered:?}"
    );
    assert!(
        answered.iter().any(|d| matches!(
            d,
            Decision::EndWorker { peer: p, cancel: false } if *p == peer(1)
        )),
        "{answered:?}"
    );
    assert!(
        answered.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceRemoteQueued { peer: p, rank: Some(5), .. })
                if *p == peer(1)
        )),
        "{answered:?}"
    );
    assert_eq!(
        spawned(&answered),
        vec![peer(2)],
        "a queued source holds no connection"
    );
    assert_eq!(state.remote_queued().collect::<Vec<_>>(), vec![peer(1)]);
}

/// A road waits for the Dial Window: the window's roads open at once, and the
/// next opens when the window turns, which the brain wakes for (ADR-0116
/// invariant 2).
#[test]
fn a_new_dial_waits_for_the_dial_window() {
    let shared = budget(2, 500);
    let mut state = seated(&shared, 1, &[peer(1), peer(2), peer(3)]);
    assert_eq!(spawned(&state.start(t0())), vec![peer(1), peer(2)]);
    assert_eq!(state.next_wake(), Some(t0() + DIAL_WINDOW));
    assert!(spawned(&state.on_tick(t0() + DIAL_WINDOW - Duration::from_millis(1))).is_empty());
    assert_eq!(spawned(&state.on_tick(t0() + DIAL_WINDOW)), vec![peer(3)]);
}

/// Every grant transfers: with the Dial Window spent and a source still
/// pooled, a queued source's uploader grants by dial-back and its worker
/// opens, is handed a part, and transfers beside three others (ADR-0116
/// invariant 1).
#[test]
fn a_fourth_grant_transfers_while_the_dial_window_is_spent() {
    let shared = budget(4, 500);
    let pool = [peer(1), peer(2), peer(3), peer(4), peer(5)];
    let mut state = seated(&shared, 1, &pool);
    let opened = spawned(&state.start(t0()));
    assert_eq!(opened, vec![peer(1), peer(2), peer(3), peer(4)]);
    for granted in [peer(1), peer(2), peer(3)] {
        let _ = probed(&mut state, t0(), granted);
        let _ = state.on_worker_event(t0(), granted, PeerWorkerEvent::SlotGranted);
    }
    let hung_up = ranked(&mut state, peer(4), 2);
    assert!(
        spawned(&hung_up).is_empty(),
        "the window is spent: {hung_up:?}"
    );

    let offered = state.on_slot_offered(t0(), peer(4));
    assert_eq!(spawned(&offered), vec![peer(4)], "a grant asks no budget");
    let _ = probed(&mut state, t0(), peer(4));
    let granted = state.on_worker_event(t0(), peer(4), PeerWorkerEvent::SlotGranted);
    assert!(
        granted.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PartAssigned { peer: p, .. }) if *p == peer(4)
        )),
        "the fourth grant is handed a part: {granted:?}"
    );
    assert!(
        spawned(&granted).is_empty(),
        "peer 5 still waits for the window"
    );
}

/// The Ceiling is the node's: a second download is refused while the first
/// holds it all, looks again when the window turns, and fills once the
/// first's republished count leaves room (ADR-0116 invariant 5).
#[test]
fn the_ceiling_is_shared_by_every_download() {
    let shared = budget(u32::MAX, 2);
    let mut first = seated(&shared, 1, &[peer(1), peer(2)]);
    let mut second = seated(&shared, 2, &[peer(3)]);
    assert_eq!(spawned(&first.start(t0())), vec![peer(1), peer(2)]);
    first.hold_connections();
    assert!(spawned(&second.start(t0())).is_empty());
    assert_eq!(second.next_wake(), Some(t0() + DIAL_WINDOW));

    let _ = first.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    first.hold_connections();
    assert_eq!(spawned(&second.on_tick(t0() + DIAL_WINDOW)), vec![peer(3)]);
}
