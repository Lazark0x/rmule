//! Who holds a peer's standing and on which clock the next holder asks
//! (ADR-0107 invariants 12 and 14).

use std::net::Ipv4Addr;

use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};

use crate::download::source_book::FILE_REASK_TIME;

use super::*;

fn peer() -> AskName {
    AskName::Endpoint(PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::new(10, 0, 0, 1),
        4662,
    )))
}

fn place(asked: Option<Instant>, needs_parts: bool) -> Place {
    Place {
        names: vec![peer()],
        asked,
        needs_parts,
        pooled: false,
        after_ping: false,
    }
}

/// A record still in a lane, which has asked nothing.
fn pooled() -> Place {
    Place {
        pooled: true,
        ..place(None, true)
    }
}

fn seat(standings: &SharedQueueStandings, id: u64) -> StandingSeat {
    StandingSeat::new(
        Arc::clone(standings),
        DownloadId::from_u64(id),
        FileHash::from_bytes([id as u8; 16]),
    )
}

/// A left place goes the moment the file's next run leaves another: a peer
/// that came to hold parts is not held back by what it once lacked.
#[test]
fn a_later_run_replaces_what_the_file_left() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let run = seat(&standings, 1);
    run.publish(vec![place(Some(t0), false)]);
    drop(run);
    let run = seat(&standings, 1);
    assert_eq!(
        run.role(&pooled()),
        Role::Returns {
            asked_at: t0,
            no_needed_parts: true
        }
    );
    let later = t0 + Duration::from_secs(1);
    run.publish(vec![place(Some(later), true)]);
    drop(run);
    assert_eq!(
        seat(&standings, 1).role(&pooled()),
        Role::Returns {
            asked_at: later,
            no_needed_parts: false
        }
    );
}

/// A file left under one id returns under a new one: a re-add is the same
/// file (ADR-0107 invariant 15).
#[test]
fn a_re_add_under_a_new_id_returns_to_the_files_place() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let file = FileHash::from_bytes([7; 16]);
    let seat_of = |id| StandingSeat::new(Arc::clone(&standings), DownloadId::from_u64(id), file);
    let run = seat_of(1);
    run.publish(vec![place(Some(t0), true)]);
    drop(run);
    assert_eq!(
        seat_of(2).role(&pooled()),
        Role::Returns {
            asked_at: t0,
            no_needed_parts: false
        }
    );
}

/// A place with no ask of its own is no place left: a run's waiter or its
/// slot holder, whose place went at the grant, leaves nothing.
#[test]
fn a_run_with_no_asked_place_leaves_only_the_clock() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let run = seat(&standings, 1);
    run.publish(vec![place(Some(t0), true)]);
    run.publish(Vec::new());
    drop(run);
    let resumed = seat(&standings, 1);
    assert_eq!(resumed.role(&pooled()), Role::Holds);
    let inside = t0 + MIN_REQUEST_TIME - Duration::from_secs(1);
    assert_eq!(
        resumed.fill_gate(&pooled(), inside, FILE_REASK_TIME),
        FillGate::Parks(Role::Spaced { asked_at: Some(t0) })
    );
    assert_eq!(
        resumed.fill_gate(&pooled(), t0 + MIN_REQUEST_TIME, FILE_REASK_TIME),
        FillGate::Open
    );
}

/// The peer's entry names the file the last slot ask asked for, so that
/// download holds and the earlier one waits; a holder holding no part we need
/// yields, and the download that takes over pings nothing — the peer still
/// holds the other file — and asks by TCP on the peer's clock.
#[test]
fn the_last_slot_ask_holds_and_a_holder_needing_nothing_yields() {
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(10);
    let standings = QueueStandings::shared();
    let (first, second) = (seat(&standings, 1), seat(&standings, 2));
    first.publish(vec![place(Some(t0), true)]);
    second.publish(vec![place(Some(later), true)]);
    assert_eq!(
        first.role(&place(Some(t0), true)),
        Role::Waits {
            asked_at: Some(later)
        }
    );
    assert_eq!(second.role(&place(Some(later), true)), Role::Holds);

    second.publish(vec![place(Some(later), false)]);
    assert_eq!(
        first.role(&place(Some(t0), true)),
        Role::Takes { asked_at: later }
    );
    assert!(matches!(
        second.role(&place(Some(later), false)),
        Role::Waits { .. }
    ));
}

/// A Pooled Place takes a standing only from a place needing nothing: against
/// a place that may need a part, or another Pooled Place, it changes nothing,
/// so two downloads that have not asked still meet on the Peer Link.
#[test]
fn a_pooled_place_outranks_only_a_place_needing_nothing() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let (holder, lane) = (seat(&standings, 1), seat(&standings, 2));
    lane.publish(vec![pooled()]);

    holder.publish(vec![place(Some(t0), true)]);
    assert_eq!(holder.role(&place(Some(t0), true)), Role::Holds);
    assert!(matches!(lane.role(&pooled()), Role::Waits { .. }));

    holder.publish(vec![place(Some(t0), false)]);
    assert!(matches!(
        holder.role(&place(Some(t0), false)),
        Role::Waits { .. }
    ));
    assert_eq!(lane.role(&pooled()), Role::Takes { asked_at: t0 });

    holder.publish(vec![pooled()]);
    assert!(lane.role(&pooled()).asks());
    assert!(holder.role(&pooled()).asks());
}

/// The holder's last ask outlives its place: a waiter left alone when the
/// holder's run ends asks a period after that ask, not after its own.
#[test]
fn the_peer_clock_outlives_the_holder_that_stamped_it() {
    let t0 = Instant::now();
    let full_ask = t0 + Duration::from_secs(1_300);
    let standings = QueueStandings::shared();
    let holder = seat(&standings, 1);
    let waiter = seat(&standings, 2);
    holder.publish(vec![place(Some(t0), true)]);
    waiter.publish(vec![place(None, true)]);
    holder.asked(&[peer()], full_ask);
    drop(holder);
    assert_eq!(
        waiter.role(&place(None, true)),
        Role::Inherits { asked_at: full_ask }
    );
}
