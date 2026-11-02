//! Who holds a peer's standing, on which clock the next holder asks, and
//! the peer's **Ask Score** (ADR-0107 invariants 12, 14 and 17).

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

/// `run`'s one record now stands at `place`.
fn hold(run: &StandingSeat, place: Option<Place>) {
    run.publish(vec![PlaceChange {
        id: PlaceId(0),
        place,
    }]);
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
    hold(&run, Some(place(Some(t0), false)));
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
    hold(&run, Some(place(Some(later), true)));
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
    hold(&run, Some(place(Some(t0), true)));
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
    hold(&run, Some(place(Some(t0), true)));
    hold(&run, None);
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
    hold(&first, Some(place(Some(t0), true)));
    hold(&second, Some(place(Some(later), true)));
    assert_eq!(
        first.role(&place(Some(t0), true)),
        Role::Waits {
            asked_at: Some(later)
        }
    );
    assert_eq!(second.role(&place(Some(later), true)), Role::Holds);

    hold(&second, Some(place(Some(later), false)));
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
    hold(&lane, Some(pooled()));

    hold(&holder, Some(place(Some(t0), true)));
    assert_eq!(holder.role(&place(Some(t0), true)), Role::Holds);
    assert!(matches!(lane.role(&pooled()), Role::Waits { .. }));

    hold(&holder, Some(place(Some(t0), false)));
    assert!(matches!(
        holder.role(&place(Some(t0), false)),
        Role::Waits { .. }
    ));
    assert_eq!(lane.role(&pooled()), Role::Takes { asked_at: t0 });

    hold(&holder, Some(pooled()));
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
    hold(&holder, Some(place(Some(t0), true)));
    hold(&waiter, Some(place(None, true)));
    holder.asked(&[peer()], full_ask);
    drop(holder);
    assert_eq!(
        waiter.role(&place(None, true)),
        Role::Inherits { asked_at: full_ask }
    );
}

/// `count` fast asks at `from`, one second apart, after a first ask a second
/// before; the last ask's instant.
fn fast_asks(run: &StandingSeat, from: Instant, count: u32) -> Instant {
    let names = [peer()];
    run.asked(&names, from - Duration::from_secs(1));
    for n in 0..count {
        run.asked(&names, from + Duration::from_secs(u64::from(n)));
    }
    from + Duration::from_secs(u64::from(count))
}

/// The score is the peer's, not the name's: a name learned after the asks
/// reads what the first name heard, and a polite ask takes one off both.
/// Stock's `m_Aggressiveness` sits on the one client (`UploadClient.cpp:806-822`).
#[test]
fn a_name_learned_late_reads_the_peers_score() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let run = seat(&standings, 1);
    let last = fast_asks(&run, t0, 3);

    let hash = AskName::User(rmule_primitives::UserHash::from_bytes([7; 16]));
    let both = [peer(), hash];
    let polite = last + MIN_REQUEST_TIME;
    run.asked(&both, polite);

    let locked = standings.lock();
    assert_eq!(locked.score(&[hash]), 8);
    assert_eq!(locked.score(&[peer()]), 8);
}

/// A recovery ask stamps the clock and takes nothing off, since 2.3.3 never
/// scored it and our count must not read lower than the uploader's.
#[test]
fn a_recovery_ask_takes_nothing_off_the_score() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let run = seat(&standings, 1);
    let last = fast_asks(&run, t0, 3);

    let recovery = last + MIN_REQUEST_TIME;
    run.asked_recovery(&[peer()], recovery);
    assert_eq!(standings.lock().score(&[peer()]), 9);
    assert_eq!(run.last_ask(&place(None, true)), Some(recovery));
}

/// The TCP fallback to an unanswered ping is the one ask the plain clock lets
/// through inside 590 s. It scores like any other if the ping arrived, so a
/// score with no room holds it to the ping's stamp, and no ask of ours goes
/// past 9.
#[test]
fn a_fallback_with_no_room_in_the_score_waits_for_the_pings_clock() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let run = seat(&standings, 1);
    let fallback = Place {
        after_ping: true,
        ..place(None, true)
    };

    let last = fast_asks(&run, t0, 2);
    let ping = last + MIN_REQUEST_TIME;
    run.pinged(&[peer()], ping);
    assert!(
        !run.clock_holds(&fallback, ping + Duration::from_secs(20)),
        "5 and 3 leave room"
    );

    run.asked(&[peer()], ping + Duration::from_secs(20));
    let ping = ping + Duration::from_secs(20) + MIN_REQUEST_TIME;
    run.pinged(&[peer()], ping);
    assert!(
        run.clock_holds(&fallback, ping + Duration::from_secs(20)),
        "7 and 3 is past 9"
    );
    assert!(!run.clock_holds(&fallback, ping + MIN_REQUEST_TIME));
}

/// A stamp with a score outlives the two periods a bare one gets, since the
/// uploader holds its client until its queue purge an hour on
/// (`UploadQueue.cpp:86`); past that the score goes with the client.
#[test]
fn a_scored_stamp_stays_until_the_uploaders_purge() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let run = seat(&standings, 1);
    let last = fast_asks(&run, t0, 1);

    let elsewhere = [AskName::Endpoint(PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::new(10, 0, 0, 2),
        4662,
    )))];
    run.asked(&elsewhere, last + STAMP_KEPT + Duration::from_secs(1));
    hold(&run, None);
    assert_eq!(standings.lock().score(&[peer()]), 3);

    run.asked(&elsewhere, last + SCORE_KEPT + Duration::from_secs(1));
    hold(&run, None);
    assert_eq!(standings.lock().score(&[peer()]), 0);
}

/// A stamp's keeping runs from the moment nothing carries its name, read from
/// its last ask: a place that stopped carrying the name lets it age at once.
#[test]
fn a_stamp_ages_only_once_no_place_carries_its_name() {
    let t0 = Instant::now();
    let standings = QueueStandings::shared();
    let run = seat(&standings, 1);
    let other = seat(&standings, 2);
    let held = AskName::Endpoint(PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::new(10, 0, 0, 3),
        4662,
    )));
    hold(&run, Some(place(Some(t0), true)));
    let past_keeping = t0 + STAMP_KEPT + Duration::from_secs(1);
    other.asked(&[held], past_keeping);
    assert!(
        standings.lock().stamps.contains_key(&peer()),
        "a carried stamp stays"
    );

    hold(
        &run,
        Some(Place {
            names: vec![held],
            ..place(Some(t0), true)
        }),
    );
    assert!(
        !standings.lock().stamps.contains_key(&peer()),
        "the place moved off the name, and the stamp was past its keeping"
    );
}
