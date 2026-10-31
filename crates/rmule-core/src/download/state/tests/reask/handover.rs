//! The **Source Handover** (ADR-0090, "Sources shared between downloads"): a
//! source holding nothing one download needs passes to another download that
//! holds the peer, as aMule swaps a `DS_NONEEDEDPARTS` client to an A4AF file
//! before it lets it go (stock 2.3.3 `PartFile.cpp:1423-1437`). Each brain
//! publishes its places after every step, as the runner does; nothing else
//! passes between them.

use std::sync::Arc;

use super::*;
use crate::download::queue_standings::{QueueStandings, SharedQueueStandings, StandingSeat};
use crate::download::source_book::{NO_NEEDED_PARTS_PURGE_SPACING, SOURCE_PURGE_AT};
use crate::download::state::sightings::SOURCE_LIMIT;
use crate::service::SourcePurgeReason;

/// Download `id` of a three-part file over `pool`, seated in `standings`, its
/// places published, not yet started.
fn seated(standings: &SharedQueueStandings, id: u64, pool: &[PeerEndpoint]) -> DownloadState {
    let download = DownloadId::from_u64(id);
    let mut state = DownloadState::new(
        download,
        file_hash_only_content(THREE_PARTS),
        no_facts(),
        tcp_only_posture(),
        CALLBACK_TIMEOUT,
        crate::download::connection_budget::BudgetSeat::ceiling(1),
    )
    .with_standings(StandingSeat::new(Arc::clone(standings), download));
    take(&mut state, Channel::Server, plain_sightings(pool));
    state.hold_standings();
    state
}

/// The worker at `peer` advertises no part we lack at `at`: its record stands
/// with the no-needed-parts mark, published.
fn holds_nothing(state: &mut DownloadState, peer: PeerEndpoint, at: Instant) {
    let _ = state.on_worker_event(at, peer, PeerWorkerEvent::Connected);
    let identity = reaskable(SOURCE).identity();
    let _ = state.on_worker_event(at, peer, PeerWorkerEvent::Identity(identity));
    let nothing = PeerWorkerEvent::PartsAdvertised {
        parts: Some(PartBitmap::decode(3, &[0]).expect("three parts")),
        complete: false,
    };
    let _ = state.on_worker_event(at, peer, nothing);
    state.hold_standings();
}

fn handed_over(decisions: &[Decision]) -> Vec<PeerEndpoint> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Emit(DownloadEvent::SourceHandedOver { peer, .. }) => Some(*peer),
            _ => None,
        })
        .collect()
}

fn purges(decisions: &[Decision]) -> Vec<SourcePurgeReason> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Emit(DownloadEvent::SourcePurged { reason, .. }) => Some(*reason),
            _ => None,
        })
        .collect()
}

/// A started download whose `peer(1)` holds nothing it needs, standing at
/// `t0`, and another that holds the peer in a lane.
fn giver_and_taker(standings: &SharedQueueStandings) -> (DownloadState, DownloadState) {
    let mut giver = seated(standings, 1, &[peer(1)]);
    let _ = giver.start(t0());
    holds_nothing(&mut giver, peer(1), t0());
    let taker = seated(standings, 2, &[peer(1)]);
    (giver, taker)
}

/// A record still in a lane takes the source: the giver reports the handover
/// once, on the purge clock and below the threshold, and keeps its record,
/// which no longer counts among its sources.
#[test]
fn a_source_needing_nothing_passes_to_a_download_holding_it_in_a_lane() {
    let standings = QueueStandings::shared();
    let (mut giver, _taker) = giver_and_taker(&standings);

    let early = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING - Duration::from_secs(1));
    assert!(handed_over(&early).is_empty(), "{early:?}");

    assert_eq!(
        giver.next_wake(),
        Some(t0() + NO_NEEDED_PARTS_PURGE_SPACING)
    );
    let due = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING);
    assert_eq!(handed_over(&due), [peer(1)]);
    assert!(purges(&due).is_empty(), "{due:?}");
    assert_eq!(giver.known_sources(), 1, "the record stays");
    assert_eq!(giver.sources.counts().known, 0, "as aMule's A4AF entry");
    assert_eq!(
        giver.sources.rank(peer(1)),
        None,
        "the peer's entry moved on"
    );

    let later = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING * 3);
    assert!(handed_over(&later).is_empty(), "{later:?}");
}

/// The taker's fill dials nothing while the peer's last ask stands: it parks
/// the record and asks by TCP a period after that ask, as aMule's swap leaves
/// `DS_NONE` (`PartFile.cpp:1472-1483`); the uploader scores a sooner ask
/// (`UploadClient.cpp:795-825`). The giver asks nothing meanwhile.
#[test]
fn the_taker_asks_by_tcp_on_the_peers_clock_and_the_giver_asks_nothing() {
    let standings = QueueStandings::shared();
    let (mut giver, mut taker) = giver_and_taker(&standings);

    let started = taker.start(t0() + Duration::from_secs(60));
    taker.hold_standings();
    assert!(spawned(&started).is_empty(), "{started:?}");
    assert_eq!(taker.next_wake(), Some(t0() + FILE_REASK_TIME));

    let before = taker.on_tick(t0() + FILE_REASK_TIME - Duration::from_secs(1));
    assert!(spawned(&before).is_empty(), "{before:?}");
    let due = taker.on_tick(t0() + FILE_REASK_TIME);
    assert_eq!(asked_by_tcp(&due), [peer(1)]);
    assert_eq!(spawned(&due), [peer(1)], "its full ask dials");
    taker.hold_standings();
    queue_and_hang_up_at(&mut taker, peer(1), false, 7, t0() + FILE_REASK_TIME);
    taker.hold_standings();

    let giver_due = giver.on_tick(t0() + FILE_REASK_TIME * NO_NEEDED_PARTS_MULTIPLIER);
    assert!(asked_by_tcp(&giver_due).is_empty(), "{giver_due:?}");
}

/// At the threshold a source another download took is not let go, and with
/// nobody to take it the same source is.
#[test]
fn at_the_threshold_only_a_source_nobody_takes_is_let_go() {
    let pool: Vec<PeerEndpoint> = (1..=SOURCE_PURGE_AT + 2)
        .map(|n| peer(u8::try_from(n % 250).expect("fits a test address")))
        .collect();
    for taker_holds_it in [true, false] {
        let standings = QueueStandings::shared();
        let mut giver = seated(&standings, 1, &pool);
        let _ = giver.start(t0());
        holds_nothing(&mut giver, peer(1), t0());
        let taker = taker_holds_it.then(|| seated(&standings, 2, &[peer(1)]));
        let due = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING);
        assert_eq!(!handed_over(&due).is_empty(), taker_holds_it, "{due:?}");
        assert_eq!(
            purges(&due),
            if taker_holds_it {
                vec![]
            } else {
                vec![SourcePurgeReason::NoNeededParts]
            }
        );
        let much_later = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING * 2);
        assert!(purges(&much_later).is_empty(), "{much_later:?}");
        drop(taker);
    }
}

/// A handed-over record leaves room at the Source Limit, as aMule's A4AF list
/// is not `m_SrcList` (`PartFile.h:144`).
#[test]
fn a_handed_over_source_leaves_room_at_the_source_limit() {
    let pool: Vec<PeerEndpoint> = (0..SOURCE_LIMIT)
        .map(|n| {
            let [.., high, low] = n.to_be_bytes();
            PeerEndpoint::V4(Ipv4Endpoint::new(
                std::net::Ipv4Addr::new(45, 55, high, low.max(1)),
                4662 + u16::from(low == 0),
            ))
        })
        .collect();
    let standings = QueueStandings::shared();
    let mut giver = seated(&standings, 1, &pool);
    let _ = giver.start(t0());
    holds_nothing(&mut giver, pool[0], t0());
    let _taker = seated(&standings, 2, &[pool[0]]);
    let _ = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING);

    let taken = take(&mut giver, Channel::Server, plain_sightings(&[peer(1)]));
    assert_eq!(taken.tally.fresh, 1, "{:?}", taken.tally);
}

/// The standing comes back when the taker's run ends: the giver counts the
/// record again and asks on its own doubled clock.
#[test]
fn the_giver_takes_the_source_back_when_the_taker_ends() {
    let standings = QueueStandings::shared();
    let (mut giver, taker) = giver_and_taker(&standings);
    let _ = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING);
    assert_eq!(giver.sources.counts().known, 0);

    drop(taker);
    let due = giver.on_tick(t0() + FILE_REASK_TIME * NO_NEEDED_PARTS_MULTIPLIER);
    assert_eq!(asked_by_tcp(&due), [peer(1)]);
    assert_eq!(giver.sources.counts().known, 1);
}

/// A Low-ID source sighted by both downloads under one key. The taker's fill
/// opens no road inside the peer's clock: the record has no address to stand
/// at, so it holds the road back, and the ask falls due a period after the
/// peer's last ask (`PartFile.cpp:1472-1483`).
#[test]
fn a_taker_a_callback_road_reaches_holds_the_road_on_the_peers_clock() {
    let standings = QueueStandings::shared();
    let sighting = SourceSighting::new(
        rmule_primitives::PeerSource::new(low(7), 4662),
        Some(SOURCE),
        None,
        Informant::Own,
    );
    let mut giver = seated(&standings, 1, &[]);
    take(&mut giver, Channel::Server, vec![sighting]);
    let started = giver.start(t0());
    assert!(asks_for_callback(&started), "{started:?}");
    let key = connected_key(low(7));
    let at = peer(1);
    let landing = giver.on_callback_connected(t0(), key, at);
    assert!(landing.worker_slot.is_some());
    holds_nothing(&mut giver, at, t0());

    let mut taker = seated(&standings, 2, &[]);
    take(&mut taker, Channel::Server, vec![sighting]);
    taker.hold_standings();
    let started = taker.start(t0() + Duration::from_secs(60));
    assert!(!asks_for_callback(&started), "{started:?}");
    assert_eq!(roads_held(&started), [low(7).as_u32()], "{started:?}");
    assert_eq!(taker.next_wake(), Some(t0() + FILE_REASK_TIME));
    assert_eq!(taker.sources.counts().known, 1, "it took the source");

    let before = taker.on_tick(t0() + FILE_REASK_TIME - Duration::from_secs(1));
    assert!(!asks_for_callback(&before), "{before:?}");
    let due = taker.on_tick(t0() + FILE_REASK_TIME);
    assert!(
        asks_for_callback(&due),
        "its full ask opens the road: {due:?}"
    );
}

/// A road that could only ride a link, and found none, is held once.
#[test]
fn a_road_no_link_carries_is_held_where_the_operator_can_read_it() {
    let standings = QueueStandings::shared();
    let sighting = SourceSighting::new(
        rmule_primitives::PeerSource::new(low(7), 4662),
        Some(SOURCE),
        None,
        Informant::Own,
    );
    let mut download = seated(&standings, 1, &[]);
    take(&mut download, Channel::Server, vec![sighting]);
    let started = download.start(t0());
    assert!(asks_for_callback(&started), "{started:?}");
    let key = connected_key(low(7));

    let held = download.on_no_link(t0(), key);
    assert_eq!(roads_held(&held), [low(7).as_u32()], "{held:?}");

    let again = download.on_no_link(t0(), key);
    assert!(roads_held(&again).is_empty(), "{again:?}");
}

/// The Low IDs `decisions` say a road was held for.
fn roads_held(decisions: &[Decision]) -> Vec<u32> {
    decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::Emit(DownloadEvent::SourceRoadHeld { low_id, .. }) => Some(low_id.as_u32()),
            _ => None,
        })
        .collect()
}

fn asks_for_callback(decisions: &[Decision]) -> bool {
    decisions.iter().any(|decision| {
        matches!(
            decision,
            Decision::RequestCallback {
                on_a_link: false,
                ..
            }
        )
    })
}

/// The giver's place ended inside the peer's clock: a fill may ride a link
/// that stands, as aMule's next file asks over the socket a transfer ended on
/// (`UploadQueue.cpp:486-493`), and may not dial. The worker finds no link and
/// is handed back, and the record asks a period after the peer's last ask.
#[test]
fn a_lane_record_after_the_givers_place_ended_rides_a_link_or_waits_its_clock() {
    let standings = QueueStandings::shared();
    let mut giver = seated(&standings, 1, &[peer(1)]);
    let _ = giver.start(t0());
    queue_and_hang_up_at(&mut giver, peer(1), false, 3, t0());
    giver.hold_standings();
    let mut taker = seated(&standings, 2, &[peer(1)]);
    drop(giver);

    let started = taker.start(t0() + Duration::from_secs(60));
    assert!(
        started.iter().any(|decision| matches!(
            decision,
            Decision::Spawn { peer: p, opening: WorkerOpening::ProbeOnLink, .. } if *p == peer(1)
        )),
        "{started:?}"
    );
    let handed_back = taker.on_worker_event(
        t0() + Duration::from_secs(60),
        peer(1),
        PeerWorkerEvent::HandedBack,
    );
    assert!(spawned(&handed_back).is_empty(), "{handed_back:?}");
    taker.hold_standings();

    assert_eq!(taker.next_wake(), Some(t0() + FILE_REASK_TIME));
    let due = taker.on_tick(t0() + FILE_REASK_TIME);
    assert_eq!(asked_by_tcp(&due), [peer(1)]);
    assert!(
        due.iter().any(|decision| matches!(
            decision,
            Decision::Spawn { peer: p, opening: WorkerOpening::Probe, .. } if *p == peer(1)
        )),
        "its full ask may dial: {due:?}"
    );
}

/// A stamp a period old holds nothing back: the record dials at once.
#[test]
fn a_lane_record_past_the_peers_clock_dials_at_once() {
    let standings = QueueStandings::shared();
    let mut giver = seated(&standings, 1, &[peer(1)]);
    let _ = giver.start(t0());
    queue_and_hang_up_at(&mut giver, peer(1), false, 3, t0());
    giver.hold_standings();
    let mut taker = seated(&standings, 2, &[peer(1)]);
    drop(giver);

    let started = taker.start(t0() + FILE_REASK_TIME);
    assert!(
        started.iter().any(|decision| matches!(
            decision,
            Decision::Spawn { peer: p, opening: WorkerOpening::Probe, .. } if *p == peer(1)
        )),
        "{started:?}"
    );
}

/// The run says which sources it handed over, for the Sources pane, and stops
/// when the standing comes back.
#[test]
fn a_handed_over_source_is_listed_until_the_standing_comes_back() {
    let standings = QueueStandings::shared();
    let (mut giver, taker) = giver_and_taker(&standings);
    let _ = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING);
    assert_eq!(
        giver.handed_over().into_iter().collect::<Vec<_>>(),
        [peer(1)]
    );

    drop(taker);
    let _ = giver.on_tick(t0() + NO_NEEDED_PARTS_PURGE_SPACING * 2);
    assert!(giver.handed_over().is_empty());
}
