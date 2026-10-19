//! One **Queue Standing** per peer across the Download Set (ADR-0107, "One
//! peer, one queue standing"): two downloads queued at one peer re-ask it once
//! per cycle, by whichever road; a download whose peer queues another of ours
//! waits on that place and dials nothing; the standing passes to it by TCP on
//! the peer's clock; and a grant on the standing calls it to the holder's
//! link. Each brain publishes its places after every step, as the runner does.

use std::sync::Arc;

use super::*;
use crate::download::queue_standings::{QueueStandings, SharedQueueStandings, StandingSeat};

/// Download `id` over `pool`, sighted from a server and seated in `standings`,
/// not yet started.
fn seated(
    standings: &SharedQueueStandings,
    id: u64,
    pool: &[PeerEndpoint],
    posture: SourcingPosture,
) -> DownloadState {
    let download = DownloadId::from_u64(id);
    let mut state = DownloadState::new(
        download,
        file_hash_only_content(ONE_PART),
        no_facts(),
        posture,
        CALLBACK_TIMEOUT,
        crate::download::connection_budget::BudgetSeat::ceiling(pool.len()),
    )
    .with_standings(StandingSeat::new(Arc::clone(standings), download));
    take(&mut state, Channel::Server, plain_sightings(pool));
    state
}

/// Our reask position with no client-UDP socket: every reask is a TCP full
/// ask.
fn tcp_only_posture() -> SourcingPosture {
    SourcingPosture {
        client_udp: false,
        ..live_posture()
    }
}

/// Which road one re-ask took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Road {
    Ping,
    FullAsk,
}

/// Drive `downloads` up to `until` at the instants their brains name, each
/// publishing its places after every step. A ping is answered at once with a
/// rank; a TCP full ask's worker is queued again and hangs up at once. The
/// re-asks each download sent, with the instant it sent them.
fn run_until(downloads: &mut [&mut DownloadState], until: Instant) -> Vec<Vec<(Instant, Road)>> {
    let mut asks = vec![Vec::new(); downloads.len()];
    let mut clock = t0();
    for _ in 0..500 {
        let next = downloads
            .iter()
            .enumerate()
            .filter_map(|(i, state)| state.next_wake().map(|wake| (wake, i)))
            .min();
        let Some((wake, i)) = next else {
            return asks;
        };
        clock = clock.max(wake);
        if clock > until {
            return asks;
        }
        let state = &mut *downloads[i];
        let due = state.on_tick(clock);
        state.hold_standings();
        for from in pinged(&due) {
            asks[i].push((clock, Road::Ping));
            let _ = state.on_reask_reply(clock, from, &v4_ack(7));
            state.hold_standings();
        }
        for peer in asked_by_tcp(&due) {
            asks[i].push((clock, Road::FullAsk));
            if spawned(&due).contains(&peer) {
                let udp = state.our_udp_enabled;
                queue_and_hang_up_at(state, peer, udp, 7, clock);
                state.hold_standings();
            }
        }
    }
    panic!("the brains kept waking without time moving on");
}

/// Two downloads that both stand queued at one peer — they reached it before
/// either stood — and how many re-asks each sends over three cycles under
/// `posture`.
fn two_standing(posture: SourcingPosture) -> [Vec<(Instant, Road)>; 2] {
    let standings = QueueStandings::shared();
    let udp = posture.client_udp;
    let mut first = seated(&standings, 1, &[peer(1)], posture);
    let mut second = seated(&standings, 2, &[peer(1)], posture);
    let _ = first.start(t0());
    let _ = second.start(t0());
    queue_and_hang_up_at(&mut first, peer(1), udp, 5, t0());
    first.hold_standings();
    let later = t0() + Duration::from_secs(10);
    queue_and_hang_up_at(&mut second, peer(1), udp, 7, later);
    second.hold_standings();
    let until = later + FILE_REASK_TIME * 3 + Duration::from_secs(60);
    let [first_asks, second_asks]: [Vec<_>; 2] = run_until(&mut [&mut first, &mut second], until)
        .try_into()
        .expect("two downloads");
    [first_asks, second_asks]
}

/// Over the UDP road: the download whose slot ask the peer read last holds
/// the standing and pings once a cycle, naming its file; the other pings
/// nothing and never falls back to TCP (aMule scores every ask,
/// `UploadClient.cpp:795-825`).
#[test]
fn two_downloads_queued_at_one_peer_ping_it_once_a_cycle() {
    let [first, second] = two_standing(live_posture());
    assert!(
        first.is_empty(),
        "the download passed over asks nothing: {first:?}"
    );
    assert_eq!(
        second.iter().map(|(_, road)| *road).collect::<Vec<_>>(),
        [Road::Ping; 3],
        "{second:?}"
    );
}

/// Over the TCP road: the holder's full ask, once a cycle, carries the
/// standing through its own absence — the other download does not take that
/// window for an ask of its own.
#[test]
fn two_downloads_queued_at_one_peer_ask_it_by_tcp_once_a_cycle() {
    let [first, second] = two_standing(tcp_only_posture());
    assert!(
        first.is_empty(),
        "the download passed over asks nothing: {first:?}"
    );
    assert_eq!(
        second.iter().map(|(_, road)| *road).collect::<Vec<_>>(),
        [Road::FullAsk; 3],
        "{second:?}"
    );
    for pair in second.windows(2) {
        assert!(pair[1].0 - pair[0].0 >= FILE_REASK_TIME, "{second:?}");
    }
}

/// A download whose source already queues another of ours dials nothing and
/// says why; it pings nothing while the other holds the standing; once the
/// other's run ends, it holds the standing it inherited and asks first by
/// TCP — the peer holds the other file — a period after the peer's last ask.
#[test]
fn a_download_whose_peer_queues_another_waits_on_it_then_asks_by_tcp_on_its_clock() {
    let standings = QueueStandings::shared();
    let mut first = seated(&standings, 1, &[peer(1)], live_posture());
    let _ = first.start(t0());
    queue_and_hang_up(&mut first, peer(1), true, 5);
    first.hold_standings();

    let mut second = seated(&standings, 2, &[peer(1)], live_posture());
    let started = second.start(t0() + Duration::from_secs(60));
    second.hold_standings();
    assert!(spawned(&started).is_empty(), "{started:?}");
    assert!(
        started.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceWaitsOnStanding { peer: p, .. }) if *p == peer(1)
        )),
        "{started:?}"
    );
    assert_eq!(second.source_activity().queued, 1);

    drop(first);
    let before = second.on_tick(t0() + FILE_REASK_TIME - Duration::from_secs(1));
    assert!(
        pinged(&before).is_empty() && asked_by_tcp(&before).is_empty(),
        "{before:?}"
    );
    assert_eq!(second.next_wake(), Some(t0() + FILE_REASK_TIME));
    let due = second.on_tick(t0() + FILE_REASK_TIME);
    assert!(pinged(&due).is_empty(), "{due:?}");
    assert_eq!(asked_by_tcp(&due), [peer(1)]);
}

/// A grant on the standing goes to the holder's file: its worker opens and,
/// once it keeps the slot, calls the downloads waiting on the peer; a called
/// waiter opens its worker on the holder's link at once, where it waits as a
/// Link Rider until the swap rule hands the link over (ADR-0107).
#[test]
fn a_grant_on_the_standing_transfers_the_holders_file_and_calls_the_waiter_to_its_link() {
    let standings = QueueStandings::shared();
    let mut first = seated(&standings, 1, &[peer(1)], live_posture());
    let _ = first.start(t0());
    queue_and_hang_up(&mut first, peer(1), true, 5);
    first.hold_standings();
    let mut second = seated(&standings, 2, &[peer(1)], live_posture());
    let _ = second.start(t0() + Duration::from_secs(60));
    second.hold_standings();
    assert!(!second.holds_standing(peer(1)) && first.holds_standing(peer(1)));

    let granted_at = t0() + Duration::from_secs(90);
    let offered = first.on_slot_offered(granted_at, peer(1));
    assert_eq!(spawned(&offered), [peer(1)]);
    let kept = connect(&mut first, granted_at, peer(1));
    assert!(
        kept.iter().any(|d| matches!(
            d,
            Decision::CallStandingWaiters { peer: p } if *p == peer(1)
        )),
        "{kept:?}"
    );

    let called = second.on_link_called(granted_at, peer(1));
    assert_eq!(spawned(&called), [peer(1)]);
    assert!(second.on_link_called(granted_at, peer(1)).is_empty());
}

/// The hello a source queued under names its User Hash past the worker that
/// read it, so the run files its Awaited Grant under that hash and the
/// granted worker looks the peer's link up by it (ADR-0049, ADR-0107).
#[test]
fn a_queued_source_keeps_the_user_hash_its_hello_named() {
    let mut state = standing();
    assert_eq!(state.peer_crypt(peer(1)).user_hash(), Some(SOURCE));
    let _ = state.on_slot_offered(t0() + Duration::from_secs(90), peer(1));
    assert_eq!(state.peer_crypt(peer(1)).user_hash(), Some(SOURCE));
}

/// A grant by dial-back to a record that never heard the peer's parts — it
/// waited on another download's standing — is taken at its probe's answer,
/// asking no slot: the probe is a file request the uploader does not score,
/// the slot ask one it does (ADR-0107, ADR-0112).
#[test]
fn a_grant_to_a_record_that_heard_no_parts_is_taken_at_its_probe_and_no_slot_ask() {
    let standings = QueueStandings::shared();
    let mut first = seated(&standings, 1, &[peer(1)], live_posture());
    let _ = first.start(t0());
    queue_and_hang_up(&mut first, peer(1), true, 5);
    first.hold_standings();
    let mut second = seated(&standings, 2, &[peer(1)], live_posture());
    let _ = second.start(t0() + Duration::from_secs(60));
    second.hold_standings();
    drop(first);

    let granted_at = t0() + Duration::from_secs(90);
    let offered = second.on_slot_offered(granted_at, peer(1));
    assert!(
        offered.iter().any(|d| matches!(
            d,
            Decision::Spawn { peer: p, opening: WorkerOpening::Probe, .. } if *p == peer(1)
        )),
        "{offered:?}"
    );
    let connected = second.on_worker_event(granted_at, peer(1), PeerWorkerEvent::Connected);
    assert!(
        !sent(&connected)
            .iter()
            .any(|(_, c)| matches!(c, PeerWorkerCommand::TakeGrant | PeerWorkerCommand::AskSlot)),
        "{connected:?}"
    );
    let answered = second.on_worker_event(
        granted_at,
        peer(1),
        PeerWorkerEvent::every_part(second.file_size),
    );
    let commands = sent(&answered);
    assert!(
        commands.contains(&(peer(1), PeerWorkerCommand::TakeGrant)),
        "{answered:?}"
    );
    assert!(!commands.contains(&(peer(1), PeerWorkerCommand::AskSlot)));
}

/// A download waiting on a link that fails under another download's rider
/// keeps its source: handed back, it stands on the peer's standing — the
/// cut rider's — and neither dials nor asks, where it used to dial once,
/// meet a refused connection and fail the download (ADR-0107 invariant 9).
#[test]
fn a_waiter_handed_back_by_a_failed_link_stands_on_the_riders_standing() {
    let standings = QueueStandings::shared();
    let mut rider = seated(&standings, 1, &[peer(1)], live_posture());
    let _ = rider.start(t0());
    let _ = connect(&mut rider, t0(), peer(1));
    rider.hold_standings();
    let mut waiter = seated(&standings, 2, &[peer(1)], live_posture());
    assert_eq!(spawned(&waiter.start(t0())), [peer(1)]);
    let _ = waiter.on_worker_event(
        t0(),
        peer(1),
        PeerWorkerEvent::LinkShared {
            turn: crate::service::LinkTurn::Waiting,
        },
    );

    let cut = t0() + Duration::from_secs(10);
    let _ = rider.on_worker_event(cut, peer(1), PeerWorkerEvent::Disconnected);
    rider.hold_standings();
    let handed = waiter.on_worker_event(cut, peer(1), PeerWorkerEvent::HandedBack);
    waiter.hold_standings();
    assert!(
        !handed.iter().any(|d| matches!(d, Decision::Fail(_))),
        "{handed:?}"
    );
    assert!(spawned(&handed).is_empty(), "{handed:?}");
    assert!(
        handed.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerRetired {
                peer: p,
                reason: PeerRetirementReason::LinkEnded,
                ..
            }) if *p == peer(1)
        )),
        "{handed:?}"
    );
    assert_eq!(waiter.source_activity().queued, 1);

    let due = cut + FILE_REASK_TIME;
    let held = waiter.on_tick(due);
    assert!(
        pinged(&held).is_empty() && asked_by_tcp(&held).is_empty(),
        "{held:?}"
    );
    let asked = rider.on_tick(due);
    assert!(
        !pinged(&asked).is_empty() || !asked_by_tcp(&asked).is_empty(),
        "the rider's standing asks: {asked:?}"
    );
}
