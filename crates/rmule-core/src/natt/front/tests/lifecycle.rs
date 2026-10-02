//! The **Traversal Attempt**'s lifecycle (ADR-0091): every ending
//! takes what the attempt holds with it, every state keeps a deadline, and one
//! peer has one attempt whose key never changes.

use super::*;

/// An Initiator introduction on the server leg: the attempt is dialing.
async fn dialing(harness: &mut Harness, target: UserHash, low_id: ClientId, now: Instant) {
    harness.asked_our_server(target, low_id, None, now).await;
    harness
        .front
        .on_command(
            NattCommand::Introduced {
                peer_hash: target,
                target: at(9, 31999),
                role: rmule_ed2k::HolepunchRole::Initiator,
                burst: false,
                source: rmule_peer::natt::PunchTargetSource::Observed,
            },
            now,
        )
        .await;
    assert!(harness.front.dials.in_flight(target));
}

/// A retirement ends the dial schedule with the attempt: no cadence re-dials a
/// peer nothing traverses toward any more, and the spent budget cannot retire
/// the target — and tell its claimant — a second time.
#[tokio::test]
async fn a_retired_attempt_takes_its_dial_schedule_and_is_reported_once() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);
    dialing(&mut harness, target, ClientId::from_u32(42), t0).await;

    harness
        .front
        .retire_attempt(
            target,
            AttemptRetirement::Schedule(rmule_peer::natt::RetireReason::TimedOut),
            t0 + Duration::from_secs(1),
        )
        .await;
    assert_eq!(harness.front.dials.len(), 0, "the schedule ended with it");

    let dials_before = harness.diagnostics.snapshot().session.natt_dials_total;
    let mut now = t0;
    while now < t0 + DIAL_BUDGET + REDIAL_INTERVAL {
        now += REDIAL_INTERVAL;
        harness
            .front
            .on_risen(Risen::DialSettled { peer: target }, now)
            .await;
        harness.front.on_tick(now).await;
        harness.drained();
    }
    let session = harness.diagnostics.snapshot().session;
    assert_eq!(session.natt_dials_total, dials_before, "nothing re-dialed");
    assert_eq!(session.natt_retirements_total, 1, "retired exactly once");
}

/// A `0xA1` re-arms a running traversal's dial, never starts one: after the
/// attempt ended, the peer behind the lingering expectation keeps punching —
/// its own burst, then its keepalive — and none of it opens a dial on a fresh
/// budget.
#[tokio::test]
async fn a_punch_after_the_attempt_ended_opens_no_dial() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);
    dialing(&mut harness, target, ClientId::from_u32(42), t0).await;
    harness
        .front
        .retire_attempt(
            target,
            AttemptRetirement::Schedule(rmule_peer::natt::RetireReason::TimedOut),
            t0 + Duration::from_secs(1),
        )
        .await;

    harness
        .front
        .on_datagram(
            PeerEndpoint::V4(at(9, 32005)),
            holepunch_datagram(),
            t0 + Duration::from_secs(2),
        )
        .await;
    assert_eq!(harness.front.dials.len(), 0);
}

/// A second `Begin` toward a peer already being traversed joins that attempt:
/// the buddy leg is not moved back to the server, and nothing goes out twice.
#[tokio::test]
async fn a_second_begin_joins_the_running_attempt() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);
    assert_eq!(harness.begin(target, t0).await.len(), 1, "one rendezvous");

    harness
        .asked_our_server(target, ClientId::from_u32(42), None, t0)
        .await;
    assert!(harness.drained().is_empty(), "nothing re-emitted");
    assert!(matches!(
        harness.front.attempts.get(&target).map(|a| a.coordinator),
        Some(AttemptCoordinator::Buddy { .. })
    ));
    assert_eq!(
        harness.front.attempts.target_of(ClientId::from_u32(42)),
        None
    );
    assert_eq!(
        harness
            .diagnostics
            .snapshot()
            .session
            .natt_attempts_server_total,
        0,
        "the join counts no second attempt"
    );
}

/// A `0x61` settles the server leg: the attempt stops answering to the Low-ID,
/// so a late silence for that id — the server's other outstanding request left
/// to its own timeout — cannot fall through to a buddy rendezvous beside the
/// dial the introduction armed.
#[tokio::test]
async fn an_introduced_attempt_stops_answering_to_its_low_id() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);
    let low_id = ClientId::from_u32(42);
    harness
        .asked_our_server(target, low_id, Some(super::known_buddy()), t0)
        .await;
    harness
        .front
        .on_command(
            NattCommand::Introduced {
                peer_hash: target,
                target: at(9, 31999),
                role: rmule_ed2k::HolepunchRole::Initiator,
                burst: false,
                source: rmule_peer::natt::PunchTargetSource::Observed,
            },
            t0,
        )
        .await;

    harness
        .front
        .on_command(
            NattCommand::IntroductionFailed {
                target: low_id,
                failure: IntroductionFailure::Silence,
            },
            t0 + Duration::from_secs(15),
        )
        .await;
    assert!(
        harness.drained().is_empty(),
        "no rendezvous beside the dial"
    );
    assert_eq!(
        harness
            .diagnostics
            .snapshot()
            .session
            .natt_attempt_fallthroughs_total,
        0
    );
    assert!(harness.front.dials.in_flight(target));
}

/// Every state has a deadline: a server introduction that named us the
/// responder arms no dial, and a peer that never dials would leave the attempt
/// — and its claimant — waiting forever. The attempt's own 120 s run retires
/// it, once.
#[tokio::test]
async fn an_attempt_no_clock_holds_retires_at_its_run() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);
    harness
        .asked_our_server(target, ClientId::from_u32(42), None, t0)
        .await;
    harness
        .front
        .on_command(
            NattCommand::Introduced {
                peer_hash: target,
                target: at(9, 31999),
                role: rmule_ed2k::HolepunchRole::Responder,
                burst: false,
                source: rmule_peer::natt::PunchTargetSource::Observed,
            },
            t0,
        )
        .await;

    harness.front.on_tick(t0 + DIAL_BUDGET / 2).await;
    assert!(harness.front.attempts.contains(&target));
    harness.front.on_tick(t0 + DIAL_BUDGET).await;
    harness.front.on_tick(t0 + DIAL_BUDGET + TICK).await;
    assert!(!harness.front.attempts.contains(&target));
    assert_eq!(
        harness
            .diagnostics
            .snapshot()
            .session
            .natt_retirements_total,
        1
    );
}

/// A claimant that lets go ends the attempt: nothing dials on for nobody, and
/// nothing is reported as retired — the traversal did not fail, it was no
/// longer wanted.
#[tokio::test]
async fn an_abandoned_attempt_ends_without_a_retirement() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);
    dialing(&mut harness, target, ClientId::from_u32(42), t0).await;

    harness
        .front
        .on_risen(
            Risen::Abandoned { peer: target },
            t0 + Duration::from_secs(30),
        )
        .await;
    assert!(!harness.front.attempts.contains(&target));
    assert_eq!(harness.front.dials.len(), 0);
    assert_eq!(
        harness
            .diagnostics
            .snapshot()
            .session
            .natt_retirements_total,
        0
    );
}
