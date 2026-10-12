//! The attempt's own clock (cadence re-dial, budget end) and the server
//! introduction path: refusals, the buddy rendezvous fallback, retirement, and the
//! closed-inbox sender close.

use super::*;

/// The dial mismatch, on the front's own clock: one dial is bounded at three
/// seconds because a lost opener is never re-sent, and the attempt spends its
/// 120 s budget on **fresh openers** instead of on one that already failed.
/// The cadence re-dial asks for a burst, and the acting path's destination
/// limiter is what decides whether it gets one.
#[tokio::test]
async fn an_attempt_redials_on_the_cadence_within_one_burst_window() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);
    harness
        .front
        .on_command(
            NattCommand::Introduced {
                peer_hash: target,
                target: at(9, 31999),
                role: rmule_ed2k::HolepunchRole::Initiator,
                burst: true,
                source: rmule_peer::natt::PunchTargetSource::Observed,
            },
            t0,
        )
        .await;
    assert_eq!(harness.drained().len(), 6 + 32, "the introduction's burst");
    assert_eq!(harness.diagnostics.snapshot().session.natt_dials_total, 1);

    // The dial ends with no tunnel; the attempt is not over.
    harness
        .front
        .on_risen(
            Risen::DialSettled { peer: target },
            t0 + DIAL_ATTEMPT_TIMEOUT,
        )
        .await;
    assert!(!harness.front.dials.in_flight(target));

    // Inside the acting path's window, the re-dial goes out without a burst.
    harness.front.on_tick(t0 + REDIAL_INTERVAL).await;
    assert!(
        harness.drained().is_empty(),
        "one burst per destination window"
    );
    assert_eq!(harness.diagnostics.snapshot().session.natt_dials_total, 2);

    // Past it, the re-dial re-opens the mapping first.
    let past = t0 + ACTING_MIN_INTERVAL + REDIAL_INTERVAL;
    harness
        .front
        .on_risen(
            Risen::DialSettled { peer: target },
            past - Duration::from_secs(1),
        )
        .await;
    harness.front.on_tick(past).await;
    assert_eq!(harness.drained().len(), 6 + 32, "the mapping may have aged");
    assert_eq!(harness.diagnostics.snapshot().session.natt_dials_total, 3);
}

/// The attempt ends at ADR-0091's budget, with the retirement vocabulary it
/// always used — and it says how many openers it spent getting there.
#[tokio::test]
async fn the_attempt_ends_at_the_budget_with_its_dial_count() {
    let mut harness = Harness::new();
    let mut now = Instant::now();
    let target = hash(0x44);
    // The server leg: its introduction left through the session, so the dial
    // budget is the attempt's whole clock — no rendezvous run beside it.
    harness
        .asked_our_server(target, ClientId::from_u32(42), None, now)
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
            now,
        )
        .await;

    // Every opener is lost; the clock runs until the budget is spent.
    let mut ticks = 0;
    loop {
        now += REDIAL_INTERVAL;
        harness
            .front
            .on_risen(Risen::DialSettled { peer: target }, now)
            .await;
        harness.front.on_tick(now).await;
        // The bursts a re-dial asks for have to go somewhere: the send half is
        // bounded, and a full one would stall the front rather than the test.
        harness.drained();
        if harness.front.dials.len() == 0 {
            break;
        }
        ticks += 1;
        assert!(
            ticks < (DIAL_BUDGET.as_secs() / REDIAL_INTERVAL.as_secs()) + 4,
            "the budget must be reached in a bounded run"
        );
    }
    let session = harness.diagnostics.snapshot().session;
    assert!(
        session
            .natt_last_attempt_dials
            .is_some_and(|dials| dials > 10),
        "the budget bought many openers, not one long wait: {:?}",
        session.natt_last_attempt_dials
    );
    assert_eq!(
        session.natt_dials_total,
        u64::from(
            session
                .natt_last_attempt_dials
                .expect("an attempt finished")
        )
    );
}

/// Both ways a server introduction dies reach the buddy, and each puts a real
/// rendezvous on the client-UDP send half addressed to the buddy the
/// candidate named — the `0x60` left on the session, so until now nothing had
/// left the client-UDP half.
///
/// The arming is the schedule's `RouteChosen` trigger, not a fresh budget: a
/// first attempt is unjittered, so the datagram is out on the same call.
#[tokio::test]
async fn a_refused_and_a_silent_introduction_each_fall_to_the_buddy_rendezvous() {
    for (fill, low, failure) in [
        (
            0x44,
            42,
            IntroductionFailure::Refused {
                reason: rmule_ed2k::HolepunchFailReason::TargetNotConnected,
                permanent: false,
            },
        ),
        (0x55, 43, IntroductionFailure::Silence),
    ] {
        let mut harness = Harness::new();
        let t0 = Instant::now();
        let target = hash(fill);
        let low_id = ClientId::from_u32(low);

        harness
            .asked_our_server(target, low_id, Some(super::known_buddy()), t0)
            .await;
        assert!(
            harness.drained().is_empty(),
            "the 0x60 leaves on the session, not the client-UDP half"
        );

        harness
            .front
            .on_command(
                NattCommand::IntroductionFailed {
                    target: low_id,
                    failure,
                },
                t0 + Duration::from_secs(1),
            )
            .await;

        let emitted = harness.drained();
        assert_eq!(emitted.len(), 1, "one rendezvous, unjittered");
        assert_eq!(emitted[0].to, PeerEndpoint::V4(buddy()));
        let relay = rmule_peer::ReaskCallbackUdp::decode_udp(&emitted[0].datagram).expect("a 0x94");
        let body = RendezvousBody::from_forwarded(&relay.forwarded)
            .expect("marked as a rendezvous")
            .expect("well-formed");
        assert_eq!(body.requester, hash(0xAA));

        let session = harness.diagnostics.snapshot().session;
        assert_eq!(session.natt_attempts_server_total, 1);
        assert_eq!(session.natt_attempt_fallthroughs_total, 1);
        assert_eq!(session.natt_server_requests_emitted_total, 1, "the 0x60");
        assert_eq!(
            session.natt_rendezvous_emitted_total, 1,
            "the fall-through's rendezvous"
        );
        assert_eq!(session.natt_retirements_total, 0, "the attempt lives on");

        // The attempt no longer answers to the Low-ID: the buddy leg's
        // failures are the schedule's, and a late `0x62` must not settle it.
        harness
            .front
            .on_command(
                NattCommand::IntroductionFailed {
                    target: low_id,
                    failure: IntroductionFailure::Silence,
                },
                t0 + Duration::from_secs(2),
            )
            .await;
        assert!(harness.drained().is_empty());
        assert_eq!(
            harness
                .diagnostics
                .snapshot()
                .session
                .natt_attempt_fallthroughs_total,
            1
        );
    }
}

/// A candidate with no buddy has nobody left once the server says no, so the
/// attempt retires carrying **what the server said** — and the download that
/// claimed the target hears it at once, rather than waiting out the 30 s
/// slot-release deadline that used to be the claim's only bound.
#[tokio::test]
async fn a_candidate_with_no_buddy_retires_with_the_servers_reason_and_tells_its_claimant() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let target = hash(0x44);
    let low_id = ClientId::from_u32(42);
    let (callback, mut retire_rx, _claim) = harness.claim(target, low_id);

    harness.asked_our_server(target, low_id, None, t0).await;
    harness
        .front
        .on_command(
            NattCommand::IntroductionFailed {
                target: low_id,
                failure: IntroductionFailure::Refused {
                    reason: rmule_ed2k::HolepunchFailReason::TargetIsHighId,
                    permanent: true,
                },
            },
            t0 + Duration::from_secs(1),
        )
        .await;

    assert!(
        harness.drained().is_empty(),
        "there was no second coordinator to ask"
    );
    let session = harness.diagnostics.snapshot().session;
    assert_eq!(session.natt_retirements_total, 1);
    assert_eq!(
        session.natt_last_retire_reason,
        Some(crate::diagnostics::NattRetirement::ServerRefused(
            rmule_ed2k::HolepunchFailReason::TargetIsHighId
        )),
        "'attempts exhausted' would be a lie: not one rendezvous was sent"
    );
    assert_eq!(
        retire_rx.try_recv().expect("the claimant was told"),
        (
            callback,
            crate::diagnostics::NattRetirement::ServerRefused(
                rmule_ed2k::HolepunchFailReason::TargetIsHighId
            )
        )
    );
    assert!(
        !harness.front.attempts.contains(&target),
        "a retired attempt is forgotten, so nothing reports it twice"
    );
}

/// The front is rung 1's one emitter: the server leg's `0x60` leaves on
/// the Server Coordinator's live session, naming the client-UDP port as
/// bound, and the attempt it opens answers to the Low-ID it named. A target
/// with no User Hash is introduced all the same — the server needs only the
/// id — and no attempt is keyed for it.
#[tokio::test]
async fn the_server_leg_puts_its_0x60_on_the_session_and_opens_the_attempt() {
    let mut harness = Harness::new();
    let now = Instant::now();
    let (target, low_id) = (hash(0x44), ClientId::from_u32(42));

    harness.asked_our_server(target, low_id, None, now).await;
    assert_eq!(
        harness.around.next_introduction().await,
        (low_id, OUR_UDP_PORT)
    );
    assert_eq!(harness.front.attempts.target_of(low_id), Some(target));

    let hashless = ClientId::from_u32(43);
    harness
        .front
        .on_command(
            NattCommand::Traverse {
                coordinator: AttemptCoordinator::Server { low_id: hashless },
                owner: None,
            },
            now,
        )
        .await;
    assert_eq!(
        harness.around.next_introduction().await,
        (hashless, OUR_UDP_PORT)
    );
    assert_eq!(harness.front.attempts.target_of(hashless), None);

    let session = harness.diagnostics.snapshot().session;
    assert_eq!(session.natt_attempts_server_total, 1);
}

/// A `0x60` that cannot leave — the session is gone — went nowhere, so
/// nothing could ever settle it: no attempt opens, and the download that
/// claimed the target hears `NoCoordinator` at once rather than holding its
/// slot to the traversal bound.
#[tokio::test]
async fn a_server_introduction_that_cannot_leave_retires_its_claimant_at_once() {
    let mut harness = Harness::new();
    let (target, low_id) = (hash(0x44), ClientId::from_u32(42));
    let (callback, mut retire_rx, _claim) = harness.claim(target, low_id);
    harness.around.end_session().await;

    harness
        .asked_our_server(target, low_id, None, Instant::now())
        .await;

    assert_eq!(
        retire_rx.try_recv(),
        Ok((callback, AttemptRetirement::NoCoordinator))
    );
    assert!(!harness.front.attempts.contains(&target));
}

/// The attempt keeps no snapshot of our position: the fall-through reads
/// Self Reach when the server fails. A client-UDP half that went dark since
/// the attempt began (Quit) leaves the buddy's rendezvous nothing to ride,
/// so the attempt retires on the server's silence rather than falling.
#[tokio::test]
async fn the_fall_through_reads_self_reach_when_the_server_fails() {
    let mut harness = Harness::new();
    let t0 = Instant::now();
    let (target, low_id) = (hash(0x44), ClientId::from_u32(42));
    harness
        .asked_our_server(target, low_id, Some(super::known_buddy()), t0)
        .await;
    harness.around.client_udp.clear();

    harness
        .front
        .on_command(
            NattCommand::IntroductionFailed {
                target: low_id,
                failure: IntroductionFailure::Silence,
            },
            t0 + crate::natt::server_punch::INTRODUCTION_TIMEOUT,
        )
        .await;

    assert!(
        harness.drained().is_empty(),
        "no rendezvous rides a dark half"
    );
    assert_eq!(
        harness
            .diagnostics
            .snapshot()
            .session
            .natt_last_retire_reason,
        Some(AttemptRetirement::ServerSilent)
    );
}

/// `SharedNattFront::is_live` reads the installed command
/// sender's own `is_closed`, never a cached "was a front ever installed"
/// flag: this proves the fact that reading rests on — `run` drops its
/// `commands` receiver on the exact same path production takes when the
/// client-UDP front closes (the rule "a closed channel ends the task").
#[tokio::test]
async fn run_returning_on_a_closed_inbox_closes_the_installed_sender() {
    let (client_udp, _sent) = mpsc::channel(256);
    let own_identity = crate::own_identity::SharedOwnIdentity::default();
    own_identity.set_user_hash(hash(0xAA));
    let assembled = assemble(
        NullSink,
        NattIdentity {
            local: RMULE_NATT_CLAIM,
        },
        Arc::new(own_identity) as Arc<dyn NattOwnHash>,
        None,
        NattWiring {
            client_udp,
            server: crate::natt::server_punch::CoordinatorSession::default(),
            reach: crate::reachability::SharedSelfReach::new(
                crate::KadReachLevel::fixed(false),
                crate::own_identity::SharedOwnIdentity::default(),
                SharedNattFront::default(),
            ),
            addresses: crate::address_learning::SharedAddressLearning::default(),
            admit: crate::adapters::SharedTunnelAdmit::default(),
            claims: crate::adapters::AwaitedInbound::default(),
            peer_pin: crate::adapters::SharedPeerPin::default(),
            diagnostics: DiagnosticsState::default(),
            events: None,
            prediction: None,
        },
    )
    .expect("the uTP engine starts");

    let (inbox_tx, inbox_rx) = mpsc::channel::<ClientUdpDatagram>(1);
    let (commands, command_rx) = mpsc::channel::<NattCommand>(1);
    let shared = SharedNattFront::default();
    shared.install(commands);
    let liveness = shared.liveness();
    assert!(liveness.is_live(), "installed with its receiver still held");

    let run = tokio::spawn(assembled.front.run(inbox_rx, command_rx, assembled.risen));
    // The client-UDP front closed: dropping the datagram sender is the exact
    // edge `run`'s own doc comment names as ending the task.
    drop(inbox_tx);
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("run returns once its inbox closes")
        .expect("run does not panic");

    assert!(
        !liveness.is_live(),
        "run returning drops its commands receiver, so the installed sender reads closed"
    );
}
