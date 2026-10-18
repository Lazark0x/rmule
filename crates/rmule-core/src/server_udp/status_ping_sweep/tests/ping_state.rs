//! The sweep's half of the **Ping State** (ADR-0080): what a row's ping says
//! while nothing is measured, and the status-answer date a restart seeds
//! from (ADR-0052) — never a login's counts.

use std::time::{Duration, SystemTime};

use super::super::super::tests::{
    VERDICTS_DUE, harness_over, round_trip_harness, row, server, stat_res_datagram, udp, udp_source,
};
use super::super::SweepState;
use crate::diagnostics::PingState;
use crate::name_resolver::FakeNameResolver;
use crate::server_list::test_facts;

/// A row's ping reads not asked yet, then awaiting once a probe is out, then
/// unanswered once the probe is judged silent — even when the offline guard
/// moves no tally — and the answer to a later probe measures it again.
#[tokio::test(start_paused = true)]
async fn a_silent_probe_reads_unanswered_until_an_answer_measures_the_ping() {
    let listed = server("127.0.0.1", 4661);
    let (sweep, engine, diagnostics) = round_trip_harness(std::slice::from_ref(&listed));
    let mut state = SweepState::default();
    assert_eq!(row(&diagnostics, &listed).ping, PingState::NotAskedYet);

    sweep.ping_next(&mut state).await;
    assert_eq!(row(&diagnostics, &listed).ping, PingState::Awaiting);

    tokio::time::advance(VERDICTS_DUE).await;
    sweep.ping_next(&mut state).await;
    let silent = row(&diagnostics, &listed);
    assert!(
        matches!(silent.ping, PingState::Unanswered { .. }),
        "the probe went unanswered: {:?}",
        silent.ping
    );
    assert_eq!(
        silent.server.fail_count, 0,
        "a list of one moves no tally, yet the ping still went unanswered"
    );

    tokio::time::advance(sweep.reask).await;
    sweep.ping_next(&mut state).await;
    assert!(
        matches!(
            row(&diagnostics, &listed).ping,
            PingState::Unanswered { .. }
        ),
        "a fresh probe continues the run of silences until something answers"
    );
    engine
        .demux(stat_res_datagram(0x55AA_ABCD, 1000), udp_source(&listed))
        .await;
    assert!(
        matches!(row(&diagnostics, &listed).ping, PingState::Measured(_)),
        "the answer measured the ping"
    );
}

/// A session that only logged in leaves counts dated as counts and no
/// status-answer date, so the next start's sweep makes a first contact
/// instead of holding the row for a re-ask window it never earned; a row
/// whose status answer is fresh is held.
#[tokio::test(start_paused = true)]
async fn a_login_only_row_gets_a_first_contact_at_the_next_start() {
    let (logged_in, answered) = (server("127.0.0.1", 4661), server("127.0.0.2", 4661));
    let seeded = test_facts(&[logged_in.clone(), answered.clone()]);
    seeded.0.reported(&logged_in, 120_000, 5_000_000);
    seeded
        .0
        .answered(
            &answered,
            Duration::from_millis(40),
            &rmule_ed2k::GlobServStatRes::decode_udp(&stat_res_datagram(0x55AA_0001, 7))
                .expect("a status answer"),
            None,
        )
        .await
        .unwrap();
    let (sweep, _engine, diagnostics) = harness_over(seeded, FakeNameResolver::knowing(&[]));
    let reported = row(&diagnostics, &logged_in);
    assert_eq!(reported.users, Some(120_000));
    assert_eq!(
        reported.server.figures.as_ref().and_then(|f| f.answered_at),
        None,
        "a login's counts are no status answer"
    );

    let rows = sweep.facts.listed().unwrap();
    let mut state = SweepState::seeded(
        &rows,
        SystemTime::now(),
        tokio::time::Instant::now(),
        sweep.reask,
    );
    for _ in 0..2 {
        sweep.ping_next(&mut state).await;
        tokio::time::advance(Duration::from_millis(250)).await;
    }
    let sent: Vec<_> = sweep
        .seal
        .transport()
        .sends
        .lock()
        .unwrap()
        .iter()
        .map(|(to, _)| *to)
        .collect();
    assert_eq!(
        sent,
        vec![udp(&logged_in, 4)],
        "the login-only row is a first contact; the answered one is held"
    );
}
