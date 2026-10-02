//! The vouching ping (ADR-0052, the offline guard): a living silence alone
//! in its window is inconclusive until a ping to the server that answered
//! last decides it.

use std::sync::Arc;
use std::time::Duration;

use rmule_primitives::ServerEndpoint;

use super::super::super::ServerUdpEngine;
use super::super::super::tests::{
    ScriptedTransport, VERDICTS_DUE, round_trip_harness, row, server, stat_res_datagram, udp_source,
};
use super::super::{StatusPingSweep, SweepState};
use crate::diagnostics::DiagnosticsState;

/// The human's run: `live` answered its ping, eight minutes later the new
/// row `fresh` got its first contact and stayed silent, and nobody else was
/// due inside the window. Returns once the verdicts are due and the tick
/// that judges them has run.
async fn a_new_row_silent_while_nobody_else_is_due() -> (
    StatusPingSweep<Arc<ScriptedTransport>>,
    ServerUdpEngine<Arc<ScriptedTransport>>,
    DiagnosticsState,
    SweepState,
    ServerEndpoint,
    ServerEndpoint,
) {
    let (live, fresh) = (server("127.0.0.1", 4661), server("127.0.0.2", 4799));
    let (sweep, engine, diagnostics) = round_trip_harness(&[live.clone(), fresh.clone()]);
    let mut state = SweepState::default();

    sweep.ping_next(&mut state).await;
    engine
        .demux(stat_res_datagram(0x55AA_ABCD, 700), udp_source(&live))
        .await;
    tokio::time::advance(Duration::from_secs(8 * 60)).await;
    sweep.ping_next(&mut state).await;
    tokio::time::advance(VERDICTS_DUE).await;
    sweep.ping_next(&mut state).await;
    (sweep, engine, diagnostics, state, live, fresh)
}

/// Where each status ping so far went, in order (the engine's own sends,
/// such as a description request after an answer, left out).
fn sent_to(sweep: &StatusPingSweep<Arc<ScriptedTransport>>) -> Vec<ServerEndpoint> {
    let sends = sweep.transport.sends.lock().unwrap();
    sends
        .iter()
        .filter(|(_, datagram)| datagram.get(1) == Some(&0x96))
        .map(|(to, _)| to.clone())
        .collect()
}

/// The vouch answers: the network carried it, so the lone silence is the new
/// row's own failure, and the network is not said to be down.
#[tokio::test(start_paused = true)]
async fn a_lone_silence_counts_once_the_last_answerer_vouches() {
    let (sweep, engine, diagnostics, mut state, live, fresh) =
        a_new_row_silent_while_nobody_else_is_due().await;
    assert_eq!(
        sent_to(&sweep),
        vec![live.clone(), fresh.clone(), live.clone()],
        "the vouch goes to the server that answered last"
    );
    assert!(!diagnostics.snapshot().status_sweep_unheard);

    engine
        .demux(stat_res_datagram(0x55AA_ABCD, 700), udp_source(&live))
        .await;
    tokio::time::advance(Duration::from_secs(1)).await;
    sweep.ping_next(&mut state).await;

    assert_eq!(row(&diagnostics, &fresh).server.fail_count, 1);
    assert_eq!(row(&diagnostics, &live).server.fail_count, 0);
    assert!(!diagnostics.snapshot().status_sweep_unheard);
}

/// The vouch is silent too: two living servers went unheard together, so the
/// network looks down and nobody's tally moves.
#[tokio::test(start_paused = true)]
async fn a_silent_vouch_says_the_network_is_down() {
    let (sweep, _engine, diagnostics, mut state, live, fresh) =
        a_new_row_silent_while_nobody_else_is_due().await;

    tokio::time::advance(VERDICTS_DUE).await;
    sweep.ping_next(&mut state).await;

    assert!(diagnostics.snapshot().status_sweep_unheard);
    assert_eq!(row(&diagnostics, &fresh).server.fail_count, 0);
    assert_eq!(row(&diagnostics, &live).server.fail_count, 0);
    assert_eq!(sent_to(&sweep).len(), 3, "one vouch per window, no more");
}

/// A list of one has nobody to vouch: its silence is dropped quietly, so the
/// network is not said to be down and the server never dies by pings alone.
#[tokio::test(start_paused = true)]
async fn a_list_of_one_sends_no_vouch_and_counts_nothing() {
    let only = server("127.0.0.1", 4661);
    let (sweep, _engine, diagnostics) = round_trip_harness(std::slice::from_ref(&only));
    let mut state = SweepState::default();

    sweep.ping_next(&mut state).await;
    tokio::time::advance(VERDICTS_DUE).await;
    sweep.ping_next(&mut state).await;
    tokio::time::advance(VERDICTS_DUE).await;
    sweep.ping_next(&mut state).await;

    assert_eq!(sent_to(&sweep), vec![only.clone()]);
    assert_eq!(row(&diagnostics, &only).server.fail_count, 0);
    assert!(!diagnostics.snapshot().status_sweep_unheard);
}
