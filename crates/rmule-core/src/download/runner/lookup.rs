//! The run's first question — who has the file — and what the run does when
//! nothing can answer it (ADR-0097, "Waiting for a connection"): a download
//! whose server login fails, with Kad off, has no connection to ask on. That
//! is a state, not a failure: the run waits until a server session or Kad
//! exists, then asks again.

use std::time::Duration;

use rmule_primitives::SourceLookupTarget;
use tracing::Instrument;

use super::server_leg::ServerLeg;
use super::{DownloadRequest, RunnerContext, stop_reason, wait_until_stop};
use crate::adapters::{SourceLookupOutcome, SourceLookupService};
use crate::error::DownloadFailure;
use crate::service::{DownloadEvent, send_download_event};

/// How long a run waits before asking again when a connection exists yet the
/// lookup could not ride it — a session that ended between the answer and the
/// ask. A fresh session is a wake of its own; this only keeps the retry from
/// spinning on one that is going.
const CONNECTED_RETRY: Duration = Duration::from_secs(5);

/// Ask for the file's sources until something answers: the server's
/// outcome, `None` for a serverless start on Kad or on the link's own
/// sources, or the run's failure. A login that finds no connection waits for
/// one instead of failing — unless `link_fed`, the link carrying sources of
/// its own (ADR-0089's amendment): those need no server, so the run
/// starts from them and its server leg asks once a session comes up.
///
/// The session each ask rides is recorded on `leg`, so the leg never asks it
/// again (ADR-0097, "The Source Ask Budget").
pub(super) async fn find_sources<S, P>(
    request: &DownloadRequest,
    runner: &RunnerContext<S, P>,
    target: SourceLookupTarget,
    link_fed: bool,
    leg: &mut ServerLeg<'_>,
) -> Result<Option<SourceLookupOutcome>, DownloadFailure>
where
    S: SourceLookupService,
{
    loop {
        match lookup_once(request, runner, target, link_fed, leg).await {
            Err(DownloadFailure::ServerDisconnected) if link_fed => {
                tracing::info!("no server session: starting from the link's own sources");
                return Ok(None);
            }
            Err(DownloadFailure::ServerDisconnected) => {
                wait_for_connection(request, runner).await?;
                // Leaving the wait: the part file may have gone meanwhile.
                crate::download::persist::check_held_part_file(runner, request.download_id).await?;
            }
            answered => return answered,
        }
    }
}

/// Park until the node has a server session or a running Kad node, or the
/// run is stopped. Says so on the event stream when it has to wait.
async fn wait_for_connection<S, P>(
    request: &DownloadRequest,
    runner: &RunnerContext<S, P>,
) -> Result<(), DownloadFailure> {
    let mut stop_rx = runner.stop_rx.clone();
    // Subscribed before the first look, so a connection that comes up in
    // between is a wake, not a miss.
    let mut changes = runner.rt.reach.changes();
    let connected = || runner.rt.reach.session().is_some() || runner.rt.reach.kad_running();
    if connected() {
        tokio::select! {
            biased;
            _ = wait_until_stop(&mut stop_rx) => {
                return Err(stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled));
            }
            () = tokio::time::sleep(CONNECTED_RETRY) => return Ok(()),
        }
    }
    tracing::info!("no server session and no Kad: waiting for a connection");
    send_download_event(
        &runner.rt.evt_tx,
        DownloadEvent::WaitingForConnection {
            download_id: request.download_id,
        },
    )
    .await;
    // The part file is looked at while the run waits, not only at
    // the next part.
    let mut part_file_tick =
        tokio::time::interval(crate::download::persist::WAITING_PART_FILE_CHECK);
    part_file_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    while !connected() {
        tokio::select! {
            biased;
            _ = wait_until_stop(&mut stop_rx) => {
                return Err(stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled));
            }
            () = changes.changed() => {}
            _ = part_file_tick.tick() => {
                crate::download::persist::check_held_part_file(runner, request.download_id)
                    .await?;
            }
        }
    }
    tracing::info!("a connection exists: asking for sources again");
    Ok(())
}

/// One source lookup on the node's server session, bounded by the lookup
/// timeout. With Kad running, a failed or silent server degrades to a
/// serverless start (`Ok(None)`) rather than failing (ADR-0043).
async fn lookup_once<S, P>(
    request: &DownloadRequest,
    runner: &RunnerContext<S, P>,
    target: SourceLookupTarget,
    link_fed: bool,
    leg: &mut ServerLeg<'_>,
) -> Result<Option<SourceLookupOutcome>, DownloadFailure>
where
    S: SourceLookupService,
{
    // The server the lookup rides is the live session's, whatever server
    // the download was started on; none without a session.
    let source_lookup_span = tracing::info_span!(
        "source_lookup",
        server = ?runner
            .rt.server_session
            .own_identity()
            .connected_session()
            .and_then(|session| session.server),
    );
    // Instrumented, never entered: a `Span::enter` guard held across the
    // awaits below leaves the span current on the worker thread while this
    // future is parked, and every other task polled there — the server
    // session, the Kad pump, the accept pump, the TUI bridge — then logs
    // under this download's lookup.
    ask_once(request, runner, target, link_fed, leg)
        .instrument(source_lookup_span)
        .await
}

/// [`lookup_once`]'s body, run inside its `source_lookup` span.
async fn ask_once<S, P>(
    request: &DownloadRequest,
    runner: &RunnerContext<S, P>,
    target: SourceLookupTarget,
    link_fed: bool,
    leg: &mut ServerLeg<'_>,
) -> Result<Option<SourceLookupOutcome>, DownloadFailure>
where
    S: SourceLookupService,
{
    let mut stop_rx = runner.stop_rx.clone();
    // Lookups run side by side (ADR-0107); what a run may wait on here is the
    // session's **Source Ask Budget**. Its stop must reach it while it waits:
    // the actor joins the run it stops, and a run deaf to its stop would hold
    // the actor. The lookup bound below starts once the ask is admitted, so a
    // wait for the window is never read as a silent server.
    tokio::select! {
        biased;
        _ = wait_until_stop(&mut stop_rx) => {
            return Err(stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled));
        }
        generation = budget_admits(runner) => leg.rode(generation),
    }
    let mut source_lookup = runner.rt.source_lookup.lock().await.clone();
    let lookup = source_lookup.lookup_sources(target);
    let outcome = tokio::select! {
        biased;
        _ = wait_until_stop(&mut stop_rx) => {
            return Err(stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled));
        }
        // A good citizen never hangs unboundedly on a sourceless file:
        // the connected server can simply stay quiet for a
        // hash it has no sources for — a live, logged-in link that never
        // sends `OP_FOUNDSOURCES`, not a disconnect — and the lookup
        // future above has no bound of its own. `--max-seconds` on the
        // CLI bounds the *whole run*; this default bounds just this one
        // RPC, so a plain `download start` always terminates.
        () = tokio::time::sleep(runner.rt.source_lookup_timeout) => {
            let error = DownloadFailure::SourceLookupTimedOut;
            // Same serverless tolerance as the Err(error) arm below
            // (ADR-0043): Kad can still feed the download, so a timed-out
            // server lookup degrades to a sourceless start instead of
            // failing outright.
            if !link_fed && !request.discovery.kad_running() {
                return Err(error);
            }
            tracing::info!(%error, "continuing serverless after source lookup timed out");
            None
        }
        outcome = lookup => match outcome {
            Ok(outcome) => Some(outcome),
            // Serverless tolerance (ADR-0043): with the Kad node running
            // the download can still be fed, so a failed server login
            // degrades to a sourceless start (no login events, empty
            // pools, no callback capability) instead of failing.
            Err(error) => {
                if !link_fed && !request.discovery.kad_running() {
                    return Err(error);
                }
                tracing::info!(%error, "server lookup failed; continuing serverless");
                None
            }
        },
    };
    Ok(outcome)
}

/// Resolve once the core's **Source Ask Budget** admits one more ask on the
/// session that will carry it (ADR-0097, "The Source Ask Budget"), with that
/// session's generation — at once while fewer than fifteen went out on it in
/// the last five minutes, else when the window has room or a new session
/// starts the count over. Every ask counts, joined or not: the budget errs on
/// the counterparty's side.
///
/// The window opens at login: an operator connect in flight is waited out
/// first, since the session it installs is the one the lookup rides
/// (`live_session`). Counted on the generation before it, the ask would be
/// forgotten when that login starts the count over.
pub(super) async fn budget_admits<S, P>(runner: &RunnerContext<S, P>) -> u64 {
    runner.rt.server_session.wait_for_operator_connect().await;
    let mut sessions = runner.rt.server_session.session_changes();
    loop {
        let generation = *sessions.borrow_and_update();
        let verdict = runner
            .rt
            .source_asks
            .lock()
            .expect("source ask budget mutex")
            .admit(generation, tokio::time::Instant::now());
        let Err(room_at) = verdict else {
            return generation;
        };
        tracing::info!(
            "fifteen source asks reached this server in five minutes: this one waits for room"
        );
        tokio::select! {
            () = tokio::time::sleep_until(room_at) => {}
            changed = sessions.changed() => {
                if changed.is_err() {
                    tokio::time::sleep_until(room_at).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
