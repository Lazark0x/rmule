//! The first lookup's tests: spans, the wait for a connection, lookups side
//! by side, and the **Source Ask Budget** on the session the asks ride.

use std::future::Future;

use rmule_primitives::{ClientIdentity, Ed2kText, UserHash};

use super::*;
use crate::adapters::SourceLookupOutcome;
use crate::download::runner::DiscoveryLiveness;

/// A server that never answers: the lookup parks, as a real one does
/// while the server thinks.
#[derive(Clone)]
struct NeverAnswers;
impl SourceLookupService for NeverAnswers {
    fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> impl Future<Output = Result<SourceLookupOutcome, DownloadFailure>> + Send {
        std::future::pending()
    }
}

/// The server connection, the Kad node and the accept pump wrote
/// their lines under `download{…}:source_lookup{…}`. A lookup parked on
/// its server must not lend its span to another task polled meanwhile on
/// the same thread — here a server-connection line from a task of its own.
#[tokio::test]
async fn a_parked_source_lookup_lends_its_span_to_no_other_task() {
    let (log, _tracing) = rmule_testkit::capture_tracing(tracing::Level::INFO);
    let (runner, _held) = crate::download::runner::test_context::runner_context(
        NeverAnswers,
        (),
        crate::diagnostics::DiagnosticsState::default(),
    );
    let file_hash = rmule_primitives::FileHash::from_bytes([0x5A; 16]);
    let request = request_for(&runner, 6, file_hash);
    let target = SourceLookupTarget::new(file_hash, 4);

    let mut leg = leg_of(&runner, target);
    let lookup = lookup_once(&request, &runner, target, false, &mut leg)
        .instrument(tracing::info_span!("download", download_id = 6));
    tokio::pin!(lookup);
    // Poll the lookup until it parks on the silent server.
    assert!(
        futures_poll_once(lookup.as_mut()).await.is_none(),
        "the lookup parks"
    );
    // Another task, polled on this thread while the lookup is parked.
    tokio::spawn(async { tracing::info!("server connection: a line of its own") })
        .await
        .expect("the task runs");

    let line = log
        .text()
        .lines()
        .find(|line| line.contains("a line of its own"))
        .map(str::to_owned)
        .expect("the server-connection line was written");
    assert!(
        !line.contains("source_lookup{") && !line.contains("download{"),
        "the line carries another activity's span: {line}"
    );
}

/// A node with no server session: every ask says so at once.
#[derive(Clone)]
struct NoSession;
impl SourceLookupService for NoSession {
    fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> impl Future<Output = Result<SourceLookupOutcome, DownloadFailure>> + Send {
        std::future::ready(Err(DownloadFailure::ServerDisconnected))
    }
}

/// With no server session and Kad off, a run waits for a connection —
/// unless its link carries sources of its own (ADR-0089):
/// those need no server, so the lookup yields a serverless start
/// at once.
#[tokio::test]
async fn a_link_with_its_own_sources_does_not_wait_for_a_server() {
    let (runner, _held) = crate::download::runner::test_context::runner_context(
        NoSession,
        (),
        crate::diagnostics::DiagnosticsState::default(),
    );
    let file_hash = rmule_primitives::FileHash::from_bytes([
        0x3C, 0x1F, 0x9A, 0x04, 0x77, 0xE2, 0x5B, 0xC8, 0x10, 0x6D, 0xA3, 0x42, 0xF5, 0x88, 0x2E,
        0x91,
    ]);
    let request = request_for(&runner, 7, file_hash);
    let target = SourceLookupTarget::new(file_hash, 4);

    let mut fed_leg = leg_of(&runner, target);
    let fed = find_sources(&request, &runner, target, true, &mut fed_leg);
    tokio::pin!(fed);
    assert!(
        matches!(futures_poll_once(fed.as_mut()).await, Some(Ok(None))),
        "a link-fed run starts serverless at once"
    );

    let mut unfed_leg = leg_of(&runner, target);
    let unfed = find_sources(&request, &runner, target, false, &mut unfed_leg);
    tokio::pin!(unfed);
    assert!(
        futures_poll_once(unfed.as_mut()).await.is_none(),
        "a run with nothing to start from waits for a connection"
    );
}

/// A run's server leg for `target`, subscribed as the run subscribes it.
fn leg_of<'a, S, P>(runner: &'a RunnerContext<S, P>, target: SourceLookupTarget) -> ServerLeg<'a> {
    ServerLeg::new(runner.rt.server_session.session_changes(), target)
}

/// One download of the **Download Set** asking for `file_hash`.
fn request_for<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: u64,
    file_hash: rmule_primitives::FileHash,
) -> DownloadRequest {
    DownloadRequest {
        download_id: crate::DownloadId::from_u64(download_id),
        file: rmule_primitives::Ed2kFileLink {
            name: Ed2kText::from_utf8("span"),
            size: 4,
            file_hash,
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        },
        identity: ClientIdentity::new(
            UserHash::from_bytes([
                0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                0xCD, 0xEF,
            ]),
            Ed2kText::from_utf8("span"),
            4662,
            60,
        ),
        verified_part_indexes: Vec::new(),
        streaming_priority: false,
        streaming_window_parts: 4,
        peer_concurrency: 1,
        discovery: DiscoveryLiveness {
            global_servers: std::sync::Arc::default(),
            reach: runner.rt.reach.clone(),
            session: runner.rt.diagnostics.clone(),
        },
        remembered: Vec::new(),
    }
}

/// A server that thinks forever about one file and answers every other
/// at once.
#[derive(Clone)]
struct SilentOn(rmule_primitives::FileHash);
impl SourceLookupService for SilentOn {
    async fn lookup_sources(
        &mut self,
        target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        if target.file_hash() == self.0 {
            std::future::pending().await
        } else {
            Ok(SourceLookupOutcome {
                client_id: rmule_primitives::ClientId::from_u32(0x0A0B_0C0D),
                sources: Vec::new(),
            })
        }
    }
}

/// Two downloads of the **Download Set** on one core (ADR-0107): while the
/// first download's lookup waits on a server that has not answered, the
/// second's is asked and answered — it does not queue behind the first.
#[tokio::test(start_paused = true)]
async fn a_second_downloads_lookup_does_not_wait_behind_the_first() {
    let slow = rmule_primitives::FileHash::from_bytes([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0,
        0x0F,
    ]);
    let quick = rmule_primitives::FileHash::from_bytes([
        0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F,
        0xF0,
    ]);
    let (runner, _held) = crate::download::runner::test_context::runner_context(
        SilentOn(slow),
        (),
        crate::diagnostics::DiagnosticsState::default(),
    );
    let first = request_for(&runner, 1, slow);
    let second = request_for(&runner, 2, quick);

    let slow_target = SourceLookupTarget::new(slow, 4);
    let mut slow_leg = leg_of(&runner, slow_target);
    let parked = lookup_once(&first, &runner, slow_target, false, &mut slow_leg);
    tokio::pin!(parked);
    assert!(
        futures_poll_once(parked.as_mut()).await.is_none(),
        "the first lookup waits on its server"
    );
    let started = tokio::time::Instant::now();
    let quick_target = SourceLookupTarget::new(quick, 4);
    let mut quick_leg = leg_of(&runner, quick_target);
    let answered = lookup_once(&second, &runner, quick_target, false, &mut quick_leg)
        .await
        .expect("the second lookup is answered");
    assert!(answered.is_some());
    assert_eq!(
        tokio::time::Instant::now(),
        started,
        "the second lookup waited on the first"
    );
}

/// Poll `future` once: `Some` with its output if it finished, `None` if it
/// parked.
async fn futures_poll_once<F: Future + Unpin>(future: F) -> Option<F::Output> {
    let mut future = future;
    std::future::poll_fn(|cx| {
        std::task::Poll::Ready(match std::pin::Pin::new(&mut future).poll(cx) {
            std::task::Poll::Ready(output) => Some(output),
            std::task::Poll::Pending => None,
        })
    })
    .await
}

/// A server that answers every ask at once and keeps when each file was
/// asked.
#[derive(Clone, Default)]
struct Recording(
    std::sync::Arc<std::sync::Mutex<Vec<(tokio::time::Instant, rmule_primitives::FileHash)>>>,
);
impl Recording {
    fn asks(&self) -> Vec<(tokio::time::Instant, rmule_primitives::FileHash)> {
        self.0.lock().expect("recording").clone()
    }
}
impl SourceLookupService for Recording {
    async fn lookup_sources(
        &mut self,
        target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        self.0
            .lock()
            .expect("recording")
            .push((tokio::time::Instant::now(), target.file_hash()));
        Ok(SourceLookupOutcome {
            client_id: rmule_primitives::ClientId::from_u32(0x0A0B_0C0D),
            sources: Vec::new(),
        })
    }
}

fn file(index: u8) -> rmule_primitives::FileHash {
    rmule_primitives::FileHash::from_bytes([
        0xB7,
        index,
        0x3E,
        0x91,
        0xC0,
        0x4D,
        0x5A,
        0x26,
        0xF8,
        0xE1,
        0xB3,
        0xC7,
        0xD9,
        0xA0,
        0x5F,
        0x40 ^ index,
    ])
}

/// An operator connect starts now and lands `after` from now: its session is
/// installed (the **Session Generation** moves), then its claim drops.
fn connect_lands(session: &crate::server_session::SharedServerSession, after: Duration) {
    let claim = session.claim_connect();
    let session = session.clone();
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        session.session_established();
        drop(claim);
    });
}

/// Sixteen downloads started together while the login is in flight (run
/// `1790869078`): fifteen asks go on the session the login makes, and the
/// sixteenth one window later — the login does not start the count over
/// under asks already waiting to ride it (ADR-0093, "The Source Ask
/// Budget").
#[tokio::test(start_paused = true)]
async fn sixteen_downloads_started_at_login_ask_fifteen_then_one_a_window_later() {
    let server = Recording::default();
    let (runner, _held) = crate::download::runner::test_context::runner_context(
        server.clone(),
        (),
        crate::diagnostics::DiagnosticsState::default(),
    );
    let runner = std::sync::Arc::new(runner);
    let start = tokio::time::Instant::now();
    connect_lands(&runner.rt.server_session, Duration::from_secs(1));
    let mut runs = Vec::new();
    for index in 0..16 {
        let runner = std::sync::Arc::clone(&runner);
        runs.push(tokio::spawn(async move {
            let target = SourceLookupTarget::new(file(index), 4);
            let request = request_for(&runner, u64::from(index) + 1, file(index));
            let mut leg = leg_of(&runner, target);
            lookup_once(&request, &runner, target, false, &mut leg)
                .await
                .map(|_| ())
        }));
    }
    for run in runs {
        run.await.expect("the run").expect("the lookup");
    }
    let mut offsets: Vec<Duration> = server
        .asks()
        .iter()
        .map(|(at, _)| at.duration_since(start))
        .collect();
    offsets.sort();
    assert_eq!(offsets.len(), 16, "one ask per download");
    assert!(
        offsets[..15].iter().all(|at| *at == Duration::from_secs(1)),
        "fifteen ride the login at once: {offsets:?}"
    );
    assert_eq!(
        offsets[15],
        Duration::from_secs(301),
        "the sixteenth waits one window from the login"
    );
}

/// The session the first lookup's login made is the session it asked: the
/// server leg, subscribed before that login, does not ask it again; a
/// session made after it is asked once.
#[tokio::test(start_paused = true)]
async fn the_server_leg_asks_no_session_the_first_lookup_already_asked() {
    let server = Recording::default();
    let (runner, _held) = crate::download::runner::test_context::runner_context(
        server.clone(),
        (),
        crate::diagnostics::DiagnosticsState::default(),
    );
    let target = SourceLookupTarget::new(file(2), 4);
    let request = request_for(&runner, 3, file(2));
    let mut leg = leg_of(&runner, target);
    connect_lands(&runner.rt.server_session, Duration::from_secs(1));
    lookup_once(&request, &runner, target, false, &mut leg)
        .await
        .expect("the first lookup");
    assert_eq!(server.asks().len(), 1);

    let again = tokio::time::timeout(Duration::from_secs(600), leg.next_answer(&runner)).await;
    assert!(again.is_err(), "the leg waited for a newer session");
    assert_eq!(server.asks().len(), 1, "one ask per file per session");

    runner.rt.server_session.session_established();
    leg.next_answer(&runner).await;
    assert_eq!(server.asks().len(), 2, "a new session is asked once");
}
