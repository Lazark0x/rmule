//! Every road a search ends by goes through its one retire (ADR-0093): a
//! stop and quit end a search the same way whatever its task is doing, and
//! a search that ended on its own retires on its own notice, once.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::{Searches, WaitingLegs, WaitingSearch};
use crate::search::SearchEnd;
use crate::service::{CoreEvent, FinishedActivity, SearchEvent, SearchFailure, SearchId};

/// What a search's task does with its stop.
#[derive(Clone, Copy, Debug)]
enum Task {
    /// Asked whole while nothing could carry it: no task yet.
    Waiting,
    /// Ends at its stop, saying nothing.
    HeedsStop,
    /// Never looks at its stop: only the join's abort ends it.
    Wedged,
    /// Says its own end at once.
    EndsOnItsOwn,
    /// Panics before it can say anything.
    Panics,
}

/// How the search is made to end.
#[derive(Clone, Copy, Debug)]
enum Road {
    Stop,
    Quit,
}

/// The ledger's surroundings: the actor's event and finish channels.
struct Bench {
    searches: Searches,
    evt_tx: mpsc::Sender<CoreEvent>,
    evt_rx: mpsc::Receiver<CoreEvent>,
    finished_tx: mpsc::Sender<FinishedActivity>,
    finished_rx: mpsc::Receiver<FinishedActivity>,
}

/// Resolves once what holds its sender is gone — a task ended or aborted.
type Gone = oneshot::Receiver<()>;

impl Bench {
    fn new() -> Self {
        let (evt_tx, evt_rx) = mpsc::channel(16);
        let (finished_tx, finished_rx) = mpsc::channel(16);
        Self {
            searches: Searches::default(),
            evt_tx,
            evt_rx,
            finished_tx,
            finished_rx,
        }
    }

    /// Hold search `id` as `task` has it, with a global sweep beside a
    /// running one. The probes say when the task and the sweep are gone.
    fn hold(&mut self, id: SearchId, task: Task) -> Option<(Gone, Gone)> {
        if let Task::Waiting = task {
            self.searches.wait(WaitingSearch {
                search_id: id,
                query: rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8(
                    "linux",
                ))
                .expect("a query"),
            });
            return None;
        }
        let (sweep_alive, sweep_gone) = oneshot::channel::<()>();
        let sweep = tokio::spawn(async move {
            let _alive = sweep_alive;
            std::future::pending::<()>().await;
        });
        let (task_alive, task_gone) = oneshot::channel::<()>();
        self.searches.start(
            id,
            Some(sweep),
            WaitingLegs::default(),
            &self.finished_tx,
            move |levers| async move {
                let _alive = task_alive;
                let mut stop = levers.cancel_rx;
                match task {
                    Task::HeedsStop => {
                        let _ = stop.wait_for(|stopped| *stopped).await;
                        SearchEnd::Stopped
                    }
                    Task::Wedged => std::future::pending().await,
                    Task::Panics => panic!("a search task that panics"),
                    Task::EndsOnItsOwn | Task::Waiting => SearchEnd::Ended,
                }
            },
        );
        Some((task_gone, sweep_gone))
    }

    async fn end(&mut self, id: SearchId, road: Road) {
        match road {
            Road::Stop => assert!(self.searches.stop(id, &self.evt_tx).await),
            Road::Quit => self.searches.stop_all(&self.evt_tx).await,
        }
    }

    /// Every word the retire said so far.
    fn said(&mut self) -> Vec<CoreEvent> {
        std::iter::from_fn(|| self.evt_rx.try_recv().ok()).collect()
    }
}

async fn gone(probe: Gone, what: &str) {
    tokio::time::timeout(Duration::from_secs(10), probe)
        .await
        .unwrap_or_else(|_| panic!("the {what} outlived the retire"))
        .expect_err("the probe is never sent, only dropped");
}

fn cancelled(said: &[CoreEvent], id: SearchId) -> bool {
    matches!(
        said,
        [CoreEvent::Search(SearchEvent::SearchCancelled { search_id })] if *search_id == id
    )
}

/// A stop and quit end a search the same way whether it waits, heeds its
/// stop or is wedged: it leaves the ledger, its sweep and its task are gone,
/// it is said to be cancelled exactly once, and no finish notice follows.
#[tokio::test(start_paused = true)]
async fn a_stop_and_quit_end_every_search_the_same() {
    for road in [Road::Stop, Road::Quit] {
        for task in [Task::Waiting, Task::HeedsStop, Task::Wedged] {
            let mut bench = Bench::new();
            let id = SearchId::from_u64(1);
            let probes = bench.hold(id, task);
            assert!(bench.searches.holds(id));

            bench.end(id, road).await;

            assert!(!bench.searches.holds(id), "{road:?} {task:?}: still held");
            assert!(bench.searches.is_empty());
            if let Some((task_gone, sweep_gone)) = probes {
                gone(task_gone, "task").await;
                gone(sweep_gone, "sweep").await;
            }
            let said = bench.said();
            assert!(cancelled(&said, id), "{road:?} {task:?}: said {said:?}");
            assert!(
                bench.finished_rx.try_recv().is_err(),
                "{road:?} {task:?}: a stopped search sends no finish notice"
            );
        }
    }
}

/// A search that ended on its own retires on its notice: its sweep stops and
/// nothing more is said for it — its own word was its end.
#[tokio::test(start_paused = true)]
async fn a_search_that_ends_on_its_own_retires_on_its_notice_saying_nothing() {
    let mut bench = Bench::new();
    let id = SearchId::from_u64(2);
    let (task_gone, sweep_gone) = bench
        .hold(id, Task::EndsOnItsOwn)
        .expect("a running search");

    let Some(FinishedActivity::Search(notice_id, run)) = bench.finished_rx.recv().await else {
        panic!("a search notice");
    };
    assert_eq!(notice_id, id);
    bench.searches.death(id, run, &bench.evt_tx).await;

    assert!(!bench.searches.holds(id));
    gone(task_gone, "task").await;
    gone(sweep_gone, "sweep").await;
    let said = bench.said();
    assert!(said.is_empty(), "said {said:?}");
}

/// A search whose task panics is a death: its notice still arrives, the same
/// retire takes it out of the ledger, and its end is reported as a failure,
/// never as a cancel.
#[tokio::test(start_paused = true)]
async fn a_search_whose_task_panics_is_retired_and_reported() {
    let mut bench = Bench::new();
    let id = SearchId::from_u64(5);
    let (task_gone, sweep_gone) = bench.hold(id, Task::Panics).expect("a running search");

    let Some(FinishedActivity::Search(notice_id, run)) = bench.finished_rx.recv().await else {
        panic!("a search notice");
    };
    assert_eq!(notice_id, id);
    bench.searches.death(id, run, &bench.evt_tx).await;

    assert!(!bench.searches.holds(id));
    gone(task_gone, "task").await;
    gone(sweep_gone, "sweep").await;
    assert!(matches!(
        bench.said().as_slice(),
        [CoreEvent::Search(SearchEvent::SearchFailed {
            search_id,
            reason: SearchFailure::TaskPanicked,
        })] if *search_id == id
    ));
}

/// The race between a search's own end and its stop: the stop retires it
/// without a second end, the notice then names a run the ledger no longer
/// holds, and it retires nothing — not even a search started since under the
/// same id.
#[tokio::test(start_paused = true)]
async fn a_finish_notice_retires_only_its_own_run() {
    let mut bench = Bench::new();
    let id = SearchId::from_u64(3);
    bench.hold(id, Task::EndsOnItsOwn);
    let Some(FinishedActivity::Search(_, run)) = bench.finished_rx.recv().await else {
        panic!("a search notice");
    };

    bench.end(id, Road::Stop).await;
    let said = bench.said();
    assert!(
        said.is_empty(),
        "the search said its own end; said {said:?}"
    );

    bench.hold(id, Task::HeedsStop);
    bench.searches.death(id, run, &bench.evt_tx).await;
    assert!(
        bench.searches.holds(id),
        "the stale notice retired the successor"
    );
    assert!(bench.said().is_empty());
}
