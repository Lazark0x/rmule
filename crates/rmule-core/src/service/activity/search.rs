//! The search side of the actor's ledger (ADR-0093): every search running
//! and every keyword search waiting whole, and the one retire each ends
//! through. A stop (`CancelSearch`), the task's own end and quit all take the
//! same road: the global sweep stops, the task is told to stop and joined
//! within [`JOIN_GRACE`](super::JOIN_GRACE) — aborted past it, which drops
//! its live-search registration with it — a search whose task panicked is
//! said to have failed, and one whose task did not say its own end is said to
//! be cancelled.

use std::collections::HashMap;
use std::future::Future;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::search::{KadKeywordLeg, SearchEnd, SentServerLeg};
use crate::service::{CoreEvent, FinishedActivity, SearchEvent, SearchFailure, SearchId};

use super::join_or_abort;

/// The searches the actor holds (ADR-0093): any number running side by
/// side, by id, and the keyword searches asked for while neither a server
/// session nor Kad existed, in the order asked (ADR-0095, "Connecting is the
/// operator's act"). Holding one is its liveness; it leaves at its retire.
#[derive(Default)]
pub(in crate::service) struct Searches {
    running: HashMap<SearchId, ActiveSearch>,
    waiting: Vec<WaitingSearch>,
    /// The run number the next started search is given; never reused, so a
    /// finish notice from a retired run never retires a later search under
    /// the same id.
    next_run: u64,
}

/// A keyword search waiting for a server session or Kad, neither of which
/// exists: everything its start needs.
pub(in crate::service) struct WaitingSearch {
    pub(in crate::service) search_id: SearchId,
    pub(in crate::service) query: rmule_primitives::KeywordQuery,
}

/// What the ledger hands a starting search's task: the stop it watches and
/// where `SearchCommand::MoreResults` reaches it (ADR-0036).
pub(in crate::service) struct SearchLevers {
    pub(in crate::service) cancel_rx: watch::Receiver<bool>,
    pub(in crate::service) more_rx: mpsc::Receiver<()>,
}

/// One running search: its task and everything its start took.
pub(in crate::service) struct ActiveSearch {
    /// Which start this is; its finish notice carries it.
    run: u64,
    cancel_tx: watch::Sender<bool>,
    /// The task, which owns the search's live-search registration: its end,
    /// or its abort, ends the search's liveness.
    handle: JoinHandle<()>,
    /// How the task ended, sent before its finish notice: whether it said its
    /// own end, read even when the join had to abort it.
    end_rx: oneshot::Receiver<SearchEnd>,
    more_tx: mpsc::Sender<()>,
    /// The global UDP sweep's task (ADR-0051), once sent. Aborted at the
    /// retire — a sweep for a dead search would only solicit answers nobody
    /// consumes.
    global_sweep: Option<JoinHandle<()>>,
    /// The legs that wait, and what sending them needs (ADR-0034).
    pub(in crate::service) waiting: WaitingLegs,
}

/// A running keyword search's legs that wait (ADR-0034, "The legs are
/// independent"): the server leg and its sweep for a session, the Kad
/// leg for Kad to run. The actor sends each on its arrival; the task drops
/// its receiver once the leg can no longer run for it.
#[derive(Default)]
pub(in crate::service) struct WaitingLegs {
    /// What the search asks, for the legs sent late.
    pub(in crate::service) query: Option<rmule_primitives::KeywordQuery>,
    /// Held only while the operator's Server Intent stands; dropped when it
    /// ends, which settles the leg.
    pub(in crate::service) server: Option<oneshot::Sender<SentServerLeg>>,
    pub(in crate::service) kad: Option<oneshot::Sender<KadKeywordLeg>>,
}

impl Searches {
    /// Whether `search_id` names a search running or waiting.
    pub(in crate::service) fn holds(&self, search_id: SearchId) -> bool {
        self.running.contains_key(&search_id)
            || self
                .waiting
                .iter()
                .any(|search| search.search_id == search_id)
    }

    /// Whether no search is held.
    pub(in crate::service) fn is_empty(&self) -> bool {
        self.running.is_empty() && self.waiting.is_empty()
    }

    /// Hold `search` whole until a session or Kad can carry a leg of it.
    pub(in crate::service) fn wait(&mut self, search: WaitingSearch) {
        self.waiting.push(search);
    }

    /// Every search waiting whole, in the order asked, taken for its start.
    pub(in crate::service) fn take_waiting(&mut self) -> Vec<WaitingSearch> {
        std::mem::take(&mut self.waiting)
    }

    /// Start search `search_id`: hand `task` its levers, spawn it and hold it
    /// running beside the others. A task that ends on its own sends its finish
    /// notice on `finished_tx`, naming this run.
    pub(in crate::service) fn start<F>(
        &mut self,
        search_id: SearchId,
        global_sweep: Option<JoinHandle<()>>,
        waiting: WaitingLegs,
        finished_tx: &mpsc::Sender<FinishedActivity>,
        task: impl FnOnce(SearchLevers) -> F,
    ) where
        F: Future<Output = SearchEnd> + Send + 'static,
    {
        let run = self.next_run;
        self.next_run = run.wrapping_add(1);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (more_tx, more_rx) = mpsc::channel(1);
        let (end_tx, end_rx) = oneshot::channel();
        let task = task(SearchLevers { cancel_rx, more_rx });
        let finished_tx = finished_tx.clone();
        let handle = tokio::spawn(async move {
            let end = run_watched(task).await;
            let _ = end_tx.send(end);
            if end != SearchEnd::Stopped {
                let _ = finished_tx
                    .send(FinishedActivity::Search(search_id, run))
                    .await;
            }
        });
        self.running.insert(
            search_id,
            ActiveSearch {
                run,
                cancel_tx,
                handle,
                end_rx,
                more_tx,
                global_sweep,
                waiting,
            },
        );
    }

    /// The running search `search_id`.
    pub(in crate::service) fn running(&self, search_id: SearchId) -> Option<&ActiveSearch> {
        self.running.get(&search_id)
    }

    /// The running search `search_id`, for its legs.
    pub(in crate::service) fn running_mut(
        &mut self,
        search_id: SearchId,
    ) -> Option<&mut ActiveSearch> {
        self.running.get_mut(&search_id)
    }

    /// Every running search, for its legs.
    pub(in crate::service) fn each_running_mut(
        &mut self,
    ) -> impl Iterator<Item = (SearchId, &mut ActiveSearch)> {
        self.running.iter_mut().map(|(id, active)| (*id, active))
    }

    /// Ask the running search `search_id` for its server's next page.
    /// `false` when no search runs under it, or a request is already on its
    /// way: the second would only be refused.
    pub(in crate::service) fn ask_more(&self, search_id: SearchId) -> bool {
        self.running
            .get(&search_id)
            .is_some_and(|active| active.more_tx.try_send(()).is_ok())
    }

    /// Stop search `search_id` (`CancelSearch`): a running one through its
    /// retire, a waiting one let go; each is said to be cancelled unless it
    /// said its own end first. `false` when no search has that id.
    pub(in crate::service) async fn stop(
        &mut self,
        search_id: SearchId,
        evt_tx: &mpsc::Sender<CoreEvent>,
    ) -> bool {
        if let Some(active) = self.running.remove(&search_id) {
            active.retire(search_id, evt_tx).await;
            return true;
        }
        let Some(at) = self
            .waiting
            .iter()
            .position(|search| search.search_id == search_id)
        else {
            return false;
        };
        self.waiting.remove(at).retire(evt_tx).await;
        true
    }

    /// Run `run` of search `search_id` ended on its own (a death, ADR-0093):
    /// the same retire. A notice from a run a stop already retired names a
    /// run the ledger no longer holds and retires nothing.
    pub(in crate::service) async fn death(
        &mut self,
        search_id: SearchId,
        run: u64,
        evt_tx: &mpsc::Sender<CoreEvent>,
    ) {
        if self
            .running
            .get(&search_id)
            .is_some_and(|active| active.run == run)
            && let Some(active) = self.running.remove(&search_id)
        {
            active.retire(search_id, evt_tx).await;
        }
    }

    /// Quit: every search through its retire, the waiting ones first — they
    /// hold nothing to join.
    pub(in crate::service) async fn stop_all(&mut self, evt_tx: &mpsc::Sender<CoreEvent>) {
        for search in self.take_waiting() {
            search.retire(evt_tx).await;
        }
        for (search_id, active) in std::mem::take(&mut self.running) {
            active.retire(search_id, evt_tx).await;
        }
    }
}

impl ActiveSearch {
    /// Whether its global sweep was ever sent.
    pub(in crate::service) fn has_swept(&self) -> bool {
        self.global_sweep.is_some()
    }

    /// Hold the global sweep sent for it late, with its server leg.
    pub(in crate::service) fn attach_sweep(&mut self, sweep: Option<JoinHandle<()>>) {
        if self.global_sweep.is_none() {
            self.global_sweep = sweep;
        }
    }

    /// The one retire (ADR-0093), whatever ended the search: its sweep stops,
    /// its task is told to stop and joined within the grace, aborted past it;
    /// a task that panicked is said to have failed, and one that did not say
    /// its own end — it stopped or the abort cut it — is said to be cancelled.
    async fn retire(self, search_id: SearchId, evt_tx: &mpsc::Sender<CoreEvent>) {
        let Self {
            cancel_tx,
            handle,
            mut end_rx,
            global_sweep,
            ..
        } = self;
        if let Some(sweep) = global_sweep {
            sweep.abort();
        }
        // The server request, if out, keeps its place on the link; its
        // answer's rows reach whichever live searches they prove, and none
        // of them is this one any more.
        let _ = cancel_tx.send(true);
        join_or_abort(handle).await;
        match end_rx.try_recv() {
            Ok(SearchEnd::Ended) => {}
            Ok(SearchEnd::Panicked) => {
                let _ = evt_tx
                    .send(
                        SearchEvent::SearchFailed {
                            search_id,
                            reason: SearchFailure::TaskPanicked,
                        }
                        .into(),
                    )
                    .await;
            }
            Ok(SearchEnd::Stopped) | Err(_) => say_cancelled(search_id, evt_tx).await,
        }
    }
}

impl WaitingSearch {
    /// A waiting search's retire: it holds nothing but its place, so it is
    /// only said to be cancelled.
    async fn retire(self, evt_tx: &mpsc::Sender<CoreEvent>) {
        say_cancelled(self.search_id, evt_tx).await;
    }
}

/// Aborts the task it holds when dropped, so aborting the watcher that owns
/// it (the retire's abort past the grace) takes the task down with it.
struct AbortOnDrop(JoinHandle<SearchEnd>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Run `task` as its own task and read how it ended from its join handle
/// (ADR-0093): a panic is a death, `SearchEnd::Panicked`, which reaches the
/// same finish notice as any other end and so the same retire.
async fn run_watched<F>(task: F) -> SearchEnd
where
    F: Future<Output = SearchEnd> + Send + 'static,
{
    let mut inner = AbortOnDrop(tokio::spawn(task));
    match (&mut inner.0).await {
        Ok(end) => end,
        Err(joined) if joined.is_panic() => SearchEnd::Panicked,
        // Aborted from outside this watcher: nobody asked for it to say more.
        Err(_) => SearchEnd::Stopped,
    }
}

async fn say_cancelled(search_id: SearchId, evt_tx: &mpsc::Sender<CoreEvent>) {
    let _ = evt_tx
        .send(SearchEvent::SearchCancelled { search_id }.into())
        .await;
}

#[cfg(test)]
mod tests;
