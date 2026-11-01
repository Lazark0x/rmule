//! The one reader of a long task's panic (ADR-0118). A build that unwinds
//! ends the one task a panic happened on, and these two doors turn that end
//! into the task's death: [`watched`] for an activity whose ledger retires
//! it, [`spawn_told`] for a front or a pump no ledger owns. A dist build
//! aborts before either is reached.

use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::task::Poll;

use tokio::task::JoinHandle;

use crate::service::{CoreEvent, LongTask, WeakOutbox};

/// The run's polling panicked. What it panicked on is the panic hook's
/// record; this says only that the run is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Panicked;

/// Run `task` in place and read a panic out of it. No second task stands
/// between the caller and the run: aborting the caller cancels the run, and
/// its end means the run has ended.
pub(crate) async fn watched<F: Future>(task: F) -> Result<F::Output, Panicked> {
    let mut task = std::pin::pin!(task);
    poll_fn(
        |cx| match catch_unwind(AssertUnwindSafe(|| task.as_mut().poll(cx))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(Panicked)),
        },
    )
    .await
}

/// Spawn `work`, a task no ledger retires, and tell its panic as
/// [`CoreEvent::TaskDied`]. `events` is weak: a told task holds the event
/// stream open no longer than its own work does.
pub(crate) fn spawn_told<F>(task: LongTask, events: Option<WeakOutbox>, work: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if watched(work).await.is_err()
            && let Some(events) = events.and_then(|events| events.upgrade())
        {
            events.send(CoreEvent::TaskDied { task });
        }
    })
}

#[cfg(test)]
mod tests;
