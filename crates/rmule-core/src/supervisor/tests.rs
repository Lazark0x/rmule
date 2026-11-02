//! A panic becomes the task's death; an abort stays the run's own cancel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{Panicked, spawn_told, watched};
use crate::run_log::LevelHandle;
use crate::service::{CoreEvent, LongTask, outbox};

async fn panics_after_a_yield() {
    tokio::task::yield_now().await;
    panic!("a defect");
}

#[tokio::test]
async fn a_panic_on_a_later_poll_is_read_as_the_runs_end() {
    assert_eq!(watched(panics_after_a_yield()).await, Err(Panicked));
}

#[tokio::test]
async fn aborting_the_caller_cancels_the_run_before_the_join_returns() {
    struct NoteDrop(Arc<AtomicBool>);
    impl Drop for NoteDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let held = NoteDrop(Arc::clone(&dropped));
    let handle = tokio::spawn(async move {
        let _ = watched(async move {
            let _held = held;
            std::future::pending::<()>().await;
        })
        .await;
    });
    tokio::task::yield_now().await;
    handle.abort();
    let _ = handle.await;
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_told_tasks_panic_reaches_the_event_stream() {
    let (events, mut stream) = outbox(LevelHandle::default());
    let weak = events.downgrade();
    let task = spawn_told(LongTask::NattFront, Some(weak), panics_after_a_yield());
    let _ = task.await;
    assert!(matches!(
        stream.recv().await,
        Some(CoreEvent::TaskDied {
            task: LongTask::NattFront
        })
    ));
}

#[tokio::test]
async fn a_told_task_holds_no_stream_open() {
    let (events, mut stream) = outbox(LevelHandle::default());
    let weak = events.downgrade();
    drop(events);
    let _task = spawn_told(
        LongTask::NattFront,
        Some(weak),
        std::future::pending::<()>(),
    );
    assert!(stream.recv().await.is_none());
}
