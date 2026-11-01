//! The runs told to stop whose tasks have not ended (ADR-0069, "Stops do not
//! join in a command arm"). The actor goes on taking commands meanwhile, and
//! finishes the operator's act when the task has ended: a stop's tail waits on
//! the store and on the actor's own finish channel, so a join in a command arm
//! would hold every other command and could never end.
//!
//! A later command about a stopping download waits here, so a Pause and the
//! Resume behind it still run in the order they were sent. So does a stop
//! that met a landing with no answer yet: its gate is waited on here, off the
//! command arm, and the command runs again on the answer.

use std::collections::HashMap;
use std::sync::Arc;

use rmule_primitives::FileHash;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

use crate::download::{CompletionGate, RunNumber, StopReason};
use crate::service::{DownloadCommand, DownloadId};

/// One run told to stop.
pub(super) struct Stop {
    pub(super) file_hash: FileHash,
    pub(super) run: RunNumber,
    pub(super) reason: StopReason,
    /// What came for this download since, in the order it came.
    pub(super) held: Vec<DownloadCommand>,
}

/// One stop's entry: its act, and the run it waits for.
struct Entry {
    stop: Stop,
    run_task: AbortHandle,
}

/// Every stop under way.
#[derive(Default)]
pub(in crate::service::actor) struct Stopping {
    stops: HashMap<DownloadId, Entry>,
    /// The commands waiting on a landing's answer, the stop that met it first.
    settling: HashMap<DownloadId, Vec<DownloadCommand>>,
    ended: JoinSet<DownloadId>,
}

impl Stopping {
    /// Watch `handle` to its end, with `stop` waiting for it.
    pub(super) fn begin(&mut self, download_id: DownloadId, handle: JoinHandle<()>, stop: Stop) {
        let run_task = handle.abort_handle();
        self.stops.insert(download_id, Entry { stop, run_task });
        self.ended.spawn(async move {
            let _ = handle.await;
            download_id
        });
    }

    /// Keep the stop `command` until `gate` has its answer; [`Self::next_ended`]
    /// names the download then. The wait closes the gate, so the command
    /// reads a settled answer when it runs again.
    pub(super) fn await_gate(
        &mut self,
        download_id: DownloadId,
        gate: Arc<CompletionGate>,
        command: DownloadCommand,
    ) {
        self.settling.insert(download_id, vec![command]);
        self.ended.spawn(async move {
            gate.stop().await;
            download_id
        });
    }

    /// The commands that waited on `download_id`'s landing.
    pub(super) fn take_settled(&mut self, download_id: DownloadId) -> Vec<DownloadCommand> {
        self.settling.remove(&download_id).unwrap_or_default()
    }

    /// Keep `command` for when the download it names has stopped; hand it
    /// back when no stop concerns it.
    pub(super) fn hold(&mut self, command: DownloadCommand) -> Option<DownloadCommand> {
        let stopping = match &command {
            DownloadCommand::StartDownload { file, .. } => self
                .stops
                .iter()
                .find(|(_, entry)| entry.stop.file_hash == file.file_hash)
                .map(|(download_id, _)| *download_id),
            DownloadCommand::PauseDownload { download_id }
            | DownloadCommand::ResumeDownload { download_id }
            | DownloadCommand::CancelDownload { download_id }
            | DownloadCommand::ClearDownload { download_id } => Some(*download_id),
            DownloadCommand::ClearDownloads { .. } => None,
        };
        let Some(download_id) = stopping else {
            return Some(command);
        };
        if let Some(entry) = self.stops.get_mut(&download_id) {
            entry.stop.held.push(command);
            return None;
        }
        match self.settling.get_mut(&download_id) {
            Some(waiting) => {
                waiting.push(command);
                None
            }
            None => Some(command),
        }
    }

    /// The next download whose run has ended. Cancel safe; never resolves
    /// with no stop under way.
    pub(in crate::service::actor) async fn next_ended(&mut self) -> DownloadId {
        loop {
            match self.ended.join_next().await {
                Some(Ok(download_id)) => return download_id,
                // A watcher is only aborted by the actor's own drop.
                Some(Err(_)) => {}
                None => std::future::pending().await,
            }
        }
    }

    /// `download_id`'s stop, for its act to finish.
    pub(super) fn finish(&mut self, download_id: DownloadId) -> Option<Stop> {
        self.stops.remove(&download_id).map(|entry| entry.stop)
    }

    /// Whether a stop is under way.
    pub(in crate::service::actor) fn is_empty(&self) -> bool {
        self.stops.is_empty()
    }

    /// End every run still stopping; the downloads they belong to. An
    /// aborted run lets go of the event stream, whose end is Quit's.
    pub(super) fn abort_all(&self) -> Vec<DownloadId> {
        for entry in self.stops.values() {
            entry.run_task.abort();
        }
        self.stops.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stop that met a landing holds what came behind it, and neither runs
    /// until the landing has its answer: the answer is what the stop asks.
    #[tokio::test]
    async fn a_stop_waits_out_a_landing_with_the_commands_behind_it() {
        let download_id = DownloadId::from_u64(7);
        let gate = Arc::new(CompletionGate::settling());
        let mut stopping = Stopping::default();
        stopping.await_gate(
            download_id,
            Arc::clone(&gate),
            DownloadCommand::PauseDownload { download_id },
        );
        let behind = DownloadCommand::ResumeDownload { download_id };
        assert!(stopping.hold(behind).is_none());

        let unsettled =
            tokio::time::timeout(std::time::Duration::from_millis(50), stopping.next_ended());
        assert!(unsettled.await.is_err(), "the landing has no answer yet");

        gate.settle(false);
        assert_eq!(stopping.next_ended().await, download_id);
        let order = stopping.take_settled(download_id);
        assert!(matches!(
            order.as_slice(),
            [
                DownloadCommand::PauseDownload { .. },
                DownloadCommand::ResumeDownload { .. }
            ]
        ));
        assert!(!gate.begin(), "the wait closed the gate behind the stop");
    }
}
