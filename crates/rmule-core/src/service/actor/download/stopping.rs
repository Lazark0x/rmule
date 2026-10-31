//! The runs told to stop whose tasks have not ended (ADR-0069, "Stops do not
//! join in a command arm"). The actor goes on taking commands meanwhile, and
//! finishes the operator's act when the task has ended: a stop's tail waits on
//! the store and on the actor's own finish channel, so a join in a command arm
//! would hold every other command and could never end.
//!
//! A later command about a stopping download waits here, so a Pause and the
//! Resume behind it still run in the order they were sent.

use std::collections::HashMap;

use rmule_primitives::FileHash;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

use crate::download::{RunNumber, StopReason};
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
        match stopping.and_then(|download_id| self.stops.get_mut(&download_id)) {
            Some(entry) => {
                entry.stop.held.push(command);
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
