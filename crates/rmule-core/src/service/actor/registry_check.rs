//! The **Registry Check** (ADR-0106, "The registry against the disk") as the
//! actor runs it: the worker is spawned with the actor and lives as long as
//! it does, on a blocking-pool thread. The actor applies its rulings, and
//! every other change to what is offered, in one place: the **Withheld
//! Row**s, the **File-Known Predicate**, the serve snapshot's trigger and the
//! Kad publisher's. The worker and the scan share one report lane into the
//! actor, so a worker's read of the registry never misses a change sent
//! before it.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

use rmule_primitives::FileHash;
use tokio::sync::mpsc;

use crate::adapters::{
    KadRuntimeFactory, NotifyFolderWatch, PeerTransferService, ServeRuntimeService,
    SourceLookupService,
};
use crate::directory_scan::FsDirectorySource;
use crate::registry::{
    AutoShared, SharedFileEntry, SharedFileRegistry, auto_share_completed_download,
};
use crate::registry_check::{
    CheckInput, CheckReport, CheckSeams, WithheldReason, WithheldRows, run_check,
};
use crate::service::activity::ScanStop;
use crate::service::{DownloadId, ServeEvent};

use super::scan::ScanMessage;
use super::{CoreActor, notify_kad_publisher, send_event};

/// What the scan's worker and the Registry Check's worker send the actor.
#[derive(Debug)]
pub(super) enum RegistryMessage {
    /// From the Download Directory Scan.
    Scan(ScanMessage),
    /// The Registry Check wants the registry as it stands after every
    /// message sent before this one.
    RowsWanted(std::sync::mpsc::Sender<Vec<SharedFileEntry>>),
    /// A ruling of the Registry Check.
    Check(CheckReport),
}

/// The sender both workers report on; the actor holds one for its whole
/// life, so its arm never sees the channel closed.
pub(super) type RegistrySender = mpsc::UnboundedSender<RegistryMessage>;

/// The running Registry Check: where to tell it things, the withheld set it
/// rules into, and its stop.
pub(super) struct RegistryCheckHandle {
    inputs: std::sync::mpsc::Sender<CheckInput>,
    pub(super) withheld: WithheldRows,
    stop: ScanStop,
    /// The worker thread, until quit retires it; `None` when it never
    /// started.
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RegistryCheckHandle {
    /// Tell the worker something; a worker that has ended hears nothing.
    pub(super) fn tell(&self, input: CheckInput) {
        let _ = self.inputs.send(input);
    }

    /// Retire the worker at quit (ADR-0093): raise its flag and join the
    /// thread, off the executor, for at most `grace`. It ends within one
    /// wait of its flag; past `grace` a wedged thread is left to end alone,
    /// since a thread cannot be aborted and this one holds no store handle.
    pub(super) async fn retire(&mut self, grace: Duration) {
        self.stop.raise();
        let Some(worker) = self.worker.take() else {
            return;
        };
        let joined = tokio::task::spawn_blocking(move || worker.join());
        match tokio::time::timeout(grace, joined).await {
            Ok(Ok(Err(_))) => tracing::error!("the registry check ended in a panic"),
            Ok(Ok(Ok(()))) => {}
            Ok(Err(error)) => tracing::error!(%error, "the registry check's join failed"),
            Err(_) => tracing::warn!("the registry check did not end within its grace"),
        }
    }

    /// Where the serve side reports a failed read.
    pub(super) fn inputs(&self) -> std::sync::mpsc::Sender<CheckInput> {
        self.inputs.clone()
    }
}

/// Start the Registry Check over the real filesystem and folder watch, on a
/// thread of its own rather than the runtime's blocking pool: it lives as
/// long as the actor, and a pool task that never ends would hold a runtime's
/// shutdown, and a paused test clock, for its whole life. It ends within one
/// wait of its flag, raised and joined at quit, or raised when the actor drops.
///
/// `at_start` is the registry as it stands before the actor takes its first
/// command, and the start look rules on exactly those rows: a row the
/// operator shares during the run is a change like any other, however late
/// the thread gets to its first look. Asked of the actor instead, a slow
/// thread start would hand the start look a file shared and deleted in the
/// run's first seconds, and a gone row at start is withheld until the first
/// recheck a minute on, not ruled gone. `None` — the registry unreadable —
/// asks the actor, as every later read does.
pub(super) fn spawn_registry_check(
    tx: RegistrySender,
    at_start: Option<Vec<SharedFileEntry>>,
) -> RegistryCheckHandle {
    let withheld = WithheldRows::before_start_look();
    let (inputs, inputs_rx) = std::sync::mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let spawned = std::thread::Builder::new()
        .name("registry-check".into())
        .spawn({
            let (withheld, stop) = (withheld.clone(), Arc::clone(&stop));
            move || {
                let mut watch = NotifyFolderWatch::new();
                let mut at_start = at_start;
                run_check(
                    CheckSeams {
                        source: &FsDirectorySource,
                        watch: &mut watch,
                        rows: &mut || at_start.take().or_else(|| rows_now(&tx, &stop)),
                        inputs: &inputs_rx,
                        report: &mut |report| {
                            let _ = tx.send(RegistryMessage::Check(report));
                        },
                    },
                    &withheld,
                    &stop,
                );
            }
        });
    let worker = match spawned {
        Ok(worker) => Some(worker),
        Err(error) => {
            tracing::error!(%error, "the registry check could not start; nothing will be offered");
            None
        }
    };
    RegistryCheckHandle {
        inputs,
        withheld,
        stop: ScanStop(stop),
        worker,
    }
}

/// The registry as the actor stands after every message sent before asking;
/// `None` once the check is stopping or the actor is gone.
fn rows_now(tx: &RegistrySender, stop: &AtomicBool) -> Option<Vec<SharedFileEntry>> {
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    tx.send(RegistryMessage::RowsWanted(reply_tx)).ok()?;
    loop {
        match reply_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(rows) => return Some(rows),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                if !stop.load(std::sync::atomic::Ordering::Relaxed) => {}
            Err(_) => return None,
        }
    }
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Apply one message from either worker.
    pub(super) async fn on_registry_message(&mut self, message: RegistryMessage) {
        match message {
            RegistryMessage::Scan(message) => self.on_scan_message(message).await,
            RegistryMessage::RowsWanted(reply) => match self.wiring.registry.list() {
                Ok(rows) => {
                    let _ = reply.send(rows);
                }
                // A dropped reply ends the asking worker.
                Err(error) => tracing::warn!(%error, "registry unreadable for a worker"),
            },
            RegistryMessage::Check(report) => self.on_check_report(report).await,
        }
    }

    async fn on_check_report(&mut self, report: CheckReport) {
        match report {
            CheckReport::Offer(file_hash) => self.offer_again(file_hash).await,
            CheckReport::Withhold { file_hash, reason } => {
                self.withhold(file_hash, None, reason).await;
            }
            CheckReport::Unshare(file_hash) => {
                let left = self.wiring.registry.unshare(file_hash);
                self.row_left(file_hash, left).await;
            }
            CheckReport::Gone { file_hash, path } => {
                let left = self.wiring.registry.gone(file_hash, &path);
                self.row_left(file_hash, left).await;
            }
            CheckReport::StartLookDone => {
                let withheld = &self.registry_check.withheld;
                withheld.looked();
                let rows = self.wiring.registry.list().unwrap_or_default();
                for row in withheld.offered(rows) {
                    self.wiring.file_known.share(row.file_hash);
                }
                self.share_set_changed();
            }
            CheckReport::WatchUnavailable(_) => {
                send_event(&self.evt_tx, ServeEvent::SharesUnwatched.into()).await;
            }
        }
    }

    /// Nothing is to be offered for `file_hash`'s row, if the registry still
    /// holds it (at `path`, when given). A row under a refused entry is
    /// withheld as refused, whatever its file looks like.
    pub(super) async fn withhold(
        &mut self,
        file_hash: FileHash,
        path: Option<&std::path::Path>,
        reason: WithheldReason,
    ) {
        let Some(row) = self
            .wiring
            .registry
            .get(file_hash)
            .ok()
            .flatten()
            .filter(|row| path.is_none_or(|path| row.path == path))
        else {
            return;
        };
        let reason = if self.directories.refuses(&row.path) {
            WithheldReason::Refused
        } else {
            reason
        };
        let since = SystemTime::now();
        if !self
            .registry_check
            .withheld
            .withhold(file_hash, reason, since)
        {
            return;
        }
        tracing::info!(
            file_hash = %file_hash.to_hex_upper(),
            ?reason,
            "shared file withheld: not readable now",
        );
        self.wiring.file_known.unshare(file_hash);
        self.share_set_changed();
        send_event(
            &self.evt_tx,
            ServeEvent::FileWithheld {
                file_hash,
                reason,
                since,
            }
            .into(),
        )
        .await;
    }

    /// A withheld row's file opens again: it is offered, unless it lies
    /// under a refused entry, where nothing is offered however readable, or
    /// the registry no longer holds it.
    async fn offer_again(&mut self, file_hash: FileHash) {
        let Ok(Some(row)) = self.wiring.registry.get(file_hash) else {
            return;
        };
        if self.directories.refuses(&row.path) || !self.registry_check.withheld.lift(file_hash) {
            return;
        }
        tracing::info!(file_hash = %file_hash.to_hex_upper(), "shared file offered again");
        self.wiring.file_known.share(file_hash);
        self.share_set_changed();
        send_event(&self.evt_tx, ServeEvent::FileOffered { file_hash }.into()).await;
    }

    /// A completing download's file in place at `path` joins the registry
    /// (ADR-0031, ADR-0115): offered, or withheld as refused when it lies
    /// under an entry the guards refuse (ADR-0101). `true` when the row was
    /// written — a share-set change either way, whose trigger is the
    /// caller's to fire once its download's Served Download has ended too
    /// (ADR-0113).
    pub(super) async fn share_completion(
        &mut self,
        download_id: DownloadId,
        path: &std::path::Path,
    ) -> bool {
        let shared = auto_share_completed_download(
            download_id,
            path,
            &*self.wiring.store,
            &*self.wiring.registry,
            |path| self.directories.refuses(path),
            &self.registry_check.withheld,
            &self.evt_tx,
        )
        .await;
        match shared {
            Some(AutoShared::Offered(file_hash)) => self.row_written(file_hash),
            Some(AutoShared::Refused(file_hash)) => {
                // Whatever row it replaced is no longer offered either.
                self.wiring.file_known.unshare(file_hash);
                self.registry_check.tell(CheckInput::RowsChanged);
            }
            None => {}
        }
        shared.is_some()
    }

    /// A row was written for `file_hash`: its content is on disk now and
    /// offered, whatever held it before.
    pub(super) fn row_shared(&self, file_hash: FileHash) {
        self.row_written(file_hash);
        self.share_set_changed();
    }

    /// [`Self::row_shared`] less the trigger.
    fn row_written(&self, file_hash: FileHash) {
        self.registry_check.withheld.lift(file_hash);
        self.wiring.file_known.share(file_hash);
        self.registry_check.tell(CheckInput::RowsChanged);
    }

    /// A row the actor was asked to remove left the registry, or did not.
    pub(super) async fn row_left(
        &mut self,
        file_hash: FileHash,
        left: Result<bool, crate::CoreError>,
    ) {
        match left {
            Ok(true) => {
                send_event(&self.evt_tx, ServeEvent::FileUnshared { file_hash }.into()).await;
                self.registry_check.withheld.lift(file_hash);
                self.wiring.file_known.unshare(file_hash);
                self.share_set_changed();
                self.registry_check.tell(CheckInput::RowsChanged);
            }
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "changed or vanished file not unshared"),
        }
    }

    /// The share set moved: the serve task re-snapshots and re-announces, and
    /// the Kad publisher re-sweeps.
    pub(super) fn share_set_changed(&self) {
        if let Some(serve) = self.activities.serving() {
            serve.share_changed();
        }
        notify_kad_publisher(&self.kad);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Quit returns only after the worker ended: its input channel is closed
    /// the moment the thread's stack is gone, so a send failing straight
    /// after `retire` proves the join, not a lucky wait.
    #[tokio::test]
    async fn retire_returns_after_the_worker_ended() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut check = spawn_registry_check(tx, Some(Vec::new()));
        let inputs = check.inputs();
        assert!(inputs.send(CheckInput::RowsChanged).is_ok());

        check.retire(Duration::from_secs(5)).await;

        assert!(inputs.send(CheckInput::RowsChanged).is_err());
    }
}
