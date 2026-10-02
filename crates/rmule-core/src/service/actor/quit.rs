//! Quit (ADR-0093): every activity's stop, in dependency order, each within
//! a bound — the one place `Core::shutdown` and a dropped `Core` end the
//! session's work, so no front end has to remember which activities to stop
//! first and no task outlives the core that spawned it.

use std::time::Duration;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};

use super::{CoreActor, send_event};
use crate::service::{CoreEvent, QuitStep};

/// How long quit waits for a search or a download task it has signalled
/// before aborting it, or for the Registry Check's thread before leaving it: both hold nothing that must reach the disk at quit,
/// so the bound only keeps a wedged task from holding the exit.
const QUIT_JOIN_GRACE: Duration = Duration::from_secs(2);

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Retire every activity (ADR-0093): the directory scan, then consumers — the search and
    /// the download read the server session and Kad's source channel — then
    /// the serve listener and the Kad node, and the port-mapping runtime
    /// last, so its release pass hands back ports no socket still holds
    /// (aMule `ShutDown`: the listen socket and the server connection close
    /// before `DeletePortMappings`, `amule.cpp:1407-1423`).
    ///
    /// Each step that has something to stop is announced first as a
    /// [`CoreEvent::Quitting`], so a front end names quit's progress from the
    /// quit itself.
    pub(super) async fn retire_all(&mut self) {
        // The scan feeds the share set every later activity reads, so it
        // stops first.
        if !self.activities.scans.is_empty() {
            announce(&self.evt_tx, QuitStep::DirectoryScan).await;
            self.stop_scans().await;
        }
        // The Registry Check rules on the same share set; it has no quit step
        // of its own, since it ends within one wait of its flag.
        self.registry_check.retire(QUIT_JOIN_GRACE).await;
        if !self.activities.searches.is_empty() {
            announce(&self.evt_tx, QuitStep::Search).await;
            for (_, mut search) in self.activities.searches.drain() {
                search.stop_global();
                let _ = search.cancel_tx.send(true);
                join_or_abort(search.handle).await;
            }
        }
        // Aborted rather than stopped: a stop writes the lifecycle
        // (`Paused`/`Cancelled`), and a quit must leave the store saying
        // `Active` so the next start recovers the download as it was.
        if !self.activities.downloads.is_empty() {
            announce(&self.evt_tx, QuitStep::Download).await;
            // Each run's last ranking, written before the runs are aborted
            // (ADR-0109, "Source Seeds").
            self.write_source_seeds();
            let ids: Vec<_> = self.activities.downloads.keys().copied().collect();
            for download_id in ids {
                if let Some(download) = self.retire_download(download_id) {
                    download.handle.abort();
                    join_or_abort(download.handle).await;
                }
            }
        }
        if self.activities.serve.is_some() {
            announce(&self.evt_tx, QuitStep::Serve).await;
            self.stop_serve().await;
        }
        if self.kad.is_some() {
            announce(&self.evt_tx, QuitStep::Kad).await;
            self.stop_kad().await;
        }
        // The server-UDP front carries the searches' sweeps and the
        // downloads' global discovery, so it goes after both; it holds the
        // server list's store view, so it goes before shutdown returns.
        if let Some(front) = self.server_udp.take() {
            front.retire().await;
        }
        if let Some(port_mapping) = self.port_mapping.take() {
            announce(&self.evt_tx, QuitStep::PortMapping).await;
            port_mapping.retire().await;
        }
        announce(&self.evt_tx, QuitStep::CreditCheckpoint).await;
    }
}

/// Report that quit's `step` begins.
async fn announce(evt_tx: &tokio::sync::mpsc::Sender<CoreEvent>, step: QuitStep) {
    send_event(evt_tx, CoreEvent::Quitting { step }).await;
}

/// Join `handle` within [`QUIT_JOIN_GRACE`], aborting it past that.
async fn join_or_abort<T>(handle: tokio::task::JoinHandle<T>) {
    let abort = handle.abort_handle();
    if tokio::time::timeout(QUIT_JOIN_GRACE, handle).await.is_err() {
        abort.abort();
    }
}
