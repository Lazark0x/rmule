//! Quit (ADR-0093): every activity's stop, in dependency order, each within
//! a bound — the one place `Core::shutdown` and a dropped `Core` end the
//! session's work, so no front end has to remember which activities to stop
//! first and no task outlives the core that spawned it.

use std::path::PathBuf;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};

use super::{CoreActor, send_event};
use crate::content::on_pool;
use crate::credit::SharedCreditStore;
use crate::service::activity::{JOIN_GRACE, join_or_abort, unix_now};
use crate::service::{CoreEvent, QuitStep};

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
        // The trail first: what Quit takes down is told by Quit's own steps,
        // not written as reachability moving.
        self.trail.abort();
        // What a front end's grace can still cut short goes first (ADR-0118):
        // every step below can be slow, and this one has nothing to wait for.
        self.credit_flush().await;
        // The scan feeds the share set every later activity reads, so it
        // stops first.
        if self.activities.scans().next().is_some() {
            announce(&self.evt_tx, QuitStep::DirectoryScan).await;
            self.stop_scans().await;
        }
        // The Registry Check rules on the same share set; it has no quit step
        // of its own, since it ends within one wait of its flag. The Offer
        // Checks end before their next part.
        self.registry_check.retire(JOIN_GRACE).await;
        self.offer_checks.stop_all();
        if !self.activities.searches.is_empty() {
            announce(&self.evt_tx, QuitStep::Search).await;
            self.activities.searches.stop_all(&self.evt_tx).await;
        }
        // Aborted rather than stopped: a stop writes the lifecycle
        // (`Paused`/`Cancelled`), and a quit must leave the store saying
        // `Active` so the next start recovers the download as it was.
        if !self.activities.downloads_idle() || !self.stopping.is_empty() {
            announce(&self.evt_tx, QuitStep::Download).await;
            // Each run's last ranking, written before the runs are aborted
            // (ADR-0109, "Source Seeds").
            self.write_source_seeds();
            // A stop the operator asked for is kept: its run ends and its row
            // says so, unlike the runs below.
            self.finish_stops().await;
            let ids: Vec<_> = self.activities.downloads().map(|(id, _)| id).collect();
            for download_id in ids {
                if let Some(download) = self.retire_download(download_id) {
                    download.handle.abort();
                    join_or_abort(download.handle).await;
                }
            }
        }
        if self.activities.serving().is_some() {
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
        // Its readers are gone, and the server hears the end before the ports
        // go, as aMule disconnects in `ShutDown` before `DeletePortMappings`
        // (`amule.cpp:1412-1423`). Bounded: a quit outlasts no stalled link.
        let live = self.wiring.shared_server_session.slot().lock().await.take();
        if let Some(live) = live {
            announce(&self.evt_tx, QuitStep::ServerSession).await;
            let _ = tokio::time::timeout(JOIN_GRACE, live.disconnect()).await;
        }
        if let Some(port_mapping) = self.port_mapping.take() {
            announce(&self.evt_tx, QuitStep::PortMapping).await;
            port_mapping.retire().await;
        }
        // Nothing is offered a route over the client-UDP send half once the
        // session quits; the socket itself closes with the core.
        self.client_udp_bound.clear();
        announce(&self.evt_tx, QuitStep::CreditCheckpoint).await;
    }

    /// The credit's owners, handed to [`flush_credit`] so the actor is not
    /// held across the pool's wait.
    pub(super) fn credit_flush(&self) -> impl Future<Output = ()> + Send + 'static {
        flush_credit(
            self.wiring.credit.clone(),
            self.wiring.clients_met_dir.clone(),
        )
    }
}

/// Make the ring durable, then snapshot it back to `clients.met`, off the
/// actor. The checkpoint is unconditional: the ring is durable whether or not
/// a `clients.met` copy was asked for.
async fn flush_credit(credit: SharedCreditStore, clients_met_dir: Option<PathBuf>) {
    on_pool(move || {
        if let Err(error) = credit.checkpoint() {
            tracing::warn!(%error, "credit checkpoint failed; the last accrual may not be durable");
        }
        let Some(dir) = clients_met_dir.as_deref() else {
            return;
        };
        match credit.snapshot() {
            Ok(snapshot) => {
                if let Err(error) = crate::clients_met::save_clients_met(dir, &snapshot, unix_now())
                {
                    tracing::warn!(%error, "clients.met save failed; credit ring not persisted");
                }
            }
            Err(error) => {
                tracing::warn!(%error, "credit snapshot failed; clients.met not written");
            }
        }
    })
    .await;
}

/// Report that quit's `step` begins.
async fn announce(evt_tx: &crate::service::Outbox, step: QuitStep) {
    send_event(evt_tx, CoreEvent::Quitting { step });
}
