//! The **credit ring**'s minute: what moved in memory goes to the Durable Store
//! on the blocking pool, never on a loop that accrues it (ADR-0083). The bound:
//! a crash loses at most [`CREDIT_FLUSH_INTERVAL`] of accrual, and however busy
//! the transfers the store sees one transaction a minute. The same minute
//! says a store a failed write stopped (ADR-0083), whichever seam it failed on.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::content::on_pool;
use crate::credit::SharedCreditStore;
use crate::download::persist::tell_store_stop;
use crate::store::download::DurableDownloadRepository;

/// How often what moved is written.
const CREDIT_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The periodic write, running on its own task until
/// [`finish`](CreditFlush::finish).
pub(super) struct CreditFlush {
    stop: mpsc::Sender<()>,
    periodic: JoinHandle<()>,
}

impl CreditFlush {
    /// Start writing `credit` once a minute.
    pub(super) fn start(
        credit: SharedCreditStore,
        store: Arc<DurableDownloadRepository>,
        evt_tx: crate::service::Outbox,
    ) -> Self {
        let (stop, mut stopped) = mpsc::channel::<()>(1);
        let periodic = tokio::spawn(async move {
            let mut tick = tokio::time::interval(CREDIT_FLUSH_INTERVAL);
            tick.tick().await; // nothing has moved at start
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let credit = credit.clone();
                        if let Err(error) = on_pool(move || credit.checkpoint()).await {
                            tracing::warn!(%error, "credit flush failed; retried next time");
                        }
                        tell_store_stop(&store, &evt_tx);
                    }
                    _ = stopped.recv() => return,
                }
            }
        });
        Self { stop, periodic }
    }

    /// Stop, so no older write lands after Quit's own checkpoint.
    pub(super) async fn finish(self) {
        drop(self.stop);
        let _ = self.periodic.await;
    }
}
