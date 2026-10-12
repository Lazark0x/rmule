//! The serve activity's ledger value (ADR-0093): the spawned `ServeTask`, the
//! channels to stop it and to tell it the share set changed, and its own stop
//! — signal, then join within [`SERVE_STOP_GRACE`], aborting past it. What its
//! start installed outside the task is the actor's retire to return.

use std::net::SocketAddrV4;

use tokio::sync::{mpsc, watch};
use tokio::task::{JoinError, JoinHandle};

use crate::adapters::ServeConnection;
use crate::mailbox::Lease;
use crate::serve::ServeOutcome;

/// How long a retire waits for the serve task it stopped before aborting it
/// (ADR-0093 invariant 3): the task can be parked writing to a connection
/// whose peer stopped reading, and then it never sees its stop signal. An
/// aborted task takes the adapter with it, so the stop reads `TaskFailed`.
const SERVE_STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// A running serve activity.
pub(in crate::service) struct ServeActivity<L> {
    /// Which start this is: the value the task's end bumps `serve_ended` to
    /// (ADR-0093), so a stale bump never retires a successor.
    generation: u64,
    stop_tx: watch::Sender<bool>,
    share_changed_tx: mpsc::Sender<()>,
    /// The task, whose *result* is the serve adapter. One serve
    /// adapter exists per core and the activity holds it for its life, so the
    /// only place it can come back from is here — awaiting this handle is how
    /// the actor takes it back, and why serving is restartable at all.
    handle: JoinHandle<ServeOutcome<L>>,
    /// The address the listener actually bound — the one a peer dials to reach
    /// us, and so the one an outbound callback must name. aMule reads the same
    /// fact from `thePrefs::GetPort()` when it writes its own `0x95` body. The
    /// *requested* address is never stored: with port 0 the OS chooses, and a
    /// `0x95` naming the requested 0 would be a dead invitation.
    ///
    /// A plain value, not a shared cell: the actor binds before it spawns the
    /// task, so this activity exists only once the bind is a fact
    /// and there is no window in which it could be unknown.
    bound: SocketAddrV4,
    /// This start's claim on the dialed-serve sink: dropped when the activity
    /// ends, after the task is joined, so dialed connections stop being handed
    /// to a serve task that no longer exists.
    _dialed_sink: Lease<ServeConnection>,
}

impl<L> ServeActivity<L> {
    /// The activity a start made: start `generation`, its task `handle`
    /// listening on `bound`, stopped through `stop_tx` and told of share-set
    /// changes through `share_changed_tx`, with `dialed_sink` the lease that
    /// opened the dialed-serve sink for it.
    pub(in crate::service) const fn new(
        generation: u64,
        stop_tx: watch::Sender<bool>,
        share_changed_tx: mpsc::Sender<()>,
        handle: JoinHandle<ServeOutcome<L>>,
        bound: SocketAddrV4,
        dialed_sink: Lease<ServeConnection>,
    ) -> Self {
        Self {
            generation,
            stop_tx,
            share_changed_tx,
            handle,
            bound,
            _dialed_sink: dialed_sink,
        }
    }

    /// Which start this is.
    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    /// The address the listener actually bound.
    pub(in crate::service) const fn bound(&self) -> SocketAddrV4 {
        self.bound
    }

    /// The actually-bound listener port — the one route 2 invites a dial to.
    pub(in crate::service) const fn bound_listen_port(&self) -> u16 {
        self.bound.port()
    }

    /// Tell the task the share set moved: it re-snapshots and re-announces.
    /// One pending nudge already covers the next.
    pub(in crate::service) fn share_changed(&self) {
        let _ = self.share_changed_tx.try_send(());
    }

    /// End the task, whatever ended the activity: signal its stop — a task
    /// already ended ignores it — and join it within [`SERVE_STOP_GRACE`],
    /// aborting it past that. The task's outcome carries the adapter back; an
    /// error means the adapter is lost.
    pub(in crate::service) async fn end(self) -> Result<ServeOutcome<L>, JoinError> {
        let _ = self.stop_tx.send(true);
        let mut handle = self.handle;
        match tokio::time::timeout(SERVE_STOP_GRACE, &mut handle).await {
            Ok(joined) => joined,
            Err(_) => {
                tracing::warn!("the stopped serve task did not end within its grace; aborting it");
                handle.abort();
                handle.await
            }
        }
    }
}
