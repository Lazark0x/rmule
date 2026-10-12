//! Whether a serve activity's listener is bound *right now*:
//! **Callback Capability**'s listener conjunct, read live rather than
//! captured once at a download's spawn. A serve started after a download
//! began used to never make it callable, and a serve that later stopped left
//! it believing it still was — the other two conjuncts (Server High ID, the
//! Kad TCP verdict) were already live ([`crate::own_identity::SharedOwnIdentity`],
//! [`crate::KadReachLevel`]); this is the listener's turn.
//!
//! [`SharedServeListener`] holds the exact `JoinHandle` the actor's ledger
//! owns for the current serve activity, as an [`AbortHandle`] clone —
//! [`AbortHandle::is_finished`] answers the identical question
//! `Activities::serve_is_live` used to ask of the ledger directly, so a
//! reader outside the actor (a download runner's own task) gets the same
//! truth, not a second copy of it that a start or a stop could forget to
//! flip in sync.
//!
//! The cell is a `watch`: every [`bind`](SharedServeListener::bind) and
//! [`clear`](SharedServeListener::clear) is a change event, folded into
//! **Self Reach**'s **Reach Generation** (ADR-0060), so a
//! subscriber re-derives Callback Capability at the listener's move rather
//! than on a tick.

use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinHandle};

/// A live, cheaply-cloneable read of "is a serve listener bound right now,
/// and on which port." `None` (the default) is the actor's resting state — no
/// serve activity has ever bound one, or the last one has been
/// [`clear`](Self::clear)ed.
#[derive(Clone, Debug)]
pub(crate) struct SharedServeListener(Arc<watch::Sender<Option<BoundListener>>>);

/// The serve activity a [`SharedServeListener`] points at: its task, and the
/// port its listener actually bound — the port a callback invites a dial to.
#[derive(Clone, Debug)]
pub(crate) struct BoundListener {
    task: AbortHandle,
    port: u16,
}

impl Default for SharedServeListener {
    fn default() -> Self {
        Self(Arc::new(watch::Sender::new(None)))
    }
}

impl SharedServeListener {
    /// Point at the serve activity the actor just spawned, listening on
    /// `port` — called once, at the same site `Activities::serve` is set to
    /// `Some` (`StartServing`).
    pub(crate) fn bind<T>(&self, handle: &JoinHandle<T>, port: u16) {
        self.0.send_replace(Some(BoundListener {
            task: handle.abort_handle(),
            port,
        }));
    }

    /// The activity ended, requested or not — called once, at the same site
    /// `Activities::serve` is taken back (`StopServing` or the serve-ended
    /// reclaim). Nobody is listening until the next [`bind`](Self::bind).
    pub(crate) fn clear(&self) {
        self.0.send_replace(None);
    }

    /// Whether the bound activity, if any, is still running.
    pub(crate) fn is_live(&self) -> bool {
        self.port().is_some()
    }

    /// The port the bound listener answers on, while its activity runs.
    pub(crate) fn port(&self) -> Option<u16> {
        self.0
            .borrow()
            .as_ref()
            .filter(|bound| !bound.task.is_finished())
            .map(|bound| bound.port)
    }

    /// A change subscription: wakes on every [`bind`](Self::bind) and
    /// [`clear`](Self::clear).
    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<BoundListener>> {
        self.0.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_bound_reads_not_live() {
        assert!(!SharedServeListener::default().is_live());
    }

    /// The listener-death property, relocated: a task's `JoinHandle` (and so its
    /// `AbortHandle`) resolves the moment its loop ends, before any reclaim
    /// runs — `is_live` must not be fooled by a listener that finished but
    /// has not yet been `clear`ed.
    #[tokio::test]
    async fn a_finished_task_reads_not_live_though_it_was_never_cleared() {
        let listener = SharedServeListener::default();
        let handle = tokio::spawn(async {});
        listener.bind(&handle, 4662);
        assert!(listener.is_live());

        handle.await.expect("task completes");
        assert!(
            !listener.is_live(),
            "a resolved task cannot be the listener a download's callback capability needs"
        );

        listener.clear();
        assert!(!listener.is_live());
    }

    /// A serve started after a download began must be picked up on the very
    /// next read — the defect this cell exists to close.
    #[tokio::test]
    async fn a_later_bind_makes_a_previously_dark_listener_live() {
        let listener = SharedServeListener::default();
        assert!(!listener.is_live(), "no serve activity yet");

        let handle = tokio::spawn(std::future::pending::<()>());
        listener.bind(&handle, 4662);
        assert!(listener.is_live(), "the new activity is live immediately");

        handle.abort();
        listener.clear();
        assert!(!listener.is_live());
    }
}
