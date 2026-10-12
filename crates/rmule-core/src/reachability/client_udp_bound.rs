//! The **client-UDP send half bound** family of **Self Reach** (ADR-0060):
//! whether the one client-UDP socket (ADR-0057) is up, so a route that rides
//! its send half — the direct `0x95` callback, every rung-1 punch — can be
//! offered at all. One writer, the client-UDP bind: set once at the actor's
//! prologue when the socket binds, cleared at Quit.

use std::sync::Arc;

use tokio::sync::watch;

/// The family's cell. Cheap to clone; every clone reads the same fact.
#[derive(Clone, Debug)]
pub(crate) struct ClientUdpBound(Arc<watch::Sender<bool>>);

impl Default for ClientUdpBound {
    /// Unbound: no socket has come up.
    fn default() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }
}

impl ClientUdpBound {
    /// The socket bound, and its send half is up.
    pub(crate) fn set(&self) {
        self.0
            .send_if_modified(|bound| !std::mem::replace(bound, true));
    }

    /// Quit ran: nothing is offered a route over the send half again.
    pub(crate) fn clear(&self) {
        self.0
            .send_if_modified(|bound| std::mem::replace(bound, false));
    }

    /// Whether the send half is up.
    pub(crate) fn is_bound(&self) -> bool {
        *self.0.borrow()
    }

    /// A change subscription: wakes on the bind and on its clear.
    pub(crate) fn subscribe(&self) -> watch::Receiver<bool> {
        self.0.subscribe()
    }
}
