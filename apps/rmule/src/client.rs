//! The `CoreClient` seam (ADR-0069): the only door UI code has to the core.

use rmule_core::CoreCommand;

/// Command door to the core. Fire-and-forget: every outcome — acceptance,
/// rejection, progress — comes back as an event on the action bus, never as a
/// return value, so the UI has exactly one read path for state.
///
/// v1 binds this in-process ([`crate::bridge`]); the daemon-era remote
/// transport (EC revival) implements the same trait and the UI runs unchanged.
pub trait CoreClient: Send + Sync {
    /// Hand `command` over and return, whatever the core is doing: the UI
    /// loop never waits on a binding (ADR-0069, "The bridge is two tasks").
    /// Errs only when the core has stopped.
    fn send(&self, command: CoreCommand) -> Result<(), CoreClientError>;
}

/// Why a [`CoreClient::send`] could not land.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CoreClientError {
    /// The core (or its bridge) has stopped; no further commands can land.
    #[error("core stopped")]
    CoreStopped,
}
