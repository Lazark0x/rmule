//! The activity-lifecycle vocabulary events name (ADR-0093): why an activity
//! ended, and which step of quit is running.

/// Why the Kad activity ended, mirroring [`ServeStopReason`].
/// `Ended` also covers a lever-confirmed `CoreCommand::DisableKad`;
/// an abort the reaper had to fall back to reads the same as a panic
/// — `TaskFailed` — the same split `finish_serve` draws from a `JoinHandle`'s
/// own result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadStopReason {
    /// The channel behind the pump closed on its own: the deep node's event
    /// stream ended (a receive-error budget exhaustion, or any
    /// other transport failure that makes the node give up its event
    /// stream), which drops the sources channel the actor's discovery task
    /// rides and ends that task cleanly.
    Ended,
    /// The operator's `DisableKad` stopped it, cleanly.
    Stopped,
    /// The task that rides the pump's channel ended abnormally — panicked or
    /// was cancelled — rather than returning, the `JoinHandle`'s own `Err`.
    TaskFailed,
}

/// Why a serve activity ended — the difference between an operator closing the
/// listener and the listener closing itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServeStopReason {
    /// A `StopServing`, or the core shutting the activity down on its way out.
    Requested,
    /// The accept pump ended on its own — a fatal listener error. Nothing asked
    /// for it, and nothing else would have said so.
    ListenerClosed,
    /// The serve task itself ended abnormally. The adapter went with it, so the
    /// next `StartServing` has no listener to bind with — the one case where
    /// this event does not mean "startable again".
    TaskFailed,
}

/// One step of quit (ADR-0093 "Quit order"), in the order it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QuitStep {
    /// The download directory scan stops, abandoning the file in hand.
    DirectoryScan,
    /// The running search stops.
    Search,
    /// The running download is aborted (its store row keeps `Active`).
    Download,
    /// The serve listener closes.
    Serve,
    /// The Kad node stops through its one lever.
    Kad,
    /// The port-mapping runtime releases every lease.
    PortMapping,
    /// The credit ring is checkpointed and `clients.met` written.
    CreditCheckpoint,
}

impl QuitStep {
    /// The step as a front end names it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DirectoryScan => "directory scan",
            Self::Search => "search",
            Self::Download => "download",
            Self::Serve => "serve",
            Self::Kad => "Kad",
            Self::PortMapping => "port mappings",
            Self::CreditCheckpoint => "credit checkpoint",
        }
    }
}
