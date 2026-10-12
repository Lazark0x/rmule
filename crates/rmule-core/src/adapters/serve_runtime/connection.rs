//! The **serve connection**: the two channel-borne halves core and one peer
//! connection speak through, and the handle that owns them.
//!
//! No socket, no listener, no task — a [`ServeConnection`] is a pair of
//! channel ends already wired to whatever drives the wire, which is why core's
//! serve queue can be exercised end to end without a socket. What crosses it
//! is the peer session's own vocabulary (ADR-0031): its `Server` requests and
//! `Connection` facts in, its `Server` commands out, plus the two things only
//! core says — a connection was readopted, or it is to be closed.

use rmule_peer::{ConnectionCommand, ConnectionEvent, PeerCommand, ServerCommand, ServerEvent};
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use crate::CoreError;

/// What one connection hands the **Serve State**: the peer's Server
/// Capability requests and its connection facts, exactly as its session
/// reported them, plus the one fact that exists only in core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeInput {
    /// The peer asked something of our Server Capability.
    Server(ServerEvent),
    /// A fact about the link: the peer's identification and its revisions,
    /// the Secure User Identification verdict, the close. `Identified`
    /// arrives once, before any request on the connection; its
    /// `(connected_server, client_id)` is the Low-ID callback correlation key
    /// the accept-router read first (ADR-0039).
    Connection(ConnectionEvent),
    /// The accept-router matched this inbound peer to a pending callback and
    /// adopted it as a download worker (ADR-0039). It never served, so the
    /// serve task just drops it from the serve set — distinct from
    /// `Disconnected`, which would release a slot it never held.
    Readopted,
}

impl ServeInput {
    /// The close a connection's driver reports by ending its event stream
    /// without a `Disconnected` of its own, or that core reports for a
    /// connection it let go: our side ended it.
    #[must_use]
    pub const fn closed_here() -> Self {
        Self::Connection(ConnectionEvent::Disconnected {
            reason: rmule_peer::PeerCloseReason::Local,
        })
    }

    /// Whether this is the connection's close — the last input it sends.
    #[must_use]
    pub const fn is_disconnect(&self) -> bool {
        matches!(self, Self::Connection(ConnectionEvent::Disconnected { .. }))
    }
}

/// What the Serve State sends down one connection: an answer of the Server
/// Capability, or the connection's close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeOutput {
    /// Frame this Server Capability command on the connection.
    Server(ServerCommand),
    /// Close the connection (queue eviction, a malformed ask, shutdown). On a
    /// connection rmule dialed, only the serve half stops: the download half
    /// may still be pulling over the socket.
    Disconnect,
}

impl From<ServeOutput> for PeerCommand {
    fn from(output: ServeOutput) -> Self {
        match output {
            ServeOutput::Server(command) => Self::Server(command),
            ServeOutput::Disconnect => Self::Connection(ConnectionCommand::Disconnect),
        }
    }
}

/// Core's handle to one accepted, identified serve connection. Mirrors
/// [`PeerWorker`](crate::PeerWorker): outputs go down `command_tx`, inputs
/// arrive on `event_rx`.
pub struct ServeConnection {
    peer: PeerEndpoint,
    command_tx: mpsc::Sender<ServeOutput>,
    event_rx: mpsc::Receiver<ServeInput>,
}

impl ServeConnection {
    /// Wrap an already-accepted connection's two channel halves. The caller
    /// owns the task that drives the socket behind them.
    #[must_use]
    pub fn new(
        peer: PeerEndpoint,
        command_tx: mpsc::Sender<ServeOutput>,
        event_rx: mpsc::Receiver<ServeInput>,
    ) -> Self {
        Self {
            peer,
            command_tx,
            event_rx,
        }
    }

    /// The remote address this connection came in on. It is the *inbound
    /// socket*'s endpoint, so its port is ephemeral — the peer's advertised
    /// listen port arrives with its `Connection(Identified)` instead.
    #[must_use]
    pub const fn peer(&self) -> PeerEndpoint {
        self.peer
    }

    /// Push one output down the connection. Fails once the peer's task is
    /// gone, which is not an error worth retrying — the connection is over.
    pub async fn send(&self, command: ServeOutput) -> Result<(), CoreError> {
        self.command_tx
            .send(command)
            .await
            .map_err(|_| CoreError::Repository("serve connection closed".into()))
    }

    /// The next input, or `None` once the connection is gone. A `None` is the
    /// terminal signal — equivalent to a `Disconnected` — so the consumer must
    /// free the peer's queue slot on either.
    pub async fn next_event(&mut self) -> Option<ServeInput> {
        self.event_rx.recv().await
    }
}
