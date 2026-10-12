//! The wait for a peer's hello, shared by the connection rmule dialed and the
//! one it accepted: drain the session's events until the peer identifies or
//! the link ends first, reporting a refused hello on the way (ADR-0050).
//!
//! The handshake guarantees no request precedes the identification, so
//! nothing a capability needs is lost by waiting; a node-wide side-channel
//! frame can arrive first (a Kad dial-back may ack before its hello is
//! folded), and goes to the caller.

use std::future::Future;

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{ConnectionEvent, PeerCloseReason, PeerEvent, PeerIdentity, SideEvent};
use tokio::sync::mpsc;

use crate::hello_refusals::SharedHelloRefusals;

/// Where a peer's events come from while its hello is awaited: the
/// connection itself, or the stream a router fans its events into.
pub(crate) trait PeerEvents {
    /// The next event, or `None` once the source is gone.
    fn next_peer_event(&mut self) -> impl Future<Output = Option<PeerEvent>> + Send;
}

impl PeerEvents for PeerConnection {
    fn next_peer_event(&mut self) -> impl Future<Output = Option<PeerEvent>> + Send {
        self.next_event()
    }
}

impl PeerEvents for mpsc::Receiver<PeerEvent> {
    fn next_peer_event(&mut self) -> impl Future<Output = Option<PeerEvent>> + Send {
        self.recv()
    }
}

/// How the wait for a hello ended.
pub(crate) enum Opening {
    /// The peer identified itself.
    Identified(Box<PeerIdentity>),
    /// The session closed before it did, for this reason.
    Closed(PeerCloseReason),
    /// The events stopped with no close reported.
    Ended,
}

/// Wait for the peer behind `events` to identify. A refused hello is reported
/// to `hello_refusals` (its close follows); a side-channel frame is handed to
/// `on_side`; anything else before the hello is dropped.
pub(crate) async fn await_hello(
    events: &mut impl PeerEvents,
    hello_refusals: &SharedHelloRefusals,
    mut on_side: impl FnMut(SideEvent),
) -> Opening {
    while let Some(event) = events.next_peer_event().await {
        match event {
            PeerEvent::Connection(ConnectionEvent::Identified { identity }) => {
                return Opening::Identified(Box::new(identity));
            }
            PeerEvent::Connection(ConnectionEvent::HelloRefused { refusal }) => {
                hello_refusals.report(refusal).await;
            }
            PeerEvent::Connection(ConnectionEvent::Disconnected { reason }) => {
                return Opening::Closed(reason);
            }
            PeerEvent::Side(side) => on_side(side),
            PeerEvent::Connection(_)
            | PeerEvent::Requester(_)
            | PeerEvent::Server(_)
            | PeerEvent::Notice(_) => {}
        }
    }
    Opening::Ended
}
