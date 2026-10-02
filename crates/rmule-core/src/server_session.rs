//! The standing eD2k **server session**: one shared login, the operator's,
//! that every activity rides (single-server, single-identity — ADR-0032),
//! carved along its three responsibilities. The [`slot`] is the cross-activity
//! cell pairing the live handle with the self-facts only a login produces
//! (ADR-0046) and the operator's standing server choice; the [`multiplexer`]
//! is the spawned task that drives every request down the one link and routes
//! the server's statements back into their sinks (ADR-0080); and
//! [`establishment`] owns the dial + login + switch trail
//! behind the IP-filter gate, projecting the login's products
//! into the peer handshake context. A session dies with its link; the slot
//! survives and only the operator's next connect re-establishes (ADR-0095).

mod establishment;
mod hello;
mod multiplexer;
mod slot;

pub use establishment::build_peer_handshake_context;
pub(crate) use establishment::connect_to_server;
pub(crate) use hello::{HelloSource, live_peer_handshake_context};
pub(crate) use multiplexer::{
    SearchStream, ServerSearchEvent, ServerSearchStartError, ServerSessionHandle,
};
pub(crate) use slot::SharedServerSession;

/// Shared fixtures for the submodules' tests: the fake server link the loop
/// and establishment tests both drive, plus the identity/endpoint builders.
#[cfg(test)]
pub(crate) mod tests {
    use rmule_ed2k::{Ed2kCommand, Ed2kEvent};
    use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, ServerEndpoint, UserHash};
    use tokio::sync::mpsc;

    use super::multiplexer::{ServerLink, SessionSinks};
    use crate::own_identity::SharedOwnIdentity;
    use crate::server_list::ServerFacts;

    /// A fake server link: the test pushes `Ed2kEvent`s in and observes the
    /// `Ed2kCommand`s the session sends out. Same channel shape as a real
    /// `Connection` (cmd out, events in), so it exercises the real loop.
    pub(crate) struct FakeLink {
        pub(crate) events: mpsc::Receiver<Ed2kEvent>,
        pub(crate) sent: mpsc::Sender<Ed2kCommand>,
    }

    impl ServerLink for FakeLink {
        async fn send(&self, command: Ed2kCommand) -> Result<(), ()> {
            self.sent.send(command).await.map_err(|_| ())
        }
        async fn next_event(&mut self) -> Option<Ed2kEvent> {
            self.events.recv().await
        }
    }

    pub(crate) fn client_id() -> ClientId {
        ClientId::from_u32(0x0100_007F)
    }

    pub(crate) fn identity() -> ClientIdentity {
        ClientIdentity::new(
            UserHash::from_bytes([0x42; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("rmule-server-session-test"),
            4662,
            60,
        )
    }

    /// The endpoint every test session is bound to — also the row the
    /// welcome-burst tests expect the server's own facts to land on.
    pub(crate) fn connected() -> ServerEndpoint {
        ServerEndpoint::new("10.0.0.1", 4661).expect("valid endpoint")
    }

    /// Sinks over a throwaway list + diagnostics pair: the loop tests that do
    /// not look at the server's own facts still drive the real writes.
    pub(crate) fn test_sinks(own: SharedOwnIdentity) -> SessionSinks {
        SessionSinks {
            server_ip: None,
            own,
            server: connected(),
            facts: ServerFacts::default(),
            ipv6_probe: crate::reachability::SharedIpv6Probe::default(),
            over_ipv6: false,
            punch: Default::default(),
            // Granted, so a related search goes out unless a test withdraws it.
            grants: rmule_ed2k::ServerGrants {
                related_search: true,
                ..rmule_ed2k::ServerGrants::default()
            },
        }
    }

    /// A live session over a fake link for tests outside this module: the
    /// handle, the sender that keeps the link open (drop it and the session
    /// ends), and what the session puts on the wire.
    pub(crate) fn fake_session(
        server: rmule_primitives::ServerEndpoint,
        grants: rmule_ed2k::ServerGrants,
    ) -> (
        super::ServerSessionHandle,
        tokio::sync::mpsc::Sender<rmule_ed2k::Ed2kEvent>,
        tokio::sync::mpsc::Receiver<rmule_ed2k::Ed2kCommand>,
    ) {
        let (events_tx, events) = tokio::sync::mpsc::channel(8);
        let (sent, sent_rx) = tokio::sync::mpsc::channel(8);
        let mut sinks = test_sinks(crate::own_identity::SharedOwnIdentity::default());
        sinks.server = server;
        sinks.grants = grants;
        let handle =
            super::multiplexer::ServerSession::spawn(FakeLink { events, sent }, client_id(), sinks);
        (handle, events_tx, sent_rx)
    }
}
