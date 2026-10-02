//! **Callback Capability**: our own half of the **Low-ID Admission** — whether
//! we may ask anyone to dial us back, and for which candidate.
//!
//! It is aMule's `CamuleApp::CanDoCallback` (`amule.cpp:3207-3256` at the
//! pinned tree), stated over three facts rather than aMule's nested branches:
//! a bound inbound listener (nothing can dial back a node that is not
//! listening, ADR-0039), the **Server High ID**, and the ADR-0058 Kad TCP
//! verdict. Either reachability fact is enough — the same union as
//! `IsFirewalled()` — with one carve-out aMule states in a comment: a node that
//! is Low-ID on its server but Kad-open must not have *its own server* relay a
//! callback, "as this breaks the protocol and will get you banned". So the
//! answer is per candidate, not per download: the carve-out turns on the
//! candidate's server namespace.
//!
//! The value is **Self Reach**'s answer (`SharedSelfReach::callback_capability`, ADR-0060),
//! the only place it is built outside tests. The
//! runner re-reads it on every Reach Generation and on its tick and hands the
//! brain a new one when it moves; the brain never holds a
//! login-time copy.

use rmule_primitives::Ipv4Endpoint;

use super::LowIdCandidate;
use crate::own_identity::ConnectedSession;

/// A sample of [`CanDoCallback`](self)'s three facts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CallbackCapability {
    /// The inbound listener is bound: the conjunct every road shares.
    listener_bound: bool,
    /// Where the live eD2k session leaves us.
    server: ServerStanding,
    /// The ADR-0058 Kad TCP verdict reads reachable.
    kad_open: bool,
}

/// Our standing on the eD2k server, as far as a callback cares.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ServerStanding {
    /// No live session.
    #[default]
    Disconnected,
    /// Logged in with a Low ID, on `server` (`None` when its host is not an
    /// IPv4 literal — then no candidate can be proven to share it by address).
    LowId { server: Option<Ipv4Endpoint> },
    /// Logged in with a High ID: the server dialled our TCP port and reached it.
    HighId,
}

impl CallbackCapability {
    /// Callable by nobody: no listener, no session, Kad not open.
    #[cfg(test)]
    pub(crate) const UNCALLABLE: Self = Self {
        listener_bound: false,
        server: ServerStanding::Disconnected,
        kad_open: false,
    };

    /// Sample the three facts: whether the listener is bound, the live
    /// session's self-facts, and whether the Kad TCP verdict reads reachable.
    pub(crate) fn of(
        listener_bound: bool,
        session: Option<ConnectedSession>,
        kad_open: bool,
    ) -> Self {
        let server = match session {
            None => ServerStanding::Disconnected,
            Some(live) if live.client_id.is_high_id() => ServerStanding::HighId,
            Some(live) => ServerStanding::LowId {
                server: live.server,
            },
        };
        Self {
            listener_bound,
            server,
            kad_open,
        }
    }

    /// aMule's `CanDoCallback(candidate's server)`: may we ask for a callback
    /// that makes `candidate` dial us?
    pub(crate) fn admits(&self, candidate: &LowIdCandidate) -> bool {
        if !self.listener_bound {
            return false;
        }
        match self.server {
            ServerStanding::HighId => true,
            ServerStanding::Disconnected => self.kad_open,
            // The carve-out: Kad-open saves a Low-ID node everywhere except on
            // its own server, where a callback would be relayed for a Low ID.
            ServerStanding::LowId { server } => self.kad_open && !on_server(candidate, server),
        }
    }

    /// Whether a *server* may relay a callback for us — the connected server's
    /// `OP_CALLBACKREQUEST` or a per-server `OP_GLOBCALLBACKREQUEST` (ADR-0039,
    /// ADR-0051). Only on a server High ID: on our own server that is exactly
    /// what the carve-out leaves, and the global form's payload is our High-ID
    /// contact, which a Low ID does not have. aMule has no road to a
    /// remote-server Low-ID source without a buddy at all (`TryToConnect`
    /// removes it, `BaseClient.cpp:2114-2121`), so this is never wider than
    /// aMule.
    pub(crate) fn server_relays(&self) -> bool {
        self.listener_bound && self.server == ServerStanding::HighId
    }

    /// A server High ID with a bound listener: the capability before a Kad
    /// verdict alone could count, and still the one a test states when it
    /// means "callable".
    #[cfg(test)]
    pub(crate) fn server_high_id() -> Self {
        Self {
            listener_bound: true,
            server: ServerStanding::HighId,
            kad_open: false,
        }
    }
}

/// Whether `candidate` is on the server we are logged into: its id is in that
/// server's namespace (a connected-server record, or a global one the same
/// server answered for). A Kad row is on no server.
fn on_server(candidate: &LowIdCandidate, ours: Option<Ipv4Endpoint>) -> bool {
    if candidate.from_kad {
        return false;
    }
    match candidate.source_server {
        None => true,
        Some(source_server) => ours == Some(source_server),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::{ClientId, ExchangedSource, PeerSource};

    use super::*;

    const OUR_SERVER: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661);
    const OTHER_SERVER: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4661);

    fn session(client_id: u32) -> Option<ConnectedSession> {
        Some(ConnectedSession {
            server: Some(OUR_SERVER),
            client_id: ClientId::from_u32(client_id),
        })
    }

    const HIGH: u32 = 0x0A00_0001;
    const LOW: u32 = 7;

    fn server_candidate(source_server: Option<Ipv4Endpoint>) -> LowIdCandidate {
        LowIdCandidate::from_source(
            ExchangedSource::plain(PeerSource::new(ClientId::from_u32(9), 4662)),
            source_server,
        )
        .expect("a Low-ID source is a candidate")
    }

    fn kad_candidate() -> LowIdCandidate {
        LowIdCandidate {
            from_kad: true,
            ..server_candidate(None)
        }
    }

    /// aMule's `CanDoCallback` without its carve-out: either reachability fact
    /// admits every candidate, neither admits none, and nothing is callable
    /// without a listener to dial.
    #[test]
    fn a_server_high_id_or_an_open_kad_verdict_makes_us_callable() {
        let candidates = [
            server_candidate(None),
            server_candidate(Some(OTHER_SERVER)),
            kad_candidate(),
        ];
        for (capability, callable) in [
            // Only server connected - HighID; both connected, Kad don't care.
            (CallbackCapability::of(true, session(HIGH), false), true),
            (CallbackCapability::of(true, session(HIGH), true), true),
            // Only Kad connected - Kad open / firewalled.
            (CallbackCapability::of(true, None, true), true),
            (CallbackCapability::of(true, None, false), false),
            // Both connected - both firewalled; only server - LowID.
            (CallbackCapability::of(true, session(LOW), false), false),
            // Reachable, but nobody can dial a listener that is not bound.
            (CallbackCapability::of(false, session(HIGH), true), false),
        ] {
            for candidate in &candidates {
                assert_eq!(
                    capability.admits(candidate),
                    callable,
                    "{capability:?} for {candidate:?}"
                );
            }
        }
    }

    /// The carve-out: Low-ID on the server but Kad-open is callable for a
    /// candidate on any *other* server or on Kad, never for one on our own —
    /// by namespace or by address. And no server relays for a Low ID at all.
    #[test]
    fn a_low_id_kad_open_node_is_never_callable_on_its_own_server() {
        let capability = CallbackCapability::of(true, session(LOW), true);

        assert!(!capability.admits(&server_candidate(None)));
        assert!(!capability.admits(&server_candidate(Some(OUR_SERVER))));
        assert!(capability.admits(&server_candidate(Some(OTHER_SERVER))));
        assert!(capability.admits(&kad_candidate()));
        assert!(!capability.server_relays());
    }
}
