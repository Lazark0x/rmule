//! The live facts behind one download's **Callback Capability**, read where
//! they are owned rather than copied at the run's start (so the `callback_capability`
//! reader no longer misses a mid-session `OP_IDCHANGE`).
//!
//! Its reachability facts — the **Server High ID** and the Kad TCP verdict —
//! and the union aMule's `CanDoCallback` states over them are **Self
//! Reach**'s ([`SharedSelfReach::callback_capability`]), the
//! listener conjunct included — its binds and clears are Reach
//! Generation wakes. The runner samples at start, on every
//! **Reach Generation**, and on its one-second tick, and hands the brain a
//! new [`CallbackCapability`]
//! when the sample moves; the enactment of a per-server global callback reads
//! the requester contact from the same session, so the road the brain admits
//! and the payload the runner sends never disagree.
//!
//! [`SharedSelfReach::callback_capability`]: crate::reachability::SharedSelfReach::callback_capability

use rmule_primitives::{Ipv4Endpoint, PeerSource};

use crate::download::state::CallbackCapability;

/// Where a download reads its **Callback Capability** from.
pub(crate) struct CallbackFacts {
    /// **Self Reach**: the owner that answers `CanDoCallback`.
    pub(crate) reach: crate::reachability::SharedSelfReach,
    /// The TCP port the Core Settings name; a `0` presents the port the
    /// listener holds bound as each request is sent — the one a called-back
    /// peer dials.
    pub(crate) our_tcp_port: u16,
}

impl CallbackFacts {
    /// The capability the facts state now.
    pub(crate) fn sample(&self) -> CallbackCapability {
        self.reach.callback_capability()
    }

    /// The server we are logged into now, when its host is an IPv4 literal —
    /// the brain's [`CallbackCapability::server`], read live.
    pub(crate) fn server(&self) -> Option<Ipv4Endpoint> {
        self.reach.session().and_then(|session| session.server)
    }

    /// Our own contact for an `OP_GLOBCALLBACKREQUEST` payload (ADR-0051): our
    /// High-ID address (decoded exactly as a source is) and the TCP port a
    /// hello presents now. `None` off a server High ID, which is also when
    /// [`CallbackCapability::server_relays`] admits no global callback.
    pub(crate) fn requester(&self) -> Option<Ipv4Endpoint> {
        let session = self.reach.session()?;
        let port = self.reach.presented_tcp_port(self.our_tcp_port);
        PeerSource::new(session.client_id, port).high_id()
    }
}

#[cfg(test)]
mod tests {
    use rmule_primitives::{ClientId, SourceSighting};

    use super::*;
    use crate::KadReachLevel;
    use crate::download::state::LowIdCandidate;
    use crate::own_identity::ConnectedSession;
    use crate::own_identity::SharedOwnIdentity;
    use crate::reachability::{SharedKadVerdicts, SharedSelfReach, TcpReachability};

    /// Self Reach over `own` and a Kad level — the owner the actor weaves.
    fn reach_over(own: &SharedOwnIdentity, kad: KadReachLevel) -> SharedSelfReach {
        SharedSelfReach::new(
            kad,
            own.clone(),
            crate::natt::front::SharedNattFront::default(),
        )
    }

    /// Bind `reach`'s listener to a task a test holds live for as long as it
    /// keeps the returned handle pending — mirrors production's `bind`
    /// without a real serve activity. The caller aborts the handle when done.
    fn live_listener(reach: &SharedSelfReach) -> tokio::task::JoinHandle<()> {
        let handle = tokio::spawn(std::future::pending::<()>());
        reach.listener().bind(&handle, 4662);
        handle
    }

    fn low_id_candidate() -> LowIdCandidate {
        LowIdCandidate::from_sighting(
            SourceSighting::plain(PeerSource::new(ClientId::from_u32(9), 4662)),
            None,
        )
        .expect("a Low-ID source is a candidate")
    }

    /// A settings port of `0` gives the called-back peer the port the
    /// listener holds bound as the request is sent, as the hello does: a
    /// listener restarted on another port is named from then on.
    #[test]
    fn a_requester_port_of_zero_is_the_port_the_listener_holds_now() {
        let own = SharedOwnIdentity::default();
        own.set_connected_session(Some(ConnectedSession {
            server: None,
            client_id: ClientId::from_u32(0x0A00_0001),
        }));
        let facts = CallbackFacts {
            reach: reach_over(&own, KadReachLevel::fixed(false)),
            our_tcp_port: 0,
        };
        let v4 = rmule_net::family::FamilyBinds {
            bound: vec![rmule_primitives::AddressFamily::V4],
            refused: Vec::new(),
        };
        for port in [51_234, 51_235] {
            own.addresses()
                .record_bind(crate::address_learning::SocketRole::Tcp, &v4, port);
            assert_eq!(
                facts.requester().map(|requester| requester.port),
                Some(port)
            );
        }
    }

    /// The login-snapshot defect, for this reader: the capability used to be computed from
    /// the download's login answer, so a server that re-assigned us a Low ID
    /// mid-run left the download asking it to relay callbacks. Read from the
    /// self-facts, the re-assignment and the session's end both land.
    #[tokio::test]
    async fn a_mid_session_reassignment_withdraws_the_server_relay() {
        let own = SharedOwnIdentity::default();
        own.set_connected_session(Some(ConnectedSession {
            server: None,
            client_id: ClientId::from_u32(0x0A00_0001),
        }));
        let facts = CallbackFacts {
            reach: reach_over(&own, KadReachLevel::fixed(false)),
            our_tcp_port: 4662,
        };
        let handle = live_listener(&facts.reach);
        assert!(facts.sample().server_relays());
        assert!(facts.requester().is_some());

        own.reassign_client_id(ClientId::from_u32(7));
        assert!(!facts.sample().server_relays(), "the Low ID is read live");
        assert_eq!(facts.requester(), None, "a Low ID has no contact to give");

        own.set_connected_session(None);
        assert_eq!(facts.sample(), CallbackCapability::of(true, None, false));
        handle.abort();
    }

    /// The listener half, first case: a serve started *after* this download's
    /// spawn — the listener facts hold nothing live at first — is picked up
    /// the moment it binds, on the very next sample. Server-disconnected +
    /// Kad-open isolates the listener conjunct from the own-server carve-out.
    #[tokio::test]
    async fn a_serve_started_mid_download_admits_a_waiting_low_id_row_on_the_next_sample() {
        let facts = CallbackFacts {
            reach: reach_over(&SharedOwnIdentity::default(), KadReachLevel::fixed(true)),
            our_tcp_port: 4662,
        };
        let candidate = low_id_candidate();
        assert!(
            !facts.sample().admits(&candidate),
            "nothing can dial a listener that has not started yet"
        );

        let handle = tokio::spawn(std::future::pending::<()>());
        facts.reach.listener().bind(&handle, 4662);
        assert!(
            facts.sample().admits(&candidate),
            "the serve activity that just started admits the waiting row"
        );
        handle.abort();
    }

    /// The listener half, second case: a serve that stops mid-download
    /// withdraws the capability for a *new* admission. A candidate already on
    /// a callback road keeps its slot until its own release — that is the
    /// brain's concern over an unmoving
    /// sample, not this reader's, and is untouched by this change.
    #[tokio::test]
    async fn a_stopped_serve_withdraws_the_capability_for_new_admissions() {
        let facts = CallbackFacts {
            reach: reach_over(&SharedOwnIdentity::default(), KadReachLevel::fixed(true)),
            our_tcp_port: 4662,
        };
        let handle = live_listener(&facts.reach);
        let candidate = low_id_candidate();
        assert!(
            facts.sample().admits(&candidate),
            "serving and Kad-open admits the row"
        );

        handle.abort();
        facts.reach.listener().clear();
        assert!(
            !facts.sample().admits(&candidate),
            "the stopped serve leaves no listener for a new admission"
        );
    }

    /// The capability is Self Reach's `CanDoCallback`, so an
    /// open Kad TCP verdict admits a Kad-sourced Low-ID row on the very next
    /// sample — and a stopped node (its verdicts reset) withdraws it — with no
    /// copy of the verdict in the download.
    #[tokio::test]
    async fn the_capability_follows_the_kad_verdict_self_reach_publishes() {
        let own = SharedOwnIdentity::default();
        own.set_connected_session(Some(ConnectedSession {
            server: None,
            client_id: ClientId::from_u32(7), // Low ID
        }));
        let kad = SharedKadVerdicts::default();
        let facts = CallbackFacts {
            reach: reach_over(&own, KadReachLevel::published(kad.clone())),
            our_tcp_port: 4662,
        };
        let handle = live_listener(&facts.reach);
        let row = LowIdCandidate {
            from_kad: true,
            ..low_id_candidate()
        };
        assert!(!facts.sample().admits(&row), "Low ID and Kad firewalled");

        let lease = kad.lease();
        kad.set_tcp(TcpReachability::Open);
        assert!(facts.sample().admits(&row), "Kad TCP open");
        drop(lease);
        assert!(!facts.sample().admits(&row), "the node stopped");
        handle.abort();
    }
}
