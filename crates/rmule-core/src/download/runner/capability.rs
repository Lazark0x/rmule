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
//! when the sample moves.
//!
//! [`SharedSelfReach::callback_capability`]: crate::reachability::SharedSelfReach::callback_capability

use rmule_primitives::Ipv4Endpoint;

use crate::download::state::CallbackCapability;

/// Where a download reads its **Callback Capability** from.
pub(crate) struct CallbackFacts {
    /// **Self Reach**: the owner that answers `CanDoCallback`.
    pub(crate) reach: crate::reachability::SharedSelfReach,
}

impl CallbackFacts {
    /// The capability the facts state now.
    pub(crate) fn sample(&self) -> CallbackCapability {
        self.reach.callback_capability()
    }

    /// The server we are logged into now, by the IPv4 address it reached —
    /// the brain's [`CallbackCapability::server`], read live.
    pub(crate) fn server(&self) -> Option<Ipv4Endpoint> {
        self.reach.session().and_then(|session| session.server)
    }
}

#[cfg(test)]
mod tests {
    use rmule_primitives::{ClientId, Informant, SourceSighting};

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
            SourceSighting::plain(rmule_primitives::PeerSource::new(ClientId::from_u32(9), 4662), Informant::Own),
            None,
        )
        .expect("a Low-ID source is a candidate")
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
        };
        let handle = live_listener(&facts.reach);
        assert!(facts.sample().server_relays());

        own.reassign_client_id(ClientId::from_u32(7));
        assert!(!facts.sample().server_relays(), "the Low ID is read live");

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
