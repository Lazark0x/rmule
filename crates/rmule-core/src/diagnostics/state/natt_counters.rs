//! The NAT Traversal counters and records the diagnostics state keeps
//! (ADR-0091): what was attempted, punched, relayed, adopted and refused.

use super::DiagnosticsState;

impl DiagnosticsState {
    /// Count one rendezvous emitted toward a target's serving buddy.
    pub fn count_natt_rendezvous_emitted(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_rendezvous_emitted_total = inner
            .session
            .natt_rendezvous_emitted_total
            .saturating_add(1);
    }

    /// Count one server introduction that became a punch burst.
    pub fn count_natt_server_punch(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_server_punches_total =
            inner.session.natt_server_punches_total.saturating_add(1);
    }

    /// Record one introduction the server refused, and why.
    pub fn record_natt_server_refusal(&self, reason: rmule_ed2k::HolepunchFailReason) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_server_refusals_total =
            inner.session.natt_server_refusals_total.saturating_add(1);
        inner.session.natt_server_last_refusal = Some(reason);
    }

    /// Record one risen **Tunnel**: which transport carried it, and whether
    /// rmule dialed it or accepted it (ADR-0091).
    pub fn record_natt_tunnel(
        &self,
        transport: rmule_net::natt::TunnelTransport,
        role: rmule_net::peer::PeerStreamRole,
    ) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = match role {
            rmule_net::peer::PeerStreamRole::Dialer => &mut inner.session.natt_tunnels_dialed_total,
            rmule_net::peer::PeerStreamRole::Responder => {
                &mut inner.session.natt_tunnels_accepted_total
            }
        };
        *counter = counter.saturating_add(1);
        inner.session.natt_last_tunnel_transport = Some(transport);
    }

    /// Record one endpoint hint the requester ledger refused, and why.
    pub fn record_natt_hint_refusal(&self, refusal: crate::diagnostics::NattHintRefusal) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_hint_refusals_total =
            inner.session.natt_hint_refusals_total.saturating_add(1);
        inner.session.natt_last_hint_refusal = Some(refusal);
    }

    /// Count one `OP_HOLEPUNCH` from an endpoint nothing was expected from.
    pub fn count_natt_unexpected_holepunch(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_unexpected_holepunches_total = inner
            .session
            .natt_unexpected_holepunches_total
            .saturating_add(1);
    }

    /// Count one risen Tunnel closed because the serve pipeline's hand-off
    /// backlog was full (ADR-0091).
    pub fn count_natt_adoption_dropped(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_adoptions_dropped_total =
            inner.session.natt_adoptions_dropped_total.saturating_add(1);
    }

    /// Count one NAT-T datagram the client-UDP front could not hand on.
    pub fn count_natt_inbox_drop(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_inbox_drops_total =
            inner.session.natt_inbox_drops_total.saturating_add(1);
    }

    /// Count one `OP_HOLEPUNCH` whose address expects several peers to dial and
    /// whose port named none of them.
    pub fn count_natt_ambiguous_holepunch(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_ambiguous_holepunches_total = inner
            .session
            .natt_ambiguous_holepunches_total
            .saturating_add(1);
    }

    /// Count one dial started over a punched path — a `connect()`, of which one
    /// attempt may spend several.
    pub fn count_natt_dial(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_dials_total = inner.session.natt_dials_total.saturating_add(1);
    }

    /// Record how many dials an attempt spent, however it ended.
    pub fn record_natt_attempt_dials(&self, dials: u32) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_last_attempt_dials = Some(dials);
    }

    /// Count one **Punch Expectation** evicted by the per-address bound.
    pub fn count_natt_expectation_evicted(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_expectations_evicted_total = inner
            .session
            .natt_expectations_evicted_total
            .saturating_add(1);
    }

    /// Count one accepted Tunnel deliberately attributed to no peer.
    pub fn count_natt_tunnel_unattributed(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_tunnels_unattributed_total = inner
            .session
            .natt_tunnels_unattributed_total
            .saturating_add(1);
    }

    /// Record one target retired as *temporarily unreachable*, and why.
    pub fn record_natt_retirement(&self, reason: crate::diagnostics::NattRetirement) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_retirements_total =
            inner.session.natt_retirements_total.saturating_add(1);
        inner.session.natt_last_retire_reason = Some(reason);
    }

    /// Count one **Traversal Attempt** begun, by which **Rendezvous
    /// coordinator** opened it.
    pub fn count_natt_attempt(&self, by_server: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = if by_server {
            &mut inner.session.natt_attempts_server_total
        } else {
            &mut inner.session.natt_attempts_buddy_total
        };
        *counter = counter.saturating_add(1);
    }

    /// Count one attempt falling through from the server coordinator to the
    /// target's buddy (ADR-0091's fallback ordering).
    pub fn count_natt_fallthrough(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_attempt_fallthroughs_total = inner
            .session
            .natt_attempt_fallthroughs_total
            .saturating_add(1);
    }

    /// Count one download falling to NAT traversal after twelve seconds of
    /// callback silence (ADR-0091), and whether its candidate carried the
    /// User Hash a Tunnel could be claimed by.
    pub fn count_natt_download_fallback(&self, claimable: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_download_fallbacks_total = inner
            .session
            .natt_download_fallbacks_total
            .saturating_add(1);
        if !claimable {
            inner.session.natt_download_fallbacks_unclaimable_total = inner
                .session
                .natt_download_fallbacks_unclaimable_total
                .saturating_add(1);
        }
    }

    /// Count one fallback the selector refused for want of a coordinator.
    pub fn count_natt_download_no_coordinator(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_download_adoptions_no_coordinator_total = inner
            .session
            .natt_download_adoptions_no_coordinator_total
            .saturating_add(1);
    }

    /// Count one **Dialer Tunnel** a download adopted.
    pub fn count_natt_download_adoption(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_download_adoptions_total = inner
            .session
            .natt_download_adoptions_total
            .saturating_add(1);
    }

    /// Count one adoption refused because the hello named another user hash.
    pub fn count_natt_download_adoption_refused(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_download_adoptions_refused_total = inner
            .session
            .natt_download_adoptions_refused_total
            .saturating_add(1);
    }

    /// Count one claim retracted without an adoption.
    pub fn count_natt_download_claim_retired(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_download_claims_retired_total = inner
            .session
            .natt_download_claims_retired_total
            .saturating_add(1);
    }

    /// Count one rendezvous relay, forwarded or refused.
    pub fn count_natt_relay(&self, forwarded: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = if forwarded {
            &mut inner.session.natt_relays_forwarded_total
        } else {
            &mut inner.session.natt_relays_refused_total
        };
        *counter = counter.saturating_add(1);
    }
}
