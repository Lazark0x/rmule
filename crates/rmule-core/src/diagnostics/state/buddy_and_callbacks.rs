//! The firewalled node's counters and records on the level: buddy slot state
//! and link, relayed and direct callbacks, upload refusals, malformed asks,
//! the accept backlog and the acting punch.

use super::*;

impl DiagnosticsState {
    /// Record the buddy slot's state (ADR-0061 firewalled-node operation) and
    /// its most recent recruit refusal, exactly as the slot
    /// reports them. A level, not a count: the slot is the single writer of
    /// its own state, so copying it in is the only way the snapshot cannot
    /// drift from it.
    pub(crate) fn set_buddy_state(
        &self,
        state: crate::diagnostics::BuddyState,
        held_since: Option<Instant>,
        recruit_refusal: Option<crate::diagnostics::RecruitRefusal>,
    ) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.buddy_state = state;
        inner.session.buddy_held_since = held_since;
        inner.session.buddy_last_recruit_refusal = recruit_refusal;
    }

    /// Count one buddy link held (`true`) or lost/released (`false`).
    pub(crate) fn record_buddy_link(&self, held: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = if held {
            &mut inner.session.buddy_links_held_total
        } else {
            &mut inner.session.buddy_links_lost_total
        };
        *counter = counter.saturating_add(1);
    }

    /// Count one buddy dial that failed before a link was held.
    pub(crate) fn record_buddy_dial_failed(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.buddy_dials_failed_total =
            inner.session.buddy_dials_failed_total.saturating_add(1);
    }

    /// Count one buddy dial not started because one to the same buddy was in
    /// flight.
    pub(crate) fn record_buddy_dial_refused(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.buddy_dials_refused_total =
            inner.session.buddy_dials_refused_total.saturating_add(1);
    }

    /// Count one buddy refused before any dial because its `0x5A`
    /// connect-options and our obfuscation policy cannot meet.
    pub(crate) fn record_buddy_dial_crypt_incompatible(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = &mut inner.session.buddy_dials_crypt_incompatible_total;
        *counter = counter.saturating_add(1);
    }

    /// Count one **open-node** buddy link held (`true`) or lost (`false`) — the
    /// link a recruit dialed to us, not the one we dialed.
    pub(crate) fn record_served_buddy_link(&self, held: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = if held {
            &mut inner.session.served_buddy_links_held_total
        } else {
            &mut inner.session.served_buddy_links_lost_total
        };
        *counter = counter.saturating_add(1);
    }

    /// Count one inbound `OP_BUDDYPING` answered with `OP_BUDDYPONG` (`true`)
    /// or refused (`false`).
    pub(crate) fn record_served_buddy_ping(&self, answered: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = if answered {
            &mut inner.session.served_buddy_pings_answered_total
        } else {
            &mut inner.session.served_buddy_pings_refused_total
        };
        *counter = counter.saturating_add(1);
    }

    /// Count one relayed `OP_CALLBACK` (`0x99`), dialed back or dropped.
    pub(crate) fn record_relayed_callback(&self, dialed: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = if dialed {
            &mut inner.session.relayed_callbacks_dialed_total
        } else {
            &mut inner.session.relayed_callbacks_dropped_total
        };
        *counter = counter.saturating_add(1);
    }

    /// Count one relayed `OP_CALLBACK` (`0x99`) dropped while this node held
    /// no buddy link at all — a subset of the drops counted
    /// above, distinct from a genuine ADR-0061 gate refusal.
    pub(crate) fn record_relayed_callback_no_buddy(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = &mut inner.session.relayed_callbacks_no_buddy_total;
        *counter = counter.saturating_add(1);
    }

    /// Count one `OP_DIRECTCALLBACKREQ` (`0x95`), dialed back or refused.
    pub(crate) fn record_direct_callback(&self, dialed: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = if dialed {
            &mut inner.session.direct_callbacks_dialed_total
        } else {
            &mut inner.session.direct_callbacks_refused_total
        };
        *counter = counter.saturating_add(1);
    }

    /// Count one `0x95` dial-back opened obfuscated — a subset of
    /// the dials counted above, never a dial of its own.
    pub(crate) fn record_direct_callback_obfuscated(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = &mut inner.session.direct_callbacks_obfuscated_total;
        *counter = counter.saturating_add(1);
    }

    /// Count one `0x95` this node's own obfuscation policy refused to dial
    /// A subset of the refusals counted above.
    pub(crate) fn record_direct_callback_crypt_incompatible(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = &mut inner.session.direct_callbacks_crypt_incompatible_total;
        *counter = counter.saturating_add(1);
    }

    /// Count one ADR-0058 firewall-check (`0x53`) dial-back this node's own
    /// obfuscation policy refused to dial — the two-reading
    /// rule's incompatible leg, lifted from the `0x95` route into the shared home both
    /// routes call.
    pub(crate) fn record_kad_dial_back_crypt_incompatible(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = &mut inner.session.kad_dial_backs_crypt_incompatible_total;
        *counter = counter.saturating_add(1);
    }

    /// Count one upload-slot ask the per-address queue cap turned away
    /// (ADR-0088). Nothing goes out on the wire for such a refusal, so this is
    /// the whole of its record.
    pub(crate) fn record_upload_address_cap_refusal(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.upload_address_cap_refusals_total = inner
            .session
            .upload_address_cap_refusals_total
            .saturating_add(1);
    }

    /// Count one upload-slot ask the **Low-ID abuse guard** turned away
    /// (ADR-0031 amendment). Silent on the wire, so this is the whole
    /// of its record.
    pub(crate) fn record_upload_low_id_abuse_refusal(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.upload_low_id_abuse_refusals_total = inner
            .session
            .upload_low_id_abuse_refusals_total
            .saturating_add(1);
    }

    /// Count one `OP_REASKFILEPING` left unanswered as malformed for its
    /// sender's claim (ADR-0055's name-ask / reask audit). Silent on the wire, so
    /// this is the whole of its record.
    pub(crate) fn record_malformed_reask_ping(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.malformed_reask_pings_total =
            inner.session.malformed_reask_pings_total.saturating_add(1);
    }

    /// Count one `OP_REQUESTFILENAME` refused as malformed for its sender's
    /// claim, its connection closed (ADR-0055's name-ask / reask audit).
    pub(crate) fn record_malformed_name_ask(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.malformed_name_asks_total =
            inner.session.malformed_name_asks_total.saturating_add(1);
    }

    /// Raise the serve **accept backlog** high-water mark to `depth`.
    /// A gauge, not a counter: only a deeper reading moves it.
    pub(crate) fn observe_serve_accept_backlog(&self, depth: usize) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let seen = inner.session.serve_accept_backlog_max.unwrap_or(0);
        inner.session.serve_accept_backlog_max = Some(seen.max(depth));
    }

    /// Count one relayed rendezvous this node acted on. `enacted` is false
    /// when the verdict was a punch but no NAT-T front was running to fire it
    /// — the attempt is still the acting path's, and a punch nobody sent must
    /// not read as one that landed, so it counts as a refusal with no reason.
    pub(crate) fn record_acting_punch(&self, enacted: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if enacted {
            inner.session.acting_punches_total =
                inner.session.acting_punches_total.saturating_add(1);
        } else {
            inner.session.acting_refusals_total =
                inner.session.acting_refusals_total.saturating_add(1);
            inner.session.acting_last_refusal = None;
        }
    }

    /// Count one relayed rendezvous refused, and why. `None` is a frame that
    /// claimed the rendezvous marker and was malformed — it never reached a
    /// gate that could name a reason.
    pub(crate) fn record_acting_refusal(&self, refusal: Option<crate::diagnostics::ActingRefusal>) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.acting_refusals_total = inner.session.acting_refusals_total.saturating_add(1);
        inner.session.acting_last_refusal = refusal;
    }
}
