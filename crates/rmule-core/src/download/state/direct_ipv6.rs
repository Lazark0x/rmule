//! **Rung 0** of a download's Low-ID route (ADR-0061's route tree, ADR-0087's
//! rung): a Low-ID candidate that named a usable IPv6, while we hold a Known
//! IPv6 of our own, is dialed there directly — ahead of every callback road and
//! the punch — and falls to those roads only when that dial never connects.
//!
//! The classic "Low ID ⇒ callback" rule governs a peer's *IPv4 identity*; its
//! IPv6 address stands on its own, and a firewalled peer that has one needs no
//! broker at all. `ReachPeer` has taken this rung since ADR-0087 through
//! [`select_callback_route`](crate::callback::select_callback_route); this is
//! the download's reading of the same rung, through the same
//! [`choose_dial`] AND, so the two cannot disagree about when an IPv6 half is
//! dialable. Which half of a candidate is spent or held is the **Source
//! Book**'s to judge, before it asks this rule.

use std::time::Instant;

use rmule_primitives::PeerEndpoint;

use crate::dialable::{DialPosition, choose_dial};

use super::{CallbackCapability, Decision, DownloadState, LowIdCandidate, LowIdRoad};

/// How a Low-ID candidate is reached **first** — the admission rule a
/// download's slot fill reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::download) enum LowIdRoute {
    /// Rung 0: dial the candidate's IPv6 half, as a plain worker. A dial that
    /// never connects hands the candidate to [`Self::Road`]'s rule, once.
    DirectIpv6(PeerEndpoint),
    /// A callback road or the punch ([`LowIdRoad::of`]).
    Road(LowIdRoad),
}

impl LowIdRoute {
    /// The one site that orders rung 0 ahead of the callback roads.
    ///
    /// Rung 0 is the [`choose_dial`] AND — the candidate named an IPv6 half
    /// **and** `dial` holds a Known IPv6 of ours — and nothing else: no
    /// callback capability is consulted, because nobody is asked to dial us.
    /// Otherwise the candidate's road is [`LowIdRoad::of`]'s, unchanged, and
    /// `None` is still the honest starvation it always was.
    ///
    /// Stated here rather than in [`DownloadState`] because the runner asks it
    /// too, of the lookup snapshot, before any brain exists.
    pub(in crate::download) fn of(
        capability: &CallbackCapability,
        dial: DialPosition,
        candidate: &LowIdCandidate,
    ) -> Option<Self> {
        match choose_dial(None, candidate.ipv6, dial) {
            Some(half) => Some(Self::DirectIpv6(half)),
            None => LowIdRoad::of(capability, candidate).map(Self::Road),
        }
    }
}

impl DownloadState {
    /// Our Known IPv6 moved (ADR-0087: re-derived on every advert, never
    /// cached). A candidate starved under the old sample may be dialable now,
    /// so the free slots fill; a dial already under way is left alone.
    pub(crate) fn on_dial_position(&mut self, now: Instant, dial: DialPosition) -> Vec<Decision> {
        if dial == self.dial {
            return Vec::new();
        }
        self.dial = dial;
        let mut out = Vec::new();
        self.fill(now, &mut out);
        out
    }
}
