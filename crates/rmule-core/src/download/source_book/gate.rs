//! The **Source Book**'s intake gate: the IP filter and the address family,
//! judged per half of one sighting before the book's other blocks (ADR-0090).
//! The caller lends a [`Gate`] for the one call — the filter's current view and
//! our Dial Position — so the book stays pure and a reload applies from the
//! next sighting.

use rmule_primitives::{PeerEndpoint, SourceSighting};

use super::Blocked;
use crate::dialable::{DialPosition, admit_halves};
use crate::ip_filter::{IpFilter, admits_source};

/// What a sighting is judged by, borrowed for one call.
#[derive(Clone, Copy)]
pub(crate) struct Gate<'a> {
    /// The IP filter's view (aMule `CPartFile::AddSources`): a filtered
    /// address never enters a download's pool.
    pub(crate) filter: &'a IpFilter,
    /// Our Known IPv6, which decides whether an IPv6 address can be dialed
    /// from here (ADR-0087).
    pub(crate) dial: DialPosition,
}

impl Gate<'_> {
    /// The sighting with its addresses judged, or why nothing of it passes.
    ///
    /// Each half is judged on its own ([`admit_halves`]): a refused IPv6 half
    /// is dropped from the sighting, a refused client id leaves the source on
    /// its IPv6 half, both refused blocks it. Then the one address left is
    /// judged by family — an IPv6 address needs an IPv6 of ours to be dialed
    /// from — and by the filter again, for a sighting that named no pair. A
    /// Low-ID row has no address to judge and passes: its real address is
    /// enforced later at the accept and dial gates (aMule's `!IsLowID`). A
    /// Kad callback row is judged by the publisher address it was observed at.
    pub(crate) fn judge(&self, sighting: SourceSighting) -> Result<SourceSighting, Blocked> {
        let judged = admit_halves(sighting, |half| admits_source(self.filter, Some(half)))
            .ok_or(Blocked::IpFiltered)?;
        let endpoint = judged.filter_endpoint();
        if let Some(PeerEndpoint::V6(half)) = endpoint
            && !self.dial.can_dial_ipv6()
        {
            tracing::debug!(
                %half,
                "dropping an IPv6 source: this node holds no IPv6 to dial it from"
            );
            return Err(Blocked::FamilyUnreachable);
        }
        if !admits_source(self.filter, endpoint) {
            return Err(Blocked::IpFiltered);
        }
        Ok(judged)
    }

    /// Whether any half of `sighting` passes the gate.
    pub(crate) fn admits(&self, sighting: SourceSighting) -> bool {
        self.judge(sighting).is_ok()
    }
}
