//! The **Related-Files Search** gate (ADR-0037): when the
//! search can be asked at all. One rule, read by two parties — the front-end
//! dimming its menu item off the diagnostics level, and the actor refusing a
//! command — so the two can never disagree about why.

use rmule_ed2k::ServerGrants;

use crate::diagnostics::DiagnosticsSnapshot;

/// Why a **Related-Files Search** cannot be asked right now. Nothing is sent
/// in either case, and nothing is dialed: the search belongs to a server the
/// operator is already connected to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelatedSearchRefusal {
    /// No eD2k server session is up. The search goes to the connected server
    /// alone (eMule `CanSearchRelatedFiles`, `SearchResultsWnd.cpp:1658-1663`).
    NotConnected,
    /// The connected server did not grant `SRV_TCPFLG_RELATEDSEARCH` (`0x40`)
    /// in its `OP_IDCHANGE`. eMule greys the item out; aMule refuses with a
    /// message (`SearchListCtrl.cpp:999-1016`).
    NotOffered,
}

/// The gate itself, over the two facts it reads.
pub(crate) const fn refusal(connected: bool, grants: ServerGrants) -> Option<RelatedSearchRefusal> {
    if !connected {
        Some(RelatedSearchRefusal::NotConnected)
    } else if !grants.related_search {
        Some(RelatedSearchRefusal::NotOffered)
    } else {
        None
    }
}

impl DiagnosticsSnapshot {
    /// Why a **Related-Files Search** would be refused now, or `None` when the
    /// connected server grants it — the level a menu dims its item by, and the
    /// same verdict a `StartSearch` with a related query gets.
    #[must_use]
    pub const fn related_search_refusal(&self) -> Option<RelatedSearchRefusal> {
        refusal(
            self.connected_server.is_some(),
            self.connected_server_grants,
        )
    }
}
