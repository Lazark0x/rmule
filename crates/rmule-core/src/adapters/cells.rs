//! The **Adapter Cells** (ADR-0048 "Identity ownership"):
//! every shared cell `Core::builder` creates once and every runtime adapter
//! must hold the *same* instance of — the server session, the ban store, the
//! IP filter, Address Learning (through the session's own-identity cell), the
//! ed2k→Kad handoff, the Peer Roster, the Hello Adverts and the rest.
//!
//! The builder is the one wiring point: its own default adapters and any
//! adapter a caller injects adopt the one set through the same
//! `adopt_cells` trait method, so an injected adapter can never run on a
//! private copy of a cell the node owns. A type rather than a list of setters
//! so a cell added here reaches every adapter that holds it by the compiler's
//! word, not by a reviewer remembering four call sites.

use std::time::Duration;

use rmule_net::family::FamilySelection;

use super::{
    HelloAdverts, SharedCallbackTable, SharedDialedServeSink, SharedKadBootstrap, SharedKadPump,
    SharedTunnelAdmit, SharedTunnelClaims,
};
use crate::address_learning::SharedAddressLearning;
use crate::ban_store::SharedBanStore;
use crate::buddy_link::SharedBuddySlot;
use crate::ip_filter::SharedIpFilter;
use crate::own_identity::SharedOwnIdentity;
use crate::peer_roster::SharedPeerRoster;
use crate::server_session::SharedServerSession;

/// The cells one node's adapters share (see the module docs). Opaque outside
/// the crate: an adapter implemented elsewhere cannot name it, so it keeps the
/// traits' no-op `adopt_cells` — the truth for a fake that touches no cell.
#[derive(Clone)]
pub struct AdapterCells {
    /// The one eD2k server session (ADR-0032); also the home of the node's
    /// own-identity cell and, through it, Address Learning.
    pub(crate) session: SharedServerSession,
    /// The Low-ID callback table (ADR-0039).
    pub(crate) callbacks: SharedCallbackTable,
    /// Where a dialed download connection's serve half goes (ADR-0031).
    pub(crate) dialed_serve_sink: SharedDialedServeSink,
    /// `CoreConfig::slot_wait_timeout`, which the serve half of a called-back
    /// link waits with.
    pub(crate) slot_wait_timeout: Duration,
    /// The ban store (ADR-0064).
    pub(crate) ban_store: SharedBanStore,
    /// The ed2k→Kad handoff sink (ADR-0067).
    pub(crate) kad_bootstrap: SharedKadBootstrap,
    /// The out-of-band Kad signal sink (ADR-0058/0086).
    pub(crate) kad_pump: SharedKadPump,
    /// The Peer Roster (ADR-0059 "Roster relations").
    pub(crate) peer_roster: SharedPeerRoster,
    /// What every hello states about this node, SUI key included.
    pub(crate) hello_adverts: HelloAdverts,
    /// The enacted buddy slot (ADR-0061).
    pub(crate) buddy_slot: SharedBuddySlot,
    /// The IP filter.
    pub(crate) ip_filter: SharedIpFilter,
    /// The firewalled front's command half.
    pub(crate) firewalled_front: crate::firewalled::front::SharedFirewalledFront,
    /// The file-known predicate.
    pub(crate) file_known: crate::known_files::SharedFileKnown,
    /// Where a risen NAT-T Tunnel enters the serve pipeline (ADR-0091).
    pub(crate) tunnel_admit: SharedTunnelAdmit,
    /// The Pending Tunnel Claim table (ADR-0091).
    pub(crate) tunnel_claims: SharedTunnelClaims,
    /// `CoreConfig::address_families` (ADR-0085).
    pub(crate) address_families: FamilySelection,
    /// Where a refused peer hello is counted and raised (ADR-0050).
    pub(crate) hello_refusals: crate::hello_refusals::SharedHelloRefusals,
}

impl AdapterCells {
    /// The node's own-identity cell: its user hash, fixed at build (ADR-0048
    /// "Identity ownership"), and its live session facts.
    pub(crate) fn own_identity(&self) -> &SharedOwnIdentity {
        self.session.own_identity()
    }

    /// The one Address Learning store (ADR-0084).
    pub(crate) fn addresses(&self) -> &SharedAddressLearning {
        self.session.own_identity().addresses()
    }

    /// A set of cells shared with nothing, for an adapter-level unit test that
    /// builds one adapter on its own.
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self {
            session: SharedServerSession::default(),
            callbacks: SharedCallbackTable::default(),
            dialed_serve_sink: SharedDialedServeSink::default(),
            slot_wait_timeout: crate::DEFAULT_SLOT_WAIT_TIMEOUT,
            ban_store: SharedBanStore::default(),
            kad_bootstrap: SharedKadBootstrap::default(),
            kad_pump: SharedKadPump::default(),
            peer_roster: SharedPeerRoster::default(),
            hello_adverts: HelloAdverts::default(),
            buddy_slot: SharedBuddySlot::default(),
            ip_filter: SharedIpFilter::default(),
            firewalled_front: crate::firewalled::front::SharedFirewalledFront::default(),
            file_known: crate::known_files::SharedFileKnown::default(),
            tunnel_admit: SharedTunnelAdmit::default(),
            tunnel_claims: SharedTunnelClaims::default(),
            address_families: FamilySelection::default(),
            hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
        }
    }
}
