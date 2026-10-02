//! [`RuntimeKadFactory`]'s shape: the shared cells and config it is built
//! from, and the builder methods that wire them in before `start` ever runs.
//! The trait implementation that spawns the node and pumps its events —
//! `KadRuntimeFactory for RuntimeKadFactory` — stays in the parent module,
//! which is why every field here is `pub(super)`: this file owns the struct,
//! `node.rs` owns what it does once started.

use crate::adapters::kad_runtime::{KadPresenceView, SharedKadBootstrap, SharedKadPump};
use crate::adapters::{AdapterCells, HelloAdverts};
use crate::address_learning::SharedAddressLearning;
use crate::ban_store::SharedBanStore;
use crate::buddy_link::SharedBuddySlot;
use crate::ip_filter::SharedIpFilter;
use crate::reachability::SharedKadVerdicts;

/// Starts the real `rmule_net::kad` driver on `EnableKad`. No `Default`: its
/// only constructor takes the builder's `AdapterCells`, so no factory holds
/// a private copy of a cell the node owns.
pub struct RuntimeKadFactory {
    /// The core-owned `BanStore` (ADR-0064): every `FloodOffenderDetected`
    /// event the node reports folds into it here. Default/empty on the
    /// non-`Core::new` constructor (nothing is ever banned); `Core::builder`
    /// shares the one production instance with the two peer-TCP adapters.
    pub(super) ban_store: SharedBanStore,
    /// The ed2k→Kad handoff sink (ADR-0067): `start` installs its sender here
    /// so the peer surfaces can broker Kad hints to the running node. Default/
    /// empty on the non-`Core::new` constructor (no handoff); `Core::builder`
    /// shares the one production instance with the two peer adapters that push.
    pub(super) kad_bootstrap: SharedKadBootstrap,
    /// The enacted buddy slot (socket unification, ADR-0061): the pump's
    /// `0x51` recruit fills it and its `0x52` relay rides the held link it
    /// holds. `Core::builder` shares the one production instance with the
    /// accept path (which attaches the link) and the client-UDP front (the
    /// `0x94` relay).
    pub(super) buddy_slot: SharedBuddySlot,
    /// The one [`HelloAdverts`], read here for four things:
    /// - its **firewalled** slot (ADR-0061) — this pump runs the
    ///   recruit trigger over the `Reachability` store below (the only place
    ///   both verdicts and the recheck clock are live) and fills the slot from
    ///   a verified `0x5A`; everything after that is the firewalled front's,
    ///   reached through the cell beside it;
    /// - its **Advertised IPv6** (ADR-0087), carried into the node ahead of
    ///   every source publish so the `ip6` tag names an address rmule holds
    ///   *now*;
    /// - its obfuscation policy (ADR-0046): the recruit gate refuses while it
    ///   reads `Required` — aMule's own limitation, callback requests are not
    ///   obfuscatable, so a node that will only ever speak crypt recruits no
    ///   buddy it could not use — and the ADR-0058 dial-back
    ///   broker meets it with the requester's stance;
    /// - the whole bundle, for the hellos this pump's own dials send: the
    ///   firewall-check dial-back and the UDP-check helper dial.
    ///
    /// Default/empty on the non-`Core::builder` constructor (no advert, crypt
    /// off); `Core::builder` shares the one production instance.
    pub(super) hello: HelloAdverts,
    /// The firewalled front's command half: where this pump
    /// reports a Kad start/stop, every TCP-verdict change, and the buddy a
    /// `0x5A` just named so the front can dial it.
    pub(super) firewalled_front: crate::firewalled::front::SharedFirewalledFront,
    /// The ADR-0058 Kad verdicts this factory's pump publishes — the Kad
    /// family of **Self Reach**. Owned here rather than handed
    /// in: the pump that settles them is the one this factory spawns, so the
    /// cell has exactly one writer and every reader goes through
    /// `RuntimeKadFactory::kad_reach`.
    pub(super) kad_verdicts: SharedKadVerdicts,
    /// aMule's `HasHadContact` latch (ADR-0067): set by this factory's pump on
    /// the node's silent→heard edge (`HadContact`) or a probe answer,
    /// read by the actor when answering `DumpDiagnostics`. The same
    /// single-writer owned-cell shape as `kad_verdicts`; an atomic because
    /// the fact is a monotonic boolean.
    pub(super) had_contact: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Live routing-table size: the pump counts the node's paired
    /// `ContactAdded`/`ContactEvicted` events into it; the actor reads it when
    /// answering `DumpDiagnostics`. Same owned-cell discipline as the latch.
    pub(super) contact_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// The node's keyword index size: the pump stores the `stored`
    /// figure every index change reports; reset with the table at start.
    pub(super) keywords_stored: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Kad traffic across the shared client-UDP bind: the node's
    /// transport counts into it, the actor reads it when answering
    /// `DumpDiagnostics`. Not reset at start — a session total across every
    /// node this factory runs.
    pub(super) kad_traffic: rmule_net::kad::KadTraffic,
    /// The **Address Learning** store (ADR-0084) the pump folds the node's
    /// `0x58`/`0x61` observations into, and reads the settled Kad-UDP verdict
    /// back out of. Shared with every other feeder through the session cell,
    /// so the ladder ranks a Kad report against the server's assignment rather
    /// than beside it.
    pub(super) addresses: SharedAddressLearning,
    /// The core-owned IP filter: `start` arms the node's
    /// contact-admission predicate over it, the Kad half of aMule's four
    /// `kademlia/` `IsFiltered` sites. Default/empty on the non-`Core::new`
    /// constructor (everything admitted); `Core::builder` shares the one
    /// production instance with every other enforcement surface.
    pub(super) ip_filter: SharedIpFilter,
    /// The out-of-band Kad signal sink (ADR-0058/0086): `start` installs its
    /// pump sender here so a port-mapping grant and an inbound
    /// `OP_KAD_FWTCPCHECK_ACK` can both reach the running node. Default/empty on
    /// the non-`Core::builder` constructor (nothing to signal); `Core::builder`
    /// shares the one production instance with the port-mapping runtime, the
    /// accept path and the actor's operator command.
    pub(super) kad_pump: SharedKadPump,
    /// The live diagnostics state, installed once by the actor
    /// before `start` (see `KadRuntimeFactory::install_diagnostics`): the
    /// ADR-0058 dial-back broker's pump is the single writer of its own
    /// crypt-incompatible refusal counter. Default/empty on the non-`Core::new`
    /// constructor and until installed (nothing counted, same as any other
    /// silent refusal).
    pub(super) diagnostics: crate::diagnostics::DiagnosticsState,
    /// The session self-facts (ADR-0032), read for one level: the **Server
    /// High ID** the pump copies into its `Reachability` store, so the
    /// direct-callback bit reads aMule's `IsFirewalled()` union.
    /// Default on the non-`Core::builder` constructor: no session, Low ID.
    pub(super) own: crate::own_identity::SharedOwnIdentity,
    /// The core-owned Peer Roster (ADR-0059): the pump's
    /// requester gate consults it before dialling an engaged UDP Firewall
    /// Helper candidate. Default/empty on the non-`Core::builder`
    /// constructor (nobody is ever known); `Core::builder` shares the one
    /// production instance with `RuntimeServeRuntimeService`'s
    /// `InboundPeerDeps`.
    pub(super) peer_roster: crate::peer_roster::SharedPeerRoster,
    /// The ed2k→Kad handoff forwarder's task handle: `start`
    /// fills this the same run it installs the sender into `kad_bootstrap`,
    /// so `KadRuntimeFactory::take_handoff_handle` has something to hand
    /// `DisableKad` back. `None` before the first `start` and again once
    /// taken.
    pub(super) handoff_handle: Option<tokio::task::JoinHandle<()>>,
    /// **Kad Presence**: whether a node runs, and as which Kad
    /// ID. The cell lives here so the surfaces this runtime wires read it;
    /// its one writer is the Kad Activity's lease in the actor's ledger
    /// (ADR-0093), taken through **Self Reach**.
    pub(super) kad_presence: KadPresenceView,
}

impl RuntimeKadFactory {
    /// A factory over `cells` — `Core::builder`'s one set, or a unit test's
    /// detached one.
    #[must_use]
    pub(crate) fn new(cells: &AdapterCells) -> Self {
        let mut factory = Self {
            ban_store: SharedBanStore::default(),
            kad_bootstrap: SharedKadBootstrap::default(),
            addresses: SharedAddressLearning::default(),
            kad_pump: SharedKadPump::default(),
            had_contact: std::sync::Arc::default(),
            contact_count: std::sync::Arc::default(),
            keywords_stored: std::sync::Arc::default(),
            kad_traffic: rmule_net::kad::KadTraffic::default(),
            buddy_slot: SharedBuddySlot::default(),
            hello: HelloAdverts::default(),
            firewalled_front: crate::firewalled::front::SharedFirewalledFront::default(),
            kad_verdicts: SharedKadVerdicts::default(),
            ip_filter: SharedIpFilter::default(),
            diagnostics: crate::diagnostics::DiagnosticsState::default(),
            own: crate::own_identity::SharedOwnIdentity::default(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            handoff_handle: None,
            kad_presence: KadPresenceView::default(),
        };
        factory.adopt(cells);
        factory
    }

    /// Point every builder-owned cell this factory holds at `cells`' one
    /// instance (the `KadRuntimeFactory::adopt_cells` body).
    pub(super) fn adopt(&mut self, cells: &AdapterCells) {
        self.ban_store = cells.ban_store.clone();
        self.kad_bootstrap = cells.kad_bootstrap.clone();
        self.addresses = cells.addresses().clone();
        self.kad_pump = cells.kad_pump.clone();
        self.buddy_slot = cells.buddy_slot.clone();
        self.hello = cells.hello_adverts.clone();
        self.firewalled_front = cells.firewalled_front.clone();
        self.ip_filter = cells.ip_filter.clone();
        self.own = cells.own_identity().clone();
        self.peer_roster = cells.peer_roster.clone();
    }

    /// The wire identity this node's Kad dials present: the credentials as
    /// the node's hash, fixed at build (ADR-0048 "Identity ownership")
    /// — also the Kad source ID and the buddy identity's hash. Its port
    /// is the one peers dial; aMule's `RequestTCP` self-connect guard compares
    /// a requester against it together with the live public IPv4
    /// — Address Learning's projection, re-read at every guard check
    /// — and matches on port alone while no IPv4 is known yet.
    pub(super) fn node_identity(
        &self,
        config: &crate::adapters::KadEnableConfig,
    ) -> Result<rmule_primitives::ClientIdentity, crate::CoreError> {
        let user_hash = self.own.user_hash().ok_or_else(|| {
            crate::CoreError::KadUnavailable("no node user hash: never adopted by a builder".into())
        })?;
        Ok(config.peer_credentials.identity(user_hash))
    }

    /// Re-point this factory's firewalled slot and front (a unit test's
    /// seam).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_firewalled(
        mut self,
        hello: HelloAdverts,
        front: crate::firewalled::front::SharedFirewalledFront,
    ) -> Self {
        self.hello = hello;
        self.firewalled_front = front;
        self
    }
}
