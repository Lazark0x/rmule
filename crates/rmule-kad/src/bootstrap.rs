//! Where a node starts: the `(IP, UDP port)` endpoint every Kad datagram is
//! addressed to, the seed contacts a config or a nodes.dat hands over, and the
//! Bootstrap Dial List that paces them into one dial at a time.

use std::net::Ipv4Addr;

use crate::KadId;
use crate::nodes_dat_bootstrap::{self, BootstrapEditionError};

/// Where a Kad node is reached: an IP and a **UDP** port.
///
/// Kad speaks only datagrams, so this is deliberately not the node's eD2k TCP
/// port — the two live on the same host but are never interchangeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadNodeEndpoint {
    ip: Ipv4Addr,
    udp_port: u16,
}

impl KadNodeEndpoint {
    /// An endpoint from its two parts.
    #[must_use]
    pub const fn new(ip: Ipv4Addr, udp_port: u16) -> Self {
        Self { ip, udp_port }
    }

    /// The node's address.
    #[must_use]
    pub const fn ip(self) -> Ipv4Addr {
        self.ip
    }

    /// The node's Kad UDP port.
    #[must_use]
    pub const fn udp_port(self) -> u16 {
        self.udp_port
    }
}

/// A dial candidate: somewhere worth sending a bootstrap request, with an ID
/// only if the source happened to know one.
///
/// Deliberately thinner than a routing contact — no TCP port, version,
/// lifecycle state or verified flag — so a candidate cannot be admitted to a
/// routing table without first answering and being re-discovered through the
/// ordinary intake path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadBootstrapNode {
    endpoint: KadNodeEndpoint,
    kad_id: Option<KadId>,
}

impl KadBootstrapNode {
    /// A candidate at this endpoint, with its ID when the source knew one.
    #[must_use]
    pub const fn new(endpoint: KadNodeEndpoint, kad_id: Option<KadId>) -> Self {
        Self { endpoint, kad_id }
    }

    /// Where to dial.
    #[must_use]
    pub const fn endpoint(self) -> KadNodeEndpoint {
        self.endpoint
    }

    /// The candidate's Kad ID, when known. A config seed has none; a
    /// file-loaded candidate does, which is what lets the loader pick the
    /// closest fifty.
    #[must_use]
    pub const fn kad_id(self) -> Option<KadId> {
        self.kad_id
    }
}

/// The CONTEXT.md **Bootstrap Dial List**: an ordered list of candidate
/// contacts dialed one at a time with bootstrap requests until the routing
/// table warms — sourced from config endpoints or a v3 bootstrap-edition
/// nodes.dat (closest-50 to own ID, ADR-0066). Its contacts are never
/// merged into a [`crate::KadRoutingTable`] directly; only their *answers*
/// seed it, through the ordinary contact-intake path. Exists so bootstrap
/// files don't concentrate load on a few famous nodes.
///
/// It is both the file-load target (a v3 bootstrap-edition nodes.dat loads
/// its closest-50 into a fresh list) and the live join-cadence queue: the
/// join sequence unifies config-endpoint seeds with file-loaded candidates
/// into one list ([`extend`](Self::extend)) and dials the front one at a
/// time ([`pop_front`](Self::pop_front), ADR-0067). The cadence
/// itself lives on [`crate::KadNode`].
///
/// The element type is [`KadBootstrapNode`] — endpoint plus an optionally
/// known [`KadId`] — not [`crate::KadContact`]: a dial candidate carries no
/// TCP port, protocol version, lifecycle state, or verified flag, so it
/// cannot be handed to [`crate::KadRoutingTable::upsert`] without first
/// being re-discovered through the ordinary contact intake path. The
/// routing-table/dial-list separation is structural, not just documented.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootstrapDialList {
    candidates: Vec<KadBootstrapNode>,
}

impl BootstrapDialList {
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            candidates: Vec::new(),
        }
    }

    /// Whether the list has no candidates left — the node has run out of
    /// places to dial.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// How many candidates remain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Candidates in dial order — closest-first when loaded from a v3
    /// bootstrap-edition file.
    #[must_use]
    pub fn candidates(&self) -> &[KadBootstrapNode] {
        &self.candidates
    }

    /// Take the candidates in dial order, consuming the list.
    #[must_use]
    pub fn into_candidates(self) -> Vec<KadBootstrapNode> {
        self.candidates
    }

    /// Append candidates to the tail of the list — the join sequence's
    /// **unification** step (ADR-0067): config-endpoint seeds and
    /// file-loaded candidates fold into the one list, dialed in the order they
    /// were fed. Unlike [`load_v3_bootstrap_edition`](Self::load_v3_bootstrap_edition)
    /// (which refuses a non-empty list, aMule's one-bootstrap-file guard), this
    /// deliberately accepts repeated feeds from independent sources.
    pub fn extend(&mut self, candidates: impl IntoIterator<Item = KadBootstrapNode>) {
        self.candidates.extend(candidates);
    }

    /// Remove and return the front candidate — the next one to dial (ADR-0067
    /// s2). The list drains front-to-back; a dialed candidate is discarded
    /// (never re-queued), so bootstrap files don't concentrate load.
    pub fn pop_front(&mut self) -> Option<KadBootstrapNode> {
        if self.candidates.is_empty() {
            None
        } else {
            Some(self.candidates.remove(0))
        }
    }

    /// Load a v3 bootstrap-edition nodes.dat, replacing this list's
    /// (empty) contents with its closest-50-by-XOR-distance selection.
    ///
    /// Refuses with [`BootstrapEditionError::AlreadyLoaded`] if this list
    /// already holds any candidates — aMule's own guard against a second
    /// bootstrap-file load (`RoutingZone.cpp#L237`) — and leaves the list
    /// untouched on any error.
    pub fn load_v3_bootstrap_edition(
        &mut self,
        bytes: &[u8],
        own_id: KadId,
    ) -> Result<(), BootstrapEditionError> {
        if !self.is_empty() {
            return Err(BootstrapEditionError::AlreadyLoaded);
        }
        self.candidates = nodes_dat_bootstrap::decode(bytes, own_id)?;
        Ok(())
    }
}
