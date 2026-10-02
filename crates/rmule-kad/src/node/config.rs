//! The node's construction and arming vocabulary: the immutable
//! [`KadNodeConfig`] a node is built from, plus the three seams a driver arms
//! it with — contact admission, reachability inputs, and the UDP firewall
//! helper it offers a stranger.

use std::net::Ipv4Addr;

use rmule_primitives::{Ipv4Endpoint, UserHash};

use crate::KadId;

/// Static identity and endpoint facts the driver injects at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadNodeConfig {
    /// This node's Kad ID (random, independent of the eD2k User Hash).
    pub id: KadId,
    /// The eD2k TCP listen port advertised in hello/bootstrap headers.
    pub tcp_port: u16,
    /// The Kad UDP listen port advertised via the hello UDP-port tag.
    pub udp_port: u16,
    /// The eD2k User Hash the **Kad Publisher** announces as its source ID
    /// (documentation-backed `SourceIdMeaning`; the identities stay
    /// independent — this is carried, never derived from the Kad ID).
    pub user_hash: UserHash,
}

/// The node's **contact-admission verdict**: whether an IP may
/// become Kad traffic at all. aMule consults its IP filter at every Kad
/// contact intake — routing admission (`CRoutingZone::Add`,
/// `RoutingZone.cpp#L406`), the nodes.dat load (`#L195`), the bootstrap-file
/// dial selection (`#L252`), and lookup-response rows before they reach the
/// search manager (`KademliaUDPListener.cpp#L733`) — and rmule funnels those
/// same intakes through this one predicate: [`KadNode`](crate::KadNode)'s `store`, its
/// bootstrap dial-list seed, and its lookup-response row intake.
///
/// The default admits everything — the empty-filter posture every
/// non-production constructor keeps, and byte-identical behavior for every
/// existing sim harness. `rmule-core` arms the production closure over its
/// core-owned IP filter, so a future filter reload there is visible here with
/// no re-arm. Determinism in sim tests holds as long as the injected closure
/// is itself deterministic (the node only ever *calls* it).
#[derive(Clone)]
pub struct KadContactAdmission(std::sync::Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync>);

impl KadContactAdmission {
    /// A live admission predicate: `true` admits `ip` as Kad contact traffic,
    /// `false` refuses it (the IP is filtered).
    #[must_use]
    pub fn new(admits: impl Fn(Ipv4Addr) -> bool + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(admits))
    }

    /// Whether `ip` may be admitted.
    #[must_use]
    pub fn admits(&self, ip: Ipv4Addr) -> bool {
        (self.0)(ip)
    }
}

impl Default for KadContactAdmission {
    /// Admit everything (an empty IP filter table).
    fn default() -> Self {
        Self::new(|_| true)
    }
}

impl std::fmt::Debug for KadContactAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KadContactAdmission(..)")
    }
}

/// The node's own self-reachability and buddy state — the keyword layer's
/// publish-gate and storer-refusal inputs (ADR-0062).
///
/// aMule reads these from ADR-0058 `Reachability` and ADR-0061 buddy state.
/// Only the reachability *responder* exists (which proves *other* peers
/// reachable), not a self-check requester, so the node has no self-verdict to
/// thread — it holds this **injected** value ([`KadNode::set_reachability`](crate::KadNode::set_reachability)),
/// defaulting to the assume-open posture the hello misc-options already present
/// (not firewalled, no buddy). The moment a self-check requester lands the
/// driver feeds a real verdict through the same seam — the conservative bool
/// seam ADR-0062 calls for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct KadReachability {
    /// This node's UDP port is firewalled: the **Kad Storer** silently refuses
    /// inbound keyword publishes (a firewalled node could not be found to serve
    /// the rows it stored) — aMule's `Process2PublishKeyRequest` early return.
    pub udp_firewalled: bool,
    /// This node's TCP port is firewalled: the **Kad Publisher** stays silent
    /// unless a buddy is connected (a firewalled node's rows would carry buddy
    /// info, ADR-0061).
    pub tcp_firewalled: bool,
    /// A buddy is connected (ADR-0061): lets a TCP-firewalled node still publish.
    pub buddy_connected: bool,
}

/// One candidate helper the UDP firewall self-check may engage (ADR-0058
/// requester, breakdown 3): one row of the node's own helper lookup, or one a
/// driver offers through
/// [`KadNode::offer_udp_firewall_helper`](crate::KadNode::offer_udp_firewall_helper).
/// The tester queues it and applies the freshness rules (version ≥ 6, not
/// this node, an IP never used for a UDP test, and one not already in our
/// routing zone) when it pops it; a fresh one is engaged while the two-helper
/// budget has room.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpFirewallHelper {
    /// The helper's dial endpoint: its IP and eD2k TCP port (aMule dials the TCP
    /// port and sends `OP_FWCHECKUDPREQ`; the `0x62` answer returns over UDP).
    pub endpoint: Ipv4Endpoint,
    /// The helper's Kad ID — the self-test guard (never test ourselves).
    pub id: KadId,
    /// The helper's Kad protocol version — UDP firewall checks need ≥ 6.
    pub version: u8,
}
