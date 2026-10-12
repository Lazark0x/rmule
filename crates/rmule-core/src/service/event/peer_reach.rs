//! The peer-reach vocabulary [`CoreEvent`](super::CoreEvent) names: what a
//! `ReachPeer` routes on, the route it took, and why reaching a peer stopped.

use rmule_primitives::UserHash;

/// The counterparty facts [`CoreCommand::ReachPeer`](crate::CoreCommand::ReachPeer) routes on — the public
/// mirror of the ADR-0061 chooser's `CallbackTarget`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerReach {
    /// The peer's server-assigned client id: its LowID/HighID class, and (when
    /// LowID) the id a server callback names.
    pub id: rmule_primitives::ClientId,
    /// Its dialable TCP endpoint. Used only when the peer turns out to be
    /// HighID; a LowID peer has no plain dial, so a last-seen endpoint is fine.
    pub tcp: rmule_primitives::PeerEndpoint,
    /// The peer advertised `SupportsDirectUDPCallback` (ADR-0047): it can be
    /// reached by an `OP_DIRECTCALLBACKREQ` (`0x95`) to its Kad UDP port.
    pub supports_direct_udp_callback: bool,
    /// Its Kad UDP endpoint — the `0x95` destination, and where aMule's own
    /// direct callback goes (`BaseClient.cpp` sends to `GetKadPort()`, and the
    /// Kad port is the same socket its `CClientUDPSocket` demuxes `0x95` on).
    /// `None` forecloses the direct route however the advert reads.
    pub kad_udp: Option<rmule_primitives::Ipv4Endpoint>,
    /// The peer is on the server we are connected to, so a server callback
    /// (`0x1C`) can relay to it.
    pub on_our_server: bool,
    /// Its Kad buddy, when it published one.
    pub buddy: Option<PeerBuddy>,
    /// Its usable IPv6, when it named one — a `CT_MOD_IP_V6` hello tag, an
    /// ExtSX record's tag, or a Kad `ip6` row (ADR-0087). Rung 0 of the
    /// ADR-0061 route tree dials it directly, Low ID included, whenever rmule
    /// holds a Known IPv6 of its own. Defaults to `None` for an IPv4-only
    /// caller; a `tcp` that is already IPv6 is read as one too.
    pub ipv6: Option<rmule_primitives::Ipv6Endpoint>,
    /// The peer speaks eMuleAI's NAT-T (ADR-0091): `CT_MOD_MISCOPTIONS` bit 1
    /// in its hello, or the uTP bit in a source record's connect options.
    /// With it, rung 1 of the route tree punches rather than drops.
    pub supports_natt: bool,
    /// The peer's eD2k user hash, when the caller holds it (a hello, a source
    /// record, a Kad publish). It is the **one name for a peer that survives
    /// its address changing under a NAT**, so it is what the rendezvous ledger
    /// is keyed by and what an `OP_NATT_ENDPOINT_HINT` names. Without it rung
    /// 1's buddy coordinator cannot be enacted — a hint could never be matched
    /// to the attempt it answers.
    pub user_hash: Option<UserHash>,
}

/// A peer's Kad buddy as [`PeerReach`] carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerBuddy {
    /// The buddy's Kad ID — the `0x52` walk/verify target.
    pub buddy_id: crate::KadId,
    /// The buddy's UDP endpoint when known (`0x52` straight to it); `None` means
    /// a walk toward `buddy_id` must find it first.
    pub buddy_udp: Option<rmule_primitives::Ipv4Endpoint>,
}

/// Which of the ADR-0061 routes reaches a peer: the route tree's verdict, and —
/// once **Peer Reach** carried it out — the road taken, reported as
/// [`CoreEvent::PeerReachRouted`](super::CoreEvent::PeerReachRouted). A road
/// one of our own facts kept from leaving reads as its `…Unavailable` twin.
/// Callers watch it to know what core actually did, and the capture bench
/// reads it as rmule's own disposition trail beside the counterparty's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerReachRoute {
    /// Dialed straight, no callback: a HighID peer, or — rung 0 — a peer that
    /// named a usable IPv6 while we hold a Known one of our own.
    Direct {
        /// Where the dial goes: the IPv6 endpoint when rung 0 chose it, else
        /// the HighID peer's own IPv4 endpoint.
        endpoint: rmule_primitives::PeerEndpoint,
    },
    /// Route 2: an `OP_DIRECTCALLBACKREQ` (`0x95`) went out to the peer's Kad
    /// UDP endpoint.
    DirectUdp {
        /// Where the `0x95` was sent — the peer's Kad UDP endpoint.
        target_kad_udp: rmule_primitives::Ipv4Endpoint,
    },
    /// Route 2 was chosen but could not be enacted: no client-UDP send half is
    /// bound, so nothing was emitted. Distinct from a route that was never
    /// chosen — Honest Capability Advertisement applied to our own enactment.
    DirectUdpUnavailable {
        /// Where the `0x95` would have gone had a send half been bound.
        target_kad_udp: rmule_primitives::Ipv4Endpoint,
    },
    /// Route 3: the server callback (`0x1C`) naming this LowID.
    Server {
        /// The peer's server-assigned Low-ID, which is what the `0x1C` names.
        low_id: rmule_primitives::ClientId,
    },
    /// Route 4: through the peer's Kad buddy.
    Buddy {
        /// The buddy's Kad ID — the target of the `0x52` walk that reaches it.
        buddy_id: crate::KadId,
        /// Where the `0x52 KADEMLIA_CALLBACK_REQ` went, or `None` when nothing
        /// was emitted: a `ReachPeer` names no file for it to carry, or our Kad
        /// node, our listener or the buddy's endpoint was missing.
        emitted_to: Option<rmule_primitives::Ipv4Endpoint>,
    },
    /// Route 4 for a buddy the source named by ID alone: a
    /// **Callback Walk** toward `buddy_id` began, and sends its `0x52` to
    /// whichever responders sit close enough to the ID to be the buddy. A walk
    /// that finds none retires the road; one that sends leaves the dial-back
    /// to the slot's own deadline.
    CallbackWalk {
        /// The buddy's Kad ID — the walk's target.
        buddy_id: crate::KadId,
    },
    /// Rung 1 (ADR-0091) through the peer's Kad serving buddy: the NAT-T
    /// Front took the traversal and puts an `OP_RENDEZVOUS`, embedded in an
    /// `OP_REASKCALLBACKUDP`, on the wire toward the buddy.
    NatTraversal {
        /// The buddy's Kad ID — the rendezvous' routing key.
        buddy_id: crate::KadId,
        /// Where the rendezvous was sent.
        buddy_udp: rmule_primitives::Ipv4Endpoint,
    },
    /// Rung 1 through the **server coordinator** (ADR-0091): the NAT-T Front
    /// took the traversal and puts an `OP_LOWID_HOLEPUNCH_REQUEST` naming this
    /// Low-ID on our session. The introduction, a refusal, or silence follows
    /// on the session — this event says only that we asked.
    ServerPunch {
        /// The peer's server-assigned Low-ID.
        low_id: rmule_primitives::ClientId,
    },
    /// The server coordinator was chosen and no NAT-T Front took the
    /// traversal, so no request was put on the session.
    ServerPunchUnavailable {
        /// The Low-ID the request would have named.
        low_id: rmule_primitives::ClientId,
    },
    /// Rung 1 was chosen but no rendezvous went out — Honest Capability
    /// Advertisement applied to our own enactment, as for
    /// [`DirectUdpUnavailable`](Self::DirectUdpUnavailable).
    NatTraversalUnavailable {
        /// The buddy's Kad ID the rendezvous would have been routed by.
        buddy_id: crate::KadId,
        /// What was missing.
        reason: NatTraversalUnavailableReason,
    },
    /// Unreachable — the candidate is dropped, with the chooser's reason.
    Dropped {
        /// Why no route applied.
        reason: PeerReachDropReason,
    },
}

/// Why a chosen NAT-T route ([`PeerReachRoute::NatTraversalUnavailable`])
/// emitted nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatTraversalUnavailableReason {
    /// The buddy's UDP endpoint is unknown. No Kad walk follows: `0x94` has
    /// no dialect-sanctioned walk toward an ID alone, so a download's
    /// candidate is retired at once and an operator's reach begins nothing.
    BuddyEndpointUnknown,
    /// No client-UDP send half is bound, our user hash is not yet known, or no
    /// NAT-T front is running to own the attempt.
    NotEnactable,
    /// The caller holds no user hash for the target (ADR-0091): the rendezvous
    /// ledger is keyed by it and a hint names it, so an attempt begun without
    /// one could never recognise its own answer.
    TargetIdentityUnknown,
}

/// Why a [`PeerReachRoute::Dropped`] peer cannot be reached (aMule's
/// `DS_LOWTOLOWIP` and the no-buddy fall-through, plus the download road's
/// own defensive guard).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerReachDropReason {
    /// LowID→LowID with no shared server to relay through and no NAT
    /// traversal possible (ADR-0091).
    LowToLow,
    /// No usable buddy route: Kad is down, or the peer published no buddy.
    NoBuddy,
    /// A download's `LowIdRoad::DirectUdp` candidate reached the actor with no
    /// Kad UDP endpoint on its projected [`PeerReach`].
    /// `LowIdRoad::of` never opens this road without one, so
    /// this is the brain's invariant failing to cross the channel, not a
    /// route aMule itself drops.
    NoKadUdpEndpoint,
    /// A download's Low-ID candidate had no NAT-T coordinator to introduce it:
    /// no live server session for a target on our server, and no usable Kad
    /// buddy. The candidate is retired at once.
    NoCoordinator,
}
