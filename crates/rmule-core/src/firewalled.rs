//! The core-owned **firewalled-node operation** (ADR-0061, execution breakdown
//! 3): the citizen that lets rmule participate as a LowID/firewalled node — the
//! sibling of the open-node [`buddy`](crate::buddy) service. aMule keeps one
//! `m_pBuddy` for both directions; where [`buddy`](crate::buddy) owns the
//! open-node half (the firewalled client *we* relay for), this owns the
//! firewalled half: **our** buddy (the open node relaying for us), how we recruit
//! it, the relayed callbacks we consume through it, the direct-UDP callbacks we
//! consume without one, and the buddy info our source publishes carry.
//!
//! Its four decisions, all keyed off the ADR-0058
//! [`Reachability`](crate::reachability) verdict. Three are consumes with
//! disjoint vocabularies and a refusal matrix each, stated in the submodule
//! that owns it — they share only the buddy slot this module holds and the
//! [`inverted`] XOR helper every buddy-ID check runs:
//!
//! - [`recruit`] — the FINDBUDDY walk toward `~ourKadID`, run only while
//!   **both** our surfaces are firewalled, and the verified `0x5A` answer that
//!   fills the slot. The rule that starts the walk is the Kad pump's; it
//!   reads the slot through the snapshot [`link`] publishes.
//! - [`relayed_callback`] — the `OP_CALLBACK` (`0x99`) our buddy forwards over
//!   its TCP link. Its twin `OP_REASKCALLBACKTCP` (`0x9A`) is answered over UDP
//!   through the ADR-0057 reask reply matrix and needs no gate here — beyond
//!   the one structural fact that it arrived on the held link, which [`link`]
//!   applies where the link lives.
//! - [`direct_callback`] — the `OP_DIRECTCALLBACKREQ` (`0x95`) a requester
//!   sends straight to our UDP surface, rate-limited per source IP.
//!
//! The fourth is **publish**
//! ([`publish_buddy_info`](FirewalledNode::publish_buddy_info)): while
//! firewalled with a buddy, our Kad source publishes carry the buddy's endpoint
//! and the relationship ID — the named integration point with the ADR-0043 Kad
//! Publisher (which assumed a reachable node).
//!
//! This module is pure and sans-I/O, the [`reachability`](crate::reachability)
//! broker's shape: it decides, and the two modules beside it enact. [`link`]
//! holds the decisions together with the buddy TCP link *we* dialed — aMule's
//! `m_pBuddy` seen from the firewalled side — and [`front`] is the one task
//! that dials it, keeps it alive, and answers everything that arrives on it or
//! on the client-UDP socket — the slot's one owner, whose published snapshot
//! every other reader goes through. Explicit `Instant` only, here and in
//! [`link`].

use rmule_kad::KadId;
use rmule_primitives::Ipv4Endpoint;

pub(crate) mod direct_callback;
pub(crate) mod front;
pub(crate) mod link;
pub(crate) mod recruit;
pub(crate) mod relayed_callback;

use direct_callback::{DIRECT_CALLBACK_MIN_INTERVAL, DIRECT_CALLBACK_TRACKED_MAX};

use crate::interval_limiter::IntervalLimiter;

/// The firewalled-node operation: our buddy slot and the per-IP
/// direct-callback rate-limit tracker. The recruitment pacing is the Kad
/// pump's ([`recruit::Recruiter`]).
pub(crate) struct FirewalledNode {
    /// Our own Kad ID — the walk target basis (`~ourKadID`) and the anchor every
    /// buddy-ID XOR check (`0x5A`, `0x99`) verifies against.
    our_kad_id: KadId,
    /// Our recruited buddy's UDP endpoint (the open node relaying for us), or
    /// `None` — never recruited, or lost. The relationship ID is `~ourKadID` by
    /// construction (the walk target [`adopt_buddy`](FirewalledNode::adopt_buddy)
    /// verified), so it is derived, not stored. Only the UDP endpoint: it is what
    /// a source publish advertises and what the ADR-0091 acting path's carrier
    /// gate compares against. The link we dial, its keepalive and the identity
    /// it presents are enactment, and live in [`link`] beside this — where the
    /// link's close arrives and calls
    /// [`on_buddy_lost`](FirewalledNode::on_buddy_lost).
    buddy: Option<Ipv4Endpoint>,
    /// The `0x95` per-source-IP rate limit.
    direct_callbacks: IntervalLimiter,
}

/// The buddy info our Kad source publishes carry while firewalled (ADR-0061 →
/// ADR-0043 publisher): the buddy's UDP endpoint a searcher sends its `0x52` to,
/// the relationship ID (`~ourKadID`) that buddy verifies it against, and — the
/// `bi6` tag (ADR-0087) — the buddy's IPv6 while one is known.
///
/// The IPv6 is the **held link's** fact, not this pure tier's: a `0x5A` carries
/// no IPv6, so [`FirewalledNode::publish_buddy_info`] always leaves it `None`
/// and the enacted slot's [`BuddySnapshot`](link::BuddySnapshot) fills it from
/// the link it holds (see `link::buddy_ipv6` for which address wins).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BuddyPublish {
    pub(crate) buddy_udp: Ipv4Endpoint,
    pub(crate) buddy_id: KadId,
    pub(crate) buddy_ipv6: Option<std::net::Ipv6Addr>,
}

/// The bit-inverse of a Kad ID — aMule's `CUInt128::XOR(CUInt128(true))`. The
/// FINDBUDDY walk targets `~ourKadID`, and every buddy-ID check inverts the
/// received field to recover (and compare) our own KadID.
fn inverted(id: &KadId) -> KadId {
    let mut bytes = *id.as_bytes();
    for b in &mut bytes {
        *b = !*b;
    }
    KadId::from_bytes(bytes)
}

impl FirewalledNode {
    /// A fresh firewalled-node citizen with no buddy and no pacing history.
    pub(crate) fn new(our_kad_id: KadId) -> Self {
        Self {
            our_kad_id,
            buddy: None,
            direct_callbacks: IntervalLimiter::new(
                DIRECT_CALLBACK_MIN_INTERVAL,
                DIRECT_CALLBACK_TRACKED_MAX,
            ),
        }
    }

    /// Whether we currently hold a buddy. The enacted slot answers this from
    /// its own richer record ([`link::FirewalledSlot::buddy`]); this stays for
    /// the pure tier, which drives the node with no slot around it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn has_buddy(&self) -> bool {
        self.buddy.is_some()
    }

    /// The buddy info our Kad source publishes carry: `Some` only while we are
    /// firewalled **and** hold a buddy; `None` when reachable (the publisher then
    /// publishes a direct source) or when we hold no buddy yet.
    ///
    /// `firewalled` is the caller's read of aMule's `IsFirewalled()` union
    /// ([`SharedSelfReach::firewalled`](crate::reachability::SharedSelfReach::firewalled))
    /// — server High ID **or** Kad TCP open — never the Kad TCP
    /// verdict alone: a server-High-ID node holding a buddy publishes the
    /// direct row exactly as aMule's row-type choice does, not the buddy row a
    /// Kad-only read would have kept it on.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn publish_buddy_info(&self, firewalled: bool) -> Option<BuddyPublish> {
        // Only a firewalled node publishes buddy info; a reachable one publishes a
        // direct source (the ADR-0043 publisher's prior assumption). The published
        // relationship ID is `~ourKadID` — what a searcher addresses its `0x52`
        // with and the buddy verifies against.
        if !firewalled {
            return None;
        }
        self.buddy.map(|buddy_udp| BuddyPublish {
            buddy_udp,
            buddy_id: inverted(&self.our_kad_id),
            buddy_ipv6: None,
        })
    }
}

#[cfg(test)]
mod tests;
