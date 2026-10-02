//! The small-timer hello pass: aMule's per-zone
//! `CRoutingZone::OnSmallTimer`, the mechanism that makes a node known to the
//! contacts it merely holds. A merged contact (`MergeContacts`, aMule's
//! nodes.dat `AddUnfiltered`) arrives with no round trip, and a counterparty
//! learns of this node only when this node's own `HELLO_REQ` reaches it
//! (`Process2HelloRequest` → `AddContact2`, `KademliaUDPListener.cpp:577-649`).
//! aMule's `CKademlia::Process` runs the pass every minute for every zone with
//! no `IsConnected` gate (`Kademlia.cpp:187,277-280`, kno `ab483654`, unlike
//! `OnBigTimer` at `:262-273`), so neither does this one.

use std::time::Duration;

use super::{KadEvent, KadNode};
use crate::KadInstant;

impl KadNode {
    /// How often the pass fires once armed — aMule's per-zone
    /// `m_nextSmallTimer = MIN2S(1) + now` (`Kademlia.cpp:279`).
    pub const SMALL_TIMER_INTERVAL: Duration = Duration::from_secs(60);

    /// How soon after arming the first pass fires. aMule staggers zone timers
    /// across the first seconds of a run (`m_nextSmallTimer = time(NULL) +
    /// m_zoneIndex.Get32BitChunk(3)`, `RoutingZone.cpp:111`), so a table-seeded
    /// start greets its seeds within seconds.
    pub const SMALL_TIMER_INITIAL: Duration = Duration::from_secs(1);

    /// Arm the small-timer pass, anchored at `now` — the driver calls this once
    /// when it begins joining Kad, beside
    /// [`arm_self_lookup`](Self::arm_self_lookup). The first pass fires
    /// [`SMALL_TIMER_INITIAL`](Self::SMALL_TIMER_INITIAL) later, then every
    /// [`SMALL_TIMER_INTERVAL`](Self::SMALL_TIMER_INTERVAL), joined or not.
    /// Left un-armed, a node runs no pass at all — the routing-only mesh-sim
    /// posture, which must still quiesce.
    pub fn arm_small_timer(&mut self, now: KadInstant) {
        self.next_small_timer = Some(now + Self::SMALL_TIMER_INITIAL);
    }

    /// When due, run one [`small_timer_pass`](crate::KadRoutingTable::small_timer_pass)
    /// and act on what it returns — at most one hello or one eviction per
    /// bucket. A hello probe rides the ordinary machinery (an answer marks
    /// the contact alive, held out for 1–2 h by its age, and emits
    /// [`ContactResponded`](super::KadEvent::ContactResponded)) but, unlike
    /// every other probe in this node, an unanswered one evicts nothing
    /// (`probe`'s `evict_on_timeout: false`): the pass gives an aged contact
    /// a second hello with its own check window before eviction (`RoutingZone.cpp:960-968`),
    /// so eviction is the pass's own call, not
    /// [`PROBE_TIMEOUT`](Self::PROBE_TIMEOUT)'s.
    pub(super) fn tick_small_timer(&mut self, now: KadInstant) {
        let Some(due) = self.next_small_timer else {
            return;
        };
        if due > now {
            return;
        }
        self.next_small_timer = Some(now + Self::SMALL_TIMER_INTERVAL);
        let outcome = self.routing.small_timer_pass(now);
        for id in outcome.evicted {
            self.emit_event(KadEvent::ContactEvicted { id });
        }
        for contact in outcome.due {
            self.probe(now, contact.id(), contact.endpoint(), false);
        }
    }
}
