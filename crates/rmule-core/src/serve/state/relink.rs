//! A waiter is a client, not a link (ADR-0057, "A waiter on a new link"): the
//! hello of a new link that names a client already waiting moves that
//! client's place onto the new link, as aMule attaches a new socket to the
//! client it knows (`ClientList.cpp:370-412`) and keeps a queued client's
//! place (`UploadQueue.cpp:395-431`).

use rmule_peer::PeerIdentity;
use rmule_primitives::PeerEndpoint;

use crate::service::ServeEvent;

use super::{ServeDecision, ServeState};

impl ServeState {
    /// Move the place of the client `identity` names onto `peer`, the link
    /// its hello just came in on. The client is the waiter holding the same
    /// User Hash, best rank first — aMule's queue finds its client by hash
    /// (`UploadQueue.cpp:395`). It is attached when the link it waited on has
    /// ended, or comes from the same address and listen port, which aMule
    /// drops for the new one (`ClientList.cpp:395-401`); a live link from
    /// anywhere else keeps its client, and the new link is another
    /// (`:384-394`).
    pub(super) fn relink_waiter(
        &mut self,
        peer: PeerEndpoint,
        identity: &PeerIdentity,
    ) -> Vec<ServeDecision> {
        let found = self.queue.waiters().find_map(|(held, linked)| {
            let known = self.identities.get(&held)?;
            (held != peer && known.user_hash() == identity.user_hash()).then(|| {
                let same_place = held.ip() == peer.ip() && known.tcp_port() == identity.tcp_port();
                (held, linked, same_place)
            })
        });
        let Some((from, linked, same_place)) = found else {
            return Vec::new();
        };
        if (linked && !same_place) || !self.queue.relink(from, peer) {
            return Vec::new();
        }
        self.served_ranges
            .retain(|(range_peer, _), _| *range_peer != from);
        self.forget(from);
        self.sx_throttle.forget(from);
        let relinked = ServeDecision::Emit(ServeEvent::WaiterRelinked { from, to: peer });
        if linked {
            vec![relinked, ServeDecision::Disconnect { peer: from }]
        } else {
            vec![relinked]
        }
    }
}
