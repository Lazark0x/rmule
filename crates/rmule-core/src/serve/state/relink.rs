//! A waiter is a client, not a link (ADR-0057, "A client on a new link keeps
//! its standing"; ADR-0107, "One peer, one link"): the hello of a new link
//! that names a client the queue holds moves that client's place, its
//! pending dial-back grant — granted there at once — or its slot onto the new
//! link, as aMule attaches a new socket to the client it knows
//! (`ClientList.cpp:371-412`), keeps a queued client's place
//! (`UploadQueue.cpp:395-431`) and grants a client it promoted unconnected
//! once its hellos finish (`BaseClient.cpp:1707-1716`). Of two links of one
//! client the far end keeps one (`ClientList.cpp:400-403`), and the Peer Links
//! settle a hello that crosses rmule's dial before this side hears of it
//! (ADR-0107 invariant 7): a hello that reaches here is answered. A live link
//! rmule dialed keeps its client until the far end closes one of the two, and
//! the standing follows the one left, unless it is a **Dead Dial**, which the
//! far end has dropped already. Two clients under one User Hash are settled as
//! aMule settles them: an identified one still linked turns the newcomer away
//! (`ClientList.cpp:384-392`), and at a slot ask the ones not identified leave
//! the wait list (`UploadQueue.cpp:432-458`).

use std::collections::HashMap;
use std::time::Instant;

use rmule_peer::PeerIdentity;
use rmule_primitives::{PeerEndpoint, UserHash};

use rmule_peer::ServerCommand;

use crate::WaiterLeaveCause;
use crate::service::{GrantRoad, ServeEvent};
use crate::upload_queue::Relinked;

use super::{ServeDecision, ServeState};

impl ServeState {
    /// Move the standing of the client `identity` names onto `peer`, the
    /// link its hello just came in on: its place, its pending dial-back grant
    /// or its slot, found by User Hash as aMule's queue finds its client
    /// (`UploadQueue.cpp:396-397`). A standing whose link has ended moves to
    /// any link; a live one only to a link the peer opened from the same
    /// address and listen port, closing the old link, as aMule replaces the
    /// socket it held at the hello of a newer one (`ClientTCPSocket.cpp:391`,
    /// `ClientList.cpp:400-403`) — a live link from anywhere else, or one
    /// rmule dialed, keeps its client (`:384-398`). A live link rmule dialed
    /// keeps it against the peer's own link from that address too, the far
    /// end closing one of the two ([`on_link_ended`](Self::on_link_ended)
    /// moves the standing to the one left) — unless it is a **Dead Dial** at
    /// `now`, read off what its driver saw of its far end (ADR-0107 invariant
    /// 7): the far side dropped it and holds only `peer`, which takes the
    /// client as from a link that has ended.
    ///
    /// A slot is granted again on the link it moved to, so the session there
    /// serves its part asks (`UploadQueue.cpp:486-493`). Returns what moved,
    /// `None` when nothing did.
    pub(super) fn relink_waiter(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        identity: &PeerIdentity,
    ) -> Option<Vec<ServeDecision>> {
        let (from, linked, same_place) = self.queue.standings().find_map(|(held, linked)| {
            let known = self.identities.get(&held)?;
            (held != peer && known.user_hash() == identity.user_hash()).then(|| {
                let same_place = held.ip() == peer.ip() && known.tcp_port() == identity.tcp_port();
                (held, linked, same_place)
            })
        })?;
        if linked && (!same_place || self.dialed.contains_key(&peer)) {
            return None;
        }
        if linked && let Some(far_end) = self.dialed.get(&from) {
            let sign = far_end.dead_at(now)?;
            let mut moved = vec![ServeDecision::Emit(ServeEvent::DeadDialLetGo {
                peer: from,
                sign,
            })];
            moved.extend(self.move_standing(from, peer, true));
            return Some(moved);
        }
        let moved = self.move_standing(from, peer, linked);
        (!moved.is_empty()).then_some(moved)
    }

    /// The link `peer` ended while it carried a slot and another live link
    /// of the same client stands: the far end keeps one socket per client
    /// (`ClientList.cpp:400-403`), so it kept that one, and the slot moves
    /// there (ADR-0107 invariant 7). Its client may still be downloading: the
    /// attach ran no `Disconnected` (`ClientTCPSocket.cpp:278-288`), so it
    /// waits for the blocks it asked, takes them on the link it kept
    /// (`ClientTCPSocket.cpp:713-720`), and drops a grant
    /// (`:640-645`). The blocks its last ask named, which name all it has
    /// pending, are read again for that link. `None` with no such link.
    pub(super) fn on_link_ended(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Option<Vec<ServeDecision>> {
        if !self.queue.is_granted(peer) || self.queue.is_unlinked(peer) {
            return None;
        }
        let user_hash = self.identities.get(&peer)?.user_hash();
        // The lowest endpoint, so two live links of one client pick alike.
        let left = self
            .identities
            .iter()
            .filter(|(held, known)| {
                **held != peer && known.user_hash() == user_hash && !self.queue.contains(**held)
            })
            .map(|(held, _)| *held)
            .min()?;
        let asked = self.last_ask.remove(&peer);
        let mut decisions = self.move_standing(peer, left, false);
        if let Some((file_hash, ranges)) = asked {
            decisions.extend(self.on_parts_requested(now, left, file_hash, &ranges, modifiers));
        }
        Some(decisions)
    }

    /// Move the standing held at `from` onto `peer`, closing `from` when it is
    /// still `linked`; what it moved is granted again on `peer`.
    fn move_standing(
        &mut self,
        from: PeerEndpoint,
        peer: PeerEndpoint,
        linked: bool,
    ) -> Vec<ServeDecision> {
        let Some(moved) = self.queue.relink(from, peer) else {
            return Vec::new();
        };
        self.shed_link_state(from);
        let mut decisions = vec![ServeDecision::Emit(ServeEvent::WaiterRelinked {
            from,
            to: peer,
        })];
        if linked {
            decisions.push(ServeDecision::Disconnect { peer: from });
        }
        match moved {
            Relinked::Waiter => {}
            Relinked::HeldGrant { file_hash } => {
                decisions.push(ServeDecision::Send {
                    peer,
                    command: ServerCommand::GrantSlot { file_hash },
                });
                decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                    peer,
                    file_hash,
                    software: self.software_of(peer),
                    road: GrantRoad::CameBack,
                }));
            }
            Relinked::Slot { file_hash } => decisions.push(ServeDecision::Send {
                peer,
                command: ServerCommand::GrantSlot { file_hash },
            }),
        }
        decisions
    }

    /// `peer`'s link bound the key its session proved `user_hash` holds
    /// (ADR-0041): the client on it is identified while its hello carries
    /// that hash.
    pub(in crate::serve) fn on_identity_bound(&mut self, peer: PeerEndpoint, user_hash: UserHash) {
        let carries = self
            .identities
            .get(&peer)
            .is_some_and(|identity| identity.user_hash() == user_hash);
        if carries {
            self.identified.insert(peer);
        }
    }

    /// Whether the new link `peer`, whose hello is `identity`, names the User
    /// Hash of an identified client still linked from another address or
    /// listen port — aMule bans that newcomer, "Userhash invalid"
    /// (`ClientList.cpp:384-392`).
    pub(super) fn refuses_hash_thief(&self, peer: PeerEndpoint, identity: &PeerIdentity) -> bool {
        self.identities.iter().any(|(held, known)| {
            *held != peer
                && known.user_hash() == identity.user_hash()
                && self.identified.contains(held)
                && !self.queue.is_unlinked(*held)
                && (held.ip() != peer.ip() || known.tcp_port() != identity.tcp_port())
        })
    }

    /// Settle a slot ask from `peer` against the waiters holding its User
    /// Hash on other links (`UploadQueue.cpp:432-458`): each one not
    /// identified leaves the wait list, and when one clashed and `peer`
    /// itself is not identified its ask is answered nothing — the second
    /// value. A waiter whose link already ended is forgotten with its place.
    pub(super) fn settle_hash_clash(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> (Vec<ServeDecision>, bool) {
        let Some(user_hash) = self.identities.get(&peer).map(PeerIdentity::user_hash) else {
            return (Vec::new(), false);
        };
        let clashing: Vec<PeerEndpoint> = self
            .queue
            .waiters()
            .map(|(held, _)| held)
            .filter(|held| {
                *held != peer
                    && self
                        .identities
                        .get(held)
                        .is_some_and(|known| known.user_hash() == user_hash)
            })
            .collect();
        if clashing.is_empty() {
            return (Vec::new(), false);
        }
        let mut decisions = Vec::new();
        for held in clashing {
            if self.identified.contains(&held) {
                continue;
            }
            let unlinked = self.queue.is_unlinked(held);
            let promotion = self.queue.release(held, now, modifiers);
            decisions.extend(self.promotion_decisions(promotion));
            decisions.push(ServeDecision::Emit(ServeEvent::WaiterLeft {
                peer: held,
                cause: WaiterLeaveCause::UserHashClash,
            }));
            if unlinked {
                self.forget(held);
                self.sx_throttle.forget(held);
            }
        }
        (decisions, !self.identified.contains(&peer))
    }
}
