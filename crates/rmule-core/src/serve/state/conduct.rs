//! How a client's conduct ends what it holds on the serve side: an **Upload
//! Session** past its bound goes back on the wait list (ADR-0031), an **Ask
//! Pace** score bans (ADR-0055 divergence 7), and a ban reaches its live link
//! and its place, in the batch it is seen or at the next sweep (ADR-0064). A
//! source of ours is never banned here.

use std::collections::HashMap;
use std::time::Instant;

use rmule_peer::{PeerIdentity, ServerCommand};
use rmule_primitives::{AccountingKey, PeerEndpoint};

use crate::WaiterLeaveCause;
use crate::service::{GrantRoad, ServeEvent};
use crate::upload_queue::Promotion;

use super::{ServeDecision, ServeState};

impl ServeState {
    /// End the **Upload Session** the queue says is over at `now` (ADR-0031):
    /// its holder is told, the best waiter takes the slot in the same batch,
    /// and the holder asks again from the wait list with a fresh wait, its
    /// link kept (`UploadClient.cpp:493-510`).
    pub(in crate::serve) fn end_over_session(
        &mut self,
        now: Instant,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let Some(peer) = self.queue.session_to_end(now) else {
            return Vec::new();
        };
        let Some(file_hash) = self.queue.live_slot_file(peer) else {
            return Vec::new();
        };
        self.served_ranges
            .retain(|(range_peer, _), _| *range_peer != peer);
        self.last_ask.remove(&peer);
        let promotion = self.leave_queue(peer, now, modifiers);
        let mut decisions = vec![
            ServeDecision::Send {
                peer,
                command: ServerCommand::EndUploadSession,
            },
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }),
        ];
        decisions.extend(self.promotion_decisions(promotion));
        let admission = self.queue.admit(peer, file_hash, now);
        decisions.extend(self.admission_decisions(
            peer,
            file_hash,
            GrantRoad::Linked,
            false,
            admission,
        ));
        decisions
    }

    /// Whether no ban lands on `peer`: a source of ours, or a link rmule
    /// dialed, which is one (ADR-0055 divergence 7).
    pub(super) fn spares(&self, peer: PeerEndpoint) -> bool {
        self.asker.our_source || self.dialed.contains_key(&peer)
    }

    /// `peer` leaves the queue at `now`, tracked if it leaves a slot.
    pub(super) fn leave_queue(
        &mut self,
        peer: PeerEndpoint,
        now: Instant,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Promotion {
        self.track_holder(now, peer);
        self.queue.release(peer, now, modifiers)
    }

    /// `peer`'s place is tracked under its hello's User Hash if it holds a
    /// slot: stock tracks every client leaving one, proof or none
    /// (`UploadQueue.cpp:525`), so it comes back under another hash into the
    /// ban (`BaseClient.cpp:686-689`). A waiter is not tracked here.
    pub(super) fn track_holder(&mut self, now: Instant, peer: PeerEndpoint) {
        if !self.queue.is_granted(peer) {
            return;
        }
        if let Some(identity) = self.identities.get(&peer) {
            self.hashes
                .note(now, peer.ip(), identity.tcp_port(), identity.user_hash());
        }
    }

    /// One ask of `peer` on its **Ask Pace**; `true` when it bans the asker.
    pub(super) fn ask_bans(&mut self, now: Instant, peer: PeerEndpoint) -> bool {
        let Some(user_hash) = self.identities.get(&peer).map(PeerIdentity::user_hash) else {
            return false;
        };
        let key = AccountingKey::of(peer.ip());
        self.asks.ask(now, key, user_hash) && !self.spares(peer)
    }

    /// Ban `peer`'s address, and act on it at once ([`on_banned`](Self::on_banned)).
    pub(super) fn ban_asker(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let mut decisions = vec![ServeDecision::Ban { peer }];
        decisions.extend(self.on_banned(now, peer, modifiers));
        decisions
    }

    /// `peer`'s address is banned: its slot or its place goes, the next waiter
    /// takes the slot, and its link closes. Stock answers such a client
    /// nothing and lets the 40 s silence close it; a closed link is that
    /// silence, sooner (`UploadClient.cpp:628-649`, `UploadQueue.cpp:98`).
    pub(in crate::serve) fn on_banned(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let held_slot = self.queue.is_granted(peer);
        let waited = !held_slot && self.queue.contains(peer);
        let unlinked = self.queue.is_unlinked(peer);
        self.served_ranges
            .retain(|(range_peer, _), _| *range_peer != peer);
        self.last_ask.remove(&peer);
        let promotion = self.leave_queue(peer, now, modifiers);
        let mut decisions = self.promotion_decisions(promotion);
        if held_slot {
            decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }));
        } else if waited {
            decisions.push(ServeDecision::Emit(ServeEvent::WaiterLeft {
                peer,
                cause: WaiterLeaveCause::Banned,
            }));
        }
        decisions.push(ServeDecision::Disconnect { peer });
        if unlinked {
            self.forget(peer);
            self.sx_throttle.forget(peer);
        }
        decisions
    }

    /// Every standing's peer, for the sweep of what a ban reached.
    pub(in crate::serve) fn standing_peers(&self) -> Vec<PeerEndpoint> {
        self.queue.standings().map(|(peer, _)| peer).collect()
    }

    /// The bans that reached `banned` while no input of theirs came: they
    /// leave the queue. A link rmule dialed stays.
    pub(in crate::serve) fn on_banned_standings(
        &mut self,
        now: Instant,
        banned: &[PeerEndpoint],
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let mut decisions = Vec::new();
        for &peer in banned {
            if !self.dialed.contains_key(&peer) {
                decisions.extend(self.on_banned(now, peer, modifiers));
            }
        }
        decisions
    }
}
