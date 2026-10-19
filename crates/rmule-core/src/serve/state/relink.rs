//! A waiter is a client, not a link (ADR-0057, "A waiter on a new link";
//! ADR-0107, "One peer, one link"): the hello of a new link that names a
//! client already waiting moves that client's place — or its pending dial-back
//! grant, granted there at once — onto the new link, as aMule attaches a new
//! socket to the client it knows (`ClientList.cpp:371-412`), keeps a queued
//! client's place (`UploadQueue.cpp:395-431`) and grants a client it promoted
//! unconnected once its hellos finish (`BaseClient.cpp:1707-1716`). Two clients under one User Hash are settled
//! as aMule settles them: an identified one still linked turns the newcomer
//! away (`ClientList.cpp:384-392`), and at a slot ask the ones not identified
//! leave the wait list (`UploadQueue.cpp:432-458`).

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
    /// Move the place of the client `identity` names onto `peer`, the link
    /// its hello just came in on. The client is the waiter — or the pending
    /// dial-back grantee — holding the same User Hash, best rank first:
    /// aMule's queue finds its client by hash (`UploadQueue.cpp:396-397`),
    /// and a client it promoted unconnected is granted on the first link its
    /// hellos finish on (`ClientTCPSocket.cpp:328`, `:417`), so a held grant
    /// goes on `peer` at once. It is attached when the link
    /// it waited on has ended, or comes from the same address and listen
    /// port, which aMule drops for the new one (`ClientList.cpp:400-403`); a
    /// live link from anywhere else keeps its client, and the new link is
    /// another (`:384-398`).
    pub(super) fn relink_waiter(
        &mut self,
        peer: PeerEndpoint,
        identity: &PeerIdentity,
    ) -> Vec<ServeDecision> {
        let standings = self
            .queue
            .waiters()
            .chain(self.queue.pending_dial_backs().map(|held| (held, false)));
        let found = standings.into_iter().find_map(|(held, linked)| {
            let known = self.identities.get(&held)?;
            (held != peer && known.user_hash() == identity.user_hash()).then(|| {
                let same_place = held.ip() == peer.ip() && known.tcp_port() == identity.tcp_port();
                (held, linked, same_place)
            })
        });
        let Some((from, linked, same_place)) = found else {
            return Vec::new();
        };
        if linked && !same_place {
            return Vec::new();
        }
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
        if let Relinked::HeldGrant { file_hash } = moved {
            decisions.push(ServeDecision::Send {
                peer,
                command: ServerCommand::GrantSlot { file_hash },
            });
            decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer,
                file_hash,
                software: Some(identity.software().clone()),
                road: GrantRoad::CameBack,
            }));
        }
        decisions
    }

    /// The credit ledger bound `user_hash`'s proven key on `peer`'s link, or
    /// refused it (`bound`, ADR-0041): a client proven and bound is
    /// identified while its link carries that hash.
    pub(in crate::serve) fn on_identity_bound(
        &mut self,
        peer: PeerEndpoint,
        user_hash: UserHash,
        bound: bool,
    ) {
        let carries = self
            .identities
            .get(&peer)
            .is_some_and(|identity| identity.user_hash() == user_hash);
        if bound && carries {
            self.identified.insert(peer);
        } else {
            self.identified.remove(&peer);
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
