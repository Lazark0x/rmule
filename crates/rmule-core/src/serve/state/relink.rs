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
//!
//! That rule holds where a client has one address, which is IPv4 alone
//! (ADR-0107, "One client on two addresses"). Elsewhere two links under one
//! hash are one client when both proved the key or the held link's hello
//! names the other's address; anything else is unproved, and a ban waits for
//! a proof of another key.

use std::net::IpAddr;
use std::time::Instant;

use rmule_peer::PeerIdentity;
use rmule_primitives::{PeerEndpoint, UserHash};

use rmule_peer::ServerCommand;

use crate::WaiterLeaveCause;
use crate::service::{GrantRoad, ServeEvent};
use crate::upload_queue::Relinked;
use crate::upload_queue::ScoreModifiers;

use super::{ServeDecision, ServeState};

/// Whether two addresses are two parties when one hash names both: only
/// between two IPv4 addresses. A dual-stack client holds one in each family
/// and an IPv6 host several (ADR-0107).
const fn addresses_part_clients(one: PeerEndpoint, other: PeerEndpoint) -> bool {
    matches!((one, other), (PeerEndpoint::V4(_), PeerEndpoint::V4(_)))
}

/// Whether the hello `known` names `address` as the client's own: its High
/// ID, or its `CT_MOD_IP_V6`.
pub(super) fn names_address(known: &PeerIdentity, address: PeerEndpoint) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => {
            let id = known.client_id();
            id.is_high_id() && id.as_u32() == u32::from_le_bytes(ip.octets())
        }
        IpAddr::V6(ip) => known.peer_ipv6() == Some(ip),
    }
}

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
        modifiers: &dyn ScoreModifiers,
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
                **held != peer
                    && known.user_hash() == user_hash
                    && !self.queue.contains(**held)
                    && self.may_carry_standing(peer, **held)
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

    /// Whether the links `held` and `link` are proved one client (ADR-0107,
    /// "One client on two addresses"): under one User Hash, both proved the
    /// key, or — the two not both IPv4 — `held`'s own hello names `link`'s
    /// address on the same listen port. What `link`'s hello says of `held`
    /// proves nothing: a thief copies a claim as easily as a hash.
    fn proved_one_client(&self, held: PeerEndpoint, link: PeerEndpoint) -> bool {
        let (Some(known), Some(other)) = (self.identities.get(&held), self.identities.get(&link))
        else {
            return false;
        };
        let both_proved = self.identified.contains(&held) && self.identified.contains(&link);
        let named = !addresses_part_clients(held, link)
            && known.tcp_port() == other.tcp_port()
            && names_address(known, link);
        known.user_hash() == other.user_hash() && (both_proved || named)
    }

    /// Whether a standing of the link `held` may ride on on `link`, another
    /// of its User Hash: a verified client's goes to a link of that client,
    /// never to one that only says so (ADR-0107).
    pub(super) fn may_carry_standing(&self, held: PeerEndpoint, link: PeerEndpoint) -> bool {
        let same_place = held.ip() == link.ip()
            && self.identities.get(&held).map(PeerIdentity::tcp_port)
                == self.identities.get(&link).map(PeerIdentity::tcp_port);
        !self.identified.contains(&held) || same_place || self.proved_one_client(held, link)
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
    /// that hash. The place it proved from is tracked: another hash there is
    /// a change, as `HashTrack` reads it.
    pub(in crate::serve) fn on_identity_bound(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        user_hash: UserHash,
    ) {
        let carries = self
            .identities
            .get(&peer)
            .is_some_and(|identity| identity.user_hash() == user_hash);
        if carries {
            self.identified.insert(peer);
            if let Some(identity) = self.identities.get(&peer) {
                self.hashes
                    .note(now, peer.ip(), identity.tcp_port(), user_hash);
            }
        }
    }

    /// Whether the new link `peer`, whose hello is `identity`, names the User
    /// Hash of an identified client still linked from another IPv4 address or
    /// listen port — aMule bans that newcomer, "Userhash invalid"
    /// (`ClientList.cpp:384-392`), at the `OP_HELLO` of a socket the peer
    /// opened (`ClientTCPSocket.cpp:391`), so never on a link rmule dialed.
    /// Off IPv4 a second address is no proof of a second party (ADR-0107):
    /// [`on_key_mismatch`](Self::on_key_mismatch) bans there, on proof.
    pub(super) fn refuses_hash_thief(&self, peer: PeerEndpoint, identity: &PeerIdentity) -> bool {
        !self.dialed.contains_key(&peer)
            && self.identities.iter().any(|(held, known)| {
                *held != peer
                    && addresses_part_clients(*held, peer)
                    && known.user_hash() == identity.user_hash()
                    && self.identified.contains(held)
                    && !self.queue.is_unlinked(*held)
                    && (held.ip() != peer.ip() || known.tcp_port() != identity.tcp_port())
            })
    }

    /// `peer`'s session proved a key that is not the one the ledger binds to
    /// `user_hash`, the hash its hello names. With the client that holds the
    /// bound key still linked that is two parties for certain, and `peer` is
    /// the thief: its address is banned (ADR-0107). A client on two addresses
    /// holds one key, so it never lands here.
    pub(in crate::serve) fn on_key_mismatch(
        &self,
        peer: PeerEndpoint,
        user_hash: UserHash,
    ) -> Vec<ServeDecision> {
        let names_it = self
            .identities
            .get(&peer)
            .is_some_and(|identity| identity.user_hash() == user_hash);
        let holder_linked = self.identities.iter().any(|(held, known)| {
            *held != peer
                && known.user_hash() == user_hash
                && self.identified.contains(held)
                && !self.queue.is_unlinked(*held)
        });
        if names_it && holder_linked {
            vec![
                ServeDecision::Ban { peer },
                ServeDecision::Disconnect { peer },
            ]
        } else {
            Vec::new()
        }
    }

    /// Settle a slot ask from `peer`, which holds no standing, against a
    /// standing of its User Hash that an address cannot part from it
    /// (ADR-0107, "One client on two addresses"). A standing whose link ended
    /// moves to `peer`, and the ask goes on. A live one stays where it is:
    /// a proved second link is answered the client's rank, and an unproved
    /// one nothing. `None` with no such standing; otherwise the
    /// [`settle_hash_clash`](Self::settle_hash_clash) pair.
    fn settle_second_address(
        &mut self,
        peer: PeerEndpoint,
        user_hash: UserHash,
    ) -> Option<(Vec<ServeDecision>, bool)> {
        if self.queue.contains(peer) {
            return None;
        }
        let (held, linked, proved) = self.queue.standings().find_map(|(held, linked)| {
            let same_hash = held != peer
                && self
                    .identities
                    .get(&held)
                    .is_some_and(|known| known.user_hash() == user_hash);
            let proved = same_hash && self.proved_one_client(held, peer);
            (proved || same_hash && !addresses_part_clients(held, peer))
                .then_some((held, linked, proved))
        })?;
        if !linked {
            let moved = self.move_standing(held, peer, false);
            let granted = self.queue.is_granted(peer);
            return Some((moved, granted));
        }
        if !proved {
            return Some((Vec::new(), true));
        }
        let rank = self.queue.standing_rank(held)?;
        let answer = ServeDecision::Send {
            peer,
            command: ServerCommand::SetQueueRank { rank },
        };
        Some((vec![answer], true))
    }

    /// Settle a slot ask from `peer` against the standings holding its User
    /// Hash on other links. Where an address cannot part two clients,
    /// [`settle_second_address`](Self::settle_second_address) decides;
    /// between two IPv4 addresses each waiter not identified leaves the wait
    /// list (`UploadQueue.cpp:432-458`), and when one clashed and `peer`
    /// itself is not identified its ask is answered nothing. The second value
    /// says the ask stops here. A waiter whose link already ended is
    /// forgotten with its place.
    pub(super) fn settle_hash_clash(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        modifiers: &dyn ScoreModifiers,
    ) -> (Vec<ServeDecision>, bool) {
        let Some(user_hash) = self.identities.get(&peer).map(PeerIdentity::user_hash) else {
            return (Vec::new(), false);
        };
        if let Some(settled) = self.settle_second_address(peer, user_hash) {
            return settled;
        }
        let clashing: Vec<PeerEndpoint> = self
            .queue
            .waiters()
            .map(|(held, _)| held)
            .filter(|held| {
                *held != peer
                    && addresses_part_clients(*held, peer)
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
            let promotion = self.leave_queue(held, now, modifiers);
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
