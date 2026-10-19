//! A waiter is a client, not a link (ADR-0057, "A client on a new link keeps
//! its standing"; ADR-0107, "One peer, one link"): the hello of a new link
//! that names a client the queue holds moves that client's place, its
//! pending dial-back grant — granted there at once — or its slot onto the new
//! link, as aMule attaches a new socket to the client it knows
//! (`ClientList.cpp:371-412`), keeps a queued client's place
//! (`UploadQueue.cpp:395-431`) and grants a client it promoted unconnected
//! once its hellos finish (`BaseClient.cpp:1707-1716`). Of two links of one
//! client crossing, the one both ends keep takes the client: each end keeps
//! the socket it read the other's hello on (`ClientList.cpp:400-403`), so a
//! link rmule dialed keeps it once its hello went out, and the link the peer
//! opened is let go. Two clients
//! under one User Hash are settled as aMule settles them: an identified one
//! still linked turns the newcomer away (`ClientList.cpp:384-392`), and at a
//! slot ask the ones not identified leave the wait list
//! (`UploadQueue.cpp:432-458`).

use std::collections::HashMap;
use std::time::Instant;

use rmule_peer::PeerIdentity;
use rmule_primitives::{PeerEndpoint, UserHash};

use rmule_peer::ServerCommand;

use crate::WaiterLeaveCause;
use crate::adapters::DialBackCallOff;
use crate::service::{GrantRoad, ServeEvent};
use crate::upload_queue::Relinked;

use super::{ServeDecision, ServeState};

/// What a new link's hello does to the standing of the client it names.
pub(super) enum Relink {
    /// No standing of the client is the new link's.
    None,
    /// The client's standing moved onto the new link.
    Moved(Vec<ServeDecision>),
    /// The standing stays where it is — on a link rmule dialed, the new link
    /// let go — or waits on its dial-back's call-off.
    Held(Vec<ServeDecision>),
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
    /// keeps it against the peer's own link from that address too: its hello
    /// went out, so the far side keeps it and closes its own, and `peer` is
    /// let go.
    ///
    /// A grant held for a dial-back waits on the dial's call-off: `peer` takes
    /// it only when no byte of the dial's hello went out
    /// ([`on_dial_back_call_off`](Self::on_dial_back_call_off)). A slot is
    /// granted again on the link it moved to, so the session there serves its
    /// part asks (`UploadQueue.cpp:486-493`).
    pub(super) fn relink_waiter(&mut self, peer: PeerEndpoint, identity: &PeerIdentity) -> Relink {
        let found = self.queue.standings().find_map(|(held, linked)| {
            let known = self.identities.get(&held)?;
            (held != peer && known.user_hash() == identity.user_hash()).then(|| {
                let same_place = held.ip() == peer.ip() && known.tcp_port() == identity.tcp_port();
                (held, linked, same_place)
            })
        });
        let Some((from, linked, same_place)) = found else {
            return Relink::None;
        };
        if linked && (!same_place || self.dialed.contains(&peer)) {
            return Relink::None;
        }
        if linked && self.dialed.contains(&from) {
            return Relink::Held(vec![
                ServeDecision::Disconnect { peer },
                ServeDecision::Emit(ServeEvent::CrossedLinkLetGo { peer }),
            ]);
        }
        if self.queue.pending_grant(from).is_some() {
            return Relink::Held(vec![ServeDecision::CallOffDialBack {
                waiter: from,
                link: peer,
            }]);
        }
        let moved = self.move_standing(from, peer, linked);
        if moved.is_empty() {
            Relink::None
        } else {
            Relink::Moved(moved)
        }
    }

    /// The dial-back to `waiter` was called off for `link`, the link the
    /// client came back on, and the call-off found `found` (ADR-0057, "Two
    /// hellos of one client race"). Stopped before its hello, the dial left
    /// the peer its own link: the held grant moves onto `link` and goes on it
    /// at once, as aMule grants a client it promoted unconnected on the first
    /// link its hellos finish on (`ClientTCPSocket.cpp:328`, `:417`). Past its
    /// hello, the peer keeps the dial and closes `link`: the grant stays held
    /// for the dial, and `link` is let go.
    pub(in crate::serve) fn on_dial_back_call_off(
        &mut self,
        waiter: PeerEndpoint,
        link: PeerEndpoint,
        found: DialBackCallOff,
    ) -> Vec<ServeDecision> {
        match found {
            DialBackCallOff::Stopped => {
                let moved = self.move_standing(waiter, link, false);
                if !moved.is_empty() {
                    self.stamp_contact(link);
                }
                moved
            }
            DialBackCallOff::PastHello => vec![
                ServeDecision::Disconnect { peer: link },
                ServeDecision::Emit(ServeEvent::CrossedLinkLetGo { peer: link }),
            ],
        }
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
