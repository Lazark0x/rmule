//! The **Dial-Back Grant** (ADR-0057): a waiter promoted while no link of it
//! was up is reached as aMule's `AddUpNextClient` reaches an unconnected
//! client (`UploadQueue.cpp:206-210`) — on a live link of the same client
//! when one exists, else by dialing it where its hello says a dial reaches
//! it — and granted after the hellos (`BaseClient.cpp:1707-1716`). A dial that
//! ends first, or reaches another client, ends the grant and the waiter's
//! place, as aMule deletes a client whose upload connect failed
//! (`BaseClient.cpp:1333-1337`), and the slot goes on to the next waiter.

use std::collections::HashMap;
use std::time::Instant;

use rmule_peer::{PeerIdentity, ServerCommand};
use rmule_primitives::{FileHash, PeerCrypt, PeerEndpoint, PeerSource};

use crate::adapters::DialBack;
use crate::service::{DialBackEnd, DialEnd, GrantRoad, ServeEvent};
use crate::upload_queue::Relinked;

use super::{ServeDecision, ServeState};

impl ServeState {
    /// Reach `waiter`, promoted to `file_hash`'s slot with no link of its own
    /// up: grant on a live link whose hello names its User Hash, its place
    /// moving there, or dial it back where its hello says a dial reaches it.
    /// With neither — a waiter whose hello this side no longer holds — its
    /// grant waits for its next connection, and the purge reclaims one that
    /// never comes.
    pub(super) fn reach_promoted(
        &mut self,
        waiter: PeerEndpoint,
        file_hash: FileHash,
    ) -> Vec<ServeDecision> {
        let Some(identity) = self.identities.get(&waiter) else {
            return Vec::new();
        };
        let user_hash = identity.user_hash();
        let at = identity
            .source_coordinate(waiter)
            .peer_source()
            .and_then(PeerSource::as_peer_endpoint);
        let crypt = PeerCrypt::new(identity.crypt_stance(), Some(user_hash));
        let software = Some(identity.software().clone());
        // The lowest endpoint, so two live links of one client pick alike.
        let live = self
            .identities
            .iter()
            .filter(|(held, known)| {
                **held != waiter
                    && known.user_hash() == user_hash
                    && !self.queue.is_unlinked(**held)
            })
            .map(|(held, _)| *held)
            .min();
        if let Some(link) = live
            && let Some(Relinked::HeldGrant { file_hash }) = self.queue.relink(waiter, link)
        {
            self.shed_link_state(waiter);
            return vec![
                ServeDecision::Emit(ServeEvent::WaiterRelinked {
                    from: waiter,
                    to: link,
                }),
                ServeDecision::Send {
                    peer: link,
                    command: ServerCommand::GrantSlot { file_hash },
                },
                ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                    peer: link,
                    file_hash,
                    software: self.software_of(link),
                    road: GrantRoad::Linked,
                }),
            ];
        }
        let Some(at) = at else {
            return Vec::new();
        };
        vec![
            ServeDecision::DialBack(DialBack { waiter, at, crypt }),
            ServeDecision::Emit(ServeEvent::UploadDialBack {
                peer: waiter,
                file_hash,
                software,
            }),
        ]
    }

    /// The dial-back to `waiter` came up as `link`, whose hello is `identity`
    /// (ADR-0057). The waiter's held grant moves onto the link and
    /// `OP_ACCEPTUPLOADREQ` goes on it. A hello that names another client
    /// ends the grant; a grant already delivered elsewhere — the client came
    /// back first — or reclaimed leaves the link to whatever its hello finds,
    /// and a link nothing of ours stands on is let go.
    pub(in crate::serve) fn on_dial_back_linked(
        &mut self,
        now: Instant,
        waiter: PeerEndpoint,
        link: PeerEndpoint,
        identity: PeerIdentity,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let mut decisions = Vec::new();
        if self.queue.pending_grant(waiter).is_some() {
            let theirs = self.identities.get(&waiter).map(PeerIdentity::user_hash);
            if theirs == Some(identity.user_hash())
                && let Some(Relinked::HeldGrant { file_hash }) = self.queue.relink(waiter, link)
            {
                let software = Some(identity.software().clone());
                self.shed_link_state(waiter);
                self.identities.insert(link, identity);
                return vec![
                    ServeDecision::Emit(ServeEvent::WaiterRelinked {
                        from: waiter,
                        to: link,
                    }),
                    ServeDecision::Send {
                        peer: link,
                        command: ServerCommand::GrantSlot { file_hash },
                    },
                    ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                        peer: link,
                        file_hash,
                        software,
                        road: GrantRoad::DialedBack,
                    }),
                ];
            }
            decisions.extend(self.end_dial_back(
                now,
                waiter,
                DialBackEnd::AnotherClient,
                modifiers,
            ));
        }
        // An ordinary new link now: its hello may still name a waiter of ours.
        let mut found = self.on_connection_fact(
            now,
            link,
            rmule_peer::ConnectionEvent::Identified { identity },
            modifiers,
        );
        if found.is_empty() {
            found.push(ServeDecision::Disconnect { peer: link });
        }
        decisions.extend(found);
        decisions
    }

    /// The dial-back to `waiter` ended before a hello, for `cause`: its held
    /// grant ends with its place, and the slot promotes the next waiter. A
    /// grant already delivered on a link the client came back on is left as
    /// it is.
    pub(in crate::serve) fn on_dial_back_failed(
        &mut self,
        now: Instant,
        waiter: PeerEndpoint,
        cause: DialEnd,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        if self.queue.pending_grant(waiter).is_none() {
            return Vec::new();
        }
        self.end_dial_back(now, waiter, DialBackEnd::Dial(cause), modifiers)
    }

    /// End `waiter`'s held grant unsent: the waiter leaves the queue — its
    /// next ask starts its wait from zero (`UploadQueue.cpp:501`) — and the
    /// freed slot promotes the next waiter.
    fn end_dial_back(
        &mut self,
        now: Instant,
        waiter: PeerEndpoint,
        cause: DialBackEnd,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let promotion = self.queue.release(waiter, now, modifiers);
        self.shed_link_state(waiter);
        let mut decisions = vec![ServeDecision::Emit(ServeEvent::UploadDialBackFailed {
            peer: waiter,
            cause,
        })];
        decisions.extend(self.promotion_decisions(promotion));
        decisions
    }

    /// Shed what is kept under `peer`, a key the client's standing just left.
    pub(super) fn shed_link_state(&mut self, peer: PeerEndpoint) {
        self.served_ranges
            .retain(|(range_peer, _), _| *range_peer != peer);
        self.forget(peer);
        self.sx_throttle.forget(peer);
    }
}
