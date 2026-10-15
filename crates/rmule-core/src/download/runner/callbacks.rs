//! The runner-side enactment state of one download's pending callbacks: the
//! **Awaited Inbound** registration each outstanding callback holds.
//!
//! No policy lives here. The sans-I/O brain (`DownloadState`) decides which
//! callbacks exist, when they lapse and what a lapse releases, and holds their
//! deadlines on its records (ADR-0090); this only resolves its keys against
//! runtime facts the brain deliberately does not hold.
//!
//! # Two roads, one key
//!
//! A pending Low-ID callback can be answered twice over (ADR-0039 + ADR-0091):
//! the server relays it, or a punch or a buddy's relay brings the peer in by
//! its **User Hash**. Both roads are filed in the callback's one registration,
//! held here under the brain's [`CallbackKey`], so the brain's single
//! `EndCallback` ends both by dropping it, and a run's end drops every one it
//! still holds.

use std::collections::HashMap;

use rmule_peer::PartBitmap;
use rmule_primitives::Ed2kFileLink;

use crate::adapters::{
    AdoptSender, AdoptionBrief, AwaitedInbound, AwaitedInboundHandle, CallbackKey, PeerWorker,
    RetireSender,
};
use crate::download::state::LowIdCandidate;

use super::CallbackFacts;

/// The runner-side Low-ID callback enactment state (ADR-0039 / ADR-0051 /
/// ADR-0091), owned by `apply_peer_workers_download` for the download's life:
/// - `facts`: the live facts behind the **Callback Capability** — sampled
///   for the brain on the loop's tick, the source of rmule's own contact
///   for a per-server global callback's `OP_GLOBCALLBACKREQUEST` payload, and
///   the live session a key minted with no server resolves against.
/// - `retire_tx`: the road not taken — where the NAT-T front reports that the
///   **Traversal Attempt** beside a callback retired, tagged with its key
///   (ADR-0091).
/// - `awaiting`: each outstanding callback's registration, by the brain's key.
///   Dropping one releases both of its roads, so the context's own drop ends
///   every callback the run still has pending (ADR-0093 invariant 1), on
///   whatever road the run ends — an aborted task included.
pub(super) struct CallbackContext {
    pub(super) facts: CallbackFacts,
    pub(super) retire_tx: RetireSender,
    adopt_tx: AdoptSender,
    registry: AwaitedInbound,
    awaiting: HashMap<CallbackKey, AwaitedInboundHandle>,
}

impl CallbackContext {
    /// A download's callback state at the start of its run, filing into the
    /// core-wide `registry`; `adopt_tx` is where either road hands a worker
    /// back, tagged with the callback key it settles.
    pub(super) fn new(
        facts: CallbackFacts,
        adopt_tx: AdoptSender,
        retire_tx: RetireSender,
        registry: AwaitedInbound,
    ) -> Self {
        Self {
            facts,
            retire_tx,
            adopt_tx,
            registry,
            awaiting: HashMap::new(),
        }
    }

    /// Resolve a brain-side [`CallbackKey`] to the key the called-back peer
    /// reports: one minted with no server known (`server: None`) is read
    /// against the server we are logged into *now*, the one whose session
    /// relays its `OP_CALLBACKREQUEST`. A key naming its server is already
    /// concrete and passes through.
    pub(super) fn routing_key(&self, key: CallbackKey) -> CallbackKey {
        CallbackKey {
            server: key.server.or_else(|| self.facts.server()),
            ..key
        }
    }

    /// File `key`'s server-relayed road, under the key the called-back peer
    /// will report, before the callback is asked for: an unusually fast
    /// dial-back always finds it.
    pub(super) fn await_callback(&mut self, key: CallbackKey, brief: AdoptionBrief) {
        let routing = self.routing_key(key);
        self.registration(key).await_callback(routing, brief);
    }

    /// Hand `worker`, which reaches `key`'s peer over its Peer Link
    /// (ADR-0107), to the fleet's adopt arm under the key the peer would
    /// report, as a callback's connection would be; `Err` gives it back when
    /// the arm is full, and the callback is asked for as before.
    pub(super) fn hand_ridden(
        &self,
        key: CallbackKey,
        worker: PeerWorker,
    ) -> Result<(), PeerWorker> {
        self.adopt_tx
            .try_send((self.routing_key(key), worker))
            .map_err(|refused| refused.into_inner().1)
    }

    /// Claim the **Dialer Tunnel** `candidate`'s punch may raise, so it comes
    /// back to this download instead of taking the serve road (ADR-0091).
    /// Reports whether a claim was made.
    ///
    /// A candidate with no **User Hash** claims nothing, and that is the whole
    /// of the condition: a claim has no other key, and no hello could
    /// confirm one filed under something a peer never states. Its
    /// fallback still runs — the server coordinator is asked by id — and
    /// whatever Tunnel it raises is served as the ordinary inbound peer it is.
    pub(super) fn claim_tunnel(
        &mut self,
        candidate: &LowIdCandidate,
        file: &Ed2kFileLink,
        own_status: PartBitmap,
        want_sources: bool,
    ) -> bool {
        self.claim(candidate, file, own_status, want_sources, false)
    }

    /// Claim the connection a **buddy callback** asks `candidate` to open to
    /// us (ADR-0061 route 4): the same claim a punch files, with
    /// the dial-back admitted too, because the target dials a path nothing
    /// here aimed and names itself only by its User Hash. Reports whether a
    /// claim was made; the admission rule never opens this road without one.
    pub(super) fn claim_dial_back(
        &mut self,
        candidate: &LowIdCandidate,
        file: &Ed2kFileLink,
        own_status: PartBitmap,
        want_sources: bool,
    ) -> bool {
        self.claim(candidate, file, own_status, want_sources, true)
    }

    fn claim(
        &mut self,
        candidate: &LowIdCandidate,
        file: &Ed2kFileLink,
        own_status: PartBitmap,
        want_sources: bool,
        dial_back: bool,
    ) -> bool {
        let Some(target) = candidate.user_hash else {
            return false;
        };
        let brief = AdoptionBrief {
            file: file.clone(),
            own_status,
            want_sources,
        };
        self.registration(candidate.key())
            .claim_tunnel(target, brief, dial_back);
        true
    }

    /// Retract just `key`'s tunnel claim, leaving the callback running
    /// (ADR-0091): its **Traversal Attempt** retired, so no Tunnel
    /// will ever be dialed toward that target for it, but the server-relayed
    /// road is still open and still holds the slot.
    ///
    /// The narrow sibling of [`Self::end_callback`], which ends both roads.
    /// Idempotent: a callback that was never claimable claimed nothing.
    pub(super) fn retract_claim(&mut self, key: CallbackKey) {
        if let Some(registration) = self.awaiting.get(&key) {
            registration.retract_claim();
        }
    }

    /// `key`'s callback is over — adopted down either road, or lapsed. Drop
    /// its registration, which releases both roads.
    pub(super) fn end_callback(&mut self, key: CallbackKey) {
        self.awaiting.remove(&key);
    }

    /// `key`'s registration, opened on its first road.
    fn registration(&mut self, key: CallbackKey) -> &AwaitedInboundHandle {
        let Self {
            registry,
            adopt_tx,
            retire_tx,
            awaiting,
            ..
        } = self;
        awaiting
            .entry(key)
            .or_insert_with(|| registry.register(key, adopt_tx.clone(), retire_tx.clone()))
    }
}

#[cfg(test)]
mod tests;
