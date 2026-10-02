//! The **dual-stack fallback** of a download's High-ID pool (ADR-0087):
//! a source that named both families is dialed first in the family the Dial
//! Chooser picks, and a first dial that never completes its handshake — no
//! route, refused, timed out — falls to the same peer's other family once
//! before the source retires.
//!
//! The pool and every worker are keyed by one endpoint, so the record keeps
//! the second half beside the endpoint it dials, until one of them connects.
//! The attempt budget is one dial per family: a half whose dial failed — first
//! family or second — is **spent** ([`spent`](super::spent)), so a later
//! sighting of the same peer dials only a half not yet spent, rather than
//! paying a failed family's timeout again. A single-address source is spent
//! the same way: it is one half with no other.
//! Rung 0 of a Low-ID candidate ([`direct_ipv6`](super::direct_ipv6)) is the
//! same shape for the Low-ID case; this is the High-ID one.

use rmule_primitives::{PeerEndpoint, UserHash};

use crate::dialable::{DialOrder, choose_dial};

use super::DownloadState;

impl DownloadState {
    /// Pool a High-ID source by its dial order: its first unspent half at the
    /// back of the pool, the other kept for [`Self::on_high_id_dial_ended`].
    ///
    /// A spent half is never pooled nor kept as a fallback, so a source both
    /// of whose halves are spent is not dialed again until one sits out a
    /// re-ask period. A peer either of whose halves an owner already holds —
    /// pooled, worked or remote-queued — is in hand already — one
    /// peer is one worker, never two in two families — and a sighting that
    /// names a half the held record lacks merges it there: a peer first
    /// pooled as plain IPv4 gains the IPv6 half a later source exchange names.
    ///
    /// A source whose record names a distrusted User Hash is not pooled at
    /// all.
    pub(super) fn pool_high_id(&mut self, order: DialOrder, user_hash: Option<UserHash>) {
        if self.distrusts(user_hash) {
            return;
        }
        if let Some(held) = order.halves().find(|&half| self.holds(half)) {
            let other = order.halves().find(|&half| half != held);
            if let Some(other) = other.filter(|&other| self.fallback_open(other)) {
                self.dual_stack_fallbacks.entry(held).or_insert(other);
            }
            return;
        }
        let mut unspent = order.halves().filter(|half| !self.spent.contains(half));
        let Some(first) = unspent.next() else {
            return;
        };
        let fallback = unspent.next();
        self.pool.push_back(first);
        self.seeds.dialable(first);
        if let Some(other) = fallback {
            self.dual_stack_fallbacks.insert(first, other);
        }
    }

    /// A High-ID dial at `peer` ended: `failed` when it never completed its
    /// handshake — a worker that could not start, or one that retired before
    /// its hello answer, for any reason but a `CryptIncompatible` refusal,
    /// which dialed nothing. A dial that did connect reached the peer, and its
    /// end is an ordinary worker's.
    ///
    /// A failed dial spends `peer` — a single-address source's one endpoint as
    /// much as a dual-stack half — and, for a dual-stack half, puts the other
    /// half, unless it is spent too, at the **front** of the pool, so the
    /// refill that follows dials it. The second dial keeps the spent first
    /// half as its own other half, so its failure spends it as well and falls
    /// nowhere: one dial per family.
    ///
    /// The other half is dialed only if it is dialable from here now: an IPv6
    /// half needs our Known IPv6 (the [`choose_dial`] AND), which may have
    /// arrived since the IPv4 was picked first.
    pub(super) fn on_high_id_dial_ended(&mut self, peer: PeerEndpoint, failed: bool) {
        let other = self.dual_stack_fallbacks.remove(&peer);
        if !failed {
            return;
        }
        self.spent.spend(peer);
        let Some(other) = other else {
            return;
        };
        let dialable = match other {
            PeerEndpoint::V4(_) => true,
            PeerEndpoint::V6(half) => choose_dial(None, Some(half), self.dial).is_some(),
        };
        if !dialable || !self.fallback_open(other) {
            return;
        }
        // Info, not debug: the fall is the one live trace of the other family
        // taking over, and the `ipv6-extsx-emit` bench scenario's IPv4 fallback leg reads it.
        tracing::info!(
            %peer,
            %other,
            "a dual-stack source's first-family dial failed; dialing its other family once"
        );
        self.pool.push_front(other);
        self.seeds.dialable(other);
        self.dual_stack_fallbacks.insert(other, peer);
    }

    /// Whether `half` may still be dialed as a peer's other family: not spent,
    /// and not already pooled or worked.
    fn fallback_open(&self, half: PeerEndpoint) -> bool {
        !self.spent.contains(&half) && !self.holds(half)
    }

    /// Whether an owner already holds `peer`: pooled, worked, or standing in
    /// the runner's Remote-Queued Pool (ADR-0090 "Source ownership").
    pub(super) fn holds(&self, peer: PeerEndpoint) -> bool {
        self.workers.contains_key(&peer)
            || self.pool.contains(&peer)
            || self.remote_queued.contains(&peer)
    }
}
