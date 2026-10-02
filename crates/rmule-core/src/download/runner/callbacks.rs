//! The runner-side enactment state of one download's pending callbacks: the
//! deadline heap the fleet loop sleeps on, the two shared routing tables an
//! outstanding callback is registered in, and the rule that keeps them in step.
//!
//! No policy lives here. The sans-I/O brain (`DownloadState`) decides which
//! callbacks exist, when they lapse and what a lapse releases; this only
//! resolves the brain's spans against a clock and its keys against runtime
//! facts the brain deliberately does not hold.
//!
//! # Two roads, one key
//!
//! A pending Low-ID callback can be answered twice over (ADR-0039 + ADR-0091).
//! The peer may dial in because the server relayed the callback — matched by
//! `(connected_server, low_id)` in the **pending-callback table**. Or, twelve
//! seconds later, a punch may raise a **Dialer Tunnel** toward it — matched by
//! the target's **User Hash** in the **Pending Tunnel Claim** table. Both are
//! attempts on the *one* callback, so both register under the one
//! [`CallbackKey`] and the brain's single `CancelCallbackTimeout` ends both:
//! [`CallbackContext::end_callback`] is the one place that says so, which is
//! what keeps a landed connection on either road from leaving the other road's
//! registration behind to adopt a second worker for a slot already taken.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use rmule_peer::PartBitmap;
use rmule_primitives::{Ed2kFileLink, Ipv4Endpoint, UserHash};
use tokio::sync::mpsc;

use crate::adapters::{
    CallbackKey, PeerWorker, PendingTunnelEntry, SharedCallbackTable, SharedTunnelClaims,
};
use crate::diagnostics::NattRetirement as AttemptRetirement;
use crate::download::state::LowIdCandidate;

use super::CallbackFacts;

/// Which of a pending callback's two deadlines an entry is (ADR-0039 /
/// ADR-0091). Both key on the same [`CallbackKey`], because both belong to the
/// one callback — and a `CancelCallbackTimeout` therefore drops both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CallbackDeadline {
    /// The **callback-silence fallback** (12 s): if the callback is still
    /// pending, its candidate falls to a NAT-T attempt *beside* it. First in
    /// the derived order, which is also the order they fire in.
    SilenceFallback,
    /// The slot-release deadline (the injected 30 s): the callback lapsed and
    /// the held slot goes to the next candidate — unless a traversal is still
    /// running, which the slot then waits on.
    SlotRelease,
    /// The traversal bound: the latest the **Traversal Attempt** the callback
    /// fell to can still be running. Last in the order, as it is
    /// the last to fire.
    TraversalBound,
}

/// The runner-side Low-ID callback enactment state (ADR-0039 / ADR-0051 /
/// ADR-0091), owned by `apply_peer_workers_download` for the download's life:
/// - `server_key`: the download's connected server, used to resolve a brain-side
///   connected-server key (`server: None`) to the concrete endpoint the routing
///   index and inbound peer report — a runtime fact the brain deliberately omits.
/// - `facts`: the live facts behind the **Callback Capability** — sampled
///   for the brain on the loop's tick, and the source of rmule's own contact
///   for a per-server global callback's `OP_GLOBCALLBACKREQUEST` payload.
/// - `adopt_tx`: the channel either adoption road hands a worker back on,
///   tagged with the callback key it settles.
/// - `retire_tx`: the road not taken — where the NAT-T front reports that the
///   **Traversal Attempt** beside this callback retired, tagged the same way
///   (ADR-0091).
/// - `deadlines`: a dumb per-callback deadline min-heap the select! loop sleeps on
///   (`Reverse` makes `BinaryHeap` a min-heap). It carries the brain's [`CallbackKey`]
///   verbatim plus which of the two deadlines it is, so a fire calls the brain back
///   with no resolution; ties break by the key's then the kind's derived order.
/// - `natt_claims`: which target hash this runner claimed for which callback —
///   the index that lets a cancel carrying the *callback's* key retract a claim
///   the shared table holds under the *target's hash*.
/// - `pending_callbacks` / `tunnel_claims`: the two core-wide tables every
///   registration above lands in, held so the context's `Drop` can empty them
///   of this download's entries on whatever road the run ends.
pub(super) struct CallbackContext {
    pub(super) server_key: Option<Ipv4Endpoint>,
    pub(super) facts: CallbackFacts,
    pub(super) adopt_tx: mpsc::Sender<(CallbackKey, PeerWorker)>,
    pub(super) retire_tx: mpsc::Sender<(CallbackKey, AttemptRetirement)>,
    pub(super) deadlines:
        BinaryHeap<Reverse<(tokio::time::Instant, CallbackKey, CallbackDeadline)>>,
    natt_claims: HashMap<CallbackKey, UserHash>,
    pending_callbacks: SharedCallbackTable,
    tunnel_claims: SharedTunnelClaims,
}

impl CallbackContext {
    /// A download's callback state at the start of its run, registering into
    /// the core-wide `pending_callbacks` and `tunnel_claims`.
    pub(super) fn new(
        server_key: Option<Ipv4Endpoint>,
        facts: CallbackFacts,
        adopt_tx: mpsc::Sender<(CallbackKey, PeerWorker)>,
        retire_tx: mpsc::Sender<(CallbackKey, AttemptRetirement)>,
        pending_callbacks: SharedCallbackTable,
        tunnel_claims: SharedTunnelClaims,
    ) -> Self {
        Self {
            server_key,
            facts,
            adopt_tx,
            retire_tx,
            deadlines: BinaryHeap::new(),
            natt_claims: HashMap::new(),
            pending_callbacks,
            tunnel_claims,
        }
    }

    /// Resolve a brain-side [`CallbackKey`] to the routing-index key the
    /// called-back peer reports: the connected-server form (`server: None`)
    /// becomes this download's live connected server, which the sans-I/O brain
    /// does not hold (a runtime fact, like the clock). A per-server global key
    /// is already concrete and passes through.
    pub(super) fn routing_key(&self, key: CallbackKey) -> CallbackKey {
        CallbackKey {
            server: key.server.or(self.server_key),
            low_id: key.low_id,
        }
    }

    /// Claim the **Dialer Tunnel** `candidate`'s punch may raise, so it comes
    /// back to this download instead of taking the serve road (ADR-0091).
    /// Reports whether a claim was made.
    ///
    /// A candidate with no **User Hash** claims nothing, and that is the whole
    /// of the condition: the claim table has no other key, and no hello could
    /// confirm an entry filed under something a peer never states. Its
    /// fallback still runs — the server coordinator is asked by id — and
    /// whatever Tunnel it raises is served as the ordinary inbound peer it is.
    pub(super) async fn claim_tunnel(
        &mut self,
        claims: &SharedTunnelClaims,
        candidate: &LowIdCandidate,
        file: &Ed2kFileLink,
        own_status: PartBitmap,
        want_sources: bool,
    ) -> bool {
        self.claim(claims, candidate, file, own_status, want_sources, false)
            .await
    }

    /// Claim the connection a **buddy callback** asks `candidate` to open to
    /// us (ADR-0061 route 4): the same entry a punch claims, with
    /// the dial-back admitted too, because the target dials a path nothing
    /// here aimed and names itself only by its User Hash. Reports whether a
    /// claim was made; the admission rule never opens this road without one.
    pub(super) async fn claim_dial_back(
        &mut self,
        claims: &SharedTunnelClaims,
        candidate: &LowIdCandidate,
        file: &Ed2kFileLink,
        own_status: PartBitmap,
        want_sources: bool,
    ) -> bool {
        self.claim(claims, candidate, file, own_status, want_sources, true)
            .await
    }

    async fn claim(
        &mut self,
        claims: &SharedTunnelClaims,
        candidate: &LowIdCandidate,
        file: &Ed2kFileLink,
        own_status: PartBitmap,
        want_sources: bool,
        dial_back: bool,
    ) -> bool {
        let Some(target) = candidate.user_hash else {
            return false;
        };
        let key = candidate.key();
        claims
            .register(
                target,
                PendingTunnelEntry {
                    file: file.clone(),
                    own_status,
                    want_sources,
                    callback: key,
                    adopt_tx: self.adopt_tx.clone(),
                    retire_tx: self.retire_tx.clone(),
                    dial_back,
                },
            )
            .await;
        self.natt_claims.insert(key, target);
        true
    }

    /// Retract just `key`'s tunnel claim, leaving the callback running
    /// (ADR-0091): its **Traversal Attempt** retired, so no Tunnel
    /// will ever be dialed toward that target for it, but the server-relayed
    /// road is still open and still holds the slot.
    ///
    /// The narrow sibling of [`Self::end_callback`], which ends both roads.
    /// Idempotent: a callback that was never claimable claimed nothing.
    pub(super) async fn retract_claim(&mut self, key: CallbackKey, claims: &SharedTunnelClaims) {
        if let Some(target) = self.natt_claims.remove(&key) {
            claims.retract(target, &self.adopt_tx).await;
        }
    }

    /// `key`'s callback is over — adopted down either road, or lapsed. Drop
    /// both its deadlines and retract both its registrations.
    ///
    /// Every step is idempotent, because each is already half-done depending
    /// on how the callback ended: an adoption spent the table entry it came
    /// through, a lapse already popped the deadline that fired. What must not
    /// happen is any of them being left behind — a stale claim would hand this
    /// download a second worker for a slot the first one took.
    pub(super) async fn end_callback(
        &mut self,
        key: CallbackKey,
        pending_callbacks: &SharedCallbackTable,
        claims: &SharedTunnelClaims,
    ) {
        self.deadlines.retain(|Reverse((_, held, _))| *held != key);
        let routing = self.routing_key(key);
        pending_callbacks
            .lock()
            .await
            .retract(&routing, &self.adopt_tx);
        if let Some(target) = self.natt_claims.remove(&key) {
            claims.retract(target, &self.adopt_tx).await;
        }
    }
}

/// A download's run is over — completed, failed, cancelled, paused, ended by a
/// `?` or aborted by a quit — so every callback it still has pending ends
/// with it (ADR-0093 invariant 1). The brain's own terminal emits
/// no `CancelCallbackTimeout` per pending key, and an aborted task runs no
/// terminal at all; the drop is the one exit every road passes. Left behind,
/// an entry would hold a dead `adopt_tx`, mark a later dial-back `Readopted`
/// only to lose it, and block the target's hash for every other download.
///
/// Both tables are `tokio` mutexes, so the drop takes them without waiting;
/// a table busy at that instant is emptied by a task spawned for it.
impl Drop for CallbackContext {
    fn drop(&mut self) {
        self.deadlines.clear();
        self.natt_claims.clear();
        let owner = self.adopt_tx.clone();
        let callbacks_done = self
            .pending_callbacks
            .try_lock()
            .map(|mut table| table.release_owner(&owner))
            .is_ok();
        let claims_done = self.tunnel_claims.try_release_owner(&owner);
        if callbacks_done && claims_done {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let pending_callbacks = self.pending_callbacks.clone();
        let tunnel_claims = self.tunnel_claims.clone();
        runtime.spawn(async move {
            if !callbacks_done {
                pending_callbacks.lock().await.release_owner(&owner);
            }
            if !claims_done {
                tunnel_claims.release_owner(&owner).await;
            }
        });
    }
}

/// Sleep until `deadline`, or never if no callback is outstanding — the
/// callback-timeout select! arm's timer (ADR-0039).
pub(super) async fn sleep_until_optional(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests;
