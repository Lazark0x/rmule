//! **Rung 0** of a download's Low-ID route (ADR-0061's route tree, ADR-0087's
//! rung): a Low-ID candidate that named a usable IPv6, while we hold a Known
//! IPv6 of our own, is dialed there directly — ahead of every callback road and
//! the punch — and falls to those roads only when that dial never connects.
//!
//! The classic "Low ID ⇒ callback" rule governs a peer's *IPv4 identity*; its
//! IPv6 address stands on its own, and a firewalled peer that has one needs no
//! broker at all. `ReachPeer` has taken this rung since ADR-0087 through
//! [`select_callback_route`](crate::callback::select_callback_route); this is
//! the download's reading of the same rung, through the same
//! [`choose_dial`] AND, so the two cannot disagree about when an IPv6 half is
//! dialable.

use rmule_primitives::PeerEndpoint;

use crate::dialable::{DialPosition, choose_dial};

use super::{CallbackCapability, Decision, DownloadState, LowIdCandidate, LowIdRoad, WorkerSlot};

/// How a Low-ID candidate is reached **first** — the admission rule a
/// download's slot fill reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::download) enum LowIdRoute {
    /// Rung 0: dial the candidate's IPv6 half, as a plain worker. A dial that
    /// never connects hands the candidate to [`Self::Road`]'s rule, once.
    DirectIpv6(PeerEndpoint),
    /// A callback road or the punch ([`LowIdRoad::of`]).
    Road(LowIdRoad),
}

impl LowIdRoute {
    /// The one site that orders rung 0 ahead of the callback roads.
    ///
    /// Rung 0 is the [`choose_dial`] AND — the candidate named an IPv6 half
    /// **and** `dial` holds a Known IPv6 of ours — and nothing else: no
    /// callback capability is consulted, because nobody is asked to dial us.
    /// Otherwise the candidate's road is [`LowIdRoad::of`]'s, unchanged, and
    /// `None` is still the honest starvation it always was.
    ///
    /// Stated here rather than in [`DownloadState`] because the runner asks it
    /// too, of the lookup snapshot, before any brain exists.
    pub(in crate::download) fn of(
        capability: &CallbackCapability,
        dial: DialPosition,
        candidate: &LowIdCandidate,
    ) -> Option<Self> {
        match choose_dial(None, candidate.ipv6, dial) {
            Some(half) => Some(Self::DirectIpv6(half)),
            None => LowIdRoad::of(capability, candidate).map(Self::Road),
        }
    }
}

impl DownloadState {
    /// Which route, if any, a Low-ID `candidate` can be reached by — the
    /// brain's reading of [`LowIdRoute::of`], with our half filled in.
    ///
    /// Rung 0 is offered at most once per **half** per spent term: after a
    /// failed IPv6 dial that address is spent ([`spent`](super::spent) — the same two re-ask
    /// generations as a High-ID endpoint), and the
    /// candidate is read as if we held no IPv6 to dial from — until a later
    /// sighting names a different half, which re-opens rung 0 there, once
    /// Or when the road it is on ends, or once the
    /// half has sat out a re-ask period. Nor is it offered for an
    /// endpoint a worker already holds — that peer is being dialed or worked
    /// by another road, and one endpoint keys one worker.
    pub(super) fn low_id_route(&self, candidate: &LowIdCandidate) -> Option<LowIdRoute> {
        let spent = candidate.ipv6.is_some_and(|half| {
            let endpoint = PeerEndpoint::V6(half);
            self.spent.contains(&endpoint) || self.workers.contains_key(&endpoint)
        });
        let dial = if spent {
            DialPosition::default()
        } else {
            self.dial
        };
        LowIdRoute::of(&self.callback_capability, dial, candidate)
    }

    /// Open rung 0 for `candidate` on `slot`: dial its IPv6 half as an ordinary
    /// worker, and keep the candidate so a dial that never connects can fall
    /// to its callback roads ([`Self::on_direct_ipv6_ended`]). The kept record
    /// is also the crypt side the dial meets with our policy — its stated
    /// stance and User Hash ([`Self::peer_crypt`]), as a
    /// High ID's is.
    pub(super) fn open_direct_ipv6(
        &mut self,
        candidate: LowIdCandidate,
        half: PeerEndpoint,
        slot: WorkerSlot,
        out: &mut Vec<Decision>,
    ) {
        self.direct_ipv6_dials.insert(half, candidate);
        self.spawn_worker(half, slot, out);
    }

    /// A worker at `peer` retired. If it was a rung-0 dial that never
    /// connected, the candidate goes back to the **front** of its queue with
    /// that half spent, so the refill that follows opens its callback road —
    /// or, when none is open, keeps it as the skipped-not-dropped record every
    /// inadmissible candidate is. A dial that did connect reached the peer:
    /// its end is an ordinary worker's, and the candidate is done.
    pub(super) fn on_direct_ipv6_ended(&mut self, peer: PeerEndpoint, connected: bool) {
        let Some(candidate) = self.direct_ipv6_dials.remove(&peer) else {
            return;
        };
        if connected {
            return;
        }
        // Info, not debug: the fall-through is the one live trace of rung 0
        // giving way, and the `ipv6-download-rung0` bench scenario reads it.
        tracing::info!(
            %peer,
            low_id = candidate.low_id.as_u32(),
            "rung-0 IPv6 dial failed; the Low-ID candidate falls to its callback roads"
        );
        self.spent.spend(peer);
        self.requeue_low_id(candidate);
    }

    /// `candidate`'s callback road or punch ended without a connection. A
    /// lapsed road has always ended its candidate — except when rung 0 is open
    /// for it now: a sighting merged while the road was pending named a half
    /// not yet spent, or our Known IPv6 arrived meanwhile. Then it
    /// goes back to the **front** of its queue, and the refill that follows
    /// dials that half before any next road. Whether rung 0 is open is
    /// [`Self::low_id_route`]'s answer — the one road choice — so a spent half
    /// seen again during the road re-opens nothing.
    pub(super) fn on_low_id_road_ended(&mut self, candidate: LowIdCandidate) {
        if let Some(LowIdRoute::DirectIpv6(half)) = self.low_id_route(&candidate) {
            tracing::debug!(
                %half,
                low_id = candidate.low_id.as_u32(),
                "a Low-ID road ended; rung 0 is open at the candidate's half"
            );
            self.requeue_low_id(candidate);
        }
    }

    /// Put `candidate` back at the front of the queue its `source_server`
    /// names, for the refill that follows.
    fn requeue_low_id(&mut self, candidate: LowIdCandidate) {
        if candidate.source_server.is_none() {
            self.low_id_pool.push_front(candidate);
        } else {
            self.low_id_global_pool.push_front(candidate);
        }
    }

    /// Fold a later sighting into a rung-0 dial in flight for the same source,
    /// so it is neither pooled a second time nor lost. `false` when no dial
    /// is in flight for it.
    pub(super) fn merge_into_direct_ipv6(&mut self, candidate: LowIdCandidate) -> bool {
        match self
            .direct_ipv6_dials
            .values_mut()
            .find(|held| held.key() == candidate.key())
        {
            Some(held) => {
                held.merge(candidate);
                true
            }
            None => false,
        }
    }

    /// Our Known IPv6 moved (ADR-0087: re-derived on every advert, never
    /// cached). A candidate starved under the old sample may be dialable now,
    /// so the free slots fill; a dial already under way is left alone.
    pub(crate) fn on_dial_position(&mut self, dial: DialPosition) -> Vec<Decision> {
        if dial == self.dial {
            return Vec::new();
        }
        self.dial = dial;
        let mut out = Vec::new();
        self.fill(&mut out);
        out
    }
}
