//! The **Source Book**'s stage transitions: a fill takes the next record in
//! lane order under the Low-ID admission rule, a worker's or a callback's end
//! hands its record to the road it has left — its RemoteQueued stage when it
//! holds a queue standing — and a worker's identity rides its Worker stage
//! (ADR-0090). Every transition moves one record from one stage to one other.

use rmule_peer::PeerIdentity;
use rmule_primitives::{Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, UserHash};

use super::record::{DialRoad, Heard, Lane, Live, RecordId, Stage};
use super::road::PendingRoad;
use super::standing::ReaskFacts;
use super::{Adopted, DialEnd, NextDial, Release, SourceBook, WorkerEnd};
use crate::adapters::CallbackKey;
use crate::dialable::{DialPosition, choose_dial};
use crate::download::state::{CallbackCapability, LowIdCandidate, LowIdRoute};

impl SourceBook {
    /// Take the next dial for a free slot, while the stages hold fewer than
    /// `cap`: the High-ID lane's first record, else the first Low-ID candidate
    /// the admission rule admits — the connected server's lane before the
    /// global one, a skipped candidate keeping its place. The record moves to
    /// Dialing or CallbackPending here.
    pub(crate) fn next_dial(
        &mut self,
        cap: usize,
        capability: &CallbackCapability,
        dial: DialPosition,
    ) -> Option<NextDial> {
        if self.slots_in_use() >= cap {
            return None;
        }
        if let Some(id) = self.lanes.pop_front(Lane::HighId) {
            let record = self.records.get_mut(&id)?;
            let endpoint = *record.endpoints.first()?;
            record.stage = Stage::Dialing(Live {
                road: DialRoad::HighId,
                endpoint,
            });
            return Some(NextDial::Worker(endpoint));
        }
        let (lane, id, route) = [Lane::LowIdConnected, Lane::LowIdGlobal]
            .into_iter()
            .find_map(|lane| {
                self.lanes
                    .iter(lane)
                    .find_map(|id| Some((lane, id, self.low_id_route(id, capability, dial)?)))
            })?;
        self.lanes.remove(lane, id);
        let record = self.records.get_mut(&id)?;
        let candidate = record.candidate?;
        match route {
            LowIdRoute::DirectIpv6(half) => {
                record.stage = Stage::Dialing(Live {
                    road: DialRoad::Rung0,
                    endpoint: half,
                });
                self.add_endpoint(id, half);
                Some(NextDial::Worker(half))
            }
            LowIdRoute::Road(road) => {
                record.stage = Stage::CallbackPending(PendingRoad::opened(road));
                Some(NextDial::Callback { candidate, road })
            }
        }
    }

    /// Whether nothing the book holds can still reach a slot: no High ID
    /// pooled, no Low-ID candidate any road admits, and nothing holding a
    /// queue standing, whose TCP full ask re-dials.
    pub(crate) fn starved(&self, capability: &CallbackCapability, dial: DialPosition) -> bool {
        self.lanes.is_empty(Lane::HighId)
            && [Lane::LowIdConnected, Lane::LowIdGlobal]
                .into_iter()
                .all(|lane| {
                    self.lanes
                        .iter(lane)
                        .all(|id| self.low_id_route(id, capability, dial).is_none())
                })
            && !self
                .records
                .values()
                .any(|record| matches!(record.stage, Stage::RemoteQueued(_)))
    }

    /// Which route, if any, `id`'s candidate is reached by — the admission
    /// rule ([`LowIdRoute::of`]) with rung 0 offered at most once per half per
    /// spent term, and never at a half another record answers to: that peer
    /// is held, and one endpoint keys one worker.
    pub(super) fn low_id_route(
        &self,
        id: RecordId,
        capability: &CallbackCapability,
        dial: DialPosition,
    ) -> Option<LowIdRoute> {
        let candidate = self.records.get(&id)?.candidate.as_ref()?;
        let dial = if self.half_closed(id, candidate) {
            DialPosition::default()
        } else {
            dial
        };
        LowIdRoute::of(capability, dial, candidate)
    }

    /// Whether `candidate`'s IPv6 half is closed to `id`'s rung 0: spent, or
    /// held by another record, or unbindable to a record already at two
    /// endpoints.
    fn half_closed(&self, id: RecordId, candidate: &LowIdCandidate) -> bool {
        candidate.ipv6.is_some_and(|half| {
            let endpoint = PeerEndpoint::V6(half);
            self.blocks.is_spent(endpoint)
                || match self.aliases.endpoint(endpoint) {
                    Some(holder) => holder != id,
                    None => self
                        .records
                        .get(&id)
                        .is_none_or(|record| record.endpoints.len() >= 2),
                }
        })
    }

    /// The worker at `endpoint` completed its handshake.
    pub(crate) fn connected(&mut self, endpoint: PeerEndpoint) {
        let Some(id) = self.aliases.endpoint(endpoint) else {
            return;
        };
        if let Some(record) = self.records.get_mut(&id)
            && let Stage::Dialing(live) = record.stage
            && live.endpoint == endpoint
        {
            record.stage = Stage::Worker(live, Heard::default());
        }
    }

    /// Whether the worker at `endpoint` completed its handshake.
    pub(crate) fn is_connected(&self, endpoint: PeerEndpoint) -> bool {
        self.record_at(endpoint).is_some_and(
            |record| matches!(record.stage, Stage::Worker(live, _) if live.endpoint == endpoint),
        )
    }

    /// The worker at `endpoint` ended — `failed` when its dial never completed
    /// a handshake. Its identity goes with its stage (ADR-0049). A failed dial
    /// spends its endpoint and ends any standing. A record with queue
    /// standing waits in the RemoteQueued stage at the endpoint, its other
    /// half done; a source reached by a Low-ID road keeps its candidate and
    /// `CallbackKey` for its TCP full ask, a High ID's Low-ID road is done.
    /// Otherwise a called-back source returns to its Low-ID lane
    /// ([`Self::end_called_back`]); a failed High-ID dial falls to the same
    /// peer's other half once; a failed rung-0 dial hands its candidate to its
    /// callback roads; anything else leaves the book.
    pub(crate) fn end_worker(
        &mut self,
        endpoint: PeerEndpoint,
        failed: bool,
        dial: DialPosition,
    ) -> Option<WorkerEnd> {
        let id = self.aliases.endpoint(endpoint)?;
        let live = self.records.get(&id)?.live_at(endpoint)?;
        // The identity's hash is one of the record's Ask Names until it goes.
        self.keep_asks(id);
        let record = self.records.get_mut(&id)?;
        let hello_hash = record.stage.identity().map(PeerIdentity::user_hash);
        if failed {
            self.blocks.spend(endpoint);
            record.standing = None;
        }
        if record.standing.is_some() {
            // The IPv6 the peer's session says it now holds is where this
            // queued source is dialed from here on, on the port it was
            // reached at. An IPv4 road is not redirected, and an address
            // another record holds stays that record's.
            let queued_at = match (
                endpoint,
                record.stage.identity().and_then(PeerIdentity::peer_ipv6),
            ) {
                (PeerEndpoint::V6(old), Some(address)) if old.ip != address => {
                    let moved = PeerEndpoint::V6(Ipv6Endpoint::new(address, old.port));
                    match self.aliases.endpoint(moved) {
                        None => {
                            record.endpoints.retain(|&held| held != endpoint);
                            record.endpoints.push(moved);
                            self.aliases.unbind_endpoint(endpoint, id);
                            self.aliases.bind_endpoint(moved, id);
                            moved
                        }
                        Some(_) => endpoint,
                    }
                }
                _ => endpoint,
            };
            record.stage = Stage::RemoteQueued(queued_at);
            if live.road == DialRoad::HighId {
                self.drop_candidate(id);
            }
            self.keep_only_endpoint(id, Some(queued_at));
            return Some(WorkerEnd::Release(Release::RemoteQueued));
        }
        if live.road == DialRoad::Callback {
            return Some(self.end_called_back(id, failed, hello_hash));
        }
        if !failed {
            self.remove(id);
            return Some(WorkerEnd::Release(Release::Gone));
        }
        Some(WorkerEnd::Dial(match live.road {
            DialRoad::HighId => self.fall(id, endpoint, dial),
            DialRoad::Rung0 => {
                // Info, not debug: the fall-through is the one live trace of
                // rung 0 giving way, and the `ipv6-download-rung0` bench
                // scenario reads it.
                tracing::info!(
                    peer = %endpoint,
                    low_id = record.candidate.map_or(0, |candidate| candidate.low_id.as_u32()),
                    "rung-0 IPv6 dial failed; the Low-ID candidate falls to its callback roads"
                );
                self.hand_to_callback_road(id)
            }
            DialRoad::Callback => unreachable!("a called-back worker's end is taken above"),
        }))
    }

    /// A called-back source's worker ended without a queue rank (ADR-0090): its
    /// record keeps its candidate and `CallbackKey` and returns to its Low-ID
    /// lane, so its next road is a callback again rather than only a fresh
    /// sighting. A worker that dropped before its handshake goes first, its
    /// inbound endpoint spent; one whose session ran waits its turn last. A
    /// source the download distrusts — by its record's hash or its hello's —
    /// leaves the book instead.
    fn end_called_back(
        &mut self,
        id: RecordId,
        failed: bool,
        hello_hash: Option<UserHash>,
    ) -> WorkerEnd {
        let candidate = self
            .records
            .get(&id)
            .and_then(|record| record.candidate)
            .filter(|candidate| {
                !self.blocks.distrusts(candidate.user_hash) && !self.blocks.distrusts(hello_hash)
            });
        let Some(candidate) = candidate else {
            self.remove(id);
            return if failed {
                WorkerEnd::Dial(DialEnd::Spent)
            } else {
                WorkerEnd::Release(Release::Gone)
            };
        };
        if failed {
            return WorkerEnd::Dial(self.hand_to_callback_road(id));
        }
        let lane = Lane::of(&candidate, self.own_server);
        self.keep_only_endpoint(id, candidate.ipv6.map(PeerEndpoint::V6));
        if let Some(record) = self.records.get_mut(&id) {
            record.stage = Stage::Pooled(lane);
        }
        self.lanes.push_back(lane, id);
        WorkerEnd::Release(Release::BackToLane)
    }

    /// A High-ID dial at `spent` failed: the other half, unless it is spent too
    /// or not dialable from here now (an IPv6 half needs our Known IPv6), goes
    /// first in the High-ID lane, keeping the spent half as its own other half
    /// so its failure falls nowhere — one dial per family.
    fn fall(&mut self, id: RecordId, spent: PeerEndpoint, dial: DialPosition) -> DialEnd {
        let Some(record) = self.records.get_mut(&id) else {
            return DialEnd::Spent;
        };
        let other = record.other_than(spent).filter(|&other| {
            !self.blocks.is_spent(other)
                && match other {
                    PeerEndpoint::V4(_) => true,
                    PeerEndpoint::V6(half) => choose_dial(None, Some(half), dial).is_some(),
                }
        });
        if let Some(other) = other {
            // Info, not debug: the fall is the one live trace of the other
            // family taking over, and the `ipv6-extsx-emit` bench scenario's
            // IPv4 fallback leg reads it.
            tracing::info!(
                peer = %spent,
                %other,
                "a dual-stack source's first-family dial failed; dialing its other family once"
            );
            record.endpoints = vec![other, spent];
            record.stage = Stage::Pooled(Lane::HighId);
            self.lanes.push_front(Lane::HighId, id);
            return DialEnd::FellToOtherHalf(other);
        }
        if record.candidate.is_some() {
            return self.hand_to_callback_road(id);
        }
        self.remove(id);
        DialEnd::Spent
    }

    /// Put `id`'s candidate first in its Low-ID lane, keeping only its current
    /// IPv6 half, for the refill that follows to open its next road.
    fn hand_to_callback_road(&mut self, id: RecordId) -> DialEnd {
        let Some(candidate) = self.records.get(&id).and_then(|record| record.candidate) else {
            self.remove(id);
            return DialEnd::Spent;
        };
        let lane = Lane::of(&candidate, self.own_server);
        self.keep_only_endpoint(id, candidate.ipv6.map(PeerEndpoint::V6));
        if let Some(record) = self.records.get_mut(&id) {
            record.stage = Stage::Pooled(lane);
        }
        self.lanes.push_front(lane, id);
        DialEnd::ToCallbackRoad
    }

    /// The candidate a callback in flight under `key` was requested for.
    pub(crate) fn callback_candidate(&self, key: CallbackKey) -> Option<LowIdCandidate> {
        let record = self.records.get(&self.aliases.key(key)?)?;
        matches!(record.stage, Stage::CallbackPending(_))
            .then_some(record.candidate)
            .flatten()
    }

    /// The peer `key`'s callback asked for dialed in at `endpoint` and was
    /// adopted (ADR-0039): its record moves to Dialing there, keeping its
    /// candidate and `CallbackKey` beside the worker. The inbound endpoint
    /// joins the record — a record that answered to it is the same peer.
    pub(crate) fn adopt(&mut self, key: CallbackKey, endpoint: PeerEndpoint) -> Option<Adopted> {
        let id = self.aliases.key(key)?;
        if !matches!(self.records.get(&id)?.stage, Stage::CallbackPending(_)) {
            return None;
        }
        let holder = self
            .aliases
            .endpoint(endpoint)
            .filter(|&holder| holder != id);
        if let Some(holder) = holder
            && self
                .records
                .get(&holder)
                .is_some_and(|record| record.stage.live().is_some())
        {
            let _ = self.merge(holder, id);
            self.remove(id);
            return Some(Adopted::Joined);
        }
        self.records.get_mut(&id)?.stage = Stage::Dialing(Live {
            road: DialRoad::Callback,
            endpoint,
        });
        if let Some(holder) = holder {
            let _ = self.merge(id, holder);
        }
        self.force_endpoint(id, endpoint);
        Some(Adopted::Worker)
    }

    /// Bind `endpoint` to `id` whatever answered to it before: a live worker's
    /// endpoint must name its record. A record left with no address to wait
    /// at leaves the book.
    fn force_endpoint(&mut self, id: RecordId, endpoint: PeerEndpoint) {
        if let Some(holder) = self
            .aliases
            .endpoint(endpoint)
            .filter(|&holder| holder != id)
        {
            self.keep_asks(holder);
            if let Some(record) = self.records.get_mut(&holder) {
                record.endpoints.retain(|&held| held != endpoint);
                self.aliases.unbind_endpoint(endpoint, holder);
                let orphaned = match record.stage {
                    Stage::RemoteQueued(at) => at == endpoint,
                    Stage::Pooled(Lane::HighId) => record.endpoints.is_empty(),
                    _ => false,
                };
                if orphaned {
                    self.remove(holder);
                }
            }
        }
        if self
            .records
            .get(&id)
            .is_none_or(|record| record.endpoints.contains(&endpoint))
        {
            return;
        }
        self.keep_asks(id);
        let Some(record) = self.records.get_mut(&id) else {
            return;
        };
        if record.endpoints.len() >= 2
            && let Some(dropped) = record.endpoints.pop()
        {
            self.aliases.unbind_endpoint(dropped, id);
        }
        record.endpoints.push(endpoint);
        self.aliases.bind_endpoint(endpoint, id);
    }

    /// `key`'s callback road ended without a connection — lapsed, or its only
    /// punch retired. A lapsed road has always ended its candidate, except
    /// when rung 0 is open now — a sighting named a half not yet spent while
    /// the road was pending, or our Known IPv6 arrived — or the record holds a
    /// dialable half another channel proved: then it goes first in that lane.
    pub(crate) fn end_callback(&mut self, key: CallbackKey, dial: DialPosition) -> Option<Release> {
        let id = self.aliases.key(key)?;
        let record = self.records.get(&id)?;
        if !matches!(record.stage, Stage::CallbackPending(_)) {
            return None;
        }
        let candidate = record.candidate?;
        if !self.half_closed(id, &candidate)
            && let Some(half) = choose_dial(None, candidate.ipv6, dial)
        {
            tracing::debug!(
                %half,
                low_id = candidate.low_id.as_u32(),
                "a Low-ID road ended; rung 0 is open at the candidate's half"
            );
            return Some(self.back_to(id, Lane::of(&candidate, self.own_server), None));
        }
        let half = candidate.ipv6.map(PeerEndpoint::V6);
        let dialable = record.endpoints.iter().copied().find(|&endpoint| {
            Some(endpoint) != half
                && !self.blocks.is_spent(endpoint)
                && match endpoint {
                    PeerEndpoint::V4(_) => true,
                    PeerEndpoint::V6(other) => choose_dial(None, Some(other), dial).is_some(),
                }
        });
        if let Some(first) = dialable {
            return Some(self.back_to(id, Lane::HighId, Some(first)));
        }
        self.remove(id);
        Some(Release::Gone)
    }

    /// Put `id` first in `lane`, `first` leading its endpoints when given.
    fn back_to(&mut self, id: RecordId, lane: Lane, first: Option<PeerEndpoint>) -> Release {
        if let Some(record) = self.records.get_mut(&id) {
            if let Some(first) = first {
                record.endpoints.retain(|&held| held != first);
                record.endpoints.insert(0, first);
            }
            record.stage = Stage::Pooled(lane);
        }
        self.lanes.push_front(lane, id);
        Release::BackToLane
    }

    /// The worker at `endpoint` identified as `identity` — at its hello, or
    /// again whole at every revision its session made since. The identity
    /// rides the worker's record, its Dialing stage becoming its Worker stage,
    /// and so ends with that worker (ADR-0049). What the run keeps past the
    /// worker is derived here: the peer's source-exchange facts on its
    /// record's Ask Names (ADR-0108), its serving buddy under its User Hash
    /// (ADR-0061), and the reask contact and crypt target of a queue standing
    /// the worker holds (ADR-0057). `true` when its hash is distrusted: the
    /// brain retires the worker before any part is assigned. An identity for
    /// an endpoint no live worker holds states nothing about any record and
    /// is dropped.
    ///
    /// A later `IdentityRevised` re-points the identity the worker holds and
    /// nothing else: a record's idle IPv6 half is not moved by an IPv6
    /// revision. That costs nothing today, because the record is dropped when
    /// its worker ends; a change that keeps idle dual-stack records alive
    /// must re-point that half here.
    pub(crate) fn identify(&mut self, endpoint: PeerEndpoint, identity: PeerIdentity) -> bool {
        let Some(record) = self.live_record_mut(endpoint) else {
            return false;
        };
        let Some(live) = record.live_at(endpoint) else {
            return false;
        };
        if let Some(standing) = record.standing.as_mut() {
            standing.restate(ReaskFacts::of(live, &identity));
        }
        let hash = identity.user_hash();
        let support = identity.source_exchange();
        let buddy = identity.serving_buddy();
        let answered = matches!(&record.stage, Stage::Worker(_, heard) if heard.answered);
        record.stage = Stage::Worker(
            live,
            Heard {
                identity: Some(Box::new(identity)),
                answered,
            },
        );
        self.learned(endpoint, support);
        if let Some(buddy) = buddy {
            self.hello_buddy(hash, buddy.buddy_udp);
        }
        self.blocks.distrusts(Some(hash))
    }

    /// The source `hash` named its **serving buddy** in its own hello
    /// (ADR-0061): kept under the hash for every later sighting of the
    /// source, and folded at once into every candidate the book holds for it,
    /// since the hello is the newest statement of where the buddy is.
    fn hello_buddy(&mut self, hash: UserHash, buddy_udp: Ipv4Endpoint) {
        self.run.note_hello_buddy(hash, buddy_udp);
        self.records
            .values_mut()
            .filter_map(|record| record.candidate.as_mut())
            .filter(|candidate| candidate.user_hash == Some(hash))
            .for_each(|candidate| candidate.learn_hello_buddy(buddy_udp));
    }

    /// The live worker at `endpoint` is proven to have served this file bad
    /// data: distrust the User Hash its hello named. `Some` with that hash when
    /// the distrust is new, for the brain to persist; a peer whose hello named
    /// none leaves nothing to key it by.
    pub(crate) fn distrust(&mut self, endpoint: PeerEndpoint) -> Option<UserHash> {
        let hash = self.identity(endpoint)?.user_hash();
        self.blocks.distrust(hash).then_some(hash)
    }
}
