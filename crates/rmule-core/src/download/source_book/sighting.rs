//! The **Source Book**'s one entry: every channel's **Source Sighting** is
//! checked against the blocks — a spent name of the source among them — merged
//! into the record that already holds the source, or pooled as a new record —
//! never a second copy (ADR-0090 invariants 2–4). Two held records become one only on wire proof: a
//! dual-stack pairing, a Low-ID candidate's IPv6 half, an adopted callback's
//! inbound endpoint.

use std::cmp::Reverse;

use rmule_primitives::{Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, SourceSighting, UserHash};

use super::asks::{AskName, low_id_name};
use super::record::{Lane, Record, RecordId, Stage};
use super::{Blocked, Gate, MergeEnd, Sighted, SourceBook};
use crate::dialable::{DialOrder, resolve_family};
use crate::download::state::LowIdCandidate;

impl SourceBook {
    /// Take one sighting, once the `gate` has judged each half of it. A
    /// dialable one — dual-stack ordered by the Dial
    /// Chooser (ADR-0087) — first leaves the crypt side its record stated at
    /// each half, for the dial to meet; a Low-ID or Kad callback one becomes a
    /// **Low-ID Candidate Record** in the namespace `source_server` names.
    pub(crate) fn sight(
        &mut self,
        sighting: SourceSighting,
        source_server: Option<Ipv4Endpoint>,
        gate: &Gate<'_>,
    ) -> Sighted {
        let sighting = match gate.judge(sighting) {
            Ok(judged) => judged,
            Err(why) => return Sighted::Blocked(why),
        };
        if let Some(order) = resolve_family(sighting, gate.dial) {
            let crypt = sighting.peer_crypt();
            for half in order.halves() {
                self.run.note_crypt(half, crypt);
            }
            return self.sight_dialable(order, sighting.user_hash());
        }
        match LowIdCandidate::from_sighting(sighting, source_server) {
            Some(candidate) => self.sight_candidate(candidate),
            None => Sighted::Blocked(Blocked::Unreachable),
        }
    }

    /// A dialable source, by its dial order. A record holding either half
    /// takes the sighting: a half it lacks joins it as the same peer's other
    /// family, and a half another record holds proves the two one peer. Else
    /// its first unspent half is pooled last in the High-ID lane, the other
    /// kept beside it; a source both of whose halves are spent is not pooled.
    fn sight_dialable(&mut self, order: DialOrder, user_hash: Option<UserHash>) -> Sighted {
        if self.blocks.distrusts(user_hash) {
            return Sighted::Blocked(Blocked::Distrusted);
        }
        if user_hash.is_some_and(|hash| self.blocks.is_spent(AskName::User(hash))) {
            return Sighted::Blocked(Blocked::Spent);
        }
        if let Some((held, id)) = order
            .halves()
            .find_map(|half| Some((half, self.aliases.endpoint(half)?)))
        {
            let other = order
                .halves()
                .find(|&half| half != held)
                .filter(|&other| !self.blocks.is_spent(other));
            let Some(other) = other else {
                return Sighted::Merged(None);
            };
            return Sighted::Merged(match self.aliases.endpoint(other) {
                Some(holder) if holder != id => self.merge(id, holder),
                Some(_) => None,
                None => {
                    if self.takes_other_half(id) {
                        self.add_endpoint(id, other);
                    }
                    None
                }
            });
        }
        let mut unspent = order.halves().filter(|&half| !self.blocks.is_spent(half));
        let Some(first) = unspent.next() else {
            return Sighted::Blocked(Blocked::Spent);
        };
        let mut record = Record::new(Stage::Pooled(Lane::HighId));
        record.endpoints.push(first);
        record.endpoints.extend(unspent.next());
        let id = self.insert(record);
        self.lanes.push_back(Lane::HighId, id);
        Sighted::Pooled(Some(first))
    }

    /// Whether `id` keeps a dialable source's other half as a fallback: a
    /// record dialed as a High ID, waiting for it, or holding a queue
    /// standing — a Low-ID road never falls to one.
    fn takes_other_half(&self, id: RecordId) -> bool {
        self.records
            .get(&id)
            .is_some_and(|record| match record.stage {
                Stage::Pooled(lane) => lane == Lane::HighId,
                Stage::Dialing(live) | Stage::Worker(live, _) => {
                    live.road == super::record::DialRoad::HighId
                }
                Stage::RemoteQueued(_) => true,
                Stage::CallbackPending(_) => false,
            })
    }

    /// A Low-ID candidate, merged into the record its key names rather than
    /// held twice (ADR-0039 / ADR-0051), or replacing that record's candidate
    /// whole when it names another owner of the key (ADR-0090). A candidate
    /// naming its buddy by ID alone takes the endpoint the source's own hello
    /// named earlier this run. One whose IPv6 half another record answers to
    /// is that record's peer: the candidate joins it. A candidate naming a
    /// distrusted User Hash is not pooled. Reached only through
    /// [`Self::sight`], once the gate judged the sighting it came from.
    fn sight_candidate(&mut self, mut candidate: LowIdCandidate) -> Sighted {
        if self.blocks.distrusts(candidate.user_hash) {
            return Sighted::Blocked(Blocked::Distrusted);
        }
        let spent_hash = candidate
            .user_hash
            .is_some_and(|hash| self.blocks.is_spent(AskName::User(hash)));
        if spent_hash || low_id_name(&candidate).is_some_and(|name| self.blocks.is_spent(name)) {
            return Sighted::Blocked(Blocked::Spent);
        }
        if let (Some(hash), Some(buddy)) = (candidate.user_hash, candidate.buddy)
            && buddy.buddy_udp.is_none()
            && let Some(buddy_udp) = self.run.hello_buddy(hash)
        {
            candidate.learn_hello_buddy(buddy_udp);
        }
        if let Some(id) = self.aliases.key(candidate.key()) {
            let Some(held) = self
                .records
                .get_mut(&id)
                .and_then(|record| record.candidate.as_mut())
            else {
                return Sighted::Merged(None);
            };
            let before = held.ipv6;
            if held.names_another_owner(&candidate) {
                *held = candidate;
            } else {
                held.merge(candidate);
            }
            return Sighted::Merged(self.sync_half(id, before));
        }
        if let Some(holder) = candidate
            .ipv6
            .and_then(|half| self.aliases.endpoint(PeerEndpoint::V6(half)))
            && let Some(record) = self.records.get_mut(&holder)
            && record.candidate.is_none()
        {
            record.candidate = Some(candidate);
            self.aliases.bind_key(candidate.key(), holder);
            return Sighted::Merged(None);
        }
        let lane = Lane::of(&candidate, self.own_server);
        let mut record = Record::new(Stage::Pooled(lane));
        record.candidate = Some(candidate);
        let id = self.insert(record);
        self.lanes.push_back(lane, id);
        let _ = self.sync_half(id, None);
        Sighted::Pooled(None)
    }

    /// Re-bind `id`'s candidate half after its candidate changed from naming
    /// `before`: an older half no live worker dials leaves, and the current
    /// one joins — merging with the record that answers to it, which is the
    /// same peer.
    pub(super) fn sync_half(
        &mut self,
        id: RecordId,
        before: Option<Ipv6Endpoint>,
    ) -> Option<MergeEnd> {
        let record = self.records.get(&id)?;
        let now = record
            .candidate
            .as_ref()
            .and_then(|candidate| candidate.ipv6);
        if let Some(before) = before.filter(|&before| Some(before) != now) {
            let endpoint = PeerEndpoint::V6(before);
            if record.endpoints.contains(&endpoint) && record.live_at(endpoint).is_none() {
                self.keep_asks(id);
                let record = self.records.get_mut(&id)?;
                record.endpoints.retain(|&held| held != endpoint);
                self.aliases.unbind_endpoint(endpoint, id);
            }
        }
        let half = PeerEndpoint::V6(now?);
        match self.aliases.endpoint(half) {
            Some(holder) if holder != id => self.merge(id, holder),
            Some(_) => None,
            None => {
                self.add_endpoint(id, half);
                None
            }
        }
    }

    /// Fold two records the wire proved one peer into one (ADR-0090): the
    /// higher stage keeps the record — Worker > Dialing > CallbackPending >
    /// RemoteQueued > Pooled, a High-ID lane ahead of a Low-ID one, else the
    /// older — and the other's aliases and attachments join it. The record that
    /// gave way ends whatever it had in flight; its Advertised Parts join the
    /// keeper only when the keeper has none, as a standing does. Two records that cannot be one
    /// — three endpoints between them, or two Low-ID candidates — stay apart.
    pub(super) fn merge(&mut self, a: RecordId, b: RecordId) -> Option<MergeEnd> {
        let (left, right) = (self.records.get(&a)?, self.records.get(&b)?);
        let mut endpoints = left.endpoints.clone();
        for &endpoint in &right.endpoints {
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
        if endpoints.len() > 2 || (left.candidate.is_some() && right.candidate.is_some()) {
            return None;
        }
        let precedence = |id: RecordId, record: &Record| {
            let dialable_lane = matches!(record.stage, Stage::Pooled(Lane::HighId));
            (record.stage.rank(), dialable_lane, Reverse(id))
        };
        let (keep, fold) = if precedence(a, left) >= precedence(b, right) {
            (a, b)
        } else {
            (b, a)
        };
        let folded = self.remove(fold)?;
        let ended = match folded.stage {
            Stage::Dialing(live) | Stage::Worker(live, _) => Some(MergeEnd::Worker(live.endpoint)),
            Stage::CallbackPending(_) => folded
                .candidate
                .as_ref()
                .map(|candidate| MergeEnd::Callback(candidate.key())),
            Stage::Pooled(_) | Stage::RemoteQueued(_) => None,
        };
        for &endpoint in &folded.endpoints {
            self.add_endpoint(keep, endpoint);
        }
        let keeper = self.records.get_mut(&keep)?;
        if let Some(candidate) = folded.candidate {
            keeper.candidate = Some(candidate);
            self.aliases.bind_key(candidate.key(), keep);
        }
        keeper.standing = keeper.standing.or(folded.standing);
        // The folded record's parts left the count with it; the keeper takes
        // them only when it advertised none.
        if keeper.advertised.is_none()
            && let Some(parts) = folded.advertised
        {
            self.frequency.add(&parts);
            keeper.advertised = Some(parts);
        }
        keeper.seed = keeper.seed.or(folded.seed);
        keeper.asks = keeper.asks.merge(folded.asks);
        ended
    }
}
