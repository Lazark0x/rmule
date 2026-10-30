//! The **Source Book**'s side of the node's **Queue Standings** (ADR-0107,
//! "One peer, one queue standing"): the places its records hold, published
//! under their **Ask Names**, and the record a fill parks on another
//! download's standing instead of dialing it.

use std::time::Instant;

use rmule_primitives::PeerEndpoint;

use super::SourceBook;
use super::record::{Record, Stage};
use super::standing::Standing;
use crate::download::queue_standings::{Place, Role};

impl SourceBook {
    /// `record`'s place: its standing's, or its Pooled Place while it waits in
    /// a lane.
    pub(super) fn place(&self, record: &Record) -> Option<Place> {
        let pooled = matches!(record.stage, Stage::Pooled(_));
        if record.standing.is_none() && !pooled {
            return None;
        }
        Some(Place {
            names: self.ask_names(record, &self.user_hashes(record)),
            asked: record.last_ask,
            needs_parts: record
                .standing
                .is_none_or(|standing| standing.needs_parts()),
            pooled,
        })
    }

    /// Every place the book's records hold: each record holding a standing,
    /// waiting in the RemoteQueued stage or at the live worker whose slot ask
    /// earned it, and each record still in a lane (ADR-0090).
    pub(crate) fn places(&self) -> Vec<Place> {
        self.records
            .values()
            .filter_map(|record| self.place(record))
            .collect()
    }

    /// The place the record a fill just took to dial at `endpoint` would hold:
    /// its names and the claim its last slot ask left, as a record that may
    /// need a part of the peer.
    pub(crate) fn dial_place(&self, endpoint: PeerEndpoint) -> Option<Place> {
        let record = self.record_at(endpoint)?;
        Some(Place {
            names: self.ask_names(record, &self.user_hashes(record)),
            asked: record.last_ask,
            needs_parts: true,
            pooled: true,
        })
    }

    /// The record a fill just took to dial at `endpoint` parks on the peer's
    /// standing instead, as `role` says (ADR-0107 invariant 13, ADR-0090): it
    /// stands in the RemoteQueued stage with no rank and no contact, its clock
    /// at the peer's last ask, or `now`. Whether a record was dialing there.
    pub(crate) fn wait_on_standing(
        &mut self,
        endpoint: PeerEndpoint,
        role: Role,
        now: Instant,
    ) -> bool {
        let asked_at = match role {
            Role::Waits { asked_at } => asked_at,
            Role::Takes { asked_at } | Role::Inherits { asked_at } => Some(asked_at),
            Role::Holds => None,
        };
        let Some(record) = self.live_record_mut(endpoint) else {
            return false;
        };
        if !matches!(record.stage, Stage::Dialing(live) if live.endpoint == endpoint) {
            return false;
        }
        record.stage = Stage::RemoteQueued(endpoint);
        record.standing = Some(Standing::waiting(asked_at, now).in_role(role));
        true
    }

    /// The worker at `endpoint` waited on a link that ended before its turn
    /// (ADR-0107 invariant 9): its record stands on the peer's standing as a
    /// fill's parked record does — no rank, no contact, its clock at
    /// `asked_at`, the peer's last ask, or `now` — unless it holds one.
    pub(crate) fn handed_back(
        &mut self,
        endpoint: PeerEndpoint,
        asked_at: Option<Instant>,
        now: Instant,
    ) {
        if let Some(record) = self.live_record_mut(endpoint)
            && record.standing.is_none()
        {
            record.standing = Some(Standing::waiting(asked_at, now));
        }
    }

    /// Whether the record waiting at `at` in the RemoteQueued stage holds its
    /// peer's standing — it re-asks — rather than waiting on another
    /// download's.
    pub(crate) fn holds_standing(&self, at: PeerEndpoint) -> bool {
        self.record_at(at)
            .filter(|record| matches!(record.stage, Stage::RemoteQueued(queued) if queued == at))
            .and_then(|record| record.standing)
            .is_some_and(|standing| standing.role.asks())
    }
}
