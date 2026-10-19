//! The **Source Book**'s side of the node's **Queue Standings** (ADR-0107,
//! "One peer, one queue standing"): the places its records hold, published
//! under their **Ask Names**, and the record a fill parks on another
//! download's standing instead of dialing it.

use std::time::Instant;

use rmule_primitives::PeerEndpoint;

use super::SourceBook;
use super::record::{Record, Stage};
use super::standing::Standing;
use crate::download::queue_standings::Place;

impl SourceBook {
    /// `record`'s place, when it holds a standing.
    pub(super) fn place(&self, record: &Record) -> Option<Place> {
        let standing = record.standing?;
        Some(Place {
            names: self.ask_names(record, &self.user_hashes(record)),
            asked: record.last_ask,
            needs_parts: standing.needs_parts(),
        })
    }

    /// Every place the book's records hold: each record holding a standing,
    /// waiting in the RemoteQueued stage or at the live worker whose slot ask
    /// earned it.
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
        })
    }

    /// The record a fill just took to dial at `endpoint` waits on another
    /// download's standing at that peer instead (ADR-0107 invariant 13): it
    /// stands in the RemoteQueued stage with no rank and no contact, its clock
    /// at `asked_at`, the peer's last ask, or `now`. Whether a record was
    /// dialing there.
    pub(crate) fn wait_on_standing(
        &mut self,
        endpoint: PeerEndpoint,
        asked_at: Option<Instant>,
        now: Instant,
    ) -> bool {
        let Some(record) = self.live_record_mut(endpoint) else {
            return false;
        };
        if !matches!(record.stage, Stage::Dialing(live) if live.endpoint == endpoint) {
            return false;
        }
        record.stage = Stage::RemoteQueued(endpoint);
        record.standing = Some(Standing::waiting(asked_at, now));
        true
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
