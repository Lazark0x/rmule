//! The **Source Book**'s grant transition (ADR-0057, "A grant by dial-back is
//! taken"): an uploader granted a slot on a link of its own to a source
//! waiting in the RemoteQueued stage, and the record's worker opens on it.

use rmule_primitives::PeerEndpoint;

use super::SourceBook;
use super::record::{DialRoad, Live, Stage};

impl SourceBook {
    /// The source waiting at `at` was granted a slot on a link of its own: its
    /// record moves to Dialing there — its worker rides that link — and its
    /// standing goes, as a TCP full ask's does, for the worker's ask to earn
    /// again; the hello it queued under stays the run's word on the peer's
    /// crypt side, so the worker finds the link under its User Hash wherever
    /// the peer came back from (ADR-0049, ADR-0107). A source a Low-ID road
    /// reached keeps its candidate, its worker ending as a called-back one
    /// does. Whether a record was waiting there. A waiter called to its
    /// standing holder's link moves the same way.
    pub(crate) fn take_grant(&mut self, at: PeerEndpoint) -> bool {
        let Some(record) = self
            .aliases
            .endpoint(at)
            .and_then(|id| self.records.get_mut(&id))
        else {
            return false;
        };
        if !matches!(record.stage, Stage::RemoteQueued(queued_at) if queued_at == at) {
            return false;
        }
        let road = if record.candidate.is_some() {
            DialRoad::Callback
        } else {
            DialRoad::HighId
        };
        let stated = record.standing.and_then(|standing| standing.stated_crypt());
        record.standing = None;
        record.stage = Stage::Dialing(Live { road, endpoint: at });
        if let Some(stated) = stated {
            self.run.note_crypt(at, stated);
        }
        true
    }
}
