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
    /// again. A source a Low-ID road reached keeps its candidate, its worker
    /// ending as a called-back one does. Whether a record was waiting there.
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
        record.standing = None;
        record.stage = Stage::Dialing(Live { road, endpoint: at });
        true
    }
}
