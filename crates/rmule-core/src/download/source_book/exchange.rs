//! The pool a source-exchange answer for the file is drawn from while it
//! downloads (ADR-0113): the sources the book downloads from or waits at
//! with a place, each with its Advertised Parts.

use rmule_peer::PartBitmap;
use rmule_primitives::{Informant, PeerEndpoint, PeerSource, SourceSighting};

use super::SourceBook;
use super::record::RecordId;

impl SourceBook {
    /// The sources a source-exchange answer for the file may name, with the
    /// parts each advertised (aMule `CPartFile::CreateSrcInfoPacket`, stock
    /// 2.3.3 `PartFile.cpp:2596-2605`): each we download from — a live
    /// worker `downloading` says holds a part — or wait at with a place in
    /// its queue
    /// ([`names_a_place`](super::standing::Standing::names_a_place)). In
    /// record order.
    pub(crate) fn exchange_pool(
        &self,
        downloading: impl Fn(PeerEndpoint) -> bool,
    ) -> Vec<(SourceSighting, Option<PartBitmap>)> {
        let mut pool: Vec<(RecordId, SourceSighting, Option<PartBitmap>)> = self
            .records
            .iter()
            .filter_map(|(id, record)| {
                let waits = record
                    .standing
                    .is_some_and(|standing| standing.names_a_place());
                let downloads = record
                    .stage
                    .live()
                    .is_some_and(|live| downloading(live.endpoint));
                if !waits && !downloads {
                    return None;
                }
                let source = match record.stage.live().zip(record.stage.identity()) {
                    Some((live, identity)) => identity.source_coordinate(live.endpoint),
                    None => {
                        let source = match *record.endpoints.first()? {
                            PeerEndpoint::V4(v4) => PeerSource::HighId(v4),
                            PeerEndpoint::V6(v6) => PeerSource::Ipv6(v6),
                        };
                        let user_hash = record
                            .standing
                            .and_then(|standing| standing.crypt())
                            .map(|crypt| crypt.user_hash);
                        // The book's own record, which rmule states to the asker.
                        SourceSighting::new(source, user_hash, None, Informant::Own)
                    }
                };
                Some((*id, source, record.advertised.clone()))
            })
            .collect();
        pool.sort_unstable_by_key(|(id, ..)| id.0);
        pool.into_iter()
            .map(|(_, source, parts)| (source, parts))
            .collect()
    }
}
