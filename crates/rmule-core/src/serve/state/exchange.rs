//! Serve State's source-exchange side (ADR-0055 §Serving): the part status
//! each asker last wrote, kept per peer and file, and a source-exchange ask
//! answered from the file's pool — a row's upload-engaged clients, a Partial
//! Share's download's own (ADR-0113).

use std::time::Instant;

use rmule_peer::{PartBitmap, ServerCommand};
use rmule_primitives::{FileHash, PeerEndpoint};

use super::{ServeDecision, ServeState};
use crate::serve::source_exchange::{SxCandidate, SxRequester, select_sources};

impl ServeState {
    /// Keep the part status `peer` just wrote for `file_hash` — its name ask's
    /// or its UDP reask's: one reader ([`PartBitmap::advertised_parts`], the
    /// one every status goes through) and one rule for both, as aMule's
    /// `ProcessExtendedInfo` serves both (ADR-0055 §Serving). aMule's uploader
    /// clears a status whose count is not the file's (`UploadClient.cpp:418-421`)
    /// and so does this; it reads a count of zero as all-zero
    /// (`UploadClient.cpp:415-416`), which would drop a complete source from
    /// every answer, where this reads the writer's meaning, every part.
    /// A status this file cannot read leaves the peer's parts unknown,
    /// as aMule clears it; so does any status from a peer whose hello claimed
    /// extended requests `0` — aMule clears it and returns before reading
    /// (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:400-406`).
    pub(super) fn record_part_status(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
        file_size: u64,
        wire: Option<PartBitmap>,
    ) {
        let claims_status = self
            .identities
            .get(&peer)
            .is_some_and(|identity| identity.extended_requests_version() > 0);
        match wire
            .filter(|_| claims_status)
            .and_then(|wire| wire.advertised_parts(file_size))
        {
            Some(held) => self.sx_part_status.insert((peer, file_hash), held),
            None => self.sx_part_status.remove(&(peer, file_hash)),
        };
    }

    /// Answer a peer's source-exchange request (ADR-0055 §Serving): build the
    /// candidate pool for `file_hash`, apply the per-peer throttle, filter it
    /// (LowID / self skip, needed-chunk, 500 cap), and — if anything survives —
    /// frame an `OP_ANSWERSOURCES(2)` plus a served-sources event. A file we do
    /// not offer, a throttled ask, or an empty result all send nothing
    /// (aMule's `NULL` reply packet).
    ///
    /// A registry row's pool is its upload-engaged clients; a Partial Share's
    /// is its download's own, as the run published it from its Source Book
    /// (ADR-0113): the sources it downloads from or waits at that are not
    /// queue-full, of which [`ServedFileKind::InProgress`](crate::serve::source_exchange::ServedFileKind::InProgress) keeps only those
    /// whose parts are known.
    pub(super) fn answer_source_exchange(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
    ) -> Vec<ServeDecision> {
        let Some((kind, pool)) = self.lookup(file_hash).and_then(|found| found.exchange()) else {
            return Vec::new();
        };
        let (candidates, known): (Vec<SxCandidate>, usize) = match pool {
            Some(pool) => (
                pool.sources
                    .iter()
                    .map(|(source, parts)| SxCandidate {
                        source: *source,
                        part_status: parts.clone(),
                    })
                    .collect(),
                usize::try_from(pool.known).unwrap_or(usize::MAX),
            ),
            None => {
                let engaged: Vec<SxCandidate> = self
                    .queue
                    .engaged_peers(file_hash)
                    .into_iter()
                    .filter_map(|engaged| {
                        let source = self.identities.get(&engaged)?.source_coordinate(engaged);
                        Some(SxCandidate {
                            source,
                            part_status: self.sx_part_status.get(&(engaged, file_hash)).cloned(),
                        })
                    })
                    .collect();
                let known = engaged.len();
                (engaged, known)
            }
        };
        // Rarity (rare vs common reask gate) follows how many sources we know
        // for the file — aMule's `GetSourceCount`: a row's engaged clients, a
        // download's every source.
        if !self.sx_throttle.admit(peer, now, known) {
            return Vec::new();
        }
        // The needed-chunk gate reads the requester's own last status (name ask or UDP reask);
        // without one only sources holding a
        // part, plus the unknowns, are offered. The self-skip compares source identity, so the requester's
        // *own* source coordinate (its advertised id + listen port, not the
        // ephemeral socket) is what we exclude.
        let requester = SxRequester {
            endpoint: self
                .identities
                .get(&peer)
                .and_then(|identity| identity.source_coordinate(peer).as_peer_endpoint()),
            part_status: self.sx_part_status.get(&(peer, file_hash)).cloned(),
        };
        // Which of these the answer's wire form can carry is the peer
        // session's call: a classic answer leaves an IPv6-only source out, and
        // one left empty sends nothing (ADR-0087).
        let sources = select_sources(kind, &requester, &candidates);
        if sources.is_empty() {
            return Vec::new();
        }
        vec![ServeDecision::Send {
            peer,
            command: ServerCommand::AnswerSources { file_hash, sources },
        }]
    }
}
