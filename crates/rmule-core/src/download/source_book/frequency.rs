//! **Advertised Parts** and **Part Frequency** in the **Source Book**
//! (ADR-0112): each record carries the parts its source last advertised — a
//! worker's probe answer or a `0x91` status, each replacing the last — and the
//! book counts, per part, the records holding it. The count moves with every
//! write, merge and removal, so `frequency[i]` is the number of records whose
//! Advertised Parts hold part `i` after every transition and an assignment
//! reads it without walking the records. aMule keeps the same count per source
//! whose status is known, connected or queued (`UpdatePartsFrequency`, stock
//! 2.3.3 `PartFile.cpp:3526`). Nothing here is stored: a restart's first
//! probes write it again.

use rmule_peer::PartBitmap;
use rmule_primitives::PeerEndpoint;

use super::SourceBook;
use super::record::Stage;

/// How many records hold each part, and how many hold Advertised Parts at all.
#[derive(Debug)]
pub(super) struct PartFrequency {
    counts: Vec<u32>,
    holders: u32,
}

impl PartFrequency {
    /// No record holds anything yet, for a file of `part_count` parts.
    pub(super) fn new(part_count: u32) -> Self {
        Self {
            counts: vec![0; part_count as usize],
            holders: 0,
        }
    }

    /// A record's Advertised Parts joined the count.
    pub(super) fn add(&mut self, parts: &PartBitmap) {
        self.holders += 1;
        for part in parts.iter_present() {
            if let Some(count) = self.counts.get_mut(part.value() as usize) {
                *count += 1;
            }
        }
    }

    /// A record's Advertised Parts left the count.
    pub(super) fn subtract(&mut self, parts: &PartBitmap) {
        self.holders = self.holders.saturating_sub(1);
        for part in parts.iter_present() {
            if let Some(count) = self.counts.get_mut(part.value() as usize) {
                *count = count.saturating_sub(1);
            }
        }
    }
}

impl SourceBook {
    /// The source at `endpoint` advertised `parts` — its worker's probe answer,
    /// `None` when it said it lacks the file, or a `0x91` status — replacing
    /// what its record held.
    pub(crate) fn write_parts(&mut self, endpoint: PeerEndpoint, parts: Option<PartBitmap>) {
        let Some(record) = self
            .aliases
            .endpoint(endpoint)
            .and_then(|id| self.records.get_mut(&id))
        else {
            return;
        };
        if let Some(held) = &record.advertised {
            self.frequency.subtract(held);
        }
        if let Some(parts) = &parts {
            self.frequency.add(parts);
        }
        record.advertised = parts;
    }

    /// The worker at `endpoint` answered its probe with `parts`: they replace
    /// what its record held, and from here on they are the worker's own
    /// ([`Self::worker_parts`]).
    pub(crate) fn probe_answered(&mut self, endpoint: PeerEndpoint, parts: Option<PartBitmap>) {
        self.write_parts(endpoint, parts);
        if let Some(record) = self.record_at_mut(endpoint)
            && let Stage::Worker(live, heard) = &mut record.stage
            && live.endpoint == endpoint
        {
            heard.answered = true;
        }
    }

    /// The Advertised Parts the worker at `endpoint` may be handed a part
    /// from: its record's, once that worker's own probe answered, and `None`
    /// before — whatever an earlier connection or a merged-in record left on
    /// the record is not this peer's word now (ADR-0112 §3).
    pub(crate) fn worker_parts(&self, endpoint: PeerEndpoint) -> Option<&PartBitmap> {
        let record = self.record_at(endpoint)?;
        match &record.stage {
            Stage::Worker(live, heard) if live.endpoint == endpoint && heard.answered => {
                record.advertised.as_ref()
            }
            _ => None,
        }
    }

    /// Whether the record at `endpoint` heard its source's parts — a probe's
    /// answer or a reask answer's status — that a grant its link carries can
    /// be taken on without a probe (ADR-0107, ADR-0112).
    pub(crate) fn heard_parts(&self, endpoint: PeerEndpoint) -> bool {
        self.record_at(endpoint)
            .is_some_and(|record| record.advertised.is_some())
    }

    /// The worker at `endpoint` takes a grant its link carries without a
    /// probe: the parts its record last heard are its probe's answer, as
    /// aMule's downloader asks blocks off the part status its client kept
    /// (`ClientTCPSocket.cpp:635-644`). Whether it holds any.
    pub(crate) fn take_heard_parts(&mut self, endpoint: PeerEndpoint) -> bool {
        let Some(record) = self.record_at_mut(endpoint) else {
            return false;
        };
        if record.advertised.is_none() {
            return false;
        }
        match &mut record.stage {
            Stage::Worker(live, heard) if live.endpoint == endpoint => {
                heard.answered = true;
                true
            }
            _ => false,
        }
    }

    /// The Advertised Parts of the record at `endpoint`, once its source
    /// advertised any.
    #[cfg(test)]
    pub(crate) fn parts(&self, endpoint: PeerEndpoint) -> Option<&PartBitmap> {
        self.record_at(endpoint)?.advertised.as_ref()
    }

    /// Part Frequency: per part index, how many records' Advertised Parts hold
    /// it.
    pub(crate) fn part_frequency(&self) -> &[u32] {
        &self.frequency.counts
    }

    /// How many records hold Advertised Parts — the sources whose parts are
    /// known, the `n` of the very-rare bound.
    pub(crate) fn parts_known(&self) -> u32 {
        self.frequency.holders
    }
}
