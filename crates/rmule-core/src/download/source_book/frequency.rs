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

    /// The Advertised Parts of the record at `endpoint`, once its source
    /// advertised any.
    pub(crate) fn parts(&self, endpoint: PeerEndpoint) -> Option<&PartBitmap> {
        self.record_at(endpoint)?.advertised.as_ref()
    }

    /// Part Frequency: per part index, how many records' Advertised Parts hold
    /// it.
    #[cfg_attr(not(test), expect(dead_code, reason = "the rank reads it next"))]
    pub(crate) fn part_frequency(&self) -> &[u32] {
        &self.frequency.counts
    }

    /// How many records hold Advertised Parts — the sources whose parts are
    /// known, the `n` of the very-rare bound.
    #[cfg_attr(not(test), expect(dead_code, reason = "the rank reads it next"))]
    pub(crate) fn parts_known(&self) -> u32 {
        self.frequency.holders
    }
}
