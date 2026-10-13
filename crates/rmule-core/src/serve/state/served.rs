//! What a peer's ask is about, as Serve State finds it (ADR-0113 §"What each
//! ask is answered"): an offered registry row, or a **Served Download** — a
//! **Partial Share** when it is offered, else a download answering probes
//! only. One lookup every handler asks; each gate is read off what it finds,
//! and a registry row for the same hash wins.
//!
//! The brain keeps its own copy of the **Served Downloads** cell, refreshed
//! before every peer input and reask ping ([`ServeState::on_served`]). Which
//! files are in the share set — the rows and the Partial Shares — changes only
//! at the share trigger ([`ServeState::on_share_set`]), so a refresh never
//! drops a file between two: an entry the cell no longer holds keeps answering
//! from its last copy until the next trigger.

use std::collections::HashMap;

use rmule_peer::PartBitmap;
use rmule_primitives::{Ed2kText, FileHash, PartHash, PeerEndpoint};

use super::reask::full_bitmap;
use super::{ServeDecision, ServeState};
use crate::registry::SharedFileEntry;
use crate::serve::source_exchange::ServedFileKind;
use crate::served_downloads::{ExchangePool, ServedLook};

/// The file an ask names, as the share set holds it.
#[derive(Clone, Copy, Debug)]
pub(super) enum Found<'a> {
    /// An offered registry row: the file whole.
    Row(&'a SharedFileEntry),
    /// A Served Download; `offered` when it is a Partial Share.
    Download { look: &'a ServedLook, offered: bool },
}

impl<'a> Found<'a> {
    /// The name the file is offered under.
    pub(super) fn name(&self) -> Ed2kText {
        match self {
            Self::Row(entry) => Ed2kText::from_utf8(entry.name.as_str()),
            Self::Download { look, .. } => look.served.name.clone(),
        }
    }

    /// The file's exact size.
    pub(super) const fn file_size(&self) -> u64 {
        match self {
            Self::Row(entry) => entry.file_size,
            Self::Download { look, .. } => look.served.file_size,
        }
    }

    /// The parts we hold: every one of a row's, a download's **Verified
    /// Range** — never a bitmap a download's range does not hold.
    pub(super) fn status(&self) -> PartBitmap {
        match self {
            Self::Row(entry) => full_bitmap(entry.file_size),
            Self::Download { look, .. } => look.served.range.status(look.served.file_size),
        }
    }

    /// The part hash set we answer a hash-set ask with: a row's stored set,
    /// a download's once whole — `None` until then, answered as not found.
    pub(super) fn hash_set(&self) -> Option<Vec<PartHash>> {
        match self {
            Self::Row(entry) => Some(entry.part_hashes.clone()),
            Self::Download { look, .. } => {
                look.served.set.as_ref().map(|set| set.hashes().to_vec())
            }
        }
    }

    /// Whether the file is in the share set: a slot ask queues, an ask moves
    /// the asker's Asked File, a UDP reask is answered. A download not yet
    /// offered answers probes and moves nobody, since no slot can be granted
    /// for it.
    pub(super) const fn offered(&self) -> bool {
        match self {
            Self::Row(_) => true,
            Self::Download { offered, .. } => *offered,
        }
    }

    /// The registry row, which alone is read whole and answers AICH; a part
    /// file is never an AICH source (ADR-0113).
    pub(super) const fn row(self) -> Option<&'a SharedFileEntry> {
        match self {
            Self::Row(entry) => Some(entry),
            Self::Download { .. } => None,
        }
    }

    /// Whether an asker becomes a candidate source of the file: only a
    /// running download's, which has a run to take it (aMule's
    /// `CheckAndAddKnownSource`, `ClientTCPSocket.cpp:449-455`).
    pub(super) const fn keeps_askers(&self) -> bool {
        match self {
            Self::Row(_) => false,
            Self::Download { look, .. } => look.takes_askers,
        }
    }

    /// Which pool a source-exchange ask is answered from, and the run's pool
    /// for a Partial Share; `None` for a download not offered, which answers
    /// none.
    pub(super) const fn exchange(self) -> Option<(ServedFileKind, Option<&'a ExchangePool>)> {
        match self {
            Self::Row(_) => Some((ServedFileKind::Complete, None)),
            Self::Download {
                look,
                offered: true,
            } => Some((ServedFileKind::InProgress, Some(&look.served.pool))),
            Self::Download { offered: false, .. } => None,
        }
    }
}

impl ServeState {
    /// Refresh the brain's copy of the **Served Downloads** with every entry
    /// as the cell holds it now. A level, like our own position: an entry the
    /// cell no longer holds keeps its last copy until the next share trigger.
    pub(crate) fn on_served(&mut self, fresh: HashMap<FileHash, ServedLook>) {
        let stale: Vec<(FileHash, ServedLook)> = self
            .served
            .drain()
            .filter(|(file_hash, _)| !fresh.contains_key(file_hash))
            .collect();
        self.ended
            .retain(|file_hash| !fresh.contains_key(file_hash));
        self.served = fresh;
        for (file_hash, look) in stale {
            self.ended.insert(file_hash);
            self.served.insert(file_hash, look);
        }
    }

    /// Whether `file_hash` is in the share set: an offered row or a Partial
    /// Share.
    pub(super) fn in_share_set(&self, file_hash: FileHash) -> bool {
        self.shared.contains_key(&file_hash) || self.partials.contains(&file_hash)
    }

    /// The file `file_hash` names, as the share set holds it: an offered row,
    /// which wins, or a Served Download.
    pub(super) fn lookup(&self, file_hash: FileHash) -> Option<Found<'_>> {
        if let Some(entry) = self.shared.get(&file_hash) {
            return Some(Found::Row(entry));
        }
        self.served.get(&file_hash).map(|look| Found::Download {
            look,
            offered: self.partials.contains(&file_hash),
        })
    }

    /// The asker `peer` of `file_hash`, handed to the download's run as a
    /// candidate source from its hello's source coordinate, when the file
    /// keeps its askers.
    pub(super) fn keep_asker(
        &self,
        peer: PeerEndpoint,
        file_hash: FileHash,
    ) -> Option<ServeDecision> {
        self.lookup(file_hash)
            .filter(Found::keeps_askers)
            .and(self.identities.get(&peer))
            .map(|identity| ServeDecision::KeepAsker {
                file_hash,
                sighting: identity.source_coordinate(peer),
            })
    }
}
