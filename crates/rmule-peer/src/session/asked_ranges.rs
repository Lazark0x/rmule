//! The link's **Asked Ranges** (ADR-0107 "How a grant hands over"): every
//! block range this connection's `OP_REQUESTPARTS` carried since the uploader
//! last took the client out of its upload slots, whatever file each was for.
//!
//! A stock uploader drops a requested block whose start and end equal one it
//! holds or has sent, comparing offsets alone (stock 2.3.3
//! `UploadClient.cpp:503-521`), and keeps those across a switch to another
//! file (`SetUploadFileID`, `:464-492`). Only `RemoveFromUploadQueue` clears
//! them (`UploadQueue.cpp:540-541`): our `OP_CANCELTRANSFER`, its upload
//! session's end before the `OP_OUTOFPARTREQS` it sends
//! (`UploadClient.cpp:598-600`), or the link's close. The session forgets
//! them at the same three, and hands them to the requester at each grant.

use std::collections::BTreeSet;

use rmule_primitives::Packet;

use super::PeerSession;

/// Block ranges a link asked its uploader, each `(start, end)` with `end`
/// exclusive. A stock uploader serves none of them again while it keeps the
/// client in its upload slots, so a requester never asks one twice.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AskedRanges(BTreeSet<(u64, u64)>);

impl AskedRanges {
    /// Whether `start..end` is one of them: the uploader would drop a request
    /// repeating it.
    #[must_use]
    pub fn contains(&self, start: u64, end: u64) -> bool {
        self.0.contains(&(start, end))
    }

    /// Remember `start..end` as asked. An empty range — a zero-padded slot of
    /// `OP_REQUESTPARTS` — asks nothing and is not kept.
    pub fn insert(&mut self, start: u64, end: u64) {
        if end > start {
            self.0.insert((start, end));
        }
    }

    /// Remember every range `other` holds as well.
    pub fn extend(&mut self, other: &Self) {
        self.0.extend(other.0.iter().copied());
    }

    /// Forget them all: the uploader cleared its list.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Whether the link asked nothing the uploader still holds.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PeerSession {
    /// Write one `OP_REQUESTPARTS` carrying `ranges`, remembering each as
    /// asked on the link.
    pub(super) fn write_block_request(&mut self, packet: Packet, ranges: &[(u64, u64)]) {
        for &(start, end) in ranges {
            self.asked_ranges.insert(start, end);
        }
        self.write_packet(packet);
    }

    /// The uploader took the client out of its upload slots: what it held as
    /// asked is gone, on its side and ours.
    pub(super) fn forget_asked_ranges(&mut self) {
        self.asked_ranges.clear();
    }
}
