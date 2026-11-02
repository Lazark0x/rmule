//! The **Offer Queue** (ADR-0099): what one session still owes the server of
//! the share set, and when the next batch may leave. The follower hands it
//! whole sets; it keeps what this connection was told, as aMule marks each
//! file published per connection (`SharedFileList.cpp:636-643`), and paces the
//! difference under the connection's [`OfferPace`].

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use rmule_ed2k::{FileCompleteness, OfferPace, OfferedFile, ServerFileLimits};
use rmule_primitives::{FileHash, is_large_file};
use tokio::time::Instant;

use crate::diagnostics::SharesToServer;

/// How long the first batch waits for the session's first `OP_SERVERIDENT`,
/// which settles its size. The server answers the login, or the opening
/// `OP_GETSERVERLIST`, inside a round trip, so this bounds a server that
/// does neither.
const IDENT_WAIT: Duration = Duration::from_secs(5);

/// One session's queue. Time is the caller's, so a paused clock drives it.
#[derive(Debug)]
pub(super) struct OfferQueue {
    /// The session's pace, once settled.
    pace: Option<OfferPace>,
    /// Until when the first batch waits for the ident.
    ident_by: Instant,
    /// When the next batch may leave.
    next_at: Instant,
    /// What this connection was told, by file.
    told: HashMap<FileHash, FileCompleteness>,
    /// The newest set's files this connection still owes the server, in the
    /// order handed.
    owed: VecDeque<OfferedFile>,
    /// Files of the newest set the soft budget left untold.
    over_budget: usize,
    /// How many files the newest set holds, less those the server cannot take.
    set_len: usize,
}

impl OfferQueue {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            pace: None,
            ident_by: now + IDENT_WAIT,
            next_at: now,
            told: HashMap::new(),
            owed: VecDeque::new(),
            over_budget: 0,
            set_len: 0,
        }
    }

    /// The session's first ident settled `pace`. Later ones change nothing,
    /// and neither does one after the wait ran out: the server holds a
    /// connection to the advert its first ident carried, or to none.
    pub(super) fn settle(&mut self, pace: OfferPace) {
        self.pace.get_or_insert(pace);
    }

    /// Whether the pace is still to be settled.
    pub(super) const fn unsettled(&self) -> bool {
        self.pace.is_none()
    }

    /// The newest share set. It replaces what was owed: a file gone from the
    /// share before its turn never goes, and what was told stays told.
    pub(super) fn hand(&mut self, files: Vec<OfferedFile>, large_files: bool) {
        let takeable = files
            .into_iter()
            .filter(|file| large_files || !is_large_file(file.file_size()));
        let mut set_len = 0;
        self.owed = takeable
            .inspect(|_| set_len += 1)
            .filter(|file| self.told.get(&file.file_hash()) != Some(&file.completeness()))
            .collect();
        self.set_len = set_len;
        self.over_budget = 0;
    }

    /// Send no more of the set.
    pub(super) fn halt(&mut self) {
        self.owed.clear();
    }

    /// When the queue next wants waking; `None` with nothing to send.
    pub(super) fn next_send(&self) -> Option<Instant> {
        if self.owed.is_empty() {
            return None;
        }
        Some(self.pace.map_or(self.ident_by, |_| self.next_at))
    }

    /// The batch due at `now`, if one is. A wait that ran out with no ident
    /// settles the pace as legacy, under what `known` says of the server.
    pub(super) fn release(
        &mut self,
        now: Instant,
        known: impl FnOnce() -> ServerFileLimits,
    ) -> Option<Vec<OfferedFile>> {
        if self.pace.is_none() && now >= self.ident_by {
            self.pace = Some(OfferPace::Legacy(known()));
        }
        let pace = self.pace?;
        if now < self.next_at || self.owed.is_empty() {
            return None;
        }
        let batch = self.take_batch(pace);
        if batch.is_empty() {
            return None;
        }
        for file in &batch {
            self.told.insert(file.file_hash(), file.completeness());
        }
        self.next_at = now + pace.gap_after(batch.len());
        Some(batch)
    }

    /// Take up to one batch of what is owed. New files stop at the budget, and
    /// whatever new is left then can never go, so it leaves the queue; a
    /// re-offer takes no budget and keeps its place.
    fn take_batch(&mut self, pace: OfferPace) -> Vec<OfferedFile> {
        let size = usize::try_from(pace.batch()).unwrap_or(usize::MAX);
        let mut budget = pace.new_files_left(self.told.len());
        let mut batch = Vec::with_capacity(size.min(self.owed.len()));
        let mut kept = VecDeque::new();
        while batch.len() < size
            && let Some(file) = self.owed.pop_front()
        {
            let new = !self.told.contains_key(&file.file_hash());
            match budget.as_mut() {
                Some(0) if new => kept.push_back(file),
                Some(left) if new => {
                    *left -= 1;
                    batch.push(file);
                }
                _ => batch.push(file),
            }
        }
        if budget == Some(0) {
            let told = &self.told;
            let before = kept.len() + self.owed.len();
            kept.extend(self.owed.drain(..));
            kept.retain(|file| told.contains_key(&file.file_hash()));
            self.over_budget += before - kept.len();
        }
        kept.append(&mut self.owed);
        self.owed = kept;
        batch
    }

    /// What the operator reads of the session's progress through the set.
    pub(super) fn level(&self) -> SharesToServer {
        let of = self.set_len;
        let told = of.saturating_sub(self.owed.len() + self.over_budget);
        if told < of {
            SharesToServer::Announcing { told, of }
        } else {
            SharesToServer::Announced
        }
    }
}
