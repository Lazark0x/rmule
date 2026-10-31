//! Stock's pace on the walks a share or a queue starts in bulk (ADR-0064):
//! source publishes and source searches.
//!
//! A command only registers. The node starts the next due walk from its own
//! clock, one per spacing and never past the concurrent cap, so one owner holds
//! both paces and a share of any size reaches the network at stock's rate. No
//! walk starts into a network the node has not joined, which is what keeps an
//! empty walk from spending a 5 hour due time.
//!
//! What survives: the due list dies with the node, so a Kad restart starts
//! every file over, at the same pace. A due time does not persist across a
//! process restart, where stock's does (`KnownFile.cpp:733-761`). The search
//! list holds asks already spent on Core's **Ask Clock**; a paused download's
//! ask still walks, and its answer finds no sink.

use std::time::Duration;

use super::{KadNode, KadNodeDiagnostic};
use crate::lookup_walk::KadWalkPurpose;
use crate::{KadInstant, KadPublishRequest, KadSourceLookupRequest};

/// Source publish walks at once (`KADEMLIATOTALSTORESRC`, `Constants.h:39`).
const MOST_PUBLISH_WALKS: usize = 3;

/// Between two source publish starts (`KADEMLIAPUBLISHTIME`, `Constants.h:37`).
const PUBLISH_SPACING: Duration = Duration::from_secs(2);

/// Source search walks at once (`KADEMLIATOTALFILE`, 2.3.3 `Constants.h:34`;
/// 3.1.0 makes it a preference, the 2.3.3 value is the strictest stock).
const MOST_SEARCH_WALKS: usize = 5;

/// Between two source search starts (`KADEMLIAASKTIME`, 2.3.3 `Constants.h:33`).
const SEARCH_SPACING: Duration = Duration::from_secs(1);

/// Asks waiting at once: more downloads than stock's queue holds.
const MOST_QUEUED_SEARCHES: usize = 4096;

/// A registered publication: republished every
/// [`KadNode::SOURCE_REPUBLISH_INTERVAL`], anchored at each publish start
/// (the aMule cadence: its shared-file loop schedules the next source publish
/// when one starts).
#[derive(Clone, Copy, Debug)]
pub(super) struct ScheduledPublish {
    pub(super) request: KadPublishRequest,
    pub(super) next_at: KadInstant,
}

/// The node's own clock on bulk walk starts.
#[derive(Debug)]
pub(super) struct WalkStarts {
    next_publish: KadInstant,
    next_search: KadInstant,
    /// Whether the self-lookup ended (`SetPublish`, `SearchManager.cpp:335`).
    /// True from the start on a node with no self-lookup armed.
    pub(super) publishing: bool,
    /// The last drive's answer for [`KadNode::next_wake`]: `None` while a gate
    /// is shut, because what opens one wakes the node itself.
    pub(super) wake: Option<KadInstant>,
}

impl WalkStarts {
    pub(super) const fn new() -> Self {
        Self {
            next_publish: KadInstant::EPOCH,
            next_search: KadInstant::EPOCH,
            publishing: true,
            wake: None,
        }
    }
}

impl KadNode {
    /// Queue a source search, unless its target is already queued or walked.
    pub(super) fn start_source_search(&mut self, now: KadInstant, request: KadSourceLookupRequest) {
        let target = request.kad_target();
        if self.walks.iter().any(|walk| walk.target() == target)
            || self
                .source_searches
                .iter()
                .any(|queued| queued.kad_target() == target)
        {
            self.emit_diagnostic(KadNodeDiagnostic::DuplicateSourceSearch { target });
            return;
        }
        if self.source_searches.len() >= MOST_QUEUED_SEARCHES {
            self.emit_diagnostic(KadNodeDiagnostic::SourceSearchRefused { target });
            return;
        }
        self.source_searches.push_back(request);
        self.drive_walk_starts(now);
    }

    /// Register a publication, due at once. The tick starts it, and
    /// republishes it every [`Self::SOURCE_REPUBLISH_INTERVAL`] from each start.
    pub(super) fn register_publish(&mut self, now: KadInstant, request: KadPublishRequest) {
        let target = request.kad_target();
        if self
            .scheduled_publishes
            .iter()
            .any(|scheduled| scheduled.request.kad_target() == target)
        {
            self.emit_diagnostic(KadNodeDiagnostic::DuplicatePublish { target });
            return;
        }
        self.scheduled_publishes.push(ScheduledPublish {
            request,
            next_at: now,
        });
        self.drive_walk_starts(now);
    }

    /// Start whatever the two paces allow at `now`.
    pub(super) fn drive_walk_starts(&mut self, now: KadInstant) {
        let publishes_open = self.publish_gate_open(now);
        if publishes_open
            && now >= self.walk_starts.next_publish
            && self.publish_walks() < MOST_PUBLISH_WALKS
            && let Some(index) = self.next_publish_index(now)
        {
            let request = self.scheduled_publishes[index].request;
            self.scheduled_publishes[index].next_at = now + Self::SOURCE_REPUBLISH_INTERVAL;
            self.walk_starts.next_publish = now + PUBLISH_SPACING;
            self.start_walk(now, KadWalkPurpose::PublishSource(request));
        }
        let joined = self.joined(now);
        if joined && now >= self.walk_starts.next_search && self.search_walks() < MOST_SEARCH_WALKS
        {
            if let Some(request) = self.source_searches.pop_front() {
                self.walk_starts.next_search = now + SEARCH_SPACING;
                self.start_walk(now, KadWalkPurpose::SearchSources(request));
            }
        }
        let publish_wake = (publishes_open && self.publish_walks() < MOST_PUBLISH_WALKS)
            .then(|| self.next_publish_due())
            .flatten()
            .map(|due| due.max(self.walk_starts.next_publish));
        let search_wake =
            (joined && !self.source_searches.is_empty() && self.search_walks() < MOST_SEARCH_WALKS)
                .then_some(self.walk_starts.next_search);
        self.walk_starts.wake = publish_wake.into_iter().chain(search_wake).min();
    }

    /// `SharedFileList.cpp:773`: joined, and the self-lookup ended.
    fn publish_gate_open(&self, now: KadInstant) -> bool {
        self.joined(now) && self.walk_starts.publishing
    }

    fn publish_walks(&self) -> usize {
        self.walks
            .iter()
            .filter(|walk| matches!(walk.purpose(), KadWalkPurpose::PublishSource(_)))
            .count()
    }

    fn search_walks(&self) -> usize {
        self.walks
            .iter()
            .filter(|walk| matches!(walk.purpose(), KadWalkPurpose::SearchSources(_)))
            .count()
    }

    /// Whether a publication can start: no walk holds its target, and the node
    /// has a row to state for it (a firewalled node with no buddy has none,
    /// `SharedFileList.cpp:773`).
    fn publishable(&self, scheduled: &ScheduledPublish) -> bool {
        let target = scheduled.request.kad_target();
        !self.walks.iter().any(|walk| walk.target() == target)
            && self.publish_source_req(&scheduled.request).is_some()
    }

    /// The registration index of the longest-due publication at `now`.
    fn next_publish_index(&self, now: KadInstant) -> Option<usize> {
        self.scheduled_publishes
            .iter()
            .enumerate()
            .filter(|(_, scheduled)| scheduled.next_at <= now && self.publishable(scheduled))
            .min_by_key(|(_, scheduled)| scheduled.next_at)
            .map(|(index, _)| index)
    }

    fn next_publish_due(&self) -> Option<KadInstant> {
        self.scheduled_publishes
            .iter()
            .filter(|scheduled| self.publishable(scheduled))
            .map(|scheduled| scheduled.next_at)
            .min()
    }
}
