//! A Low-ID candidate's pending road on its **Source Book** record (ADR-0039,
//! ADR-0091): which road the admission rule opened, how far the punch beside it
//! has run, and the deadlines that govern it — the slot release, the
//! callback-silence fallback and the traversal bound. They sit on the record's
//! CallbackPending stage, so a road that ends by any route takes its deadlines
//! with it, and the brain's tick expires those that come due (ADR-0026).

use std::time::Instant;

use super::SourceBook;
use super::record::Stage;
use crate::adapters::CallbackKey;
use crate::diagnostics::NattRetirement;
use crate::download::state::LowIdRoad;

/// Which of a pending road's deadlines is due. The derived order is the order
/// they fire in when due together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Deadline {
    /// The **callback-silence fallback** (12 s): if the callback is still
    /// pending, its candidate falls to a NAT-T attempt beside it.
    SilenceFallback,
    /// The slot-release deadline (the injected 30 s): the callback lapsed and
    /// the held slot goes to the next candidate — unless a traversal is still
    /// running, which the slot then waits on.
    SlotRelease,
    /// The traversal bound: the latest the **Traversal Attempt** the callback
    /// fell to can still be running.
    TraversalBound,
}

/// One pending road: how far it has run and when it next falls due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingRoad {
    /// Which road the candidate was admitted by — and therefore what a retired
    /// traversal costs it. On a callback road the punch runs *beside* a
    /// relayed invitation that is still outstanding, so its end retracts only
    /// the claim; on the punch road it was the candidate's only road, so its
    /// end is the candidate's.
    pub(crate) road: LowIdRoad,
    /// Why the punch running beside this road ended, once it has (ADR-0091):
    /// the source is temporarily unreachable by NAT traversal, and a second
    /// silence must not start a second punch.
    pub(crate) traversal_retired: Option<NattRetirement>,
    /// Whether a punch was ever asked for this candidate — at admission on the
    /// punch road, or by the 12 s fallback.
    pub(crate) traversal_begun: bool,
    /// Whether the slot-release deadline came due while a traversal was still
    /// running: the slot waited on the attempt, so the attempt's end is the
    /// road's lapse.
    pub(crate) slot_lapsed: bool,
    /// Whether the buddy callback's one fallback-spelling `0x52` has gone out,
    /// so a second lapse ends the road.
    pub(crate) fallback_spelling_sent: bool,
    /// When the slot is released, while that is still ahead.
    slot_release_at: Option<Instant>,
    /// When the callback-silence fallback fires, when armed and still ahead.
    silence_at: Option<Instant>,
    /// When the traversal bound falls, when armed and still ahead.
    traversal_bound_at: Option<Instant>,
}

impl PendingRoad {
    /// A road just opened, nothing armed yet: on the punch road the punch is
    /// begun with it.
    pub(super) const fn opened(road: LowIdRoad) -> Self {
        Self {
            road,
            traversal_retired: None,
            traversal_begun: matches!(road, LowIdRoad::Punch),
            slot_lapsed: false,
            fallback_spelling_sent: false,
            slot_release_at: None,
            silence_at: None,
            traversal_bound_at: None,
        }
    }

    /// Arm `deadline` to fall at `at`, replacing any instant it held.
    pub(crate) fn arm(&mut self, deadline: Deadline, at: Instant) {
        *self.at_mut(deadline) = Some(at);
    }

    fn at_mut(&mut self, deadline: Deadline) -> &mut Option<Instant> {
        match deadline {
            Deadline::SilenceFallback => &mut self.silence_at,
            Deadline::SlotRelease => &mut self.slot_release_at,
            Deadline::TraversalBound => &mut self.traversal_bound_at,
        }
    }

    /// Every armed deadline, with its instant.
    fn armed(&self) -> impl Iterator<Item = (Instant, Deadline)> {
        [
            (self.silence_at, Deadline::SilenceFallback),
            (self.slot_release_at, Deadline::SlotRelease),
            (self.traversal_bound_at, Deadline::TraversalBound),
        ]
        .into_iter()
        .filter_map(|(at, deadline)| Some((at?, deadline)))
    }
}

impl SourceBook {
    /// The road pending for `key`, while its record waits on it.
    pub(crate) fn road(&self, key: CallbackKey) -> Option<&PendingRoad> {
        match &self.records.get(&self.aliases.key(key)?)?.stage {
            Stage::CallbackPending(road) => Some(road),
            _ => None,
        }
    }

    /// The road pending for `key`, to move it on.
    pub(crate) fn road_mut(&mut self, key: CallbackKey) -> Option<&mut PendingRoad> {
        let id = self.aliases.key(key)?;
        match &mut self.records.get_mut(&id)?.stage {
            Stage::CallbackPending(road) => Some(road),
            _ => None,
        }
    }

    /// Take the earliest deadline due at `now` off its road — by instant, then
    /// key, then the order they fire in — so the tick handles each once.
    pub(crate) fn take_due_deadline(&mut self, now: Instant) -> Option<(CallbackKey, Deadline)> {
        let (_, key, deadline) = self
            .records
            .values()
            .filter_map(|record| match (&record.stage, &record.candidate) {
                (Stage::CallbackPending(road), Some(candidate)) => Some((road, candidate.key())),
                _ => None,
            })
            .flat_map(|(road, key)| road.armed().map(move |(at, deadline)| (at, key, deadline)))
            .filter(|&(at, ..)| at <= now)
            .min()?;
        *self.road_mut(key)?.at_mut(deadline) = None;
        Some((key, deadline))
    }

    /// When the earliest armed deadline of any pending road falls.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.records
            .values()
            .filter_map(|record| match &record.stage {
                Stage::CallbackPending(road) => road.armed().map(|(at, _)| at).min(),
                _ => None,
            })
            .min()
    }
}
