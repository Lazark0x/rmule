//! The **Source Book**'s purges: as a file nears its source limit, aMule's
//! `CPartFile::Process` lets one source go at a time to make room for a better
//! one (stock 2.3.3 `PartFile.cpp:1406-1456`) — a Low ID no road reaches, a
//! source holding no part we lack, a source whose queue stayed full. Each kind
//! waits its own spacing since the last purge of *any* kind: one clock per
//! file (`lastpurgetime`), the run's start counting as the last (`:3644`).
//! Only a record no worker holds is let go: a pooled Low-ID candidate, or a
//! standing in the RemoteQueued stage.

use std::time::{Duration, Instant};

use rmule_primitives::PeerEndpoint;

use super::SourceBook;
use super::record::{Lane, RecordId, Stage};
use crate::adapters::CallbackKey;
use crate::dialable::DialPosition;
use crate::download::state::CallbackCapability;

/// How many sources a file holds before any is let go: 80 % of aMule's
/// default `MaxSourcesPerFile` of 300 (stock 2.3.3 `PartFile.cpp:1413`,
/// `:1428`, `:1452`; `Preferences.cpp:1027`).
pub(crate) const SOURCE_PURGE_AT: u32 = 240;

/// A Low ID no road reaches goes 30 s after the last purge (stock 2.3.3
/// `PartFile.cpp:1412`).
pub(crate) const LOW_TO_LOW_PURGE_SPACING: Duration = Duration::from_secs(30);

/// A no-needed-parts source goes 40 s after the last purge (stock 2.3.3
/// `PartFile.cpp:1425`).
pub(crate) const NO_NEEDED_PARTS_PURGE_SPACING: Duration = Duration::from_secs(40);

/// A queue-full source goes 60 s after the last purge (stock 2.3.3
/// `PartFile.cpp:1451`).
pub(crate) const QUEUE_FULL_PURGE_SPACING: Duration = Duration::from_secs(60);

/// Which purge let a source go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PurgeKind {
    /// A pooled Low-ID candidate the admission rule opens no road to while we
    /// are connected — aMule's `DS_LOWTOLOWIP`, which only an ask made while
    /// connected reaches (`BaseClient.cpp:1453-1457`), and which it
    /// re-promotes the moment a callback becomes possible, as the book's next
    /// fill does.
    LowToLow,
    /// A standing whose source holds no part we lack (`DS_NONEEDEDPARTS`).
    /// aMule first offers it to another download (`SwapToAnotherFile`);
    /// rmule's downloads share no source, so none takes it over.
    NoNeededParts,
    /// A standing whose `0x93` stands (`IsRemoteQueueFull`).
    QueueFull,
}

impl PurgeKind {
    /// How long after the last purge this kind may go.
    const fn spacing(self) -> Duration {
        match self {
            Self::LowToLow => LOW_TO_LOW_PURGE_SPACING,
            Self::NoNeededParts => NO_NEEDED_PARTS_PURGE_SPACING,
            Self::QueueFull => QUEUE_FULL_PURGE_SPACING,
        }
    }
}

/// The source a purge let go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purged {
    /// A standing, at the endpoint it stood at.
    Endpoint(PeerEndpoint),
    /// A Low-ID candidate, by its key.
    LowId(CallbackKey),
}

impl SourceBook {
    /// Let one source go at `now`, when the file holds [`SOURCE_PURGE_AT`]
    /// sources: the oldest record a purge may take whose kind's spacing has
    /// passed since the last purge or the run's start. `capability` and
    /// `dial` are what the admission rule reads of us. The first instant only
    /// starts the clock.
    pub(crate) fn purge(
        &mut self,
        now: Instant,
        capability: &CallbackCapability,
        dial: DialPosition,
    ) -> Option<(PurgeKind, Purged)> {
        let Some(last) = self.purged_at else {
            self.purged_at = Some(now);
            return None;
        };
        if self.counts().known < SOURCE_PURGE_AT {
            return None;
        }
        let elapsed = now.saturating_duration_since(last);
        let (id, kind) = self
            .purgeable(capability, dial)
            .filter(|&(_, kind)| elapsed >= kind.spacing())
            .min_by_key(|&(id, _)| id)?;
        let record = self.remove(id)?;
        self.purged_at = Some(now);
        let purged = match record.stage {
            Stage::RemoteQueued(peer) => Purged::Endpoint(peer),
            _ => Purged::LowId(record.candidate?.key()),
        };
        Some((kind, purged))
    }

    /// When the next source may be let go, while the file is at the threshold
    /// and a record a purge may take is held.
    pub(crate) fn next_purge(
        &self,
        capability: &CallbackCapability,
        dial: DialPosition,
    ) -> Option<Instant> {
        let last = self.purged_at?;
        if self.counts().known < SOURCE_PURGE_AT {
            return None;
        }
        self.purgeable(capability, dial)
            .map(|(_, kind)| last + kind.spacing())
            .min()
    }

    /// Every record a purge may take, with the purge that may take it.
    fn purgeable<'a>(
        &'a self,
        capability: &'a CallbackCapability,
        dial: DialPosition,
    ) -> impl Iterator<Item = (RecordId, PurgeKind)> + 'a {
        self.records.iter().filter_map(move |(&id, record)| {
            match (&record.stage, record.standing) {
                (Stage::RemoteQueued(_), Some(standing)) => {
                    standing.purge_mark().map(|kind| (id, kind))
                }
                (Stage::Pooled(Lane::LowIdConnected | Lane::LowIdGlobal), _) => {
                    (capability.connected() && self.low_id_route(id, capability, dial).is_none())
                        .then_some((id, PurgeKind::LowToLow))
                }
                _ => None,
            }
        })
    }
}
