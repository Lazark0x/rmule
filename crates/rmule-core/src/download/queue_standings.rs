//! The node's **Queue Standings** (ADR-0107, "One peer, one queue standing"):
//! rmule's one place in each remote uploader's queue, shared by every run of
//! the **Download Set**. aMule's uploader keeps one queue entry per client,
//! re-targeted to whichever file the client asked for last (`SetUploadFileID`,
//! stock 2.3.3 `ClientTCPSocket.cpp:462`, `:521`, `:613`), answers a UDP reask
//! only for that file (`ClientUDPSocket.cpp:196-228`), and scores every ask
//! the client makes (`CheckForAggressive`, `UploadClient.cpp:795-825`). So one
//! download holds a peer's standing and re-asks it; every other download with
//! a record there waits on it and asks nothing.
//!
//! Each run holds one [`StandingSeat`] and republishes its **places** — every
//! record holding a standing, under its **Ask Names** — after every step, never
//! by hand, and stamps each ping and TCP full ask its sweep sends. A **stamp**
//! per name keeps the peer's last ask and the download whose slot ask it last
//! read, past the place that made it, so a download the standing passes to
//! asks on the peer's clock. Time is an argument, as everywhere in the
//! download brain.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::download::source_book::AskName;
use crate::service::DownloadId;

/// How long a stamp no place carries any more is kept: two reask periods past
/// the newest stamp, the longest a standing waits between asks (aMule
/// `FILEREASKTIME * 2` for a source holding nothing we need).
const STAMP_KEPT: Duration = Duration::from_millis(2 * 1_300_000);

/// One record holding a standing, as its run publishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Place {
    /// Every name the record is known by.
    pub(crate) names: Vec<AskName>,
    /// When its download's slot ask last reached the peer; `None` for a
    /// record that waits on the standing without ever having asked.
    pub(crate) asked: Option<Instant>,
    /// Whether the record may need a part of the peer: not the
    /// no-needed-parts mark (ADR-0112).
    pub(crate) needs_parts: bool,
}

/// What a record's download is to the peer's standing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// It holds the standing, and the peer's entry names its file: its record
    /// re-asks on its own clock, by ping or TCP full ask.
    Holds,
    /// It holds the standing, but the peer's entry names a file another
    /// download asked for last: its record pings nothing, and its TCP full
    /// ask falls due a period after `asked_at`, the peer's last ask.
    Inherits {
        /// The peer's last ask.
        asked_at: Instant,
    },
    /// Another download holds the standing: the record asks nothing, and its
    /// clock follows `asked_at`, the peer's last ask, when one is known.
    Waits {
        /// The peer's last ask, when any download stamped one.
        asked_at: Option<Instant>,
    },
}

impl Role {
    /// Whether the record re-asks the peer at all.
    pub(crate) const fn asks(self) -> bool {
        !matches!(self, Self::Waits { .. })
    }
}

/// The peer's last ask under one name, and whose slot ask it last read.
#[derive(Clone, Copy, Debug)]
struct Stamp {
    asked_at: Instant,
    named: Option<(DownloadId, Instant)>,
}

/// The registry: each run's places, the downloads holding a place under each
/// name, and the stamps per name.
#[derive(Debug, Default)]
pub(crate) struct QueueStandings {
    places: HashMap<DownloadId, Vec<Place>>,
    by_name: HashMap<AskName, HashSet<DownloadId>>,
    stamps: HashMap<AskName, Stamp>,
}

/// The core's one registry, shared by every run of the **Download Set**. Held
/// only for one read or publication, never across an await.
pub(crate) type SharedQueueStandings = Arc<Mutex<QueueStandings>>;

impl QueueStandings {
    /// An empty registry, shared.
    pub(crate) fn shared() -> SharedQueueStandings {
        Arc::new(Mutex::new(Self::default()))
    }

    /// `download`'s role at the peer `place` names, read against every other
    /// download's published places that share one of its names: a place that
    /// may need a part outranks one that needs none, then the latest slot ask,
    /// then the download added first.
    fn role(&self, download: DownloadId, place: &Place) -> Role {
        let mine = rank(download, place);
        let rivals: HashSet<DownloadId> = place
            .names
            .iter()
            .filter_map(|name| self.by_name.get(name))
            .flatten()
            .copied()
            .filter(|&other| other != download)
            .collect();
        let outranked = rivals.into_iter().any(|other| {
            self.places
                .get(&other)
                .into_iter()
                .flatten()
                .filter(|p| shares_a_name(place, p))
                .any(|p| rank(other, p) > mine)
        });
        let stamps: Vec<Stamp> = place
            .names
            .iter()
            .filter_map(|name| self.stamps.get(name).copied())
            .collect();
        let asked_at = stamps.iter().map(|stamp| stamp.asked_at).max();
        if outranked {
            return Role::Waits { asked_at };
        }
        let named_elsewhere = stamps
            .iter()
            .filter_map(|stamp| stamp.named)
            .any(|(by, at)| by != download && place.asked.is_none_or(|asked| at > asked));
        match asked_at {
            Some(asked_at) if named_elsewhere => Role::Inherits { asked_at },
            _ => Role::Holds,
        }
    }

    /// Take `download`'s places as they stand now, and fold their slot asks
    /// into the stamps; a stamp no place carries goes once it is
    /// [`STAMP_KEPT`] older than the newest.
    fn publish(&mut self, download: DownloadId, places: Vec<Place>) {
        for place in &places {
            let Some(asked) = place.asked else { continue };
            for name in &place.names {
                let stamp = self.stamps.entry(*name).or_insert(Stamp {
                    asked_at: asked,
                    named: None,
                });
                stamp.asked_at = stamp.asked_at.max(asked);
                if stamp.named.is_none_or(|(_, at)| asked >= at) {
                    stamp.named = Some((download, asked));
                }
            }
        }
        self.withdraw(download);
        for name in places.iter().flat_map(|place| &place.names) {
            self.by_name.entry(*name).or_default().insert(download);
        }
        if !places.is_empty() {
            self.places.insert(download, places);
        }
        self.forget_stale_stamps();
    }

    /// Take `download`'s places out, its stamps left standing.
    fn withdraw(&mut self, download: DownloadId) {
        let Some(places) = self.places.remove(&download) else {
            return;
        };
        for name in places.iter().flat_map(|place| &place.names) {
            if let Some(holders) = self.by_name.get_mut(name) {
                holders.remove(&download);
                if holders.is_empty() {
                    self.by_name.remove(name);
                }
            }
        }
    }

    /// The peer `names` names was asked at `now`.
    fn stamp(&mut self, names: &[AskName], now: Instant) {
        for name in names {
            self.stamps
                .entry(*name)
                .and_modify(|stamp| stamp.asked_at = stamp.asked_at.max(now))
                .or_insert(Stamp {
                    asked_at: now,
                    named: None,
                });
        }
    }

    fn forget_stale_stamps(&mut self) {
        let Some(newest) = self.stamps.values().map(|stamp| stamp.asked_at).max() else {
            return;
        };
        let carried = &self.by_name;
        self.stamps.retain(|name, stamp| {
            carried.contains_key(name)
                || newest.saturating_duration_since(stamp.asked_at) < STAMP_KEPT
        });
    }
}

/// The order places outrank each other by.
fn rank(download: DownloadId, place: &Place) -> (bool, Option<Instant>, Reverse<DownloadId>) {
    (place.needs_parts, place.asked, Reverse(download))
}

fn shares_a_name(one: &Place, other: &Place) -> bool {
    one.names.iter().any(|name| other.names.contains(name))
}

/// One run's seat in the shared registry. Its drop withdraws the run's
/// places; the stamps they made stay, so the next holder asks on the peer's
/// clock.
#[derive(Debug)]
pub(crate) struct StandingSeat {
    standings: SharedQueueStandings,
    download: DownloadId,
}

impl StandingSeat {
    /// Take `download`'s seat in `standings`, holding no place yet.
    pub(crate) fn new(standings: SharedQueueStandings, download: DownloadId) -> Self {
        Self {
            standings,
            download,
        }
    }

    /// A seat alone in a registry of its own: one download's brain that no
    /// other download shares a peer with.
    pub(crate) fn alone(download: DownloadId) -> Self {
        Self::new(QueueStandings::shared(), download)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueStandings> {
        self.standings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// This run's role at the peer `place` names.
    pub(crate) fn role(&self, place: &Place) -> Role {
        self.lock().role(self.download, place)
    }

    /// Republish the places this run's records hold now.
    pub(crate) fn publish(&self, places: Vec<Place>) {
        self.lock().publish(self.download, places);
    }

    /// The peer `names` names was asked at `now`: a ping or a TCP full ask
    /// left for it.
    pub(crate) fn stamp(&self, names: &[AskName], now: Instant) {
        self.lock().stamp(names, now);
    }
}

impl Drop for StandingSeat {
    fn drop(&mut self) {
        self.lock().withdraw(self.download);
    }
}

#[cfg(test)]
mod tests;
