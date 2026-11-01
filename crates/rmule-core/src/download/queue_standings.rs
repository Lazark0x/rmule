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
//! Each run holds one [`StandingSeat`] and publishes its **places** — every
//! record holding a standing, and as **Pooled Places** every record still in a
//! lane, under its **Ask Names** — as they move, after every step, never by
//! hand, and stamps each ping and slot ask as it leaves. A publication costs
//! what moved: the records the book touched, and the stamps falling due. A
//! **stamp**
//! per name keeps the peer's last ask and the download whose slot ask it last
//! read, past the place that made it, so a download the standing passes to
//! asks on the peer's clock. A **Source Handover** (ADR-0090) is a role read
//! here and nothing else: no run reads another's book or tells it anything.
//! A **stamp** is also the **Peer Clock**: every ask reads it and stamps
//! it as it leaves, and none leaves inside [`MIN_REQUEST_TIME`] (invariant 14).
//! Each stamp carries the peer's **Ask Score** as stock computes it, the one
//! thing a Link Rider may spend to ask inside that clock (invariant 17).
//! A **Left Place** keeps, past the run that made it, a place at the peer and
//! its last ask, per file and name (invariant 15): a Resume or a re-add is a
//! new run, and the book that held them is gone.
//! Time is an argument, as everywhere in the download brain.

use parking_lot::Mutex;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_primitives::FileHash;

use crate::download::source_book::{AskName, no_needed_parts_period};
use crate::service::DownloadId;

use self::expiries::Expiries;

mod expiries;

/// aMule `MIN_REQUESTTIME` (`Constants.h:67`): an ask of a peer under this
/// past its last scores +3, and 10 bans for two hours
/// (`UploadClient.cpp:795-825`). Nothing of ours is asked inside it.
pub(crate) const MIN_REQUEST_TIME: Duration = Duration::from_secs(590);

/// How long a stamp no place carries any more is kept, past the newest stamp:
/// the longest a standing waits between asks.
const STAMP_KEPT: Duration = no_needed_parts_period();

/// How long a stamp with a score is kept: the uploader's own queue purge
/// (`MAX_PURGEQUEUETIME`, `UploadQueue.cpp:86`), the shortest it can hold the
/// client the score is on.
const SCORE_KEPT: Duration = Duration::from_secs(60 * 60);

/// What an ask inside [`MIN_REQUEST_TIME`] adds to the peer's **Ask Score**
/// (`UploadClient.cpp:806-807`).
const FAST_ASK: u16 = 3;

/// The highest **Ask Score** an ask of ours may leave: stock bans at 10
/// (`UploadClient.cpp:810`), and this keeps the margin of one.
const MOST_SCORE: u16 = 9;

/// How an ask reached the peer, which says how it reads the clock and how
/// stock scores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ask {
    /// A UDP reask: scored (`ClientUDPSocket.cpp:194`), and only a TCP ask
    /// past it is its fallback.
    Ping,
    /// A slot ask (`ClientTCPSocket.cpp:601`).
    Slot,
    /// An AICH recovery ask: on the clock always, and unscored on 2.3.3
    /// though 3.1.0 scores it (`ClientTCPSocket.cpp:1768`), so it takes
    /// nothing off.
    Recovery,
}

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
    /// Whether the record is still in a lane, holding no standing: a Pooled
    /// Place, which outranks only a place needing nothing (ADR-0090).
    pub(crate) pooled: bool,
    /// Whether its TCP full ask follows a ping of its own left unanswered:
    /// stock's fallback 20 s later (`DownloadClient.cpp:1260-1270`), the one
    /// ask a ping's stamp does not hold back.
    pub(crate) after_ping: bool,
}

/// A place's name inside its run: the record holding it, which keeps its name
/// however its place moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PlaceId(pub(crate) u64);

/// What one record's place came to stand at: `None` when it holds none now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlaceChange {
    /// The record.
    pub(crate) id: PlaceId,
    /// Its place as it stands.
    pub(crate) place: Option<Place>,
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
    /// It takes the standing from another download's place, still published,
    /// that needs no part of the peer (a **Source Handover**, ADR-0090): as
    /// [`Self::Inherits`], and a fill reaching its pooled record parks it
    /// rather than dialing it inside the peer's clock.
    Takes {
        /// The peer's last ask.
        asked_at: Instant,
    },
    /// Another download holds the standing: the record asks nothing, and its
    /// clock follows `asked_at`, the peer's last ask, when one is known.
    Waits {
        /// The peer's last ask, when any download stamped one.
        asked_at: Option<Instant>,
    },
    /// A past run of this file left a place at the peer, and this record
    /// has asked nothing since: a fill parks it there until a period past
    /// that ask, twice that when the place needed no part (invariant 15).
    Returns {
        /// The ask the place stands on.
        asked_at: Instant,
        /// Whether the source held no part the file lacks.
        no_needed_parts: bool,
    },
    /// The record has no place at the peer and its ask falls inside the
    /// peer's clock: it asks nothing until [`MIN_REQUEST_TIME`] past
    /// `asked_at`, or at the next sweep with no ask known (invariant 16).
    Spaced {
        /// The peer's last ask, when one is known.
        asked_at: Option<Instant>,
    },
}

impl Role {
    /// Whether the record re-asks the peer at all.
    pub(crate) const fn asks(self) -> bool {
        !matches!(self, Self::Waits { .. })
    }

    /// What a fill reaching a pooled record may do at `now`, the peer's clock
    /// running `period` (ADR-0090): a stamp a period old holds nothing back.
    fn fill_gate(self, now: Instant, period: Duration) -> FillGate {
        let since = |asked_at: Instant| now.saturating_duration_since(asked_at);
        match self {
            Self::Waits { .. } | Self::Spaced { .. } => FillGate::Parks(self),
            Self::Returns {
                asked_at,
                no_needed_parts: true,
            } if since(asked_at) < no_needed_parts_period() => FillGate::Parks(self),
            Self::Returns {
                asked_at,
                no_needed_parts: false,
            }
            | Self::Takes { asked_at }
                if since(asked_at) < period =>
            {
                FillGate::Parks(self)
            }
            Self::Inherits { asked_at } if since(asked_at) < period => FillGate::OnALink(self),
            Self::Holds | Self::Returns { .. } | Self::Takes { .. } | Self::Inherits { .. } => {
                FillGate::Open
            }
        }
    }
}

/// What a fill may do with a pooled record of a peer the **Queue Standings**
/// know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FillGate {
    /// Ask the peer.
    Open,
    /// Ride a link that stands, and dial nothing: the peer's last ask named a
    /// download whose place has ended, and its clock still runs.
    OnALink(Role),
    /// Ask nothing: the record stands on the peer's standing.
    Parks(Role),
}

/// The peer's last ask under one name, and whose slot ask it last read.
#[derive(Clone, Copy, Debug)]
struct Stamp {
    asked_at: Instant,
    /// The last ask that was no ping.
    tcp_asked_at: Option<Instant>,
    named: Option<(FileHash, Instant)>,
    /// The peer's **Ask Score** after that ask.
    score: u16,
}

impl Stamp {
    /// A stamp whose first ask is `asked_at`.
    const fn new(asked_at: Instant) -> Self {
        Self {
            asked_at,
            tcp_asked_at: None,
            named: None,
            score: 0,
        }
    }

    /// When a stamp no place carries goes, counted against the newest ask.
    fn expires(&self) -> Instant {
        let kept = if self.score > 0 {
            SCORE_KEPT
        } else {
            STAMP_KEPT
        };
        self.asked_at + kept
    }

    /// The peer was asked at `now`, as `ask` says.
    fn asked(&mut self, now: Instant, ask: Ask) {
        self.asked_at = self.asked_at.max(now);
        if ask != Ask::Ping {
            self.tcp_asked_at = self.tcp_asked_at.max(Some(now));
        }
    }
}

/// What a run left at the peer under one name: the ask its place stands on.
#[derive(Clone, Copy, Debug)]
struct LeftPlace {
    asked_at: Instant,
    needs_parts: bool,
}

impl LeftPlace {
    /// When it goes, counted against the newest ask.
    fn expires(&self) -> Instant {
        self.asked_at + STAMP_KEPT
    }
}

/// The registry: each run's places, the places under each name, the stamps per
/// name, and the left places per file and name. `stamp_ages` holds an entry
/// for every stamp no place carries, due no later than the stamp goes, and
/// `left_ages` one for every left place: nothing else ever walks a table.
#[derive(Debug, Default)]
pub(crate) struct QueueStandings {
    places: HashMap<DownloadId, HashMap<PlaceId, Place>>,
    by_name: HashMap<AskName, HashSet<(DownloadId, PlaceId)>>,
    stamps: HashMap<AskName, Stamp>,
    left: HashMap<(FileHash, AskName), LeftPlace>,
    /// The newest ask any stamp took, which everything here ages against.
    newest: Option<Instant>,
    stamp_ages: Expiries<AskName>,
    left_ages: Expiries<(FileHash, AskName)>,
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
    /// then the download added first; a Pooled Place outranks only a place
    /// that needs none.
    fn role(&self, download: DownloadId, file: FileHash, place: &Place) -> Role {
        let mine = rank(download, place);
        let rivals = || {
            place
                .names
                .iter()
                .filter_map(|name| self.by_name.get(name))
                .flatten()
                .filter(|(other, _)| *other != download)
                .filter_map(|&(other, id)| Some((other, self.places.get(&other)?.get(&id)?)))
        };
        let outranked =
            rivals().any(|(other, p)| (!p.pooled || !place.needs_parts) && rank(other, p) > mine);
        let stands_elsewhere = rivals().any(|(_, p)| !p.pooled);
        let stamps: Vec<Stamp> = place
            .names
            .iter()
            .filter_map(|name| self.stamps.get(name).copied())
            .collect();
        let asked_at = stamps.iter().map(|stamp| stamp.asked_at).max();
        if outranked {
            return Role::Waits { asked_at };
        }
        let unread = |at: Instant| place.asked.is_none_or(|asked| at > asked);
        let named_elsewhere = stamps
            .iter()
            .filter_map(|stamp| stamp.named)
            .any(|(by, at)| by != file && unread(at));
        match asked_at {
            Some(asked_at) if named_elsewhere && stands_elsewhere => Role::Takes { asked_at },
            Some(asked_at) if named_elsewhere => Role::Inherits { asked_at },
            _ => self.left_place(file, place, unread),
        }
    }

    /// The place a past run of `file` left under one of `place`'s names, as a
    /// role, when `unread` says this record has not asked since.
    fn left_place(&self, file: FileHash, place: &Place, unread: impl Fn(Instant) -> bool) -> Role {
        place
            .names
            .iter()
            .filter_map(|name| self.left.get(&(file, *name)))
            .max_by_key(|left| left.asked_at)
            .filter(|left| unread(left.asked_at))
            .map_or(Role::Holds, |left| Role::Returns {
                asked_at: left.asked_at,
                no_needed_parts: !left.needs_parts,
            })
    }

    /// The peer's last ask under any name `place` carries, as it binds that
    /// record.
    fn last_ask(&self, place: &Place) -> Option<Instant> {
        place
            .names
            .iter()
            .filter_map(|name| self.stamps.get(name))
            .filter_map(|stamp| {
                if place.after_ping && self.has_room(place) {
                    stamp.tcp_asked_at
                } else {
                    Some(stamp.asked_at)
                }
            })
            .max()
    }

    /// The peer's **Ask Score**, the highest any of `names` carries: a name
    /// learned late has not heard the asks before it.
    fn score(&self, names: &[AskName]) -> u16 {
        names
            .iter()
            .filter_map(|name| self.stamps.get(name))
            .map(|stamp| stamp.score)
            .max()
            .unwrap_or(0)
    }

    /// Whether an ask inside the clock leaves the peer's **Ask Score** at
    /// [`MOST_SCORE`] or under.
    fn has_room(&self, place: &Place) -> bool {
        self.score(&place.names) + FAST_ASK <= MOST_SCORE
    }

    /// Take what moved in `download`'s places, and fold the slot asks of those
    /// that moved into the stamps; a place that did not move folded its ask
    /// when it did. A Pooled Place's ask is the record's own claim on its next
    /// fill, nothing the peer read. An ask was scored as it left, so nothing
    /// folded here scores.
    fn publish(&mut self, download: DownloadId, file: FileHash, changes: Vec<PlaceChange>) {
        for PlaceChange { id, place } in changes {
            let held = self.places.get(&download).and_then(|held| held.get(&id));
            if held == place.as_ref() {
                continue;
            }
            if let Some(place) = place.as_ref().filter(|place| !place.pooled) {
                self.fold_ask(file, place);
            }
            self.replace(download, id, place);
        }
        self.forget_stale_stamps();
    }

    /// Fold `place`'s slot ask into the stamps of its names.
    fn fold_ask(&mut self, file: FileHash, place: &Place) {
        let Some(asked) = place.asked else { return };
        for name in &place.names {
            let stamp = self.stamps.entry(*name).or_insert(Stamp::new(asked));
            stamp.asked(asked, Ask::Slot);
            if stamp.named.is_none_or(|(_, at)| asked >= at) {
                stamp.named = Some((file, asked));
            }
        }
        self.newest = self.newest.max(Some(asked));
    }

    /// `place` stands for the record `id` of `download`: the names it no longer
    /// carries let go of the record, and it takes the names it now does.
    fn replace(&mut self, download: DownloadId, id: PlaceId, place: Option<Place>) {
        let holder = (download, id);
        let held = self
            .places
            .get_mut(&download)
            .and_then(|held| held.remove(&id));
        for name in held.iter().flat_map(|held| &held.names) {
            if place
                .as_ref()
                .is_none_or(|place| !place.names.contains(name))
            {
                self.unbind(*name, holder);
            }
        }
        if let Some(place) = place {
            for name in &place.names {
                self.by_name.entry(*name).or_default().insert(holder);
            }
            self.places.entry(download).or_default().insert(id, place);
        }
    }

    /// `name` no longer carries `holder`; a stamp no place carries now starts
    /// to age.
    fn unbind(&mut self, name: AskName, holder: (DownloadId, PlaceId)) {
        let Some(holders) = self.by_name.get_mut(&name) else {
            return;
        };
        holders.remove(&holder);
        if holders.is_empty() {
            self.by_name.remove(&name);
            if let Some(stamp) = self.stamps.get(&name) {
                self.stamp_ages.add(stamp.expires(), name);
            }
        }
    }

    /// Take `download`'s places out, its stamps left standing.
    fn withdraw(&mut self, download: DownloadId) {
        let Some(places) = self.places.remove(&download) else {
            return;
        };
        for (id, place) in places {
            for name in place.names {
                self.unbind(name, (download, id));
            }
        }
    }

    /// `file`'s run ends: each place it published that asked stays as a left
    /// place, and its places come out.
    fn leave(&mut self, download: DownloadId, file: FileHash) {
        let places = self
            .places
            .get(&download)
            .into_iter()
            .flat_map(HashMap::values);
        for place in places {
            let Some(asked_at) = place.asked.filter(|_| !place.pooled) else {
                continue;
            };
            for name in &place.names {
                let left = LeftPlace {
                    asked_at,
                    needs_parts: place.needs_parts,
                };
                self.left_ages.add(left.expires(), (file, *name));
                self.left.insert((file, *name), left);
            }
        }
        self.withdraw(download);
    }

    /// The peer `names` names was asked at `now`: stamp it, and score the
    /// ask as stock does (`CheckForAggressive`, `UploadClient.cpp:795-825`).
    fn stamp(&mut self, names: &[AskName], now: Instant, ask: Ask) {
        let last = names
            .iter()
            .filter_map(|name| self.stamps.get(name))
            .map(|stamp| stamp.asked_at)
            .max();
        let score = self.score(names);
        let score = match last {
            None => score,
            Some(last) if now.saturating_duration_since(last) < MIN_REQUEST_TIME => {
                score + FAST_ASK
            }
            Some(_) if ask == Ask::Recovery => score,
            Some(_) => score.saturating_sub(1),
        };
        for name in names {
            let stamp = self.stamps.entry(*name).or_insert(Stamp::new(now));
            stamp.asked(now, ask);
            stamp.score = score;
            if !self.by_name.contains_key(name) {
                self.stamp_ages.add(stamp.expires(), *name);
            }
        }
        self.newest = self.newest.max(Some(now));
        self.forget_stale_stamps();
    }

    /// Forget what fell due against the newest ask: a stamp no place carries
    /// once it is past its keeping, a left place likewise. Costs what is due.
    fn forget_stale_stamps(&mut self) {
        let Some(newest) = self.newest else { return };
        while let Some(name) = self.stamp_ages.next_due(newest) {
            let Some(expires) = self.stamps.get(&name).map(Stamp::expires) else {
                continue;
            };
            if self.by_name.contains_key(&name) {
                continue;
            }
            if expires <= newest {
                self.stamps.remove(&name);
            } else {
                self.stamp_ages.add(expires, name);
            }
        }
        while let Some(key) = self.left_ages.next_due(newest) {
            let Some(expires) = self.left.get(&key).map(LeftPlace::expires) else {
                continue;
            };
            if expires <= newest {
                self.left.remove(&key);
            } else {
                self.left_ages.add(expires, key);
            }
        }
    }
}

/// The order places outrank each other by.
fn rank(download: DownloadId, place: &Place) -> (bool, Option<Instant>, Reverse<DownloadId>) {
    (place.needs_parts, place.asked, Reverse(download))
}

/// One run's seat in the shared registry. Its drop leaves the run's places as
/// left places and withdraws them; the stamps they made stay, so the next
/// holder asks on the peer's clock.
#[derive(Debug)]
pub(crate) struct StandingSeat {
    standings: SharedQueueStandings,
    download: DownloadId,
    file: FileHash,
}

impl StandingSeat {
    /// Take the seat of `download`, a run of `file`, in `standings`, holding
    /// no place yet.
    pub(crate) fn new(
        standings: SharedQueueStandings,
        download: DownloadId,
        file: FileHash,
    ) -> Self {
        Self {
            standings,
            download,
            file,
        }
    }

    /// A seat alone in a registry of its own: one download's brain that no
    /// other download shares a peer with.
    pub(crate) fn alone(download: DownloadId, file: FileHash) -> Self {
        Self::new(QueueStandings::shared(), download, file)
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, QueueStandings> {
        self.standings.lock()
    }

    /// This run's role at the peer `place` names.
    pub(crate) fn role(&self, place: &Place) -> Role {
        self.lock().role(self.download, self.file, place)
    }

    /// The role a record at the peer `place` names takes when it may not ask:
    /// its own, or spaced when that would hold it nothing back.
    pub(crate) fn standing_aside(&self, place: &Place) -> Role {
        let standings = self.lock();
        match standings.role(self.download, self.file, place) {
            Role::Holds => Role::Spaced {
                asked_at: standings.last_ask(place),
            },
            role => role,
        }
    }

    /// What a fill may do with the record at the peer `place` names at `now`,
    /// the peer's clock running `period`: nothing is asked inside
    /// [`MIN_REQUEST_TIME`] of the peer's last ask (invariant 14).
    pub(crate) fn fill_gate(&self, place: &Place, now: Instant, period: Duration) -> FillGate {
        let standings = self.lock();
        let role = standings.role(self.download, self.file, place);
        match role.fill_gate(now, period) {
            FillGate::Parks(_) => FillGate::Parks(role),
            gate => match standings.last_ask(place) {
                Some(asked_at) if now.saturating_duration_since(asked_at) < MIN_REQUEST_TIME => {
                    FillGate::Parks(match role {
                        Role::Holds => Role::Spaced {
                            asked_at: Some(asked_at),
                        },
                        role => role,
                    })
                }
                _ => gate,
            },
        }
    }

    /// Whether the peer's clock forbids the record at the peer `place` names
    /// an ask at `now` (invariant 14).
    pub(crate) fn clock_holds(&self, place: &Place, now: Instant) -> bool {
        self.lock()
            .last_ask(place)
            .is_some_and(|at| now.saturating_duration_since(at) < MIN_REQUEST_TIME)
    }

    /// Whether the peer's clock forbids a Link Rider of the peer `place`
    /// names an ask at `now`: it runs, and the **Ask Score** has no room for
    /// a fast ask (invariant 17).
    pub(crate) fn clock_holds_rider(&self, place: &Place, now: Instant) -> bool {
        let standings = self.lock();
        !standings.has_room(place)
            && standings
                .last_ask(place)
                .is_some_and(|at| now.saturating_duration_since(at) < MIN_REQUEST_TIME)
    }

    /// The peer's last ask, as it binds the record `place` names.
    pub(crate) fn last_ask(&self, place: &Place) -> Option<Instant> {
        self.lock().last_ask(place)
    }

    /// Publish what moved in the places this run's records hold. Nothing moved
    /// takes nothing, the lock included.
    pub(crate) fn publish(&self, changes: Vec<PlaceChange>) {
        if !changes.is_empty() {
            self.lock().publish(self.download, self.file, changes);
        }
    }

    /// A ping left for the peer `names` names at `now`.
    pub(crate) fn pinged(&self, names: &[AskName], now: Instant) {
        self.lock().stamp(names, now, Ask::Ping);
    }

    /// A slot ask left for the peer `names` names at `now`.
    pub(crate) fn asked(&self, names: &[AskName], now: Instant) {
        self.lock().stamp(names, now, Ask::Slot);
    }

    /// A recovery ask left for the peer `names` names at `now`.
    pub(crate) fn asked_recovery(&self, names: &[AskName], now: Instant) {
        self.lock().stamp(names, now, Ask::Recovery);
    }
}

impl Drop for StandingSeat {
    fn drop(&mut self) {
        let (download, file) = (self.download, self.file);
        self.lock().leave(download, file);
    }
}

#[cfg(test)]
mod tests;
