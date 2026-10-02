//! The **Download Directory Scan**'s watch (ADR-0103, "The watch"): after
//! the first pass, the worker waits on [`DirectoryWatch`] for paths that
//! moved, examines them against the registry through the same plan the pass
//! uses, lets what the plan would hash settle until it holds still, and
//! hashes it one file at a time. A row found gone looks for its content
//! elsewhere first ([`Whereabouts`]), so a rename moves the row rather than
//! passing through the Had Set. An event is a reason to look, never a fact:
//! what is on disk when the path is examined is what counts. The watch seam
//! is also the loop's only clock and its only wait, so the loop runs against
//! a scripted watch without sleeping.

mod fault;
mod rewatch;
mod settle;

pub use fault::WatchFault;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rmule_primitives::FileHash;

use super::carry::{Carry, carry};
use super::plan::{FoundFile, GoneRow, Walked, plan, trusted, walk};
use super::whereabouts::Whereabouts;
use super::{
    DirectorySource, EntryKind, Known, Memory, ProgressCell, ScanPhase, ScanReport, Told, hash,
    set_phase,
};
use crate::registry::SharedFileEntry;
#[cfg(test)]
pub(crate) use rewatch::REWATCH_DELAYS;
pub(crate) use rewatch::{Rewatch, WatchStarter, pause, rewatch};
use settle::Settle;

/// The longest the loop waits between looks at its stop flag.
const TICK: Duration = Duration::from_millis(250);

/// One wake of the watch: the instant it woke, and what it saw meanwhile.
#[derive(Debug)]
pub(crate) struct WatchBatch {
    /// The scan's clock, read at the wake.
    pub(crate) now: Instant,
    /// What moved, in arrival order; empty when the wait ran out.
    pub(crate) signals: Vec<WatchSignal>,
}

/// What the watch saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WatchSignal {
    /// Something at this path moved: it is examined, not believed.
    Moved(PathBuf),
    /// Events were lost (a queue overflow): the whole directory is examined.
    Lost,
    /// The watch no longer covers this path, for the reason given; the rest
    /// of the directory is still watched.
    PathFailed {
        /// The path no longer watched.
        path: PathBuf,
        /// Why.
        reason: WatchFault,
    },
    /// The watch no longer covers the directory, for the reason given.
    Failed(WatchFault),
}

/// The seam between the scan and the operating system's change notices, and
/// the scan's clock. The one adapter over `notify` lives in core's adapters.
pub(crate) trait DirectoryWatch: Send {
    /// Wait at most `max` for something to move, and say when the wait ended.
    fn wait(&mut self, max: Duration) -> WatchBatch;
}

/// Why the watch loop returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WatchEnd {
    /// The stop flag was raised.
    Stopped,
    /// The watch itself failed: a new one may be started.
    Lost(WatchFault),
    /// The registry could not be read.
    Failed(WatchFault),
    /// The directory itself is gone.
    RootMissing,
}

/// The registry as the actor last wrote it, `None` when it cannot be had:
/// what the Registry Check's rounds ask for.
pub(crate) type RowsNow<'a> = &'a mut dyn FnMut() -> Option<Vec<SharedFileEntry>>;

/// What the loop asks the actor for: what is known as the actor last wrote
/// it, `None` when it cannot be had.
pub(crate) type KnownNow<'a> = &'a mut dyn FnMut() -> Option<Known>;

/// What the watch loop reaches the world through: the directory, the change
/// notices and clock, the registry as the actor last wrote it, and where
/// registry changes go.
pub(crate) struct WatchSeams<'a> {
    /// The filesystem.
    pub(crate) source: &'a dyn DirectorySource,
    /// The change notices, and the clock.
    pub(crate) watch: &'a mut dyn DirectoryWatch,
    /// What is known now, for each round.
    pub(crate) rows: KnownNow<'a>,
    /// Registry changes.
    pub(crate) report: &'a mut dyn FnMut(ScanReport),
}

/// Watch `root` until `stop` is raised or the watch fails. Blocking; it runs
/// on the scan's worker after the first pass, carrying on the pass's
/// `memory`; `known` is what the pass started from, until the first round
/// asks again.
pub(crate) fn watch_loop(
    seams: WatchSeams<'_>,
    root: &Path,
    known: &Known,
    stop: &AtomicBool,
    progress: &ProgressCell,
    memory: &mut Memory,
) -> WatchEnd {
    let WatchSeams {
        source,
        watch,
        rows,
        report,
    } = seams;
    let Memory {
        whereabouts,
        told,
        turn,
    } = memory;
    let mut settle = Settle::new(root);
    settle.ignore(&known.parts);
    let mut now: Option<Instant> = None;
    loop {
        set_phase(
            progress,
            root,
            ScanPhase::Watching {
                settling: settle.settling(),
            },
        );
        if stop.load(Ordering::Relaxed) {
            return WatchEnd::Stopped;
        }
        let wait = match (settle.next_deadline(), now) {
            (Some(deadline), Some(now)) => deadline.saturating_duration_since(now).min(TICK),
            _ => TICK,
        };
        let batch = watch.wait(wait);
        // The first round looks at the whole directory: whatever changed
        // between the pass's walk and the watch's start, and whatever moved
        // while the pass read it, had no event to queue it.
        if now.is_none() {
            settle.queue_all(batch.now);
        }
        now = Some(batch.now);
        for signal in batch.signals {
            match signal {
                WatchSignal::Moved(path) => settle.queue(path, batch.now),
                WatchSignal::Lost => settle.queue_all(batch.now),
                WatchSignal::PathFailed { path, reason } => {
                    settle.queue(path.clone(), batch.now);
                    told.unwatched_path(path, reason, report);
                }
                WatchSignal::Failed(reason) => return WatchEnd::Lost(reason),
            }
        }
        if stop.load(Ordering::Relaxed) {
            return WatchEnd::Stopped;
        }
        let scopes = settle.due(batch.now);
        if scopes.is_none() && settle.ripe(batch.now).is_empty() && !whereabouts.overdue(batch.now)
        {
            continue;
        }
        let Some(known) = rows() else {
            if stop.load(Ordering::Relaxed) {
                return WatchEnd::Stopped;
            }
            return WatchEnd::Failed(WatchFault::RegistryUnreadable);
        };
        settle.ignore(&known.parts);
        whereabouts.seed(&known.spares, root, &[]);
        let rows = known.rows.as_slice();
        let mut round = Round {
            source,
            root,
            live: rows
                .iter()
                .map(|row| (row.file_hash, row.path.clone()))
                .collect(),
            at_path: rows.iter().map(|row| (row.path.clone(), row)).collect(),
            whereabouts: &mut *whereabouts,
            told: &mut *told,
            report: &mut *report,
            turn,
            root_missing: false,
        };
        let seen: Vec<Seen> = scopes
            .unwrap_or_default()
            .into_iter()
            .filter_map(|scope| round.examine(scope, &known))
            .collect();
        if round.root_missing {
            return WatchEnd::RootMissing;
        }
        // Every scope of the round is examined first, so a rename's new path
        // is carried, or already settling, when its old path's row is found
        // gone.
        let gone = round.rule(seen, &known, &mut settle, batch.now);
        for row in gone {
            round.found_gone(row, &settle, batch.now);
        }
        if round.hash_ripe(&mut settle, batch.now, stop, progress) {
            return WatchEnd::Stopped;
        }
        round.whereabouts.release(
            |size| settle.holds_size(size),
            Some(batch.now),
            source,
            round.report,
        );
    }
}

/// One examined scope, before anything is ruled on: what the plan found
/// changed or gone under it, and what it would read.
struct Seen {
    scope: PathBuf,
    changed: Vec<GoneRow>,
    gone: Vec<GoneRow>,
    hash: Vec<FoundFile>,
}

/// One round's view of the registry and where it reports.
struct Round<'a, 'r> {
    source: &'a dyn DirectorySource,
    root: &'a Path,
    /// Where each shared content lives, kept current through the round.
    live: HashMap<FileHash, PathBuf>,
    /// The rows as the round began, by path.
    at_path: HashMap<PathBuf, &'r SharedFileEntry>,
    whereabouts: &'a mut Whereabouts,
    told: &'a mut Told,
    report: &'a mut dyn FnMut(ScanReport),
    turn: &'a super::HashTurn,
    /// The directory itself was found gone this round.
    root_missing: bool,
}

impl Round<'_, '_> {
    /// Look at `scope` as it is now and diff it against what is known under
    /// it; leftovers are told and spare copies that went are dropped at once.
    /// `None` when the scope cannot be looked at: it is left as it was.
    fn examine(&mut self, scope: PathBuf, known: &Known) -> Option<Seen> {
        // The directory itself is listed, never looked at: a look reports a
        // linked directory as the link, and a listing follows it.
        let kind = if scope == self.root {
            Ok(EntryKind::Directory)
        } else {
            self.source.kind(&scope)
        };
        let walked = match kind {
            Ok(EntryKind::Directory) => match walk(self.source, &scope, known) {
                Ok(walked) => walked,
                Err(_) if scope == self.root && super::missing(self.source, self.root) => {
                    self.root_missing = true;
                    return None;
                }
                Err(error) => return unreadable(&scope, &error),
            },
            Ok(EntryKind::File(stamp)) => Walked {
                found: vec![FoundFile {
                    path: scope.clone(),
                    stamp,
                }],
                ..Walked::default()
            },
            Ok(EntryKind::Symlink | EntryKind::Other) => Walked::default(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Walked::default(),
            Err(error) => return unreadable(&scope, &error),
        };
        self.told.scope_seen(&scope, &walked.found);
        let plan = plan(&scope, walked, known);
        self.told.leftovers(plan.leftovers, self.report);
        super::unreadable(plan.unreadable, self.report);
        for path in plan.spares_left {
            self.whereabouts.forget_spare(&path);
            (self.report)(ScanReport::SpareLeft(path));
        }
        Some(Seen {
            scope,
            changed: plan.changed,
            gone: plan.gone,
            hash: plan.hash,
        })
    }

    /// Rule on the round's scopes together: a file whose identity proves it
    /// is carried, unread; a changed row moves to a spare copy or leaves;
    /// what is left to read settles. The rows found gone are returned.
    fn rule(
        &mut self,
        seen: Vec<Seen>,
        known: &Known,
        settle: &mut Settle,
        now: Instant,
    ) -> Vec<GoneRow> {
        let lost: HashSet<FileHash> = seen
            .iter()
            .flat_map(|seen| seen.changed.iter().chain(&seen.gone))
            .map(|row| row.file_hash)
            .collect();
        let files = seen
            .iter()
            .flat_map(|seen| seen.hash.iter().cloned())
            .collect();
        let (carried, mut still) = carry(self.source, self.root, files, known, &lost);
        let mut moved = HashSet::new();
        for carry in carried {
            if let Carry::Spare(spare) = &carry {
                self.whereabouts.keep(spare.clone());
            }
            if let Some((file_hash, path)) = carry.report(self.report) {
                moved.insert(file_hash);
                self.live.insert(file_hash, path);
            }
        }
        let mut gone = Vec::new();
        for seen in seen {
            for lost in seen.changed {
                if moved.contains(&lost.file_hash) {
                    continue;
                }
                match self.whereabouts.relocate(&lost, self.source, self.report) {
                    Some(path) => self.live.insert(lost.file_hash, path),
                    None => {
                        (self.report)(ScanReport::Unshare(lost.file_hash));
                        self.live.remove(&lost.file_hash)
                    }
                };
            }
            let (under, rest) = still
                .into_iter()
                .partition(|file| file.path.starts_with(&seen.scope));
            still = rest;
            settle.examined(&seen.scope, under, now);
            gone.extend(
                seen.gone
                    .into_iter()
                    .filter(|row| !moved.contains(&row.file_hash)),
            );
        }
        gone
    }

    /// A row whose file is gone moves to its content elsewhere, is held
    /// while a settling file of its size may be it, or leaves.
    fn found_gone(&mut self, row: GoneRow, settle: &Settle, now: Instant) {
        let file_hash = row.file_hash;
        let moved = self.whereabouts.found_gone(
            row,
            self.source,
            |size| settle.holds_size(size),
            Some(now),
            self.report,
        );
        match moved {
            Some(path) => self.live.insert(file_hash, path),
            None => self.live.remove(&file_hash),
        };
    }

    /// Stamp every ripe file again; hash, one at a time, those whose stamp
    /// held. True when the stop flag ended the round.
    fn hash_ripe(
        &mut self,
        settle: &mut Settle,
        now: Instant,
        stop: &AtomicBool,
        progress: &ProgressCell,
    ) -> bool {
        let mut still = Vec::new();
        for file in settle.ripe(now) {
            match self.source.stamp(&file.path) {
                Ok(stamp) if settle.held(&file.path, stamp) => {
                    settle.forget(&file.path);
                    let vouched = self
                        .at_path
                        .get(&file.path)
                        .is_some_and(|row| trusted(row, stamp));
                    if !vouched {
                        still.push(file);
                    }
                }
                Ok(stamp) => settle.settle(file.path, stamp, now),
                Err(error) => {
                    settle.forget(&file.path);
                    if error.kind() != io::ErrorKind::NotFound {
                        self.told.not_hashed(file.path, &error, self.report);
                    }
                }
            }
        }
        let total = still.len();
        for (done, file) in still.into_iter().enumerate() {
            set_phase(
                progress,
                self.root,
                ScanPhase::Hashing {
                    done,
                    total,
                    current: file.path.clone(),
                },
            );
            match hash::hash_file(self.source, &file, stop, self.turn) {
                Ok(Some(entry)) => {
                    self.told.hashed(&file.path);
                    let (hash, path) = (entry.file_hash, entry.path.clone());
                    let seen = (file.stamp, self.source.identity(&path));
                    let shared_at = self.live.get(&hash).map(PathBuf::as_path);
                    if self.whereabouts.hashed(entry, seen, shared_at, self.report) {
                        self.live.insert(hash, path);
                    }
                }
                // Moved while it was read: it settles again from what it is now.
                Ok(None) => {
                    if let Ok(stamp) = self.source.stamp(&file.path) {
                        settle.settle(file.path, stamp, now);
                    }
                }
                Err(_) if stop.load(Ordering::Relaxed) => return true,
                // Gone before it was opened: its row, if any, is ruled on
                // when its path is examined.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => self.told.not_hashed(file.path, &error, self.report),
            }
        }
        false
    }
}

/// A scope that cannot be looked at now is left as it was: a disk that is
/// gone for a moment is not a deletion.
fn unreadable(scope: &Path, error: &io::Error) -> Option<Seen> {
    tracing::warn!(scope = %scope.display(), %error, "could not examine; left as it was");
    None
}

#[cfg(test)]
mod tests;
