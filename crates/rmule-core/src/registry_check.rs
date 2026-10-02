//! The **Registry Check** (ADR-0106, "The registry against the disk"): what
//! rmule offers a peer is readable now, and when it turns out not to be, the
//! row is corrected at that moment. The worker looks at every registry row
//! at start, before anything is offered. It watches the folder of each row
//! outside a live scan's directory, looks at a row whose serve read failed,
//! and every minute looks again at each **Withheld Row**. It reports rulings
//! and never writes: the actor owns the registry, the withheld set and the
//! triggers a change fires. The filesystem, the change notices and the clock
//! come through seams, so the worker runs against a scripted directory
//! without sleeping.

mod look;
mod withheld;

pub(crate) use withheld::WithheldRows;
pub use withheld::{Withheld, WithheldReason};

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use rmule_primitives::FileHash;

use crate::directory_scan::{DirectorySource, RowsNow, WatchBatch, WatchFault, WatchSignal};
use crate::registry::SharedFileEntry;
use look::{Look, look, look_after_failure, look_and_open};

/// How often each withheld row is looked at again.
pub(crate) const RECHECK: Duration = Duration::from_secs(60);

/// The longest the worker waits between looks at its inputs and its stop
/// flag.
const TICK: Duration = Duration::from_millis(250);

/// Changed paths are looked at once no notice has come for this long...
const QUIET: Duration = Duration::from_secs(1);

/// ...or this long after the first, so a steady trickle cannot hold them.
const MAX_DEFER: Duration = Duration::from_secs(5);

/// The seam between the worker and the operating system's change notices over
/// a set of folders, each watched without its subfolders; also the worker's
/// clock. The one adapter over `notify` lives in core's adapters.
pub(crate) trait FolderWatch: Send {
    /// Wait at most `max` for something to move, and say when the wait ended.
    fn wait(&mut self, max: Duration) -> WatchBatch;

    /// Watch exactly `folders`: stop watching the others, start on the new
    /// ones. A folder that is not there is left unwatched without an error;
    /// it is asked for again at the next call.
    ///
    /// # Errors
    /// Why a folder that is there could not be watched.
    fn cover(&mut self, folders: &BTreeSet<PathBuf>) -> Result<(), WatchFault>;
}

/// What the actor and the serve side tell the worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CheckInput {
    /// The registry changed; the worker reads it again before it next needs
    /// it.
    RowsChanged,
    /// The directories live, watched scans own. Rows under them are the
    /// scans' to rule on.
    ScanOwns(BTreeSet<PathBuf>),
    /// A missing shared directory is back: every withheld row is looked at
    /// now, not at the next minute.
    RecheckWithheld,
    /// A serve read of this file failed.
    ReadFailed(FileHash),
}

/// A ruling the worker asks the actor to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CheckReport {
    /// A withheld row is readable again.
    Offer(FileHash),
    /// Nothing is to be offered for this row, for `reason`.
    Withhold {
        /// The row's content.
        file_hash: FileHash,
        /// Why.
        reason: WithheldReason,
    },
    /// The row's file changed: the row leaves, and its hash is not Had.
    Unshare(FileHash),
    /// The row's file is gone from `path`: the row leaves and its hash joins
    /// the Had Set.
    Gone {
        /// The row's content.
        file_hash: FileHash,
        /// Where the row said the file lay.
        path: PathBuf,
    },
    /// Every row has been looked at once; what is not withheld is offered.
    StartLookDone,
    /// The folders could not be watched, for this reason. Said once.
    WatchUnavailable(WatchFault),
}

/// What the worker reaches the world through.
pub(crate) struct CheckSeams<'a> {
    /// The filesystem.
    pub(crate) source: &'a dyn DirectorySource,
    /// The change notices over folders, and the clock.
    pub(crate) watch: &'a mut dyn FolderWatch,
    /// The registry as the actor last wrote it.
    pub(crate) rows: RowsNow<'a>,
    /// What the actor and the serve side tell the worker.
    pub(crate) inputs: &'a Receiver<CheckInput>,
    /// Rulings.
    pub(crate) report: &'a mut dyn FnMut(CheckReport),
}

/// Why a row is being looked at: a row looked at by the start look, or owned
/// by the scan, is withheld when gone or changed but never ruled on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    Start,
    Ruling,
}

/// Run the Registry Check until `stop` is raised or the registry cannot be
/// read. Blocking; it runs on a blocking-pool thread for the core's life.
pub(crate) fn run_check(seams: CheckSeams<'_>, withheld: &WithheldRows, stop: &AtomicBool) {
    let CheckSeams {
        source,
        watch,
        rows: rows_now,
        inputs,
        report,
    } = seams;
    let Some(rows) = rows_now() else {
        return;
    };
    let mut check = Check {
        withheld,
        report,
        rows: index(rows),
        scan_dirs: BTreeSet::new(),
        told: false,
        asked: BTreeSet::new(),
        deferred: HashSet::new(),
    };
    let mut start: Vec<SharedFileEntry> = check.rows.values().cloned().collect();
    start.sort_by(|a, b| a.path.cmp(&b.path));
    for row in &start {
        check.rule(row, look(source, row), Why::Start);
    }
    (check.report)(CheckReport::StartLookDone);
    let mut changed = Changed::default();
    let mut next_recheck: Option<Instant> = None;
    let mut stale_since: Option<Instant> = None;
    let mut recover = true;
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let batch = watch.wait(TICK);
        let now = batch.now;
        let recheck_due = *next_recheck.get_or_insert(now + RECHECK);
        let mut failed = Vec::new();
        while let Ok(input) = inputs.try_recv() {
            match input {
                CheckInput::RowsChanged => {
                    stale_since.get_or_insert(now);
                }
                CheckInput::ScanOwns(dirs) => {
                    check.scan_dirs = dirs;
                    recover = true;
                }
                CheckInput::RecheckWithheld => next_recheck = Some(now),
                CheckInput::ReadFailed(file_hash) => failed.push(file_hash),
            }
        }
        for signal in batch.signals {
            match signal {
                // The folder watch reports no path failures of its own; one is
                // looked at like a change.
                WatchSignal::Moved(path) | WatchSignal::PathFailed { path, .. } => {
                    changed.queue(path, now);
                }
                WatchSignal::Lost => changed.queue_all(now),
                WatchSignal::Failed(reason) => check.unwatched(reason),
            }
        }
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let unknown = failed.iter().any(|hash| !check.rows.contains_key(hash));
        if unknown || stale_since.is_some_and(|since| now.duration_since(since) >= QUIET) {
            let Some(rows) = rows_now() else {
                return;
            };
            check.rows = index(rows);
            stale_since = None;
            recover = true;
        }
        let recheck = now >= recheck_due;
        if recover || recheck {
            recover = false;
            // A folder watched only now may change before its watch is live,
            // with no notice to say so: it is looked at as if one had come,
            // a burst's quiet from now.
            for folder in check.cover(watch) {
                changed.queue(folder, now);
            }
        }
        for file_hash in failed {
            if let Some(row) = check.rows.get(&file_hash).cloned() {
                check.rule(&row, look_after_failure(source, &row), Why::Ruling);
            }
        }
        if let Some(scopes) = changed.due(now) {
            for row in check.under(&scopes) {
                let look = check.look(source, &row);
                check.rule(&row, look, Why::Ruling);
            }
        }
        if recheck {
            next_recheck = Some(now + RECHECK);
            check.deferred.clear();
            for file_hash in withheld.hashes() {
                if let Some(row) = check.rows.get(&file_hash).cloned() {
                    check.rule(&row, look_and_open(source, &row), Why::Ruling);
                }
            }
        }
    }
}

fn index(rows: Vec<SharedFileEntry>) -> HashMap<FileHash, SharedFileEntry> {
    rows.into_iter().map(|row| (row.file_hash, row)).collect()
}

/// The worker's view: the rows, the scan's directory, and where rulings go.
struct Check<'a> {
    withheld: &'a WithheldRows,
    report: &'a mut dyn FnMut(CheckReport),
    rows: HashMap<FileHash, SharedFileEntry>,
    scan_dirs: BTreeSet<PathBuf>,
    /// The operator was told the folders cannot be watched.
    told: bool,
    /// The folders last asked of the watch.
    asked: BTreeSet<PathBuf>,
    /// Rows the start look found gone or changed: a scan started in the
    /// first minute may claim them, so they are ruled on at the first
    /// recheck.
    deferred: HashSet<FileHash>,
}

impl Check<'_> {
    /// Look at `row`, opening it when it is withheld: a **Withheld Row** is
    /// offered again only once its file opens, whichever look finds it back.
    fn look(&self, source: &dyn DirectorySource, row: &SharedFileEntry) -> Look {
        if self.withheld.get(row.file_hash).is_some() {
            look_and_open(source, row)
        } else {
            look(source, row)
        }
    }

    fn scan_owns(&self, path: &Path) -> bool {
        self.scan_dirs.iter().any(|dir| path.starts_with(dir))
    }

    /// Rule on `row` from what `look` found.
    fn rule(&mut self, row: &SharedFileEntry, look: Look, why: Why) {
        let file_hash = row.file_hash;
        let defer =
            why == Why::Start || self.scan_owns(&row.path) || self.deferred.contains(&file_hash);
        if why == Why::Start && matches!(look, Look::Gone | Look::Changed) {
            self.deferred.insert(file_hash);
        }
        let ruling = match look {
            Look::Readable => self
                .withheld
                .get(file_hash)
                .is_some()
                .then_some(CheckReport::Offer(file_hash)),
            Look::Gone if defer => self.withhold(file_hash, WithheldReason::Missing),
            Look::Gone => Some(CheckReport::Gone {
                file_hash,
                path: row.path.clone(),
            }),
            Look::Changed if defer => self.withhold(file_hash, WithheldReason::Changed),
            Look::Changed => Some(CheckReport::Unshare(file_hash)),
            Look::FolderMissing => self.withhold(file_hash, WithheldReason::FolderMissing),
            Look::Unreadable(reason) => {
                self.withhold(file_hash, WithheldReason::Unreadable(reason))
            }
        };
        if let Some(ruling) = ruling {
            (self.report)(ruling);
        }
    }

    /// A withhold, unless the row is already withheld for that reason.
    fn withhold(&self, file_hash: FileHash, reason: WithheldReason) -> Option<CheckReport> {
        let same = self
            .withheld
            .get(file_hash)
            .is_some_and(|held| held.reason == reason);
        (!same).then_some(CheckReport::Withhold { file_hash, reason })
    }

    /// The rows the check rules on whose file lies in, or is, one of
    /// `scopes`; every such row for a lost-notice scope (`None`).
    fn under(&self, scopes: &Scopes) -> Vec<SharedFileEntry> {
        let mut rows: Vec<SharedFileEntry> = self
            .rows
            .values()
            .filter(|row| !self.scan_owns(&row.path))
            .filter(|row| match scopes {
                Scopes::All => true,
                Scopes::Paths(paths) => {
                    paths.contains(&row.path)
                        || row.path.parent().is_some_and(|dir| paths.contains(dir))
                }
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.path.cmp(&b.path));
        rows
    }

    /// Watch the folder of every row the check rules on; the folders asked
    /// for now that were not asked for before are returned.
    fn cover(&mut self, watch: &mut dyn FolderWatch) -> BTreeSet<PathBuf> {
        let folders: BTreeSet<PathBuf> = self
            .rows
            .values()
            .filter(|row| !self.scan_owns(&row.path))
            .filter_map(|row| row.path.parent().map(Path::to_path_buf))
            .collect();
        if let Err(reason) = watch.cover(&folders) {
            self.unwatched(reason);
        }
        let new = folders.difference(&self.asked).cloned().collect();
        self.asked = folders;
        new
    }

    fn unwatched(&mut self, reason: WatchFault) {
        if !self.told {
            self.told = true;
            tracing::warn!(
                ?reason,
                "shared files outside the download directory not watched"
            );
            (self.report)(CheckReport::WatchUnavailable(reason));
        }
    }
}

/// What changed paths call for.
enum Scopes {
    /// A notice was lost: every row.
    All,
    /// These paths.
    Paths(BTreeSet<PathBuf>),
}

/// Changed paths waiting to be looked at together.
#[derive(Default)]
struct Changed {
    paths: BTreeSet<PathBuf>,
    all: bool,
    first: Option<Instant>,
    last: Option<Instant>,
}

impl Changed {
    fn queue(&mut self, path: PathBuf, now: Instant) {
        self.paths.insert(path);
        self.first.get_or_insert(now);
        self.last = Some(now);
    }

    fn queue_all(&mut self, now: Instant) {
        self.all = true;
        self.first.get_or_insert(now);
        self.last = Some(now);
    }

    /// The queued scopes, once the burst is over.
    fn due(&mut self, now: Instant) -> Option<Scopes> {
        let (first, last) = (self.first?, self.last?);
        if now.saturating_duration_since(last) < QUIET
            && now.saturating_duration_since(first) < MAX_DEFER
        {
            return None;
        }
        self.first = None;
        self.last = None;
        let paths = std::mem::take(&mut self.paths);
        Some(if std::mem::take(&mut self.all) {
            Scopes::All
        } else {
            Scopes::Paths(paths)
        })
    }
}

#[cfg(test)]
mod tests;
