//! The **Download Directory Scan**'s one pass (ADR-0102): walk the download
//! directory, keep every registry row the **Hash Trust Rule** vouches for
//! unread, and hash what is new or changed, one file at a time and in name
//! order. The pass decides; it touches the filesystem only through
//! [`DirectorySource`], so the walk, the trust rule and the disclosure guard
//! are tested against a scripted directory and only [`FsDirectorySource`]
//! knows the real one. It reports each registry change instead of writing it:
//! the actor owns the registry and the triggers a share fires. After the
//! pass the same worker watches the directory ([`watch`]) until it is stopped.

mod carry;
mod fs;
mod hash;
pub(crate) mod plan;
mod progress;
mod report;
#[cfg(test)]
pub(crate) mod scripted;
mod shared_directories;
mod source;
mod watch;
mod whereabouts;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rmule_primitives::FileHash;

use crate::registry::SharedFileEntry;

pub use fs::FsDirectorySource;
pub(crate) use hash::HashTurn;
use plan::{FoundFile, plan, walk};
pub use progress::{
    DirectoryOffer, DirectoryRole, DirectoryScanDiagnostics, DirectoryState, ScanPhase,
    ScanSummary, SharedDirectoryDiagnostics,
};
pub(crate) use progress::{InstalledDirectory, InstalledState};
pub(crate) use report::{PassEnd, ScanReport};
pub use shared_directories::{DirectoryRefusal, ShareGuards};
pub(crate) use shared_directories::{
    RefusedFolders, admit, canonical, covering, guard_in_place, guard_temp_dir,
};
pub use source::{DirEntry, DirectorySource, EntryKind, FileIdentity, FileStamp};
pub use watch::WatchFault;
pub(crate) use watch::{
    DirectoryWatch, KnownNow, RowsNow, WatchBatch, WatchEnd, WatchSignal, WatchStarter,
};
pub(crate) use whereabouts::Whereabouts;

/// A file under the directory whose content is already shared from another
/// path: the **Spare Copy** (ADR-0104, "Spare copies are recorded"). Trusted
/// unread while its stamp holds, it shares nothing and answers nothing on
/// the wire; a row whose file goes moves to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpareCopy {
    /// Where the copy lies.
    pub(crate) path: PathBuf,
    /// Its content, shared from the registry row's path.
    pub(crate) file_hash: FileHash,
    /// Its size and modification time when it was recorded.
    pub(crate) stamp: FileStamp,
    /// Its identity when it was recorded, if its filesystem gives one.
    pub(crate) identity: Option<FileIdentity>,
}

/// A **Set-Aside Row** (ADR-0101, "Shared Directories"): a row a removed
/// directory took out of the registry, or a spare copy under it, kept by its
/// path. A pass that finds the same path, size and modification time shares
/// `entry` instead of reading the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SetAside {
    /// The entry to share, its stamp the one the row was set aside with.
    pub(crate) entry: SharedFileEntry,
    /// Its identity when it was set aside, if its filesystem gives one.
    pub(crate) identity: Option<FileIdentity>,
}

/// The part files rmule's own downloads name (ADR-0100, "Part files are known
/// by their download rows"): the scan skips these paths, and no others, as
/// rmule's own work. A file that merely ends `.part` is not among them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PartFiles {
    /// The part paths of queued, active, completing, paused and failed
    /// downloads, and a completing one's destination (ADR-0115): work in
    /// progress, skipped silently, and a registry row standing on one is left
    /// as it is.
    pub(crate) live: HashSet<PathBuf>,
    /// The part paths of cancelled and completed downloads: a file still
    /// there is a leftover, skipped, and the operator is told.
    pub(crate) left: HashSet<PathBuf>,
}

impl PartFiles {
    /// Sort each download's part path by whether its download is live.
    pub(crate) fn of(paths: impl IntoIterator<Item = (PathBuf, bool)>) -> Self {
        let mut parts = Self::default();
        for (path, live) in paths {
            if live {
                parts.live.insert(path);
            } else {
                parts.left.insert(path);
            }
        }
        // A path a live download writes is its work, whatever an older row
        // said about it.
        parts.left.retain(|path| !parts.live.contains(path));
        parts
    }
}

/// What the scan may know about the files under the directory without
/// reading them, as the actor last wrote it: read once for the pass and
/// again for every round of the watch (ADR-0102, "What the scan knows").
#[derive(Clone, Debug, Default)]
pub(crate) struct Known {
    /// The **Shared File Registry**.
    pub(crate) rows: Vec<SharedFileEntry>,
    /// rmule's own part files.
    pub(crate) parts: PartFiles,
    /// The recorded spare copies.
    pub(crate) spares: Vec<SpareCopy>,
    /// Each row's recorded **File Identity**, by content.
    pub(crate) identities: HashMap<FileHash, FileIdentity>,
    /// The **Set-Aside Rows**, by path.
    pub(crate) set_aside: HashMap<PathBuf, SetAside>,
}

/// What one scan remembers across its pass and every round of its watch:
/// where shared content lies while a row is found gone, and what the operator
/// has already been told; and the hashing turn it shares with every other
/// scan.
#[derive(Debug, Default)]
pub(crate) struct Memory {
    /// Held rows and spare copies.
    pub(crate) whereabouts: Whereabouts,
    /// Facts told once per scan.
    pub(crate) told: Told,
    /// The one turn to read a file, shared by every scan of the core.
    pub(crate) turn: HashTurn,
}

/// What the operator has been told during one scan, so each fact is told
/// once rather than at every round.
#[derive(Debug, Default)]
pub(crate) struct Told {
    leftovers: HashSet<PathBuf>,
    /// Paths the running watch does not cover; forgotten when a new watch
    /// starts, which covers them again.
    unwatched: HashSet<PathBuf>,
    /// Files the watch could not read; each forgotten once it is hashed or
    /// found gone.
    not_hashed: HashSet<PathBuf>,
}

impl Told {
    /// The leftover part files among `found` not told before; all of `found`
    /// is told from now on. One that is no longer there may be told again if
    /// it comes back.
    fn leftovers(&mut self, found: Vec<PathBuf>, report: &mut dyn FnMut(ScanReport)) {
        let fresh: Vec<PathBuf> = found
            .into_iter()
            .filter(|path| self.leftovers.insert(path.clone()))
            .collect();
        if !fresh.is_empty() {
            report(ScanReport::LeftoverParts(fresh));
        }
    }

    /// The watch could not read the file at `path`: said once until it is
    /// hashed.
    fn not_hashed(&mut self, path: PathBuf, error: &io::Error, report: &mut dyn FnMut(ScanReport)) {
        if self.not_hashed.insert(path.clone()) {
            tracing::warn!(path = %path.display(), %error, "could not read; not shared");
            report(ScanReport::NotHashed {
                path,
                kind: error.kind(),
                os_code: error.raw_os_error(),
            });
        }
    }

    /// The file at `path` was hashed: a later failure to read it is told
    /// again.
    fn hashed(&mut self, path: &Path) {
        self.not_hashed.remove(path);
    }

    /// `scope` was looked at and `present` are the files found under it: a
    /// file told unreadable there that is no longer among them is gone, so
    /// the same path failing after it is recreated is told again.
    fn scope_seen(&mut self, scope: &Path, present: &[FoundFile]) {
        self.not_hashed.retain(|path| {
            !path.starts_with(scope) || present.iter().any(|file| file.path == *path)
        });
    }

    /// The watch does not cover `path`: said once while this watch lives.
    fn unwatched_path(
        &mut self,
        path: PathBuf,
        reason: WatchFault,
        report: &mut dyn FnMut(ScanReport),
    ) {
        if self.unwatched.insert(path.clone()) {
            tracing::warn!(path = %path.display(), ?reason, "not watched; the rest of the directory is");
            report(ScanReport::PathUnwatched { path, reason });
        }
    }
}

/// The operator's question: what the directory would offer. Blocks until
/// the answer, true to share.
pub(crate) type Ask = Box<dyn FnOnce(DirectoryOffer) -> bool + Send>;

/// The disclosure guard's state for this directory when the pass starts.
pub(crate) enum Consent {
    /// The operator said yes before, or the Settings warning was confirmed.
    Given,
    /// Never asked: if the pass would hash anything, the question is asked
    /// and the pass waits for the answer.
    Ask(Ask),
    /// A directory the operator is adding: the question is asked whatever
    /// the pass would read, since nothing under it was ever disclosed.
    Confirm(Ask),
}

/// The progress level the ledger owns and the worker writes.
pub(crate) type ProgressCell = Arc<Mutex<Option<DirectoryScanDiagnostics>>>;

fn set_phase(progress: &ProgressCell, root: &Path, phase: ScanPhase) {
    *progress.lock().expect("scan progress") = Some(DirectoryScanDiagnostics {
        dir: root.to_path_buf(),
        phase,
    });
}

/// How a scan's worker ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScanEnd {
    /// The operator declined; nothing moved.
    Declined,
    /// The directory itself could not be listed; nothing moved.
    Unlistable,
    /// The stop flag was raised; what was reported before it stands.
    Stopped,
    /// The first pass finished but the watch could not start or failed; the
    /// activity stays, unwatched.
    Unwatched(WatchFault),
}

/// What the worker reaches the world through, besides the flag and the
/// progress level: the directory, a way to start a watch, the registry as
/// the actor last wrote it, where registry changes go, and the hashing turn.
pub(crate) struct ScanSeams<'a> {
    /// The filesystem.
    pub(crate) source: &'a dyn DirectorySource,
    /// Start watching a directory, or say why not; the clock of an outage.
    pub(crate) watcher: &'a mut dyn WatchStarter,
    /// What is known now, for each watch round.
    pub(crate) rows: KnownNow<'a>,
    /// Registry changes, and the first pass's end.
    pub(crate) report: &'a mut dyn FnMut(ScanReport),
    /// The one turn to read a file, shared by every scan of the core.
    pub(crate) turn: HashTurn,
    /// How long a missing directory waits between looks for its return.
    pub(crate) missing_look: Duration,
}

/// The scan's worker: one pass over `root` against `known`, then, if it
/// finished, the watch until `stop` is raised. A directory that is not there
/// is waited for, at start or when it goes while watched, and passed over
/// afresh when it is back (ADR-0101, "Shared Directories"). Blocking.
pub(crate) fn run_scan(
    seams: ScanSeams<'_>,
    root: &Path,
    known: &Known,
    consent: Consent,
    stop: &AtomicBool,
    progress: &ProgressCell,
) -> ScanEnd {
    let ScanSeams {
        source,
        watcher,
        rows: rows_now,
        report,
        turn,
        missing_look,
    } = seams;
    let mut known = known.clone();
    let mut consent = Some(consent);
    loop {
        if missing(source, root) {
            if !await_return(source, watcher, root, missing_look, stop, progress, report) {
                return ScanEnd::Stopped;
            }
            match rows_now() {
                Some(now) => known = now,
                None => return ScanEnd::Stopped,
            }
        }
        let mut memory = Memory {
            turn: turn.clone(),
            ..Memory::default()
        };
        let summary = match run_pass(
            source,
            root,
            &known,
            consent.take().unwrap_or(Consent::Given),
            stop,
            progress,
            &mut memory,
            report,
        ) {
            PassEnd::Finished(summary) => summary,
            PassEnd::Declined => return ScanEnd::Declined,
            PassEnd::Unlistable if missing(source, root) => continue,
            PassEnd::Unlistable => return ScanEnd::Unlistable,
            PassEnd::Stopped => return ScanEnd::Stopped,
        };
        // The operating system's watch start can take seconds; the pass's
        // report never waits on it. What changes before the watch holds is
        // not lost: the watch's first round examines the whole directory.
        set_phase(progress, root, ScanPhase::StartingWatch);
        report(ScanReport::Finished(summary));
        let mut watch = match watcher.start(root) {
            Ok(watch) => watch,
            Err(_) if missing(source, root) => continue,
            Err(reason) => return unwatched(root, reason, progress),
        };
        set_phase(progress, root, ScanPhase::Watching { settling: 0 });
        loop {
            let seams = watch::WatchSeams {
                source,
                watch: &mut *watch,
                rows: &mut *rows_now,
                report: &mut *report,
            };
            let lost = match watch::watch_loop(seams, root, &known, stop, progress, &mut memory) {
                WatchEnd::Stopped => return ScanEnd::Stopped,
                WatchEnd::Failed(reason) => return unwatched(root, reason, progress),
                WatchEnd::RootMissing => break,
                WatchEnd::Lost(_) if missing(source, root) => break,
                WatchEnd::Lost(reason) => reason,
            };
            drop(watch);
            watch = match watch::rewatch(watcher, root, lost, stop, progress, report) {
                watch::Rewatch::Back(watch) => watch,
                watch::Rewatch::Stopped => return ScanEnd::Stopped,
                watch::Rewatch::GaveUp(reason) => return unwatched(root, reason, progress),
            };
            memory.told.unwatched.clear();
        }
    }
}

/// Whether the directory itself is not there: nothing at its path, or
/// something that is not a directory. A path that cannot be looked at for
/// another reason is not missing; its listing says why.
fn missing(source: &dyn DirectorySource, root: &Path) -> bool {
    match source.is_folder(root) {
        Ok(folder) => !folder,
        Err(error) => error.kind() == io::ErrorKind::NotFound,
    }
}

/// The directory is missing: say so, then look for it every `look` until
/// it is back (true) or the stop flag is raised.
fn await_return(
    source: &dyn DirectorySource,
    watcher: &mut dyn WatchStarter,
    root: &Path,
    look: Duration,
    stop: &AtomicBool,
    progress: &ProgressCell,
    report: &mut dyn FnMut(ScanReport),
) -> bool {
    let since = SystemTime::now();
    tracing::warn!(dir = %root.display(), "shared directory missing; its files are withheld");
    report(ScanReport::RootMissing { since });
    set_phase(progress, root, ScanPhase::Missing { since });
    loop {
        if !watch::pause(watcher, look, stop) {
            return false;
        }
        if !missing(source, root) {
            tracing::info!(dir = %root.display(), "shared directory back");
            report(ScanReport::RootReturned);
            return true;
        }
    }
}

/// The scan goes on unwatched, for `reason`: what it found holds.
fn unwatched(root: &Path, reason: WatchFault, progress: &ProgressCell) -> ScanEnd {
    tracing::warn!(dir = %root.display(), ?reason, "download directory not watched");
    set_phase(progress, root, ScanPhase::Unwatched { reason });
    ScanEnd::Unwatched(reason)
}

/// Run one pass over `root` against the registry rows `rows`. Blocking: it
/// runs on a blocking-pool thread, reads one file at a time, and returns
/// within one read of `stop` being raised. A row found gone is held while a
/// file of its size waits to be hashed, and leaves once the pass has hashed
/// its files unless one of them was its content (`whereabouts`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_pass(
    source: &dyn DirectorySource,
    root: &Path,
    known: &Known,
    consent: Consent,
    stop: &AtomicBool,
    progress: &ProgressCell,
    memory: &mut Memory,
    report: &mut dyn FnMut(ScanReport),
) -> PassEnd {
    let Memory {
        whereabouts,
        told,
        turn,
    } = memory;
    let set_phase = |phase: ScanPhase| set_phase(progress, root, phase);
    set_phase(ScanPhase::Walking);
    let Ok(walked) = walk(source, root, known) else {
        return PassEnd::Unlistable;
    };
    let rows = known.rows.as_slice();
    let plan = plan(root, walked, known);
    let lost: HashSet<FileHash> = plan
        .changed
        .iter()
        .chain(&plan.gone)
        .map(|row| row.file_hash)
        .collect();
    let (carried, to_hash) = carry::carry(source, root, plan.hash, known, &lost);
    let ask = match consent {
        Consent::Ask(ask) if !to_hash.is_empty() => Some(ask),
        Consent::Confirm(ask) => Some(ask),
        Consent::Given | Consent::Ask(_) => None,
    };
    if let Some(ask) = ask {
        let offer = offer(root, known, &lost, carried.len(), &to_hash);
        set_phase(ScanPhase::AwaitingConsent { offer });
        if !ask(offer) {
            return PassEnd::Declined;
        }
    }
    if stop.load(Ordering::Relaxed) {
        return PassEnd::Stopped;
    }
    told.leftovers(plan.leftovers, report);
    unreadable(plan.unreadable, report);
    whereabouts.seed(&known.spares, root, &plan.spares_left);
    for path in plan.spares_left {
        report(ScanReport::SpareLeft(path));
    }
    let carried_count = carried.len();
    let mut moved: HashMap<FileHash, PathBuf> = HashMap::new();
    for carry in carried {
        if let carry::Carry::Spare(spare) = &carry {
            whereabouts.keep(spare.clone());
        }
        moved.extend(carry.report(report));
    }
    identify(source, plan.unidentified, report);
    // Rows outside the directory are the Registry Check's.
    let gone = plan.gone;
    let mut summary = ScanSummary {
        trusted: plan.trusted,
        carried: carried_count,
        dropped: plan.changed.len() + gone.len() - moved.len(),
        ..ScanSummary::default()
    };
    // Where each shared content lives now, so a second copy of it never
    // moves the row: rows the pass keeps, plus what it shares as it goes.
    let mut live: HashMap<FileHash, PathBuf> = rows
        .iter()
        .filter(|row| {
            !plan
                .changed
                .iter()
                .any(|lost| lost.file_hash == row.file_hash)
                && !gone.iter().any(|gone| gone.file_hash == row.file_hash)
        })
        .map(|row| (row.file_hash, row.path.clone()))
        .chain(moved.clone())
        .collect();
    // A changed row's content may still lie at a spare copy: the row moves
    // there rather than leaving.
    for lost in plan
        .changed
        .into_iter()
        .filter(|row| !moved.contains_key(&row.file_hash))
    {
        match whereabouts.relocate(&lost, source, report) {
            Some(path) => {
                live.insert(lost.file_hash, path);
            }
            None => report(ScanReport::Unshare(lost.file_hash)),
        }
    }
    // A rename keeps the size: a gone row waits for the files of its size.
    let sizes: Vec<u64> = to_hash.iter().map(|file| file.stamp.size).collect();
    for row in gone
        .into_iter()
        .filter(|row| !moved.contains_key(&row.file_hash))
    {
        let file_hash = row.file_hash;
        if let Some(path) =
            whereabouts.found_gone(row, source, |size| sizes.contains(&size), None, report)
        {
            live.insert(file_hash, path);
        }
    }
    let total = to_hash.len();
    for (done, file) in to_hash.into_iter().enumerate() {
        set_phase(ScanPhase::Hashing {
            done,
            total,
            current: file.path.clone(),
        });
        let aside = set_aside(known, &file, report);
        let hashed = match aside {
            Some(aside) => Ok(Some(aside.entry.clone())),
            None => hash::hash_file(source, &file, stop, turn),
        };
        match hashed {
            Ok(Some(entry)) => {
                let (hash, path) = (entry.file_hash, entry.path.clone());
                let identity = aside
                    .and_then(|aside| aside.identity)
                    .or_else(|| source.identity(&path));
                let seen = (file.stamp, identity);
                if whereabouts.hashed(entry, seen, live.get(&hash).map(PathBuf::as_path), report) {
                    live.insert(hash, path);
                    // A set-aside row is kept unread, as a trusted one is.
                    if aside.is_some() {
                        summary.trusted += 1;
                    } else {
                        summary.hashed += 1;
                    }
                } else {
                    summary.skipped += 1;
                }
            }
            Ok(None) => summary.skipped += 1,
            Err(_) if stop.load(Ordering::Relaxed) => return PassEnd::Stopped,
            Err(error) => {
                told.not_hashed(file.path, &error, report);
                summary.unreadable += 1;
            }
        }
    }
    // Every file of a held row's size is hashed: what is still held is gone.
    whereabouts.release(|_| false, None, source, report);
    PassEnd::Finished(summary)
}

/// What the directory would offer, for the operator's question: every row
/// the trust rule keeps under it, every file carried, and every file to
/// read, with the files that need no read counted apart.
fn offer(
    root: &Path,
    known: &Known,
    lost: &HashSet<FileHash>,
    carried: usize,
    to_hash: &[FoundFile],
) -> DirectoryOffer {
    let kept: Vec<&SharedFileEntry> = known
        .rows
        .iter()
        .filter(|row| row.path.starts_with(root) && !lost.contains(&row.file_hash))
        .collect();
    let aside = to_hash
        .iter()
        .filter(|file| {
            known
                .set_aside
                .get(&file.path)
                .is_some_and(|aside| holds(aside, file))
        })
        .count();
    DirectoryOffer {
        files: kept.len() + carried + to_hash.len(),
        bytes: kept.iter().map(|row| row.file_size).sum::<u64>()
            + to_hash.iter().map(|file| file.stamp.size).sum::<u64>(),
        unread: kept.len() + carried + aside,
    }
}

/// Whether the set-aside row still describes the file found at its path.
fn holds(aside: &SetAside, file: &FoundFile) -> bool {
    aside.entry.file_size == file.stamp.size && aside.entry.modified == Some(file.stamp.modified)
}

/// The **Set-Aside Row** at `file`'s path, when it still describes the file:
/// its entry is shared unread. One that no longer does is dropped.
fn set_aside<'k>(
    known: &'k Known,
    file: &FoundFile,
    report: &mut dyn FnMut(ScanReport),
) -> Option<&'k SetAside> {
    let aside = known.set_aside.get(&file.path)?;
    if holds(aside, file) {
        Some(aside)
    } else {
        report(ScanReport::SetAsideLeft(file.path.clone()));
        None
    }
}

/// Withhold each row the walk could not look at.
fn unreadable(rows: Vec<(FileHash, PathBuf, io::ErrorKind)>, report: &mut dyn FnMut(ScanReport)) {
    for (file_hash, path, kind) in rows {
        report(ScanReport::Unreadable {
            file_hash,
            path,
            kind,
        });
    }
}

/// Record the identity of each trusted row's file that has none yet, where
/// its filesystem gives one: one more metadata read per such row, once.
fn identify(
    source: &dyn DirectorySource,
    unidentified: Vec<(FileHash, PathBuf)>,
    report: &mut dyn FnMut(ScanReport),
) {
    for (file_hash, path) in unidentified {
        if let Some(identity) = source.identity(&path) {
            report(ScanReport::Identified {
                file_hash,
                path,
                identity,
            });
        }
    }
}

/// Whether the file at `path` is gone: it is not there but its directory is.
/// A directory that is not there either may be an unmounted volume, which is
/// not a deletion. `UnshareFile` asks it of the row it removes.
pub(crate) fn file_gone(source: &dyn DirectorySource, path: &Path) -> bool {
    let missing =
        matches!(source.kind(path), Err(error) if error.kind() == io::ErrorKind::NotFound);
    missing
        && path
            .parent()
            .is_some_and(|dir| matches!(source.is_folder(dir), Ok(true)))
}

#[cfg(test)]
mod tests;
