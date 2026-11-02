//! The watch's bookkeeping, with no I/O and no clock of its own: which paths
//! wait to be examined, when a burst of them is examined together, and which
//! files are settling toward the five seconds of stillness that make them
//! worth hashing (ADR-0103, "The watch"). Every instant is handed in.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::plan::{FoundFile, skipped_name};
use super::super::{FileStamp, PartFiles};

/// How long a file's size and modification time must hold before it is hashed.
pub(super) const STILLNESS: Duration = Duration::from_secs(5);

/// Queued paths are examined once no event has come for this long...
pub(super) const QUIET: Duration = Duration::from_secs(1);

/// ...or this long after the first of them, so a steady trickle of events
/// cannot hold the queue for ever.
pub(super) const MAX_DEFER: Duration = Duration::from_secs(5);

/// A file seen with a stamp the plan would hash, waiting to hold still.
#[derive(Clone, Copy, Debug)]
struct Settling {
    stamp: FileStamp,
    since: Instant,
}

/// The queue and the settling files of one watched directory.
#[derive(Debug)]
pub(super) struct Settle {
    root: PathBuf,
    queued: BTreeSet<PathBuf>,
    first_queued: Option<Instant>,
    last_queued: Option<Instant>,
    settling: BTreeMap<PathBuf, Settling>,
    /// rmule's own part files, as last known: a download writing its part
    /// file costs the queue nothing.
    ignored: HashSet<PathBuf>,
}

impl Settle {
    pub(super) fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            queued: BTreeSet::new(),
            first_queued: None,
            last_queued: None,
            settling: BTreeMap::new(),
            ignored: HashSet::new(),
        }
    }

    /// From now on, events for these part files are dropped at the queue,
    /// and one that is settling stops: a completing download's destination
    /// found by a round that read what was known before the download stored
    /// it is the download's own from the round that knows it (ADR-0115).
    pub(super) fn ignore(&mut self, parts: &PartFiles) {
        self.ignored = parts.live.union(&parts.left).cloned().collect();
        self.settling.retain(|path, _| !self.ignored.contains(path));
    }

    /// Something at `path` moved. A path outside the directory, one whose
    /// name the walk skips, or one of rmule's own part files is dropped here
    /// and costs nothing.
    pub(super) fn queue(&mut self, path: PathBuf, now: Instant) {
        let Ok(relative) = path.strip_prefix(&self.root) else {
            return;
        };
        if self.ignored.contains(&path) {
            return;
        }
        if relative
            .components()
            .any(|part| skipped_name(part.as_os_str()))
        {
            return;
        }
        self.queued.insert(path);
        self.first_queued.get_or_insert(now);
        self.last_queued = Some(now);
    }

    /// Events were lost: the whole directory is examined.
    pub(super) fn queue_all(&mut self, now: Instant) {
        self.queue(self.root.clone(), now);
    }

    /// The queued paths, if the burst is over, as the fewest scopes that cover
    /// them: a path under another queued path is dropped.
    pub(super) fn due(&mut self, now: Instant) -> Option<Vec<PathBuf>> {
        let (first, last) = (self.first_queued?, self.last_queued?);
        if now.saturating_duration_since(last) < QUIET
            && now.saturating_duration_since(first) < MAX_DEFER
        {
            return None;
        }
        self.first_queued = None;
        self.last_queued = None;
        let mut scopes: Vec<PathBuf> = Vec::new();
        // Sorted, so an ancestor comes before everything under it.
        for path in std::mem::take(&mut self.queued) {
            if !scopes.last().is_some_and(|scope| path.starts_with(scope)) {
                scopes.push(path);
            }
        }
        Some(scopes)
    }

    /// `scope` was examined and `hash` is what the plan would hash under it.
    /// A settling file under `scope` that is not among them is forgotten; one
    /// seen again with its stamp unchanged keeps its clock; anything new or
    /// changed starts settling now.
    pub(super) fn examined(&mut self, scope: &Path, hash: Vec<FoundFile>, now: Instant) {
        let found: BTreeMap<PathBuf, FileStamp> = hash
            .into_iter()
            .map(|file| (file.path, file.stamp))
            .collect();
        self.settling
            .retain(|path, _| !path.starts_with(scope) || found.contains_key(path));
        for (path, stamp) in found {
            self.settle(path, stamp, now);
        }
    }

    /// `path` read `stamp` at `now`: its clock runs on if the stamp held,
    /// and starts over if it did not.
    pub(super) fn settle(&mut self, path: PathBuf, stamp: FileStamp, now: Instant) {
        let entry = self
            .settling
            .entry(path)
            .or_insert(Settling { stamp, since: now });
        if entry.stamp != stamp {
            *entry = Settling { stamp, since: now };
        }
    }

    /// Stop settling `path`: hashed, gone, or no longer the scan's to hash.
    pub(super) fn forget(&mut self, path: &Path) {
        self.settling.remove(path);
    }

    /// The settling files whose stamp has been seen unchanged for the full
    /// stillness, with that stamp. Each is to be stamped again before it is
    /// believed.
    pub(super) fn ripe(&self, now: Instant) -> Vec<FoundFile> {
        self.settling
            .iter()
            .filter(|(_, settling)| now.saturating_duration_since(settling.since) >= STILLNESS)
            .map(|(path, settling)| FoundFile {
                path: path.clone(),
                stamp: settling.stamp,
            })
            .collect()
    }

    /// Whether `path`'s stamp was re-read unchanged just now: the stamp it
    /// settled with holds, so it may be hashed.
    pub(super) fn held(&self, path: &Path, stamp: FileStamp) -> bool {
        self.settling
            .get(path)
            .is_some_and(|settling| settling.stamp == stamp)
    }

    /// The next instant something falls due: the queue's burst ending, or a
    /// settling file ripening.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        let queue = self
            .first_queued
            .zip(self.last_queued)
            .map(|(first, last)| (last + QUIET).min(first + MAX_DEFER));
        let ripe = self
            .settling
            .values()
            .map(|settling| settling.since + STILLNESS)
            .min();
        queue.into_iter().chain(ripe).min()
    }

    /// How many files are waiting to hold still.
    pub(super) fn settling(&self) -> usize {
        self.settling.len()
    }

    /// Whether a file of `size` is waiting to hold still — a candidate for a
    /// renamed row's new path.
    pub(super) fn holds_size(&self, size: u64) -> bool {
        self.settling.values().any(|file| file.stamp.size == size)
    }
}
