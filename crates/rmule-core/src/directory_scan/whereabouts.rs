//! Where a shared content lies while its row is found gone (ADR-0100, "The
//! Had Set"): before a row leaves the registry and its hash joins the **Had
//! Set**, the scan looks for the content elsewhere under the directory, so a
//! rename or a copy-then-delete moves the row and never passes through the
//! set.
//!
//! Two kinds of evidence. A *spare copy* is a file the scan hashed but did not
//! share, because the same content was shared from another path; it is
//! recorded durably and seeded here from what the actor knows, so a row moves
//! to it without a read (ADR-0104, "Spare copies are recorded"). A
//! *candidate* is a file of the gone row's size that is settling or waiting to
//! be hashed; a rename keeps the size, so the row is *held* until no
//! candidate of that size remains, or for [`MOVE_HOLD`] at most in the watch
//! (ADR-0106, "The registry against the disk"). A held row is withheld from
//! the moment it is held: it names a file that is not there.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rmule_primitives::FileHash;

use super::plan::GoneRow;
use super::{DirectorySource, EntryKind, FileIdentity, FileStamp, ScanReport, SpareCopy};
use crate::registry::SharedFileEntry;

/// The longest the watch holds a gone row for a candidate. A file of its size
/// that never holds still would otherwise hold it for ever.
pub(crate) const MOVE_HOLD: Duration = Duration::from_secs(30);

/// A gone row held for a candidate, and when the watch found it gone; the
/// pass's holds carry no instant and last the pass.
#[derive(Debug)]
struct Holding {
    gone: GoneRow,
    since: Option<Instant>,
}

/// The held rows and the spare copies of one scan, kept across the pass and
/// every round of the watch.
#[derive(Debug, Default)]
pub(crate) struct Whereabouts {
    /// Rows found gone and kept in the registry while a candidate of their
    /// size may turn out to be their content at a new path.
    held: HashMap<FileHash, Holding>,
    /// Files whose content is shared from another path, by content; each is
    /// used at most once, and only if its stamp still holds.
    spares: HashMap<FileHash, Vec<SpareCopy>>,
}

impl Whereabouts {
    /// The spare copies under `root` as the actor holds them, less those
    /// `left`: replaces what was known before.
    pub(crate) fn seed(&mut self, spares: &[SpareCopy], root: &Path, left: &[PathBuf]) {
        self.spares.clear();
        for spare in spares
            .iter()
            .filter(|spare| spare.path.starts_with(root) && !left.contains(&spare.path))
        {
            self.keep(spare.clone());
        }
    }

    /// A spare copy is recorded at `spare.path`.
    pub(crate) fn keep(&mut self, spare: SpareCopy) {
        let copies = self.spares.entry(spare.file_hash).or_default();
        copies.retain(|copy| copy.path != spare.path);
        copies.push(spare);
        copies.sort_by(|a, b| a.path.cmp(&b.path));
    }

    /// The spare at `path` vanished or changed.
    pub(crate) fn forget_spare(&mut self, path: &Path) {
        for copies in self.spares.values_mut() {
            copies.retain(|copy| copy.path != path);
        }
    }

    /// Move the row `lost` names to a spare copy of its content whose stamp
    /// still holds (one `stat` each), unread. The new path when it moved.
    pub(crate) fn relocate(
        &mut self,
        lost: &GoneRow,
        source: &dyn DirectorySource,
        report: &mut dyn FnMut(ScanReport),
    ) -> Option<PathBuf> {
        let copies = self.spares.get_mut(&lost.file_hash)?;
        let at = copies.iter().position(|copy| {
            source
                .stamp(&copy.path)
                .is_ok_and(|stamp| stamp == copy.stamp)
        })?;
        let to = copies.remove(at);
        let path = to.path.clone();
        report(ScanReport::Moved {
            file_hash: lost.file_hash,
            from: lost.path.clone(),
            to,
        });
        Some(path)
    }

    /// The row `gone` names a file that is no longer at its path. Its content
    /// moves to a spare copy if one still holds; failing that the row is held,
    /// and reported held, while `candidate` says a file of its size may be
    /// it; otherwise it leaves. `now` is the watch's instant, `None` in the
    /// pass. The new path when it moved.
    pub(crate) fn found_gone(
        &mut self,
        gone: GoneRow,
        source: &dyn DirectorySource,
        candidate: impl Fn(u64) -> bool,
        now: Option<Instant>,
        report: &mut dyn FnMut(ScanReport),
    ) -> Option<PathBuf> {
        if let Some(path) = self.relocate(&gone, source, report) {
            return Some(path);
        }
        if candidate(gone.size) {
            report(ScanReport::Held {
                file_hash: gone.file_hash,
                path: gone.path.clone(),
            });
            self.held
                .insert(gone.file_hash, Holding { gone, since: now });
        } else {
            report(leave(gone));
        }
        None
    }

    /// A file hashed to `entry`, whose content the registry holds at
    /// `shared_at`, if anywhere; `stamp` is the file's as it was hashed and
    /// `identity` its identity, read after the hash. It is shared if the content is not shared, or its row is held
    /// (the row moves to it); otherwise it is recorded as a spare. True when
    /// it was shared.
    pub(crate) fn hashed(
        &mut self,
        entry: SharedFileEntry,
        (stamp, identity): (FileStamp, Option<FileIdentity>),
        shared_at: Option<&Path>,
        report: &mut dyn FnMut(ScanReport),
    ) -> bool {
        if self.held.remove(&entry.file_hash).is_some() || shared_at.is_none() {
            let (file_hash, path) = (entry.file_hash, entry.path.clone());
            report(ScanReport::Share(entry));
            if let Some(identity) = identity {
                report(ScanReport::Identified {
                    file_hash,
                    path,
                    identity,
                });
            }
            return true;
        }
        tracing::info!(
            path = %entry.path.display(),
            shared_at = ?shared_at,
            "same content already shared from another path; recorded as a spare copy",
        );
        let spare = SpareCopy {
            stamp,
            path: entry.path,
            file_hash: entry.file_hash,
            identity,
        };
        report(ScanReport::Spare(spare.clone()));
        self.keep(spare);
        false
    }

    /// Held rows leave whose size no candidate has any more, or that have
    /// been held for [`MOVE_HOLD`] by `now`. One whose path holds a file
    /// again is let go without a ruling: nothing left, and the watch has
    /// examined what is there.
    pub(crate) fn release(
        &mut self,
        candidate: impl Fn(u64) -> bool,
        now: Option<Instant>,
        source: &dyn DirectorySource,
        report: &mut dyn FnMut(ScanReport),
    ) {
        let (keep, leaving): (HashMap<_, _>, HashMap<_, _>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|(_, held)| candidate(held.gone.size) && !overdue(held, now));
        self.held = keep;
        let mut leaving: Vec<GoneRow> = leaving.into_values().map(|held| held.gone).collect();
        leaving.sort_by(|a, b| a.path.cmp(&b.path));
        for gone in leaving {
            if !matches!(source.kind(&gone.path), Ok(EntryKind::File(_))) {
                report(leave(gone));
            }
        }
    }

    /// Whether a held row's bound has passed by `now`.
    pub(crate) fn overdue(&self, now: Instant) -> bool {
        self.held.values().any(|held| overdue(held, Some(now)))
    }
}

fn overdue(held: &Holding, now: Option<Instant>) -> bool {
    held.since
        .zip(now)
        .is_some_and(|(since, now)| now.saturating_duration_since(since) >= MOVE_HOLD)
}

fn leave(gone: GoneRow) -> ScanReport {
    ScanReport::Gone {
        file_hash: gone.file_hash,
        path: gone.path,
    }
}
