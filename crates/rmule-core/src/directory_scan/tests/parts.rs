//! Part files against a scripted directory (ADR-0100, "Part files are known
//! by their download rows"): the scan skips the paths the download rows
//! name, never a suffix.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::super::scripted::{ROOT, Scripted, World};
use super::super::{
    Consent, DirEntry, DirectorySource, EntryKind, FileStamp, Known, Memory, PartFiles,
    ProgressCell, ScanReport, run_pass,
};
use super::shared_paths;

fn pass_with_parts(dir: &Scripted, parts: PartFiles) -> Vec<ScanReport> {
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let mut reports = Vec::new();
    run_pass(
        dir,
        Path::new(ROOT),
        &mut || {
            Some(Known {
                parts: parts.clone(),
                ..Known::default()
            })
        },
        Consent::Given,
        &AtomicBool::new(false),
        &progress,
        &mut Memory::default(),
        &mut |report| reports.push(report),
    );
    reports
}

#[test]
fn an_operators_part_file_is_shared_and_a_downloads_own_is_never_opened() {
    let mut dir = Scripted::new();
    dir.file("/dl/notes.part", b"the operator's own", 1);
    dir.file("/dl/film.mkv.part", b"a download at work", 1);
    let reports = pass_with_parts(
        &dir,
        PartFiles::of([(PathBuf::from("/dl/film.mkv.part"), true)]),
    );
    assert_eq!(shared_paths(&reports), [PathBuf::from("/dl/notes.part")]);
    assert_eq!(dir.opens(), 1, "the download's part file is never read");
    assert!(
        !reports
            .iter()
            .any(|report| matches!(report, ScanReport::LeftoverParts(_))),
        "a live download's part file is its work, not a leftover"
    );
}

#[test]
fn a_cancelled_downloads_leftover_is_skipped_and_told() {
    let mut dir = Scripted::new();
    dir.file("/dl/old.iso.part", b"half a file", 1);
    let reports = pass_with_parts(
        &dir,
        PartFiles::of([(PathBuf::from("/dl/old.iso.part"), false)]),
    );
    assert!(shared_paths(&reports).is_empty());
    assert_eq!(dir.opens(), 0);
    assert_eq!(
        reports
            .iter()
            .filter(|report| matches!(report, ScanReport::LeftoverParts(_)))
            .collect::<Vec<_>>(),
        [&ScanReport::LeftoverParts(vec![PathBuf::from(
            "/dl/old.iso.part"
        )])]
    );
}

/// A pass while a completing download's file stands in place with its row
/// written, and one after the row is `Completed` (ADR-0115): neither reads
/// the file, the first leaves the row as it is, the second trusts it.
#[test]
fn a_completing_downloads_destination_is_left_with_its_row_then_trusted() {
    use super::super::scripted::row;

    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/film.mkv", b"the finished file", 4);
    dir.file("/dl/.other.iso.completing", b"another download's copy", 4);
    let rows = vec![row("/dl/film.mkv", stamp, 7)];
    let pass = |parts: PartFiles| {
        let progress: ProgressCell = Arc::new(Mutex::new(None));
        let mut reports = Vec::new();
        run_pass(
            &dir,
            Path::new(ROOT),
            &mut || {
                Some(Known {
                    rows: rows.clone(),
                    parts: parts.clone(),
                    ..Known::default()
                })
            },
            Consent::Given,
            &AtomicBool::new(false),
            &progress,
            &mut Memory::default(),
            &mut |report| reports.push(report),
        );
        reports
    };

    let completing = pass(PartFiles::of([(PathBuf::from("/dl/film.mkv"), true)]));
    assert!(shared_paths(&completing).is_empty());
    assert!(
        !completing
            .iter()
            .any(|report| matches!(report, ScanReport::Gone { .. } | ScanReport::Unshare(_))),
        "the row the move wrote is not taken for gone: {completing:?}"
    );
    let completed = pass(PartFiles::default());
    assert!(shared_paths(&completed).is_empty(), "the row is trusted");
    assert!(
        !completed
            .iter()
            .any(|report| matches!(report, ScanReport::Gone { .. } | ScanReport::Unshare(_))),
        "{completed:?}"
    );
    assert_eq!(dir.opens(), 0);
}

/// A download directory a completing download's file lands in while the
/// pass lists it: the move has stored its destination, then its file lands.
struct LandsWhileListed {
    dir: World,
    landed: Arc<AtomicBool>,
}

impl DirectorySource for LandsWhileListed {
    fn list(&self, dir: &Path) -> io::Result<Vec<DirEntry>> {
        if !self.landed.swap(true, Ordering::SeqCst) {
            self.dir
                .with(|dir| dir.file("/dl/film.mkv", b"the finished file", 4));
        }
        self.dir.list(dir)
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        self.dir.kind(path)
    }

    fn is_folder(&self, path: &Path) -> io::Result<bool> {
        self.dir.is_folder(path)
    }

    fn stamp(&self, path: &Path) -> io::Result<FileStamp> {
        self.dir.stamp(path)
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn io::Read + Send>> {
        self.dir.open(path)
    }
}

/// A pass whose scan started before a download stored `Completing` and
/// whose listing finds that download's file landed (ADR-0115): what the
/// pass judges by is read after the listing, so the file is the
/// download's own and never read.
#[test]
fn a_file_landed_while_the_pass_lists_is_judged_by_what_is_known_after() {
    let landed = Arc::new(AtomicBool::new(false));
    let source = LandsWhileListed {
        dir: World::new(),
        landed: Arc::clone(&landed),
    };
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let mut reports = Vec::new();
    run_pass(
        &source,
        Path::new(ROOT),
        &mut || {
            let completing = landed
                .load(Ordering::SeqCst)
                .then(|| (PathBuf::from("/dl/film.mkv"), true));
            Some(Known {
                parts: PartFiles::of(completing),
                ..Known::default()
            })
        },
        Consent::Given,
        &AtomicBool::new(false),
        &progress,
        &mut Memory::default(),
        &mut |report| reports.push(report),
    );
    assert!(shared_paths(&reports).is_empty(), "{reports:?}");
    assert_eq!(source.dir.opens(), 0, "the landed file is never read");
}
