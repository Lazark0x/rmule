//! The pass against a scripted directory: the trust rule, the diff, the skip
//! rules and the disclosure guard, with every open counted at the seam.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmule_primitives::{FileHash, FileHashSummary};

use super::scripted::{ROOT, Scripted, at, known, row};
use super::{
    Consent, DirEntry, DirectorySource, EntryKind, FileStamp, Memory, PassEnd, ProgressCell,
    ScanReport, ScanSummary, SpareCopy, run_pass,
};
use crate::registry::{ShareSource, SharedFileEntry};

struct Outcome {
    end: PassEnd,
    reports: Vec<ScanReport>,
}

fn pass_with(dir: &Scripted, rows: &[SharedFileEntry], consent: Consent) -> Outcome {
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let mut reports = Vec::new();
    let end = run_pass(
        dir,
        Path::new(ROOT),
        &mut || Some(known(rows)),
        consent,
        &AtomicBool::new(false),
        &progress,
        &mut Memory::default(),
        &mut |report| reports.push(report),
    );
    Outcome { end, reports }
}

fn pass(dir: &Scripted, rows: &[SharedFileEntry]) -> Outcome {
    pass_with(dir, rows, Consent::Given)
}

fn shared_paths(reports: &[ScanReport]) -> Vec<PathBuf> {
    reports
        .iter()
        .filter_map(|report| match report {
            ScanReport::Share(entry) => Some(entry.path.clone()),
            ScanReport::Moved { to, .. } => Some(to.path.clone()),
            ScanReport::Unshare(_)
            | ScanReport::Spare(_)
            | ScanReport::SpareLeft(_)
            | ScanReport::Identified { .. }
            | ScanReport::Gone { .. }
            | ScanReport::Held { .. }
            | ScanReport::Unreadable { .. }
            | ScanReport::NotHashed { .. }
            | ScanReport::LeftoverParts(_)
            | ScanReport::WatchInterrupted(_)
            | ScanReport::WatchRestored
            | ScanReport::PathUnwatched { .. }
            | ScanReport::RootMissing { .. }
            | ScanReport::RootReturned
            | ScanReport::SetAsideLeft(_)
            | ScanReport::Finished(_) => None,
        })
        .collect()
}

#[test]
fn an_unchanged_file_is_trusted_and_never_opened() {
    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/film.mkv", b"bytes", 100);
    let outcome = pass(&dir, &[row("/dl/film.mkv", stamp, 1)]);
    assert_eq!(dir.opens(), 0);
    assert!(outcome.reports.is_empty());
    assert_eq!(
        outcome.end,
        PassEnd::Finished(ScanSummary {
            trusted: 1,
            ..ScanSummary::default()
        })
    );
}

#[test]
fn a_changed_size_drops_the_row_and_hashes_the_file_as_new() {
    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/a.bin", b"grown bytes", 100);
    let old = FileStamp { size: 3, ..stamp };
    let outcome = pass(&dir, &[row("/dl/a.bin", old, 7)]);
    assert_eq!(dir.opens(), 1);
    assert_eq!(
        outcome.reports[0],
        ScanReport::Unshare(FileHash::from_bytes([7; 16]))
    );
    let ScanReport::Share(entry) = &outcome.reports[1] else {
        panic!("the file is shared anew");
    };
    let digest = FileHashSummary::digest_bytes(b"grown bytes");
    assert_eq!(entry.file_hash, digest.file_hash());
    assert_eq!(entry.file_size, 11);
    assert_eq!(entry.modified, Some(at(100)));
    assert_eq!(entry.source, ShareSource::DownloadDirectory);
    assert_eq!(entry.name, "a.bin");
}

#[test]
fn a_changed_time_drops_the_row_and_hashes_the_file_as_new() {
    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/a.bin", b"same size", 200);
    let old = FileStamp {
        modified: at(100),
        ..stamp
    };
    let outcome = pass(&dir, &[row("/dl/a.bin", old, 7)]);
    assert_eq!(dir.opens(), 1);
    assert_eq!(outcome.reports.len(), 2);
    assert_eq!(
        outcome.reports[0],
        ScanReport::Unshare(FileHash::from_bytes([7; 16]))
    );
}

#[test]
fn a_row_with_no_recorded_time_is_hashed_again() {
    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/a.bin", b"bytes", 100);
    let mut legacy = row("/dl/a.bin", stamp, 7);
    legacy.modified = None;
    pass(&dir, &[legacy]);
    assert_eq!(dir.opens(), 1);
}

#[test]
fn a_vanished_file_leaves_the_registry_unread() {
    let dir = Scripted::new();
    let gone = FileStamp {
        size: 5,
        modified: at(100),
    };
    let outside = row("/elsewhere/kept.bin", gone, 9);
    let outcome = pass(&dir, &[row("/dl/sub/gone.bin", gone, 3), outside]);
    assert_eq!(dir.opens(), 0);
    assert_eq!(
        outcome.reports,
        vec![ScanReport::Gone {
            file_hash: FileHash::from_bytes([3; 16]),
            path: "/dl/sub/gone.bin".into(),
        }],
        "rows outside the directory are the Registry Check's"
    );
}

#[test]
fn a_file_renamed_while_rmule_was_off_moves_its_row_and_is_never_gone() {
    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/final.txt", b"contents", 100);
    let mut old = row("/dl/draft.txt", stamp, 0);
    old.file_hash = FileHashSummary::digest_bytes(b"contents").file_hash();
    // A file of the same size that is other content: the row waits for it too.
    dir.file("/dl/other.txt", b"elsewise", 100);
    let outcome = pass(&dir, &[old.clone()]);
    assert_eq!(
        shared_paths(&outcome.reports),
        [
            PathBuf::from("/dl/final.txt"),
            PathBuf::from("/dl/other.txt")
        ]
    );
    assert!(
        outcome.reports.iter().all(|report| matches!(
            report,
            ScanReport::Held { .. } | ScanReport::Share(_) | ScanReport::Finished(_)
        )),
        "the row moved; nothing left the registry: {:?}",
        outcome.reports
    );
}

#[test]
fn a_gone_row_whose_size_matched_other_content_leaves_after_the_hashing() {
    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/other.txt", b"elsewise", 100);
    let outcome = pass(&dir, &[row("/dl/draft.txt", stamp, 4)]);
    assert_eq!(
        outcome.reports,
        vec![
            ScanReport::Held {
                file_hash: FileHash::from_bytes([4; 16]),
                path: "/dl/draft.txt".into(),
            },
            ScanReport::Share(outcome_entry(&outcome.reports[1])),
            ScanReport::Gone {
                file_hash: FileHash::from_bytes([4; 16]),
                path: "/dl/draft.txt".into(),
            },
        ]
    );
}

fn outcome_entry(report: &ScanReport) -> SharedFileEntry {
    match report {
        ScanReport::Share(entry) => entry.clone(),
        other => panic!("expected a share first, got {other:?}"),
    }
}

#[test]
fn skipped_names_are_never_opened_or_shared() {
    let mut dir = Scripted::new();
    dir.file("/dl/.hidden", b"x", 1);
    dir.dir("/dl/.cache");
    dir.file("/dl/.cache/inside.bin", b"x", 1);
    dir.entry("/dl/link.bin", EntryKind::Symlink);
    dir.entry("/dl/socket", EntryKind::Other);
    dir.file("/dl/kept.bin", b"x", 1);
    let outcome = pass(&dir, &[]);
    assert_eq!(
        shared_paths(&outcome.reports),
        [PathBuf::from("/dl/kept.bin")]
    );
    assert_eq!(dir.opens(), 1);
}

#[test]
fn nested_directories_are_walked_and_hashed_in_name_order() {
    let mut dir = Scripted::new();
    dir.file("/dl/z.bin", b"z", 1);
    dir.dir("/dl/b");
    dir.dir("/dl/b/deep");
    dir.file("/dl/b/deep/c.bin", b"c", 1);
    dir.file("/dl/b/a.bin", b"a", 1);
    dir.file("/dl/a.bin", b"aa", 1);
    let outcome = pass(&dir, &[]);
    assert_eq!(
        shared_paths(&outcome.reports),
        ["/dl/a.bin", "/dl/b/a.bin", "/dl/b/deep/c.bin", "/dl/z.bin"].map(PathBuf::from)
    );
}

#[test]
fn a_second_copy_of_shared_content_does_not_move_the_row() {
    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/a/first.bin", b"same", 1);
    dir.dir("/dl/a");
    dir.file("/dl/b.bin", b"same", 1);
    let mut first = row("/dl/a/first.bin", stamp, 0);
    first.file_hash = FileHashSummary::digest_bytes(b"same").file_hash();
    let outcome = pass(&dir, &[first.clone()]);
    assert_eq!(
        outcome.reports,
        [ScanReport::Spare(SpareCopy {
            path: "/dl/b.bin".into(),
            file_hash: first.file_hash,
            stamp,
            identity: None,
        })],
        "the second copy is recorded, never shared"
    );
    assert!(matches!(outcome.end, PassEnd::Finished(s) if s.skipped == 1 && s.trusted == 1));
}

#[test]
fn a_file_that_moves_while_it_is_hashed_is_not_shared() {
    let mut dir = Scripted::new();
    dir.file("/dl/growing.bin", b"half", 1);
    dir.moving.insert(PathBuf::from("/dl/growing.bin"));
    let outcome = pass(&dir, &[]);
    assert!(outcome.reports.is_empty());
    assert!(matches!(outcome.end, PassEnd::Finished(s) if s.skipped == 1));
}

#[test]
fn the_guard_hashes_nothing_before_the_operator_answers() {
    let dir = Arc::new({
        let mut dir = Scripted::new();
        dir.file("/dl/private.doc", b"secret", 1);
        dir
    });
    let asked = Arc::new(Mutex::new(None));
    let (seen, probe) = (Arc::clone(&asked), Arc::clone(&dir));
    let outcome = pass_with(
        &dir,
        &[],
        Consent::Ask(Box::new(move |files| {
            *seen.lock().unwrap() = Some((files.files, probe.opens()));
            false
        })),
    );
    assert_eq!(
        *asked.lock().unwrap(),
        Some((1, 0)),
        "asked with nothing opened"
    );
    assert_eq!(outcome.end, PassEnd::Declined);
    assert!(outcome.reports.is_empty());
    assert_eq!(dir.opens(), 0);
}

#[test]
fn a_yes_lets_the_pass_share() {
    let mut dir = Scripted::new();
    dir.file("/dl/a.bin", b"a", 1);
    let outcome = pass_with(&dir, &[], Consent::Ask(Box::new(|_| true)));
    assert_eq!(shared_paths(&outcome.reports), [PathBuf::from("/dl/a.bin")]);
}

#[test]
fn the_guard_does_not_ask_when_nothing_would_be_hashed() {
    let mut dir = Scripted::new();
    let stamp = dir.file("/dl/a.bin", b"a", 1);
    let outcome = pass_with(
        &dir,
        &[row("/dl/a.bin", stamp, 1)],
        Consent::Ask(Box::new(|_| panic!("nothing to disclose"))),
    );
    assert!(matches!(outcome.end, PassEnd::Finished(s) if s.trusted == 1));
}

#[test]
fn a_raised_stop_ends_the_pass_before_the_next_read() {
    let mut dir = Scripted::new();
    dir.file("/dl/a.bin", b"a", 1);
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let end = run_pass(
        &dir,
        Path::new(ROOT),
        &mut || Some(known(&[])),
        Consent::Given,
        &AtomicBool::new(true),
        &progress,
        &mut Memory::default(),
        &mut |_| panic!("nothing reported after a stop"),
    );
    assert_eq!(end, PassEnd::Stopped);
    assert_eq!(dir.opens(), 0);
}

#[test]
fn an_unlistable_directory_changes_nothing() {
    let dir = Scripted::default();
    let gone = FileStamp {
        size: 1,
        modified: at(1),
    };
    let outcome = pass(&dir, &[row("/dl/a.bin", gone, 1)]);
    assert_eq!(outcome.end, PassEnd::Unlistable);
    assert!(
        outcome.reports.is_empty(),
        "an unmounted disk unshares nothing"
    );
}

/// Several thousand files spread over subdirectories, each with the row a
/// past pass left.
fn restart_fixture(files: usize) -> (Scripted, Vec<SharedFileEntry>) {
    let mut dir = Scripted::new();
    let mut rows = Vec::with_capacity(files);
    for sub in 0..files.div_ceil(100) {
        dir.dir(&format!("/dl/d{sub:03}"));
    }
    for index in 0..files {
        let path = format!("/dl/d{:03}/f{index:05}.bin", index / 100);
        let stamp = FileStamp {
            size: 700 << 20,
            modified: at(1_000 + index as u64),
        };
        dir.entry(&path, EntryKind::File(stamp));
        let mut entry = row(&path, stamp, 0);
        entry.file_hash = FileHash::from_bytes({
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
            bytes
        });
        rows.push(entry);
    }
    (dir, rows)
}

#[test]
fn a_restart_over_thousands_of_rows_reads_no_file() {
    let (dir, rows) = restart_fixture(5_000);
    let outcome = pass(&dir, &rows);
    assert_eq!(dir.opens(), 0);
    assert!(outcome.reports.is_empty());
    assert!(matches!(outcome.end, PassEnd::Finished(s) if s.trusted == 5_000));
}

/// The restart cost as a number: `cargo test -p rmule-core --release --lib
/// restart_revalidation_wall_time -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn restart_revalidation_wall_time() {
    for files in [5_000, 20_000] {
        let (dir, rows) = restart_fixture(files);
        let started = Instant::now();
        let outcome = pass(&dir, &rows);
        let elapsed = started.elapsed();
        assert_eq!(dir.opens(), 0);
        assert!(matches!(outcome.end, PassEnd::Finished(s) if s.trusted == files));
        println!("scripted: {files} rows re-validated in {elapsed:?}, 0 files opened");
    }
}

/// [`super::FsDirectorySource`] with every open counted.
struct CountingFs(AtomicUsize);

impl DirectorySource for CountingFs {
    fn list(&self, dir: &Path) -> io::Result<Vec<DirEntry>> {
        super::FsDirectorySource.list(dir)
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        super::FsDirectorySource.kind(path)
    }

    fn is_folder(&self, path: &Path) -> io::Result<bool> {
        super::FsDirectorySource.is_folder(path)
    }

    fn stamp(&self, path: &Path) -> io::Result<FileStamp> {
        super::FsDirectorySource.stamp(path)
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn io::Read + Send>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        super::FsDirectorySource.open(path)
    }
}

/// The restart cost on a real disk (warm cache): `cargo test -p rmule-core
/// --release --lib restart_revalidation_on_disk -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn restart_revalidation_on_disk_wall_time() {
    let files: usize = 5_000;
    let tmp = tempfile::tempdir().unwrap();
    for sub in 0..files / 100 {
        std::fs::create_dir(tmp.path().join(format!("d{sub:03}"))).unwrap();
    }
    for index in 0..files {
        let path = tmp
            .path()
            .join(format!("d{:03}/f{index:05}.bin", index / 100));
        std::fs::write(path, index.to_le_bytes()).unwrap();
    }
    let source = CountingFs(AtomicUsize::new(0));
    // The rows a first pass would have left: every file's own stamp.
    let rows: Vec<_> = super::plan::walk(&source, tmp.path(), &super::Known::default())
        .unwrap()
        .found
        .into_iter()
        .enumerate()
        .map(|(index, file)| {
            let mut entry = row(file.path.to_str().unwrap(), file.stamp, 0);
            entry.file_hash = FileHash::from_bytes({
                let mut bytes = [0; 16];
                bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
                bytes
            });
            entry
        })
        .collect();
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let started = Instant::now();
    let end = run_pass(
        &source,
        tmp.path(),
        &mut || Some(known(&rows)),
        Consent::Given,
        &AtomicBool::new(false),
        &progress,
        &mut Memory::default(),
        &mut |_| panic!("an unchanged tree reports nothing"),
    );
    let elapsed = started.elapsed();
    assert_eq!(source.0.load(Ordering::SeqCst), 0);
    assert!(matches!(end, PassEnd::Finished(s) if s.trusted == files));
    println!("on disk: {files} files re-validated in {elapsed:?}, 0 files opened");
}

mod aside;
mod parts;
mod rename;
mod spares;
mod unlistable;

#[test]
fn a_file_the_first_pass_cannot_open_is_counted_unreadable_and_told_with_its_reason() {
    let mut dir = Scripted::new();
    dir.file("/dl/locked.bin", b"locked", 1);
    dir.file("/dl/fine.bin", b"fine", 2);
    dir.denied.insert(PathBuf::from("/dl/locked.bin"));
    let outcome = pass(&dir, &[]);
    assert_eq!(
        outcome.end,
        PassEnd::Finished(ScanSummary {
            hashed: 1,
            unreadable: 1,
            ..ScanSummary::default()
        })
    );
    assert!(outcome.reports.iter().any(|report| matches!(
        report,
        ScanReport::NotHashed { path, kind, .. }
            if path == Path::new("/dl/locked.bin") && *kind == std::io::ErrorKind::PermissionDenied
    )));
}
