//! Spare copies against a scripted directory (ADR-0100, "Spare copies are
//! recorded"): recorded once, trusted unread at every later start, the place
//! a row whose file goes or changes moves to without a read, and dropped —
//! never Had — when they go or change themselves.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use rmule_primitives::FileHashSummary;

use super::super::scripted::{ROOT, Scripted, known, row};
use super::super::{
    Consent, FileStamp, Known, Memory, PassEnd, ProgressCell, ScanReport, SpareCopy, run_pass,
};
use super::shared_paths;
use crate::registry::SharedFileEntry;

fn pass_knowing(dir: &Scripted, known: &Known) -> (PassEnd, Vec<ScanReport>) {
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let mut reports = Vec::new();
    let end = run_pass(
        dir,
        Path::new(ROOT),
        &mut || Some(known.clone()),
        Consent::Given,
        &AtomicBool::new(false),
        &progress,
        &mut Memory::default(),
        &mut |report| reports.push(report),
    );
    (end, reports)
}

/// The registry row for `bytes` at `path`, with its real hash.
fn shared(dir: &mut Scripted, path: &str, bytes: &[u8]) -> SharedFileEntry {
    let stamp = dir.file(path, bytes, 1);
    let mut entry = row(path, stamp, 0);
    entry.file_hash = FileHashSummary::digest_bytes(bytes).file_hash();
    entry
}

fn spare_of(row: &SharedFileEntry, path: &str, stamp: FileStamp) -> SpareCopy {
    SpareCopy {
        path: PathBuf::from(path),
        file_hash: row.file_hash,
        stamp,
        identity: None,
    }
}

#[test]
fn a_spare_copy_is_trusted_on_a_second_start_with_zero_reads() {
    let mut dir = Scripted::new();
    let original = shared(&mut dir, "/dl/film.mkv", b"the film");
    let copy_stamp = dir.file("/dl/backup/film.mkv", b"the film", 1);
    dir.dir("/dl/backup");
    let (_, first) = pass_knowing(&dir, &known(std::slice::from_ref(&original)));
    let recorded = spare_of(&original, "/dl/backup/film.mkv", copy_stamp);
    assert_eq!(first, [ScanReport::Spare(recorded.clone())]);
    assert_eq!(dir.opens(), 1);

    let second_start = Known {
        spares: vec![recorded],
        ..known(&[original])
    };
    let (end, second) = pass_knowing(&dir, &second_start);
    assert!(second.is_empty(), "{second:?}");
    assert_eq!(dir.opens(), 1, "the second start reads nothing");
    assert!(matches!(end, PassEnd::Finished(s) if s.trusted == 2 && s.hashed == 0));
}

#[test]
fn a_row_whose_file_vanished_moves_to_its_spare_without_a_read() {
    let mut dir = Scripted::new();
    let original = shared(&mut dir, "/dl/film.mkv", b"the film");
    let copy = spare_of(
        &original,
        "/dl/copy.mkv",
        dir.file("/dl/copy.mkv", b"the film", 1),
    );
    dir.remove("/dl/film.mkv");
    let (_, reports) = pass_knowing(
        &dir,
        &Known {
            spares: vec![copy.clone()],
            ..known(std::slice::from_ref(&original))
        },
    );
    assert_eq!(
        reports,
        [ScanReport::Moved {
            file_hash: original.file_hash,
            from: original.path,
            to: copy,
        }],
        "moved, never gone, never held"
    );
    assert_eq!(dir.opens(), 0);
}

#[test]
fn a_row_whose_file_changed_moves_to_its_spare_and_the_change_is_hashed() {
    let mut dir = Scripted::new();
    let original = shared(&mut dir, "/dl/film.mkv", b"the film");
    let copy = spare_of(
        &original,
        "/dl/copy.mkv",
        dir.file("/dl/copy.mkv", b"the film", 1),
    );
    dir.file("/dl/film.mkv", b"a re-encode", 7);
    let (_, reports) = pass_knowing(
        &dir,
        &Known {
            spares: vec![copy.clone()],
            ..known(std::slice::from_ref(&original))
        },
    );
    assert_eq!(
        reports[0],
        ScanReport::Moved {
            file_hash: original.file_hash,
            from: original.path.clone(),
            to: copy,
        },
        "the content is still on disk: not unshared"
    );
    assert_eq!(
        shared_paths(&reports),
        [PathBuf::from("/dl/copy.mkv"), original.path]
    );
    assert!(!reports.iter().any(|r| matches!(r, ScanReport::Unshare(_))));
    assert_eq!(dir.opens(), 1, "only the changed file is read");
}

#[test]
fn a_spare_that_vanished_or_changed_is_dropped_and_never_had() {
    let mut dir = Scripted::new();
    let original = shared(&mut dir, "/dl/film.mkv", b"the film");
    let gone = spare_of(
        &original,
        "/dl/gone.mkv",
        dir.file("/dl/gone.mkv", b"the film", 1),
    );
    let changed = spare_of(
        &original,
        "/dl/edit.mkv",
        dir.file("/dl/edit.mkv", b"the film", 1),
    );
    dir.remove("/dl/gone.mkv");
    dir.file("/dl/edit.mkv", b"now something else", 3);
    let (_, reports) = pass_knowing(
        &dir,
        &Known {
            spares: vec![gone, changed],
            ..known(&[original])
        },
    );
    assert_eq!(
        reports[..2],
        [
            ScanReport::SpareLeft("/dl/edit.mkv".into()),
            ScanReport::SpareLeft("/dl/gone.mkv".into()),
        ]
    );
    assert_eq!(shared_paths(&reports), [PathBuf::from("/dl/edit.mkv")]);
    assert!(
        !reports
            .iter()
            .any(|r| matches!(r, ScanReport::Gone { .. } | ScanReport::Unshare(_))),
        "the content is still shared from the row's path"
    );
}
