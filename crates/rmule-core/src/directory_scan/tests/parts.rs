//! Part files against a scripted directory (ADR-0100, "Part files are known
//! by their download rows"): the scan skips the paths the download rows
//! name, never a suffix.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use super::super::scripted::{ROOT, Scripted};
use super::super::{Consent, Known, Memory, PartFiles, ProgressCell, ScanReport, run_pass};
use super::shared_paths;

fn pass_with_parts(dir: &Scripted, parts: PartFiles) -> Vec<ScanReport> {
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let mut reports = Vec::new();
    run_pass(
        dir,
        Path::new(ROOT),
        &Known {
            parts,
            ..Known::default()
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
