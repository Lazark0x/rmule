//! The Extension Gap's bounds, the Hole Verdict's rule, and the Hole Probe on
//! a real temporary directory: CI runs it on ext4, APFS and NTFS, all of which
//! hold holes.

use std::io::{self, Write};

use super::{HoleVerdict, extension_gap, probe_holes, probe_path};
use crate::{ContentFileStore, DownloadPaths};

const PART: u64 = rmule_primitives::ED2K_PART_SIZE;

#[test]
fn a_write_that_extends_nothing_opens_no_gap() {
    assert_eq!(extension_gap(PART, PART), None, "contiguous");
    assert_eq!(extension_gap(2 * PART, PART), None, "inside the file");
    assert_eq!(extension_gap(0, 0), None, "the first part");
}

#[test]
fn a_gap_is_aligned_inward_to_four_kib() {
    assert_eq!(extension_gap(PART, 2 * PART), Some(PART..2 * PART));
    assert_eq!(extension_gap(100, 3 * 4096 + 5), Some(4096..3 * 4096));
}

#[test]
fn a_gap_under_four_kib_once_aligned_is_none() {
    assert_eq!(extension_gap(4096, 4096 + 4000), None);
    assert_eq!(extension_gap(10, 4000), None);
    assert_eq!(extension_gap(4000, 8000), None);
}

#[test]
fn holes_are_held_when_under_half_the_length_is_allocated() {
    let probe = 4096 + 32 * 1024 * 1024 + 4096;
    assert_eq!(
        HoleVerdict::from_sizes(8192, probe),
        HoleVerdict::HoldsHoles
    );
    assert_eq!(HoleVerdict::from_sizes(probe, probe), HoleVerdict::HoleLess);
    assert_eq!(
        HoleVerdict::from_sizes(16_711_680, 8_388_608),
        HoleVerdict::HoleLess,
        "allocated beyond the length"
    );
}

#[tokio::test]
async fn the_probe_finds_holes_and_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let part = dir.path().join("film.bin.part");
    assert_eq!(probe_holes(&part).await, HoleVerdict::HoldsHoles);
    let probe = probe_path(&part).unwrap();
    assert!(!probe.exists(), "the probe file is removed");
}

/// A dense leftover longer than half the probe would read hole-less unless
/// the next probe truncates it.
#[tokio::test]
async fn a_leftover_probe_file_is_truncated_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let part = dir.path().join("film.bin.part");
    let probe = probe_path(&part).unwrap();
    std::fs::File::create(&probe)
        .unwrap()
        .write_all(&vec![0x5Au8; 20 * 1024 * 1024])
        .unwrap();

    assert_eq!(probe_holes(&part).await, HoleVerdict::HoldsHoles);
    assert!(!probe.exists(), "the leftover is removed");
}

#[tokio::test]
async fn a_probe_in_a_missing_directory_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let part = dir.path().join("absent").join("film.bin.part");
    assert_eq!(
        probe_holes(&part).await,
        HoleVerdict::Unknown(io::ErrorKind::NotFound)
    );
}

#[tokio::test]
async fn deleting_the_part_file_removes_the_probe_file_too() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("film.bin"));
    ContentFileStore::write_verified_part(&paths, 0, b"bytes")
        .await
        .unwrap();
    let probe = probe_path(paths.part_path()).unwrap();
    std::fs::write(&probe, b"left by a crash").unwrap();

    ContentFileStore::delete_part(&paths).await.unwrap();
    assert!(!paths.part_path().exists());
    assert!(!probe.exists(), "the probe file goes with the part file");
}

#[test]
fn the_scan_passes_over_the_probe_file() {
    let probe = probe_path(std::path::Path::new("/downloads/film.bin.part")).unwrap();
    assert_eq!(
        probe.file_name().unwrap(),
        ".film.bin.part.holeprobe",
        "beside the part file"
    );
    assert!(crate::directory_scan::plan::skipped_name(
        probe.file_name().unwrap()
    ));
}
