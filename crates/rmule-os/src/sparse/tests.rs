//! The three primitives on a real file in a temporary directory: CI runs them
//! on ext4 (Linux), APFS (macOS) and NTFS (Windows).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::{allocated_bytes, punch_hole, set_sparse};

const RUN: usize = 4096;
/// Under APFS's 16 MiB zero-fill threshold: APFS allocates a gap this size
/// when a write past the end opens it, so only a working punch frees it.
const GAP: u64 = 8 * 1024 * 1024;

fn open(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("open the test file")
}

fn write_at(file: &mut File, offset: u64, bytes: &[u8]) {
    file.seek(SeekFrom::Start(offset)).expect("seek");
    file.write_all(bytes).expect("write");
}

fn read_at(file: &mut File, offset: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    file.seek(SeekFrom::Start(offset)).expect("seek");
    file.read_exact(&mut bytes).expect("read");
    bytes
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    ignore = "this platform has no punch"
)]
fn a_punched_gap_frees_its_space_and_reads_zeros() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut file = open(&dir.path().join("sparse.part"));
    set_sparse(&file).expect("set the sparse flag");

    let head = vec![0xA5u8; RUN];
    let tail = vec![0x5Au8; RUN];
    let tail_at = RUN as u64 + GAP;
    write_at(&mut file, 0, &head);
    write_at(&mut file, tail_at, &tail);
    punch_hole(&file, RUN as u64, GAP).expect("punch the gap");
    file.sync_all().expect("sync");

    let len = file.metadata().expect("metadata").len();
    assert_eq!(len, tail_at + RUN as u64, "the punch keeps the length");
    let allocated = allocated_bytes(&file).expect("allocated bytes");
    assert!(
        allocated < len / 2,
        "{allocated} bytes allocated of {len} after the punch"
    );
    assert_eq!(read_at(&mut file, 0, RUN), head);
    assert_eq!(read_at(&mut file, tail_at, RUN), tail);
    let gap = read_at(&mut file, RUN as u64, usize::try_from(GAP).unwrap());
    assert!(gap.iter().all(|&byte| byte == 0), "the gap reads zeros");
}

#[test]
fn a_dense_write_reads_its_full_allocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut file = open(&dir.path().join("dense.part"));
    let dense = vec![0x3Cu8; 1024 * 1024];
    write_at(&mut file, 0, &dense);
    file.sync_all().expect("sync");

    let allocated = allocated_bytes(&file).expect("allocated bytes");
    assert!(
        allocated >= dense.len() as u64,
        "{allocated} bytes allocated for a dense {} byte write",
        dense.len()
    );
}
