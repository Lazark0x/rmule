//! The held part file notices, at the next part, that the file at its path
//! is not the one it holds — removed, replaced or cut short — and writes
//! nothing into a file nobody can reach. A write that skips a part punches the
//! gap it opened, and the reading after it shows the space given back.

use super::*;

const PART: &[u8] = b"a verified part";

async fn held_with_one_part(dir: &Path) -> (HeldPartFile, PathBuf) {
    let path = dir.join("film.bin.part");
    let (mut held, _) = HeldPartFile::hold(&path, 0)
        .await
        .expect("hold a new part file");
    held.write_part(0, PART)
        .await
        .expect("the first part lands");
    (held, path)
}

#[tokio::test]
async fn a_new_download_creates_its_part_file_and_writes_through_the_handle() {
    let dir = tempfile::tempdir().unwrap();
    let (held, path) = held_with_one_part(dir.path()).await;
    assert_eq!(std::fs::read(&path).unwrap(), PART);
    assert_eq!(held.recorded_end, PART.len() as u64);
}

#[tokio::test]
async fn a_part_file_removed_under_the_run_is_gone_and_is_not_recreated() {
    let dir = tempfile::tempdir().unwrap();
    let (mut held, path) = held_with_one_part(dir.path()).await;
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        held.write_part(PART.len() as u64, PART).await,
        Err(HeldWriteError::Changed(PartFileChange::Gone))
    ));
    assert!(!path.exists(), "nothing recreated the part file");
}

#[tokio::test]
async fn a_part_file_replaced_under_the_run_is_not_written_into() {
    let dir = tempfile::tempdir().unwrap();
    let (mut held, path) = held_with_one_part(dir.path()).await;
    let other = dir.path().join("someone-elses.bin");
    std::fs::write(&other, b"not the part file").unwrap();
    std::fs::rename(&other, &path).unwrap();
    assert!(matches!(
        held.write_part(PART.len() as u64, PART).await,
        Err(HeldWriteError::Changed(PartFileChange::Replaced))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"not the part file");
}

#[tokio::test]
async fn a_part_file_cut_short_says_how_long_it_is_now() {
    let dir = tempfile::tempdir().unwrap();
    let (mut held, path) = held_with_one_part(dir.path()).await;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(4)
        .unwrap();
    assert!(matches!(
        held.write_part(PART.len() as u64, PART).await,
        Err(HeldWriteError::Changed(PartFileChange::Truncated {
            len: 4
        }))
    ));
}

#[tokio::test]
async fn parts_recorded_with_no_file_are_gone_at_hold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vanished.bin.part");
    assert!(matches!(
        HeldPartFile::hold(&path, 100).await,
        Err(HeldWriteError::Changed(PartFileChange::Gone))
    ));
    assert!(
        !path.exists(),
        "a download with parts recorded never recreates its file"
    );
}

/// Parts 0 and 2 of a three-part file: the one-part gap is under APFS's
/// 16 MiB fill threshold, so APFS allocates it unless the write punches it.
#[tokio::test]
async fn a_write_past_a_missing_part_punches_the_gap_it_opened() {
    const SIZE: usize = rmule_primitives::ED2K_PART_SIZE as usize;
    let part = SIZE as u64;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gapped.bin.part");
    let first = vec![0x11u8; SIZE];
    let third = vec![0x33u8; SIZE];
    let (mut held, _) = HeldPartFile::hold(&path, 0).await.unwrap();
    held.write_part(0, &first).await.unwrap();
    let allocated = held
        .write_part(2 * part, &third)
        .await
        .unwrap()
        .expect("the reading after the write");

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len() as u64, 3 * part, "the length is three parts");
    assert!(
        allocated <= 2 * part + 1024 * 1024,
        "{allocated} bytes allocated for two parts written"
    );
    assert!(bytes[..SIZE] == first[..], "part 0 reads back");
    assert!(bytes[2 * SIZE..] == third[..], "part 2 reads back");
}
