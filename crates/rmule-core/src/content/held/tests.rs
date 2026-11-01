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
    held.write_blocks(vec![(0, PART.to_vec())])
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
        held.write_blocks(vec![(PART.len() as u64, PART.to_vec())])
            .await,
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
        held.write_blocks(vec![(PART.len() as u64, PART.to_vec())])
            .await,
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
        held.write_blocks(vec![(PART.len() as u64, PART.to_vec())])
            .await,
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
    held.write_blocks(vec![(0, first.clone())]).await.unwrap();
    let allocated = held
        .write_blocks(vec![(2 * part, third.clone())])
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

/// exFAT gives an empty file a made-up number and the first write a real one,
/// through the handle and the path alike, so a held file changes key without
/// changing file. No file system CI mounts does this: run it by hand with
/// `RMULE_TEST_VOLUME` set to a directory on an exFAT volume.
#[tokio::test]
#[ignore = "needs a volume that renumbers a file at its first write"]
async fn a_first_write_that_renumbers_the_file_is_no_replacement() {
    let volume = std::env::var_os("RMULE_TEST_VOLUME").expect("RMULE_TEST_VOLUME");
    let dir = tempfile::tempdir_in(volume).unwrap();
    let path = dir.path().join("renumbered.part");
    let (mut held, _) = HeldPartFile::hold(&path, 0).await.unwrap();

    held.write_blocks(vec![(0, vec![1; 4096])]).await.unwrap();
    held.write_blocks(vec![(4096, vec![2; 4096])])
        .await
        .unwrap();

    assert_eq!(held.check().await, Ok(()));
}

/// The directory a by-hand measurement runs in, on `RMULE_TEST_VOLUME`.
fn on_test_volume() -> tempfile::TempDir {
    let volume = std::env::var_os("RMULE_TEST_VOLUME").expect("RMULE_TEST_VOLUME");
    tempfile::tempdir_in(volume).unwrap()
}

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Windows refuses to rename a directory holding an open file"
)]
async fn a_path_gone_with_the_file_whole_is_no_loss() {
    path_gone_with_the_file_whole(&tempfile::tempdir().unwrap()).await;
}

#[tokio::test]
#[ignore = "by hand, RMULE_TEST_VOLUME on an exFAT volume"]
async fn a_path_gone_with_the_file_whole_is_no_loss_on_the_test_volume() {
    path_gone_with_the_file_whole(&on_test_volume()).await;
}

async fn path_gone_with_the_file_whole(dir: &tempfile::TempDir) {
    let parent = dir.path().join("mounted");
    std::fs::create_dir(&parent).unwrap();
    let (mut held, _) = held_with_one_part(&parent).await;
    std::fs::rename(&parent, dir.path().join("elsewhere")).unwrap();

    assert_eq!(held.check().await, Err(HeldCheckFailed::PathAbsent));
    assert!(matches!(
        held.write_blocks(vec![(PART.len() as u64, PART.to_vec())])
            .await,
        Err(HeldWriteError::PathAbsent)
    ));
    assert_eq!(
        std::fs::read(dir.path().join("elsewhere/film.bin.part")).unwrap(),
        PART,
        "nothing was written into the file"
    );
}

/// exFAT keeps no link count of its own: what a removed file reads decides
/// whether the run says `Gone` or stops and lets the next hold say it.
#[tokio::test]
#[ignore = "by hand, RMULE_TEST_VOLUME on an exFAT volume"]
async fn a_removed_part_file_on_the_test_volume_keeps_or_drops_by_its_links() {
    let dir = on_test_volume();
    let (held, path) = held_with_one_part(dir.path()).await;
    std::fs::remove_file(&path).unwrap();

    let found = held.check().await;
    eprintln!("a removed file reads {found:?}");
    assert!(matches!(
        found,
        Err(HeldCheckFailed::Changed(PartFileChange::Gone) | HeldCheckFailed::PathAbsent)
    ));
    assert!(matches!(
        HeldPartFile::hold(&path, PART.len() as u64).await,
        Err(HeldWriteError::Changed(PartFileChange::Gone))
    ));
}

/// A nearly full volume stops the write before it can answer `ENOSPC` or
/// `EINVAL`, and with space back the same handle writes on.
#[tokio::test]
#[ignore = "by hand, RMULE_TEST_VOLUME on an exFAT volume with room to fill"]
async fn a_volume_under_the_floor_refuses_the_part_and_takes_it_with_space_back() {
    use std::io::Write as _;
    let dir = on_test_volume();
    let (mut held, _) = held_with_one_part(dir.path()).await;
    let ballast_path = dir.path().join("ballast");
    let mut ballast = std::fs::File::create(&ballast_path).unwrap();
    let block = vec![0_u8; 1024 * 1024];
    while rmule_os::volume::free_bytes(dir.path()).unwrap() >= 2 * block.len() as u64 {
        ballast.write_all(&block).unwrap();
    }
    ballast.sync_all().unwrap();

    let part = vec![7_u8; 1024];
    let refused = held
        .write_blocks(vec![(PART.len() as u64, part.clone())])
        .await;
    assert!(
        matches!(refused, Err(HeldWriteError::OutOfSpace { .. })),
        "{refused:?}"
    );

    drop(ballast);
    std::fs::remove_file(&ballast_path).unwrap();
    held.write_blocks(vec![(PART.len() as u64, part.clone())])
        .await
        .unwrap();
}

/// Every file made from a name at the cap fits: the part file, the probe's
/// and the copy's, the number included.
#[tokio::test]
async fn a_name_at_its_cap_fits_every_file_made_from_it() {
    names_fit(tempfile::tempdir().unwrap().path());
}

#[tokio::test]
#[ignore = "by hand, RMULE_TEST_VOLUME on an exFAT volume"]
async fn a_name_at_its_cap_fits_every_file_made_from_it_on_the_test_volume() {
    names_fit(on_test_volume().path());
}

fn names_fit(dir: &Path) {
    use rmule_primitives::{FileHash, SafeFileName};
    let hash = FileHash::from_bytes([1; FileHash::BYTE_LEN]);
    let long = format!("{}.mkv", "a".repeat(600));
    let name = SafeFileName::clean(&long, &hash);
    let numbered = crate::free_name::numbered(name.as_str(), 99_999);
    let final_path = name.path_in(dir);
    let part = dir.join(format!("{numbered}.part"));
    for path in [
        final_path.clone(),
        part.clone(),
        crate::content::copy_path(&dir.join(&numbered)),
    ] {
        std::fs::write(&path, b"fits").unwrap();
    }
    std::fs::write(sparse::probe_path(&part).unwrap(), b"fits").unwrap();
}

#[tokio::test]
async fn a_file_longer_than_the_download_is_cut_to_its_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("left.part");
    std::fs::write(&path, b"verified bytes and a leftover tail").unwrap();
    let (held, _) = HeldPartFile::hold(&path, 0).await.unwrap();

    held.cut_to(8).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"verified");
    held.cut_to(100).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"verified", "never grown");
}
