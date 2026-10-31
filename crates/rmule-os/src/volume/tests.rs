use std::path::Path;

use super::{free_bytes, is_fat};

/// By hand: `RMULE_TEST_VOLUME` on exFAT, and `RMULE_TEST_FAT_VOLUME`, when
/// set, on FAT.
#[test]
#[ignore = "by hand, RMULE_TEST_VOLUME on an exFAT volume"]
fn exfat_is_not_fat_and_fat_is() {
    let exfat = std::env::var_os("RMULE_TEST_VOLUME").expect("RMULE_TEST_VOLUME");
    assert!(!is_fat(Path::new(&exfat)).unwrap());
    assert!(free_bytes(Path::new(&exfat)).unwrap() > 0);
    if let Some(fat) = std::env::var_os("RMULE_TEST_FAT_VOLUME") {
        assert!(is_fat(Path::new(&fat)).unwrap());
    }
}

#[test]
fn a_directory_that_is_not_there_has_no_reading() {
    let dir = tempfile::tempdir().unwrap();
    let missing: &Path = &dir.path().join("away");
    assert_eq!(
        free_bytes(missing).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        is_fat(missing).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}
