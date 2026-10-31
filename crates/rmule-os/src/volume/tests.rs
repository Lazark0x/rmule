use std::path::Path;

use super::{free_bytes, is_fat};

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
