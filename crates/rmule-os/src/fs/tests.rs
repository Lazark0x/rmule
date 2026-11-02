//! The exclusive rename on real files in a temporary directory: CI runs it on
//! ext4 (Linux), APFS (macOS) and NTFS (Windows), each of which takes the
//! flag, so `Unsupported` here fails the test.

use super::rename_exclusive;

#[test]
fn a_rename_onto_a_standing_file_is_refused_and_leaves_both() {
    let dir = tempfile::tempdir().unwrap();
    let (from, to) = (
        dir.path().join("film.mkv.part"),
        dir.path().join("film.mkv"),
    );
    std::fs::write(&from, b"finished").unwrap();
    std::fs::write(&to, b"the operator's own").unwrap();

    let refused = rename_exclusive(&from, &to).unwrap_err();

    assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&from).unwrap(), b"finished");
    assert_eq!(std::fs::read(&to).unwrap(), b"the operator's own");
}

#[test]
fn a_rename_onto_a_free_name_moves_the_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("dl")).unwrap();
    let (from, to) = (
        dir.path().join("film.mkv.part"),
        dir.path().join("dl/film.mkv"),
    );
    std::fs::write(&from, b"finished").unwrap();

    rename_exclusive(&from, &to).unwrap();

    assert!(!from.exists());
    assert_eq!(std::fs::read(&to).unwrap(), b"finished");
}
