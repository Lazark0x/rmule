//! The list and the set-aside rows against a real store: the add and the
//! remove as the operator's two steps, and the climb from version 10.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rmule_primitives::{FileHash, PartHash};
use rmule_store::Ladder;

use super::SetAsideRuling;
use crate::directory_scan::{FileIdentity, FileStamp, SpareCopy};
use crate::registry::{ShareSource, SharedFileEntry, SharedFileRegistry};
use crate::store::registry::DurableSharedFileRegistry;
use crate::store::{DURABLE_STORE_FILE, DurableStore, open_durable_store};

const FILM: FileHash = FileHash::from_bytes([
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
]);
const SONG: FileHash = FileHash::from_bytes([
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0,
]);

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn row(file_hash: FileHash, path: &str) -> SharedFileEntry {
    SharedFileEntry {
        file_hash,
        file_size: 9_728_001,
        path: PathBuf::from(path),
        name: Path::new(path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        source: ShareSource::DownloadDirectory,
        part_hashes: vec![
            PartHash::from_bytes([
                0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D,
                0x8E, 0x9F,
            ]),
            PartHash::from_bytes([
                0x9F, 0x8E, 0x7D, 0x6C, 0x5B, 0x4A, 0x39, 0x28, 0x17, 0x06, 0xF5, 0xE4, 0xD3, 0xC2,
                0xB1, 0xA1,
            ]),
        ],
        modified: Some(at(1_700_000_123)),
    }
}

fn open(dir: &Path) -> DurableSharedFileRegistry {
    DurableSharedFileRegistry::new(open_durable_store(dir).unwrap())
}

#[test]
fn the_list_keeps_the_order_added_and_a_parent_takes_its_childs_place() {
    let dir = tempfile::tempdir().unwrap();
    {
        let registry = open(dir.path());
        for added in ["/media/films", "/media/books", "/archive"] {
            registry
                .add_shared_directory(Path::new(added), &[])
                .unwrap();
        }
        registry
            .add_shared_directory(
                Path::new("/media"),
                &[PathBuf::from("/media/films"), PathBuf::from("/media/books")],
            )
            .unwrap();
    }
    assert_eq!(
        open(dir.path()).shared_directories().unwrap(),
        [PathBuf::from("/archive"), PathBuf::from("/media")]
    );
}

#[test]
fn a_remove_sets_its_rows_aside_unshared_and_not_had() {
    let dir = tempfile::tempdir().unwrap();
    let registry = open(dir.path());
    registry
        .add_shared_directory(Path::new("/media"), &[])
        .unwrap();
    let film = row(FILM, "/media/film.mkv");
    registry.share(film.clone()).unwrap();
    registry.share(row(SONG, "/dl/song.ogg")).unwrap();

    let rulings = registry
        .remove_shared_directory(Path::new("/media"), &[])
        .unwrap();
    assert_eq!(rulings, Some(vec![SetAsideRuling::Left(FILM)]));
    assert!(registry.get(FILM).unwrap().is_none());
    assert!(registry.get(SONG).unwrap().is_some(), "outside, untouched");
    assert!(registry.had_set().list().unwrap().is_empty());
    assert!(registry.shared_directories().unwrap().is_empty());
    let aside = registry.set_asides().unwrap();
    assert_eq!(aside.len(), 1);
    assert_eq!(aside[0].entry, film, "everything a share needs, unread");
    assert_eq!(
        registry
            .remove_shared_directory(Path::new("/media"), &[])
            .unwrap(),
        None,
        "not listed any more"
    );

    // Shared again at its path, the row takes the set-aside one's place.
    registry.share(film).unwrap();
    assert!(registry.set_asides().unwrap().is_empty());
}

#[test]
fn a_row_with_a_spare_elsewhere_moves_there_and_the_spare_under_the_directory_is_set_aside() {
    let dir = tempfile::tempdir().unwrap();
    let registry = open(dir.path());
    registry
        .add_shared_directory(Path::new("/media"), &[])
        .unwrap();
    registry.share(row(FILM, "/media/film.mkv")).unwrap();
    registry.share(row(SONG, "/dl/song.ogg")).unwrap();
    let copy = |path: &str, file_hash| SpareCopy {
        path: PathBuf::from(path),
        file_hash,
        stamp: FileStamp {
            size: 9_728_001,
            modified: at(1_700_000_456),
        },
        identity: Some(FileIdentity {
            device: 3,
            inode: 90_210,
            born: at(1_600_000_007),
        }),
    };
    assert!(
        registry
            .record_spare(&copy("/dl/film copy.mkv", FILM))
            .unwrap()
    );
    assert!(
        registry
            .record_spare(&copy("/media/song copy.ogg", SONG))
            .unwrap()
    );

    let rulings = registry
        .remove_shared_directory(Path::new("/media"), &[PathBuf::from("/dl")])
        .unwrap();
    assert_eq!(rulings, Some(vec![SetAsideRuling::Moved(FILM)]));
    let moved = registry.get(FILM).unwrap().unwrap();
    assert_eq!(moved.path, Path::new("/dl/film copy.mkv"));
    assert_eq!(moved.part_hashes, row(FILM, "/x").part_hashes);
    assert!(registry.spares().unwrap().is_empty());
    let mut aside: Vec<PathBuf> = registry
        .set_asides()
        .unwrap()
        .into_iter()
        .map(|aside| aside.entry.path)
        .collect();
    aside.sort();
    assert_eq!(
        aside,
        [
            PathBuf::from("/media/film.mkv"),
            PathBuf::from("/media/song copy.ogg")
        ]
    );
}

#[test]
fn a_remove_keeps_the_rows_under_a_directory_it_covered() {
    let dir = tempfile::tempdir().unwrap();
    let registry = open(dir.path());
    registry
        .add_shared_directory(Path::new("/home/op/files"), &[])
        .unwrap();
    registry
        .share(row(FILM, "/home/op/files/rmule/film.mkv"))
        .unwrap();
    let rulings = registry
        .remove_shared_directory(
            Path::new("/home/op/files"),
            &[PathBuf::from("/home/op/files/rmule")],
        )
        .unwrap();
    assert_eq!(rulings, Some(Vec::new()));
    assert!(registry.get(FILM).unwrap().is_some());
}

#[test]
fn upgrade_from_a_version_ten_store_gives_an_empty_list_and_keeps_every_row() {
    let dir = tempfile::tempdir().unwrap();
    {
        let v10 = DurableStore::open(
            dir.path().join(DURABLE_STORE_FILE),
            &crate::store::registry::schema_v10(),
            &Ladder::new(10, &[]),
        )
        .unwrap();
        v10.write(|txn| crate::store::registry::share_v10(txn, &row(FILM, "/dl/film.mkv")))
            .unwrap();
    }
    let registry = open(dir.path());
    assert!(registry.shared_directories().unwrap().is_empty());
    assert!(registry.set_asides().unwrap().is_empty());
    assert_eq!(registry.list().unwrap(), [row(FILM, "/dl/film.mkv")]);
}
