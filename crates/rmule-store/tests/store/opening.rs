//! What an open leaves behind and what it says when it cannot: a climb keeps
//! a copy of the file it found, a refused open is sorted for the operator, a
//! failed write stops the store, and one bad row costs that row.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use redb::backends::InMemoryBackend;
use rmule_store::{
    Indexed, Ladder, OpenRefusal, OpeningWatch, Record, Schema, StorageBackend, Store, StoreError,
    UpgradeStep,
};
use serde::{Deserialize, Serialize};

use crate::fixture::{DOWNLOADS, V1, download, schema_v1};

static V2_STEPS: [UpgradeStep; 1] = [UpgradeStep {
    from: 1,
    run: |_| Ok(()),
}];
const V2: Ladder = Ladder::new(2, &V2_STEPS);

fn store_at_v1(dir: &Path) -> PathBuf {
    let file = dir.join("state.redb");
    let store = Store::open(&file, &schema_v1(), &V1).unwrap();
    store
        .write(|txn| DOWNLOADS.insert(txn, &1, &download(1)))
        .unwrap();
    file
}

fn copy_at(file: &Path, version: u32) -> PathBuf {
    let name = file.file_name().unwrap().to_string_lossy();
    file.with_file_name(format!("{name}.v{version}"))
}

#[test]
fn a_file_this_open_makes_reports_no_repair() {
    let dir = tempfile::tempdir().unwrap();
    let told = Arc::new(AtomicBool::new(false));
    let heard = Arc::clone(&told);
    let watch: OpeningWatch = Arc::new(move |_| heard.store(true, Ordering::Relaxed));
    Store::open_watched(dir.path().join("new.redb"), &schema_v1(), &V1, &watch).unwrap();
    assert!(!told.load(Ordering::Relaxed), "there was no last run");
}

#[test]
fn a_climb_leaves_a_copy_the_older_ladder_still_opens() {
    let dir = tempfile::tempdir().unwrap();
    let file = store_at_v1(dir.path());
    drop(Store::open(&file, &schema_v1(), &V2).unwrap());

    let older = Store::open(copy_at(&file, 1), &schema_v1(), &V1).unwrap();
    assert_eq!(older.version().unwrap(), 1);
    assert_eq!(
        DOWNLOADS.get(&older.begin_read().unwrap(), &1).unwrap(),
        Some(download(1))
    );
}

#[test]
fn an_open_with_nothing_to_climb_leaves_no_copy() {
    let dir = tempfile::tempdir().unwrap();
    let file = store_at_v1(dir.path());
    drop(Store::open(&file, &schema_v1(), &V1).unwrap());
    assert!(!copy_at(&file, 1).exists());
}

#[test]
fn a_copy_that_fails_refuses_the_climb_and_leaves_the_file_alone() {
    let dir = tempfile::tempdir().unwrap();
    let file = store_at_v1(dir.path());
    // A directory where the partial copy goes: nothing can write it.
    let name = copy_at(&file, 1).display().to_string();
    std::fs::create_dir(format!("{name}.partial")).unwrap();

    let error = Store::open(&file, &schema_v1(), &V2).unwrap_err();
    assert!(
        matches!(error.open_refusal(), OpenRefusal::NotCopied { .. }),
        "{error:?}"
    );
    let store = Store::open(&file, &schema_v1(), &V1).unwrap();
    assert_eq!(store.version().unwrap(), 1);
}

#[test]
fn a_copy_already_there_is_the_older_and_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let file = store_at_v1(dir.path());
    std::fs::write(copy_at(&file, 1), b"kept").unwrap();
    drop(Store::open(&file, &schema_v1(), &V2).unwrap());
    assert_eq!(std::fs::read(copy_at(&file, 1)).unwrap(), b"kept");
}

#[test]
fn a_held_file_and_a_newer_file_are_told_apart() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.redb");
    let held = Store::open(&file, &schema_v1(), &V2).unwrap();
    assert_eq!(
        Store::open(&file, &schema_v1(), &V2)
            .unwrap_err()
            .open_refusal(),
        OpenRefusal::Busy
    );
    drop(held);
    assert_eq!(
        Store::open(&file, &schema_v1(), &V1)
            .unwrap_err()
            .open_refusal(),
        OpenRefusal::Newer {
            found: 2,
            current: 1
        }
    );
}

#[test]
fn a_file_that_is_not_a_store_reads_as_damaged() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.redb");
    std::fs::write(&file, vec![0xA5; 8192]).unwrap();
    assert_eq!(
        Store::open(&file, &schema_v1(), &V1)
            .unwrap_err()
            .open_refusal(),
        OpenRefusal::Damaged
    );
}

/// Memory whose writes refuse once told to, as a full disk does.
#[derive(Debug)]
struct FillingDisk {
    memory: InMemoryBackend,
    full: Arc<AtomicBool>,
}

impl FillingDisk {
    fn refuse(&self) -> io::Result<()> {
        if self.full.load(Ordering::Relaxed) {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        Ok(())
    }
}

impl StorageBackend for FillingDisk {
    fn len(&self) -> io::Result<u64> {
        self.memory.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.memory.read(offset, out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.refuse()?;
        self.memory.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.refuse()?;
        self.memory.sync_data()
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.refuse()?;
        self.memory.write(offset, data)
    }
}

#[test]
fn a_write_the_disk_refused_stops_the_store_and_it_says_so() {
    let full = Arc::new(AtomicBool::new(false));
    let disk = FillingDisk {
        memory: InMemoryBackend::new(),
        full: Arc::clone(&full),
    };
    let store = Store::open_backend(disk, &schema_v1(), &V1).unwrap();
    assert!(!store.stopped());
    store
        .write(|txn| DOWNLOADS.insert(txn, &1, &download(1)))
        .unwrap();
    assert!(!store.stopped());

    full.store(true, Ordering::Relaxed);
    store
        .write(|txn| DOWNLOADS.insert(txn, &2, &download(2)))
        .unwrap_err();
    full.store(false, Ordering::Relaxed);
    // The disk has room again; the engine still answers nothing but its latch.
    let later = store
        .write(|txn| DOWNLOADS.insert(txn, &3, &download(3)))
        .unwrap_err();
    assert!(store.stopped(), "{later:?}");
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Loose {
    flag: u8,
}

impl Record for Loose {
    const NAME: &'static str = "flagged";
    const VERSION: u32 = 1;
}

/// The same table read as a shape its bytes can break: 7 is no `bool`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Strict {
    flag: bool,
}

impl Record for Strict {
    const NAME: &'static str = "flagged";
    const VERSION: u32 = 1;
}

static LOOSE: Indexed<u64, Loose> = Indexed::new("flagged", &[]);
static STRICT: Indexed<u64, Strict> = Indexed::new("flagged", &[]);

#[test]
fn one_row_that_will_not_decode_costs_that_row() {
    let schema = Schema::new().indexed(&LOOSE);
    let store = Store::open_in_memory(&schema, &V1).unwrap();
    store
        .write(|txn| {
            LOOSE.insert(txn, &1, &Loose { flag: 1 })?;
            LOOSE.insert(txn, &2, &Loose { flag: 7 })?;
            LOOSE.insert(txn, &3, &Loose { flag: 0 })
        })
        .unwrap();

    let txn = store.begin_read().unwrap();
    assert!(STRICT.iter(&txn).is_err());
    let rows = STRICT.rows(&txn).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].1.as_ref().unwrap(), &Strict { flag: true });
    assert!(matches!(rows[1].1, Err(StoreError::Decode { .. })));
    assert_eq!(rows[2].1.as_ref().unwrap(), &Strict { flag: false });
}

#[test]
fn a_stop_is_handed_on_once() {
    let full = Arc::new(AtomicBool::new(false));
    let disk = FillingDisk {
        memory: InMemoryBackend::new(),
        full: Arc::clone(&full),
    };
    let store = Store::open_backend(disk, &schema_v1(), &V1).unwrap();
    assert!(!store.stop_to_tell());
    full.store(true, Ordering::Relaxed);
    store
        .write(|txn| DOWNLOADS.insert(txn, &1, &download(1)))
        .unwrap_err();
    store
        .write(|txn| DOWNLOADS.insert(txn, &2, &download(2)))
        .unwrap_err();
    assert!(store.stop_to_tell());
    assert!(!store.stop_to_tell());
}
