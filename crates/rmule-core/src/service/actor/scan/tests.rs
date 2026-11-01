//! What a scan costs the store: its files land in commits of many, each
//! durable, and what it reported is durable before anyone is told.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rmule_store::redb::backends::InMemoryBackend;
use rmule_store::{StorageBackend, Store};

use crate::registry::SharedFileRegistry;
use crate::service::{ScanEvent, ServeEvent};
use crate::store::{LADDER, durable_schema};
use crate::{
    Core, CoreCommand, CoreConfig, CoreEvent, CoreSettings, DurableSharedFileRegistry, ScanCommand,
};

/// Memory that counts the syncs a store asks of it, each a disk's fsync.
#[derive(Debug)]
struct CountingDisk {
    memory: InMemoryBackend,
    syncs: Arc<AtomicUsize>,
}

impl StorageBackend for CountingDisk {
    fn len(&self) -> io::Result<u64> {
        self.memory.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.memory.read(offset, out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.memory.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.syncs.fetch_add(1, Ordering::Relaxed);
        self.memory.sync_data()
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.memory.write(offset, data)
    }
}

fn counted_store() -> (Arc<Store>, Arc<AtomicUsize>) {
    let syncs = Arc::new(AtomicUsize::new(0));
    let disk = CountingDisk {
        memory: InMemoryBackend::new(),
        syncs: Arc::clone(&syncs),
    };
    let store = Store::open_backend(disk, &durable_schema(), &LADDER).unwrap();
    (Arc::new(store), syncs)
}

fn fill(dir: &Path, files: usize) {
    for at in 0..files {
        std::fs::write(dir.join(format!("{at}.bin")), at.to_le_bytes()).unwrap();
    }
}

/// The first pass over a directory the operator says yes to, to its end:
/// how many syncs the store was asked for while it ran.
async fn first_pass(
    core: &mut Core,
    dir: &Path,
    registry: &DurableSharedFileRegistry,
    syncs: &AtomicUsize,
) -> usize {
    core.settings()
        .set(crate::Setting::DownloadDir {
            dir: dir.to_path_buf(),
            share_confirmed: false,
        })
        .unwrap();
    let before = loop {
        let event = core.next_event().await.expect("the stream stays open");
        if let CoreEvent::Scan(ScanEvent::ConsentRequested { .. }) = event {
            break syncs.load(Ordering::Relaxed);
        }
    };
    core.send(CoreCommand::Scan(ScanCommand::Answer {
        dir: dir.to_path_buf(),
        share: true,
    }))
    .await
    .unwrap();
    loop {
        match core.next_event().await.expect("the stream stays open") {
            CoreEvent::Scan(ScanEvent::Finished { .. }) => {
                return syncs.load(Ordering::Relaxed) - before;
            }
            CoreEvent::Serve(ServeEvent::FileShared { file_hash }) => {
                assert!(
                    registry.get(file_hash).unwrap().is_some(),
                    "told of a file before its commit"
                );
            }
            _ => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scan_does_not_commit_per_file() {
    const FILES: usize = 400;
    let dir = tempfile::tempdir().unwrap();
    fill(dir.path(), FILES);
    let (store, syncs) = counted_store();
    let registry = DurableSharedFileRegistry::new(Arc::clone(&store));
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(CoreSettings::default())
        .build();

    let spent = tokio::time::timeout(
        rmule_testkit::HANG_GUARD,
        first_pass(&mut core, dir.path(), &registry, &syncs),
    )
    .await
    .expect("the pass ended");

    assert_eq!(registry.rows().unwrap().len(), FILES);
    assert!(spent < FILES / 4, "{spent} syncs for {FILES} files");
}

/// A pass carrying what the first one hashed, moved and copied, writes them
/// in commits of many too.
#[tokio::test(flavor = "multi_thread")]
async fn a_scan_does_not_commit_per_carried_file() {
    const FILES: usize = 400;
    let dir = tempfile::tempdir().unwrap();
    fill(dir.path(), FILES);
    let (store, syncs) = counted_store();
    let registry = DurableSharedFileRegistry::new(Arc::clone(&store));
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(CoreSettings::default())
        .build();
    tokio::time::timeout(
        rmule_testkit::HANG_GUARD,
        first_pass(&mut core, dir.path(), &registry, &syncs),
    )
    .await
    .expect("the first pass ended");
    let mut ended = core.quit();
    while ended.recv().await.is_some() {}
    for at in 0..FILES {
        let (from, to) = (format!("{at}.bin"), format!("carried {at}.bin"));
        if at % 2 == 0 {
            std::fs::rename(dir.path().join(from), dir.path().join(to)).unwrap();
        } else {
            std::fs::hard_link(dir.path().join(from), dir.path().join(to)).unwrap();
        }
    }

    let before = syncs.load(Ordering::Relaxed);
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(CoreSettings::default())
        .build();
    core.settings()
        .set(crate::Setting::DownloadDir {
            dir: dir.path().to_path_buf(),
            share_confirmed: false,
        })
        .unwrap();
    tokio::time::timeout(rmule_testkit::HANG_GUARD, async {
        while !matches!(
            core.next_event().await.expect("the stream stays open"),
            CoreEvent::Scan(ScanEvent::Finished { .. })
        ) {}
    })
    .await
    .expect("the second pass ended");
    let spent = syncs.load(Ordering::Relaxed) - before;

    let moved = registry
        .rows()
        .unwrap()
        .iter()
        .filter(|row| row.name.starts_with("carried "))
        .count();
    assert_eq!(moved, FILES / 2);
    assert_eq!(registry.spares().unwrap().len(), FILES / 2);
    assert!(spent < FILES / 4, "{spent} syncs for {FILES} carried files");
}
