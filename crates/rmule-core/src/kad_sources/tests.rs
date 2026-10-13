//! The Kad Discovery Channel and the Kad Publisher against a fake Kad
//! channel and the durable registry: routed sources, one publish per
//! offered file — a Partial Share included — withdrawal and re-publication,
//! and a failed registry read.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule_primitives::{ClientId, FileHash, PeerSource, SourceLookupTarget, SourceSighting};
use tokio::sync::mpsc;

use super::{KadDiscoveryChannel, KadPublisher, KadSourceRegistry};
use crate::adapters::KadSourceChannel;
use crate::registry::{ShareSource, SharedFileEntry};
use crate::registry_check::{WithheldReason, WithheldRows};
use crate::source_discovery::SourceDiscovery;
use crate::store::registry::DurableSharedFileRegistry;

/// A fake Kad channel: records every issued publish and (when configured)
/// answers each search for `known_hash` with `sources` — mirroring a storer
/// answering the walk.
struct FakeKadChannel {
    publishes_tx: mpsc::UnboundedSender<SourceLookupTarget>,
    withdraws_tx: mpsc::UnboundedSender<SourceLookupTarget>,
    answer: Option<(FileHash, Vec<SourceSighting>)>,
    answers_tx: mpsc::Sender<(FileHash, Vec<SourceSighting>)>,
    answers_rx: tokio::sync::Mutex<mpsc::Receiver<(FileHash, Vec<SourceSighting>)>>,
}

struct FakeKadChannelProbes {
    publishes: mpsc::UnboundedReceiver<SourceLookupTarget>,
    withdraws: mpsc::UnboundedReceiver<SourceLookupTarget>,
}

fn fake_channel(
    answer: Option<(FileHash, Vec<SourceSighting>)>,
) -> (FakeKadChannel, FakeKadChannelProbes) {
    let (publishes_tx, publishes) = mpsc::unbounded_channel();
    let (withdraws_tx, withdraws) = mpsc::unbounded_channel();
    let (answers_tx, answers_rx) = mpsc::channel(8);
    (
        FakeKadChannel {
            publishes_tx,
            withdraws_tx,
            answer,
            answers_tx,
            answers_rx: tokio::sync::Mutex::new(answers_rx),
        },
        FakeKadChannelProbes {
            publishes,
            withdraws,
        },
    )
}

impl KadSourceChannel for FakeKadChannel {
    async fn search_sources(&self, target: SourceLookupTarget) {
        if let Some((hash, sources)) = &self.answer
            && *hash == target.file_hash()
        {
            let _ = self.answers_tx.send((*hash, sources.clone())).await;
        }
    }

    async fn publish_source(&self, target: SourceLookupTarget) {
        let _ = self.publishes_tx.send(target);
    }

    async fn withdraw_source(&self, target: SourceLookupTarget) {
        let _ = self.withdraws_tx.send(target);
    }

    async fn next_sources(&self) -> Option<(FileHash, Vec<SourceSighting>)> {
        self.answers_rx.lock().await.recv().await
    }
}

/// Build the discovery engine over a Kad adapter wrapping `channel`.
fn engine<C: KadSourceChannel>(
    channel: C,
    downloads: KadSourceRegistry,
    sweep: Duration,
    reask: Duration,
) -> SourceDiscovery<KadDiscoveryChannel<C>> {
    SourceDiscovery::new(KadDiscoveryChannel::new(channel), downloads, sweep, reask)
}

#[tokio::test]
async fn asks_kad_and_routes_found_sources_to_the_matching_download() {
    let file_hash = FileHash::from_bytes([0x21; FileHash::BYTE_LEN]);
    let source = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 9])), 4662);
    let (channel, _probes) = fake_channel(Some((file_hash, vec![SourceSighting::plain(source)])));

    let downloads: KadSourceRegistry = Arc::new(Mutex::new(HashMap::new()));
    let (sink_tx, mut sink_rx) = mpsc::channel(8);
    downloads.lock().unwrap().insert(file_hash, (4096, sink_tx));

    let task = tokio::spawn(
        engine(
            channel,
            downloads,
            Duration::from_millis(10),
            Duration::from_secs(3600),
        )
        .run(),
    );

    let routed = tokio::time::timeout(Duration::from_secs(2), sink_rx.recv())
        .await
        .expect("a Kad source routed within 2s")
        .expect("sink stayed open");
    assert_eq!(routed, vec![SourceSighting::plain(source)]);

    task.abort();
}

#[tokio::test]
async fn publishes_each_shared_file_exactly_once() {
    let file_hash = FileHash::from_bytes([0x44; FileHash::BYTE_LEN]);
    let (channel, mut probes) = fake_channel(None);

    let shared = DurableSharedFileRegistry::new(rmule_testkit::memory_store());
    crate::registry::SharedFileRegistry::share(
        &shared,
        SharedFileEntry {
            file_hash,
            file_size: 9000,
            path: PathBuf::from("/tmp/shared.bin"),
            name: "shared.bin".to_owned(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        },
    )
    .unwrap();

    // The **Kad Publisher** is registry-driven — no download registered
    // anywhere, so this proves publishing with zero active downloads.
    let (share_changed_tx, share_changed_rx) = mpsc::channel(8);
    let task = tokio::spawn(
        KadPublisher::new(
            channel,
            Arc::new(shared),
            WithheldRows::default(),
            Default::default(),
            share_changed_rx,
        )
        .run(),
    );

    // The file already in the registry is published by the start-up sweep.
    let first = tokio::time::timeout(Duration::from_secs(2), probes.publishes.recv())
        .await
        .expect("the shared file is published within 2s")
        .expect("channel open");
    assert_eq!(first.file_hash(), file_hash);
    assert_eq!(first.file_size(), 9000);

    // Many re-sweeps later: still exactly one publish — republish belongs to
    // the Kad node's own 5-hour cadence, not this task.
    for _ in 0..5 {
        share_changed_tx.send(()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        probes.publishes.try_recv().is_err(),
        "a shared file registers for publish exactly once"
    );

    task.abort();
}

#[tokio::test]
async fn a_withheld_file_is_withdrawn_and_published_again_once_offered() {
    let file_hash = FileHash::from_bytes([0x45; FileHash::BYTE_LEN]);
    let (channel, mut probes) = fake_channel(None);
    let shared = DurableSharedFileRegistry::new(rmule_testkit::memory_store());
    crate::registry::SharedFileRegistry::share(
        &shared,
        SharedFileEntry {
            file_hash,
            file_size: 9000,
            path: PathBuf::from("/tmp/shared.bin"),
            name: "shared.bin".to_owned(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        },
    )
    .unwrap();
    let withheld = WithheldRows::default();
    let (share_changed_tx, share_changed_rx) = mpsc::channel(8);
    let task = tokio::spawn(
        KadPublisher::new(
            channel,
            Arc::new(shared),
            withheld.clone(),
            Default::default(),
            share_changed_rx,
        )
        .run(),
    );
    let wait = Duration::from_secs(2);
    let first = tokio::time::timeout(wait, probes.publishes.recv()).await;
    assert_eq!(first.unwrap().unwrap().file_hash(), file_hash);

    withheld.withhold(
        file_hash,
        WithheldReason::FolderMissing,
        std::time::SystemTime::now(),
    );
    share_changed_tx.send(()).await.unwrap();
    let withdrawn = tokio::time::timeout(wait, probes.withdraws.recv()).await;
    assert_eq!(withdrawn.unwrap().unwrap().file_hash(), file_hash);

    withheld.lift(file_hash);
    share_changed_tx.send(()).await.unwrap();
    let again = tokio::time::timeout(wait, probes.publishes.recv()).await;
    assert_eq!(
        again.unwrap().unwrap().file_hash(),
        file_hash,
        "offered again, it is published again"
    );
    task.abort();
}

#[tokio::test]
async fn a_partial_share_is_published_once_and_withdrawn_when_its_download_ends() {
    use crate::served_downloads::{PartialEnd, ServedDownloads};
    use crate::storage::DownloadRepository;
    use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, Ed2kText, PartHash};

    let file_hash = FileHash::from_bytes([0x46; FileHash::BYTE_LEN]);
    let size = 2 * ED2K_PART_SIZE + 5;
    let set: Vec<PartHash> = (0..3)
        .map(|part| PartHash::from_bytes([part; 16]))
        .collect();
    let store = rmule_testkit::memory_store();
    let downloads = crate::store::download::DurableDownloadRepository::new(store.clone());
    let link = Ed2kFileLink {
        name: Ed2kText::from_utf8("partial.bin"),
        size,
        file_hash,
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let paths = crate::DownloadPaths::from_final_path("/downloads/partial.bin".into());
    let record = downloads.create_download(&link, None, &paths).unwrap();
    let served = ServedDownloads::default();
    assert!(served.install(&record, &set));
    let lease = served.hand_to_run(file_hash, 1).unwrap();
    lease.record_range(
        &set,
        &[crate::VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: ED2K_PART_SIZE,
            part_hash: set[0],
        }],
    );

    let (channel, mut probes) = fake_channel(None);
    let (share_changed_tx, share_changed_rx) = mpsc::channel(8);
    let task = tokio::spawn(
        KadPublisher::new(
            channel,
            Arc::new(DurableSharedFileRegistry::new(store)),
            WithheldRows::default(),
            served.clone(),
            share_changed_rx,
        )
        .run(),
    );
    let wait = Duration::from_secs(2);
    let first = tokio::time::timeout(wait, probes.publishes.recv()).await;
    let first = first.unwrap().unwrap();
    assert_eq!((first.file_hash(), first.file_size()), (file_hash, size));
    for _ in 0..3 {
        share_changed_tx.send(()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(probes.publishes.try_recv().is_err(), "published once");

    served.take_back(file_hash, 1);
    assert!(served.end(record.id(), PartialEnd::Ended));
    share_changed_tx.send(()).await.unwrap();
    let withdrawn = tokio::time::timeout(wait, probes.withdraws.recv()).await;
    assert_eq!(withdrawn.unwrap().unwrap().file_hash(), file_hash);
    task.abort();
}

/// The registry behind a switch: while `failing`, `list` fails as a broken
/// store read would; every `list` call is reported on `listed`.
struct FlakyRegistry {
    inner: DurableSharedFileRegistry,
    failing: std::sync::atomic::AtomicBool,
    listed: mpsc::UnboundedSender<bool>,
}

impl crate::registry::SharedFileRegistry for FlakyRegistry {
    fn share(&self, entry: SharedFileEntry) -> Result<(), crate::error::CoreError> {
        self.inner.share(entry)
    }
    fn unshare(&self, file_hash: FileHash) -> Result<bool, crate::error::CoreError> {
        self.inner.unshare(file_hash)
    }
    fn gone(
        &self,
        file_hash: FileHash,
        path: &std::path::Path,
    ) -> Result<bool, crate::error::CoreError> {
        self.inner.gone(file_hash, path)
    }
    fn get(&self, file_hash: FileHash) -> Result<Option<SharedFileEntry>, crate::error::CoreError> {
        self.inner.get(file_hash)
    }
    fn list(&self) -> Result<Vec<SharedFileEntry>, crate::error::CoreError> {
        let failing = self.failing.load(std::sync::atomic::Ordering::SeqCst);
        let _ = self.listed.send(!failing);
        if failing {
            return Err(crate::error::CoreError::Repository(
                "read failed".to_owned(),
            ));
        }
        self.inner.list()
    }
    fn hash_set(
        &self,
        file_hash: FileHash,
    ) -> Result<Option<Vec<rmule_primitives::PartHash>>, crate::error::CoreError> {
        self.inner.hash_set(file_hash)
    }
}

fn shared_entry(byte: u8) -> SharedFileEntry {
    SharedFileEntry {
        file_hash: FileHash::from_bytes([byte; FileHash::BYTE_LEN]),
        file_size: 9000,
        path: PathBuf::from(format!("/tmp/shared-{byte}.bin")),
        name: format!("shared-{byte}.bin"),
        source: ShareSource::Explicit,
        modified: None,
        part_hashes: Vec::new(),
    }
}

/// An unreadable registry says nothing about the offer: the sweep keeps
/// every publication, and the publisher sweeps again on its own once the
/// read can succeed.
#[tokio::test(start_paused = true)]
async fn a_failed_registry_read_withdraws_nothing_and_the_sweep_is_retried() {
    use crate::registry::SharedFileRegistry as _;

    let (channel, mut probes) = fake_channel(None);
    let (listed_tx, mut listed) = mpsc::unbounded_channel();
    let registry = Arc::new(FlakyRegistry {
        inner: DurableSharedFileRegistry::new(rmule_testkit::memory_store()),
        failing: std::sync::atomic::AtomicBool::new(false),
        listed: listed_tx,
    });
    registry.share(shared_entry(0x46)).unwrap();
    let (share_changed_tx, share_changed_rx) = mpsc::channel(8);
    let task = tokio::spawn(
        KadPublisher::new(
            channel,
            Arc::clone(&registry),
            WithheldRows::default(),
            Default::default(),
            share_changed_rx,
        )
        .run(),
    );
    assert_eq!(listed.recv().await, Some(true));
    let first = probes.publishes.recv().await.expect("channel open");
    assert_eq!(first.file_hash(), shared_entry(0x46).file_hash);

    registry
        .failing
        .store(true, std::sync::atomic::Ordering::SeqCst);
    share_changed_tx.send(()).await.unwrap();
    assert_eq!(
        listed.recv().await,
        Some(false),
        "the sweep read and failed"
    );
    // The publisher is parked again, so the failed sweep has run to its end.
    assert!(
        probes.withdraws.try_recv().is_err(),
        "a failed read withdraws nothing"
    );

    // A file shared meanwhile is published by the retry, with no change sent.
    registry.share(shared_entry(0x47)).unwrap();
    registry
        .failing
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(listed.recv().await, Some(true), "the sweep is retried");
    let retried = probes.publishes.recv().await.expect("channel open");
    assert_eq!(retried.file_hash(), shared_entry(0x47).file_hash);
    assert!(probes.withdraws.try_recv().is_err());

    task.abort();
}
