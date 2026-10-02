//! The [`SharedFileRegistry`] contract asserted against every implementation:
//! share, reshare, unshare, and list, plus the part hash set that has to
//! survive a reopen — and, at the end, the serve-side consequence of a whole
//! listed row: a restarted core answering a hash-set probe for a file shared
//! before the restart. The contract legs run twice — on the engine's
//! in-memory backend and on a real file — because only the file proves what a
//! restart re-offers.
use rmule_core::SharedFileRegistry;
use std::net::SocketAddrV4;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreError, CoreEvent, DurableSharedFileRegistry, ServeCommand,
    ServeConnCommand, ServeConnEvent, ServeConnection, ServeEvent, ServeRuntimeService,
    ShareSource, SharedFileEntry, open_durable_store,
};
use rmule_ed2k::OfferedFile;
use rmule_primitives::{ClientId, ED2K_PART_SIZE, FileHash, PartHash, PeerSource};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use crate::fixture::{durable_shared_file_registry, identity};

fn entry(hash: u8, path: &str, source: ShareSource) -> SharedFileEntry {
    SharedFileEntry {
        file_hash: FileHash::from_bytes([hash; FileHash::BYTE_LEN]),
        file_size: 9_728_001,
        path: PathBuf::from(path),
        name: "shared.bin".to_string(),
        source,
        modified: None,
        part_hashes: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// The Durable Store registry (ADR-0083)
// ---------------------------------------------------------------------------

/// A two-hash set, the smallest one a file above one part can have.
fn part_hashes() -> Vec<PartHash> {
    vec![
        PartHash::from_bytes([0xAA; PartHash::BYTE_LEN]),
        PartHash::from_bytes([0xBB; PartHash::BYTE_LEN]),
    ]
}

fn durable_file_registry(dir: &Path) -> DurableSharedFileRegistry {
    DurableSharedFileRegistry::new(open_durable_store(dir).expect("store opens"))
}

/// Run `check` on each backend the durable registry ships on, naming the one
/// that failed. Every method takes `&self`, so the check never needs `mut`.
fn on_each_store(check: impl Fn(&DurableSharedFileRegistry)) {
    let dir = tempfile::tempdir().unwrap();
    let backends = [
        ("memory", durable_shared_file_registry()),
        ("file", durable_file_registry(dir.path())),
    ];
    for (label, registry) in backends {
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| check(&registry)));
        assert!(outcome.is_ok(), "failed on the {label} store");
    }
}

#[test]
fn durable_share_then_get_returns_the_entry() {
    on_each_store(|reg| {
        let mut shared = entry(0x11, "/data/shared.bin", ShareSource::Explicit);
        shared.part_hashes = part_hashes();
        reg.share(shared.clone()).unwrap();

        assert_eq!(reg.get(shared.file_hash).unwrap(), Some(shared));
        let never_shared = FileHash::from_bytes([0x00; FileHash::BYTE_LEN]);
        assert_eq!(reg.get(never_shared).unwrap(), None);
        assert_eq!(reg.hash_set(never_shared).unwrap(), None);
    });
}

#[test]
fn durable_resharing_replaces_the_row_and_its_part_hash_set() {
    on_each_store(|reg| {
        let hash = FileHash::from_bytes([0x33; FileHash::BYTE_LEN]);
        reg.share(SharedFileEntry {
            file_hash: hash,
            file_size: 1,
            path: PathBuf::from("/old.bin"),
            name: "old.bin".to_string(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: part_hashes(),
        })
        .unwrap();

        reg.share(SharedFileEntry {
            file_hash: hash,
            file_size: 2,
            path: PathBuf::from("/new.bin"),
            name: "new.bin".to_string(),
            source: ShareSource::CompletedDownload,
            modified: None,
            part_hashes: part_hashes()[..1].to_vec(),
        })
        .unwrap();

        let got = reg.get(hash).unwrap().unwrap();
        assert_eq!(got.path, PathBuf::from("/new.bin"));
        assert_eq!(got.file_size, 2);
        assert_eq!(got.source, ShareSource::CompletedDownload);
        assert_eq!(reg.list().unwrap().len(), 1);
        // The shorter set replaced the longer one whole: nothing of the first
        // set survives the re-share.
        assert_eq!(
            reg.hash_set(hash).unwrap(),
            Some(part_hashes()[..1].to_vec())
        );
    });
}

#[test]
fn durable_unshare_takes_the_part_hashes_with_the_row() {
    on_each_store(|reg| {
        let mut shared = entry(0x22, "/data/a.bin", ShareSource::Explicit);
        shared.part_hashes = part_hashes();
        reg.share(shared.clone()).unwrap();
        assert_eq!(reg.hash_set(shared.file_hash).unwrap(), Some(part_hashes()));

        assert!(reg.unshare(shared.file_hash).unwrap()); // was present
        assert!(!reg.unshare(shared.file_hash).unwrap()); // now absent
        assert_eq!(reg.get(shared.file_hash).unwrap(), None);
        assert_eq!(reg.hash_set(shared.file_hash).unwrap(), None);

        // Re-sharing the same hash with no set at all: the hashes went with
        // the row rather than surviving it as orphans.
        shared.part_hashes = Vec::new();
        reg.share(shared.clone()).unwrap();
        assert_eq!(reg.hash_set(shared.file_hash).unwrap(), Some(Vec::new()));
    });
}

#[test]
fn durable_list_returns_every_shared_file_with_its_part_hashes() {
    on_each_store(|reg| {
        let mut first = entry(0x44, "/a.bin", ShareSource::Explicit);
        first.part_hashes = part_hashes();
        reg.share(first.clone()).unwrap();
        reg.share(entry(0x55, "/b.bin", ShareSource::CompletedDownload))
            .unwrap();

        let listed = reg.list().unwrap();
        // Rows come back in file-hash order, the store's own.
        assert_eq!(
            listed.iter().map(|e| e.file_hash).collect::<Vec<_>>(),
            vec![
                FileHash::from_bytes([0x44; FileHash::BYTE_LEN]),
                FileHash::from_bytes([0x55; FileHash::BYTE_LEN]),
            ]
        );
        // A listed row is whole: it carries the file's stored set, which is
        // what a serve state seeded from `list` answers hash-set probes out
        // of. A file below one part lists an empty set — it has none.
        assert_eq!(listed[0].part_hashes, part_hashes());
        assert!(listed[1].part_hashes.is_empty());
        // `hash_set` is now that same set projected out of the row.
        assert_eq!(reg.hash_set(first.file_hash).unwrap(), Some(part_hashes()));
    });
}

#[test]
fn durable_shared_file_and_its_hash_set_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let mut shared = entry(0x66, "/data/durable.bin", ShareSource::CompletedDownload);
    shared.part_hashes = part_hashes();
    {
        // The store holds the engine's exclusive file lock, so the reopen
        // waits for this one to be dropped.
        let registry = durable_file_registry(path);
        registry.share(shared.clone()).unwrap();
    }

    let reopened = durable_file_registry(path);

    let file_hash = shared.file_hash;
    // Whole, set and all — the row a restarted serve side re-offers *and*
    // answers probes from.
    assert_eq!(reopened.get(file_hash).unwrap(), Some(shared));
    assert_eq!(reopened.hash_set(file_hash).unwrap(), Some(part_hashes()));
}

// ---------------------------------------------------------------------------
// What a whole row is *for*: the restart
// ---------------------------------------------------------------------------

/// A serve runtime that hands the core one scripted connection and then
/// blocks: enough to put a probe in front of the serve state without a socket.
/// Announce is a no-op — the `FilesAnnounced` edge it drives is what says the
/// share-set snapshot has been seeded.
struct ScriptedServeRuntime {
    pending: Option<ServeConnection>,
}

impl ServeRuntimeService for ScriptedServeRuntime {
    async fn start(
        &mut self,
        _identity: rmule_primitives::ClientIdentity,
        _listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, CoreError> {
        Ok("127.0.0.1:4662".parse().unwrap())
    }

    async fn accept(&mut self) -> Option<ServeConnection> {
        match self.pending.take() {
            Some(conn) => Some(conn),
            None => std::future::pending().await,
        }
    }

    async fn announce(
        &mut self,
        files: Vec<OfferedFile>,
    ) -> Result<rmule_core::AnnounceOutcome, CoreError> {
        Ok(rmule_core::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }
}

/// The restart the registry's read path exists for: a multi-part file shared
/// by one session must answer `OP_HASHSETREQUEST` in the next one. The serve
/// state is seeded from `list` once, at serve start, and nothing re-reads the
/// store per probe — so an entry that arrived without its set answered every
/// probe with an empty one, for every file shared before the restart.
#[tokio::test]
async fn a_file_shared_before_a_restart_answers_a_hash_set_probe_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let file_hash = FileHash::from_bytes([0x77; FileHash::BYTE_LEN]);
    // On disk, as a row must be to be offered (sparse: nothing is read).
    let shared = dir.path().join("restarted.bin");
    std::fs::File::create(&shared)
        .unwrap()
        .set_len(2 * ED2K_PART_SIZE)
        .unwrap();
    {
        // The session before the restart. Both handles die with the block, so
        // the engine's exclusive file lock is free for the one that follows.
        let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
        registry
            .share(SharedFileEntry {
                file_hash,
                file_size: 2 * ED2K_PART_SIZE,
                path: shared.clone(),
                name: "restarted.bin".to_string(),
                source: ShareSource::Explicit,
                modified: None,
                part_hashes: part_hashes(),
            })
            .unwrap();
    }

    // The restarted session: a real core on the same store file, sharing
    // nothing of its own, with the registry its builder opens there.
    let peer = PeerSource::new(ClientId::from_u32(0x0100_007F), 5001)
        .as_peer_endpoint()
        .unwrap();
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (evt_tx, evt_rx) = mpsc::channel(16);
    let mut core = Core::builder(
        CoreConfig::default(),
        open_durable_store(dir.path()).unwrap(),
    )
    .source_lookup(rmule_testkit::PendingSourceLookup)
    .peer_transfer(rmule_testkit::RefusingPeerTransfer)
    .serve_runtime(ScriptedServeRuntime {
        pending: Some(ServeConnection::new(peer, cmd_tx, evt_rx)),
    })
    .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
        credentials: identity().into(),
    }))
    .await
    .unwrap();
    // The re-offer of the pre-restart share: the snapshot the probe is
    // answered from is now seeded.
    loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted the announce")
            .expect("core event stream stayed open");
        if let CoreEvent::Serve(ServeEvent::FilesAnnounced { file_count }) = event {
            assert_eq!(file_count, 1, "the restarted session re-offers the share");
            break;
        }
    }

    evt_tx
        .send(ServeConnEvent::HashSetRequested { file_hash })
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), cmd_rx.recv())
            .await
            .expect("the probe was answered")
            .expect("the connection stayed open"),
        ServeConnCommand::AnswerHashSet {
            file_hash,
            part_hashes: part_hashes(),
        },
        "the set the file was shared with, not an empty one",
    );
}
