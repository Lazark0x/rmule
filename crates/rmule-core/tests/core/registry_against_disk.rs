//! The registry against the disk end to end, over a real temporary directory
//! and the real folder watch (ADR-0106, "The registry against the disk"): a
//! registry row outside every shared directory (one a lone-file share wrote
//! before the Shared Directory List) whose file vanishes while rmule runs
//! leaves the registry within seconds and joins the Had Set; one whose folder
//! goes is withheld, drops out of the announce, and the file history says why.

use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DurableSharedFileRegistry, DurableStore,
    ServeCommand, ServeConnection, ServeEvent, ServeRuntimeService, ShareSource, SharedFileEntry,
    SharedFileRegistry, WithheldReason,
};
use rmule_ed2k::OfferedFile;
use rmule_primitives::{FileHash, FileHashSummary};
use rmule_testkit::{PendingSourceLookup, RefusingPeerTransfer};

use crate::fixture::next_expected;

/// A serve runtime that accepts nobody and keeps each announce's size.
struct CountingServeRuntime {
    announced: Arc<Mutex<Vec<usize>>>,
}

impl ServeRuntimeService for CountingServeRuntime {
    async fn start(
        &mut self,
        _identity: rmule_primitives::ClientIdentity,
        _listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, rmule_core::CoreError> {
        Ok("127.0.0.1:4662".parse().unwrap())
    }

    async fn accept(&mut self) -> Option<ServeConnection> {
        std::future::pending().await
    }

    async fn announce(
        &mut self,
        files: Vec<OfferedFile>,
    ) -> Result<rmule_core::AnnounceOutcome, rmule_core::CoreError> {
        self.announced.lock().unwrap().push(files.len());
        Ok(rmule_core::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }
}

fn core(store: Arc<DurableStore>, announced: &Arc<Mutex<Vec<usize>>>) -> Core {
    Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(PendingSourceLookup)
        .peer_transfer(RefusingPeerTransfer)
        .serve_runtime(CountingServeRuntime {
            announced: Arc::clone(announced),
        })
        .build()
}

/// A stored row for `path`, as a lone-file share left it: outside every
/// shared directory, so only the registry's own folder watch looks at it.
fn stored_share(path: &std::path::Path) -> (Arc<DurableStore>, FileHash) {
    let bytes = std::fs::read(path).unwrap();
    let file_hash = FileHashSummary::digest_bytes(&bytes).file_hash();
    let store = rmule_testkit::memory_store();
    DurableSharedFileRegistry::new(Arc::clone(&store))
        .share(SharedFileEntry {
            file_hash,
            file_size: bytes.len() as u64,
            path: path.to_path_buf(),
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            source: ShareSource::Explicit,
            part_hashes: Vec::new(),
            modified: std::fs::metadata(path).unwrap().modified().ok(),
        })
        .unwrap();
    (store, file_hash)
}

fn is_serve(event: &CoreEvent, wanted: ServeEvent) -> bool {
    matches!(event, CoreEvent::Serve(serve) if *serve == wanted)
}

async fn history(core: &mut Core) -> rmule_core::file_history::FileHistory {
    core.send(CoreCommand::DumpFileHistory).await.unwrap();
    let CoreEvent::FileHistory { history } = next_expected(core, "the history", |event| {
        matches!(event, CoreEvent::FileHistory { .. })
    })
    .await
    else {
        unreachable!("matched above")
    };
    history
}

#[tokio::test]
async fn a_share_outside_the_download_directory_that_vanishes_while_running_joins_the_had_set() {
    let dir = tempfile::tempdir().unwrap();
    let music = dir.path().join("music");
    std::fs::create_dir(&music).unwrap();
    let song = music.join("song.mp3");
    std::fs::write(&song, b"a song, shared by hand").unwrap();
    let (store, file_hash) = stored_share(&song);
    let mut core = core(store, &Arc::new(Mutex::new(Vec::new())));
    // The first announce follows the check's start look, which would take
    // a file gone by then for one missing at start.
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    next_expected(&mut core, "the first announce", |event| {
        is_serve(event, ServeEvent::FilesAnnounced { file_count: 1 })
    })
    .await;

    std::fs::remove_file(&song).unwrap();
    let started = std::time::Instant::now();
    next_expected(&mut core, "the vanished share leaves", |event| {
        is_serve(event, ServeEvent::FileUnshared { file_hash })
    })
    .await;
    // Two roads end in this event: the folder watch — a registry re-read a
    // quiet after the share, then the changed folder's own quiet, at most a
    // five-second trickle, so seconds — and the withheld rows' recheck, a
    // minute on. The bound sits between them, at half the minute, so machine
    // load cannot push the first road past it while the second never meets it.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "noticed while running, not at the next start: {:?}",
        started.elapsed()
    );
    let history = history(&mut core).await;
    assert!(history.shared.is_empty());
    assert_eq!(
        history
            .had
            .iter()
            .map(|file| (file.identity.file_hash, file.name.as_str()))
            .collect::<Vec<_>>(),
        [(file_hash, "song.mp3")]
    );
    core.shutdown().await;
}

#[tokio::test]
async fn a_share_whose_folder_goes_is_withheld_and_announced_no_more() {
    let dir = tempfile::tempdir().unwrap();
    let volume = dir.path().join("volume");
    std::fs::create_dir(&volume).unwrap();
    let film = volume.join("film.mkv");
    std::fs::write(&film, b"a film on a disk that will be unplugged").unwrap();
    let announced = Arc::new(Mutex::new(Vec::new()));
    let (store, file_hash) = stored_share(&film);
    let mut core = core(store, &announced);
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    next_expected(&mut core, "the first announce", |event| {
        is_serve(event, ServeEvent::FilesAnnounced { file_count: 1 })
    })
    .await;

    std::fs::remove_dir_all(&volume).unwrap();
    next_expected(&mut core, "the row withheld", |event| {
        matches!(
            event,
            CoreEvent::Serve(ServeEvent::FileWithheld {
                file_hash: withheld,
                reason: WithheldReason::FolderMissing,
                ..
            }) if *withheld == file_hash
        )
    })
    .await;
    next_expected(&mut core, "the announce without it", |event| {
        is_serve(event, ServeEvent::FilesAnnounced { file_count: 0 })
    })
    .await;
    let history = history(&mut core).await;
    assert_eq!(
        history.shared.len(),
        1,
        "an unplugged volume is not a deletion"
    );
    assert_eq!(
        history.shared[0].withheld.map(|held| held.reason),
        Some(WithheldReason::FolderMissing)
    );
    assert!(history.had.is_empty());
    core.shutdown().await;
}
