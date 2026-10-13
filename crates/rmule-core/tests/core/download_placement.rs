//! Where a download lands: core places every start in the download directory
//! its Core Settings name, judged by the share guards at the start (ADR-0069,
//! ADR-0101), with its part file in the Temp Directory (ADR-0115). A command
//! names the file only, so no front end can send a download where the guards
//! would refuse to share it.

use rmule_testkit::HANG_GUARD;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, CoreSettings,
    DirectoryRefusal, DownloadCommand, DownloadEvent, DownloadId, DownloadPaths,
    DownloadRepository, DownloadedPart, DurableDownloadRepository, DurableStore, NameTaken,
    PeerDownloadOutcome, ShareGuards,
};
use rmule_primitives::{Ed2kFileLink, Ed2kLink, SafeFileName, ServerEndpoint};
use rmule_testkit::{
    FakePeer, PeerScript, StaticPeerTransfer, file_link, file_link_without_part_hash_set,
    source_with_high_id,
};
use tokio::time::timeout;

fn core_in(download_dir: Option<&Path>, guards: ShareGuards) -> Core {
    Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(CoreSettings {
            download_dir: download_dir.map(Path::to_path_buf),
            ..CoreSettings::default()
        })
        .share_guards(guards)
        .build()
}

fn start(file: Ed2kFileLink, if_taken: NameTaken) -> CoreCommand {
    CoreCommand::Download(DownloadCommand::StartDownload {
        name: SafeFileName::of_link(&file),
        file,
        source_hint: None,
        if_taken,
    })
}

/// A start's answer: its `DownloadQueued`, or the refusal in its place.
async fn verdict(core: &mut Core) -> CoreEvent {
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core answered the start")
            .expect("core event stream stayed open");
        if matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
                | CoreEvent::CommandRejected { .. }
        ) {
            return event;
        }
    }
}

#[tokio::test]
async fn a_start_with_no_download_directory_is_refused() {
    let mut core = core_in(None, ShareGuards::default());

    core.send(start(file_link("nowhere.bin", b"abc"), NameTaken::Refuse))
        .await
        .unwrap();

    let answer = verdict(&mut core).await;
    assert!(
        matches!(
            answer,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::NoDownloadDir
            }
        ),
        "got {answer:?}",
    );
    core.shutdown().await;
}

/// A download directory the guards refuse — the operator's home here — takes
/// no download, so nothing completes where it would be shared.
#[tokio::test]
async fn a_start_into_a_refused_download_directory_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let guards = ShareGuards {
        home: Some(home.path().to_path_buf()),
        data_dir: None,
    };
    let mut core = core_in(Some(home.path()), guards);

    core.send(start(file_link("home.bin", b"abc"), NameTaken::Refuse))
        .await
        .unwrap();

    let answer = verdict(&mut core).await;
    assert!(
        matches!(
            answer,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::DownloadDirRefused(
                    DirectoryRefusal::HomeDirectory
                )
            }
        ),
        "got {answer:?}",
    );
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    core.shutdown().await;
}

/// ADR-0100, re-adding a file the operator has: the copy on disk is never
/// written over. A fresh add of the name is refused; the confirmed re-add
/// lands under the first free numbered name beside it.
#[tokio::test]
async fn a_re_add_lands_beside_the_copy_on_disk() {
    let bytes = b"the same name, fetched again".to_vec();
    let peer = FakePeer::bind().await;
    let at = peer.addr();
    let file = file_link("have.bin", &bytes);
    let peer_task = peer.spawn(PeerScript::serving(file.file_hash, bytes.clone()));
    let canonical = Ed2kLink::File(file).to_string();
    let text = format!("{}sources,{at}|/", canonical.strip_suffix('/').unwrap());
    let Ok(Ed2kLink::File(linked)) = Ed2kLink::parse(&text) else {
        panic!("the link with its source stands: {text}");
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("have.bin"), b"kept").unwrap();
    let mut core = core_in(Some(dir.path()), ShareGuards::default());

    core.send(start(linked.clone(), NameTaken::Refuse))
        .await
        .unwrap();
    let answer = verdict(&mut core).await;
    assert!(
        matches!(
            answer,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::DownloadPathConflict
            }
        ),
        "got {answer:?}",
    );
    core.send(start(linked, NameTaken::Number)).await.unwrap();
    let final_path = loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { final_path, .. }) => {
                break final_path;
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            CoreEvent::CommandRejected { reason } => panic!("re-add refused: {reason:?}"),
            _ => {}
        }
    };

    assert_eq!(std::fs::read(dir.path().join("have.bin")).unwrap(), b"kept");
    assert_eq!(
        std::fs::read(dir.path().join("have (1).bin")).unwrap(),
        bytes
    );
    // The completion names the numbered file it made, not the name asked for.
    assert_eq!(
        final_path.file_name().and_then(|name| name.to_str()),
        Some("have (1).bin")
    );
    assert_eq!(std::fs::read(&final_path).unwrap(), bytes);
    core.shutdown().await;
    let _ = timeout(Duration::from_secs(5), peer_task).await;
}

/// A machine with a download directory and a data directory, apart.
struct Machine {
    _root: tempfile::TempDir,
    downloads: PathBuf,
    data: PathBuf,
}

impl Machine {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let (downloads, data) = (root.path().join("Downloads"), root.path().join("data"));
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        Self {
            _root: root,
            downloads,
            data,
        }
    }

    /// A core over `store` whose one peer serves `bytes` as one part, under
    /// `temp_dir` — or, unset, the default in the data directory.
    fn core(&self, store: Arc<DurableStore>, temp_dir: Option<PathBuf>, bytes: &[u8]) -> Core {
        Core::builder(CoreConfig::default(), store)
            .settings(CoreSettings {
                download_dir: Some(self.downloads.clone()),
                temp_dir,
                ..CoreSettings::default()
            })
            .share_guards(ShareGuards {
                home: None,
                data_dir: Some(self.data.clone()),
            })
            .source_lookup(source_with_high_id())
            .peer_transfer(StaticPeerTransfer {
                expected_plan_count: 1,
                outcome: PeerDownloadOutcome {
                    peer_hashes: Vec::new(),
                    parts: vec![DownloadedPart {
                        part_index: 0,
                        offset: 0,
                        bytes: bytes.to_vec(),
                    }],
                },
            })
            .build()
    }
}

fn server() -> ServerEndpoint {
    ServerEndpoint::new("127.0.0.1", 4661).unwrap()
}

/// Where a started download's bytes lie as it is queued — empty for a
/// resume, which is not queued again — and where it finished.
async fn queued_then_completed(core: &mut Core) -> (PathBuf, PathBuf) {
    let mut queued = None;
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued { file_path, .. }) => {
                queued = Some(file_path);
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { final_path, .. }) => {
                return (queued.unwrap_or_default(), final_path);
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            CoreEvent::CommandRejected { reason } => panic!("start refused: {reason:?}"),
            _ => {}
        }
    }
}

/// A new download fills its part file in the Temp Directory — `Temp` in the
/// data directory when the operator set none — and finishes in the download
/// directory, leaving no part file behind.
#[tokio::test]
async fn a_new_download_fills_in_the_temp_directory_and_finishes_in_the_download_directory() {
    let machine = Machine::new();
    let bytes = b"filled apart, finished where it is shared".to_vec();
    let mut core = machine.core(rmule_testkit::memory_store(), None, &bytes);
    let temp = CoreSettings::default_temp_dir(&machine.data);

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("apart.bin", &bytes),
        source_hint: Some(server()),
        name: rmule_testkit::file_name("apart.bin"),
        if_taken: NameTaken::Refuse,
    }))
    .await
    .unwrap();
    let (filled, finished) = queued_then_completed(&mut core).await;

    assert_eq!(filled, temp.join("apart.bin.part"));
    assert_eq!(finished, machine.downloads.join("apart.bin"));
    assert_eq!(std::fs::read(&finished).unwrap(), bytes);
    assert!(!filled.exists());
    core.shutdown().await;
}

/// A name whose part file is taken in the Temp Directory numbers, as one
/// taken in the download directory does: the file and its part take the
/// first `stem (n).ext` free in both, and the file there is left alone.
#[tokio::test]
async fn a_name_whose_part_is_taken_in_the_temp_directory_numbers() {
    let machine = Machine::new();
    let temp = machine.data.join("parts");
    std::fs::create_dir_all(&temp).unwrap();
    std::fs::write(temp.join("have.bin.part"), b"left over").unwrap();
    let store = rmule_testkit::memory_store();
    let mut core = machine.core(Arc::clone(&store), Some(temp.clone()), b"abc");

    core.send(start(file_link("have.bin", b"abc"), NameTaken::Number))
        .await
        .unwrap();
    let CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) =
        verdict(&mut core).await
    else {
        panic!("the start is queued");
    };

    assert_eq!(
        stored_paths(&store, download_id),
        DownloadPaths::new(
            machine.downloads.join("have (1).bin"),
            temp.join("have (1).bin.part")
        )
    );
    assert_eq!(
        std::fs::read(temp.join("have.bin.part")).unwrap(),
        b"left over"
    );
    core.shutdown().await;
}

/// A row placed with its part file beside its final path — before the Temp
/// Directory — keeps the paths it holds: it resumes there and completes in
/// place, and nothing is made in the Temp Directory.
#[tokio::test]
async fn an_older_row_with_its_part_beside_its_file_completes_in_place() {
    let machine = Machine::new();
    let bytes = b"placed before the temp directory".to_vec();
    let temp = machine.data.join("parts");
    let store = rmule_testkit::memory_store();
    let paths = DownloadPaths::from_final_path(machine.downloads.join("old.bin"));
    let download_id = DurableDownloadRepository::new(Arc::clone(&store))
        .create_download(
            &file_link_without_part_hash_set("old.bin", &bytes),
            Some(&server()),
            &paths,
        )
        .unwrap()
        .id();
    let mut core = machine.core(store, Some(temp.clone()), &bytes);

    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id,
    }))
    .await
    .unwrap();
    let (_, finished) = queued_then_completed(&mut core).await;

    assert_eq!(finished, paths.final_path());
    assert_eq!(std::fs::read(&finished).unwrap(), bytes);
    assert!(!paths.part_path().exists());
    assert!(!temp.exists());
    core.shutdown().await;
}

fn stored_paths(store: &Arc<DurableStore>, download_id: DownloadId) -> DownloadPaths {
    DurableDownloadRepository::new(Arc::clone(store))
        .load_download(download_id)
        .unwrap()
        .paths()
        .clone()
}
