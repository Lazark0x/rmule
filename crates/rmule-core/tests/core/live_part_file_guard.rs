//! Who may touch a live part file (ADR-0094, "The run holds its part
//! file"): every path in rmule that removes, renames or clears
//! anything in the download directory, run beside a download whose run holds
//! its part file — and that part file is still the same file, with the same
//! bytes, and its run never reports it lost.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rmule_core::{
    ContentFileStore, Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent,
    DownloadCommand, DownloadEvent, DownloadId, DownloadLifecycle, DownloadPaths,
    DownloadRepository, DurableDownloadRepository, DurableStore, ScanEvent, ServeEvent,
    VerifiedPartRecord, open_durable_store,
};
use rmule_primitives::FileHashSummary;
use rmule_testkit::file_link;
use tokio::time::timeout;

use crate::fixture::{next_expected, stub_server};

const LIVE_BYTES: &[u8] = b"the live download's verified part";

/// A download directory with one running download in it — waiting for a
/// connection, its part file held — and whatever else a leg adds.
struct LiveDownload {
    core: Core,
    store: Arc<DurableStore>,
    repo: DurableDownloadRepository,
    dir: PathBuf,
    part: PathBuf,
    inode: (u64, u64),
    _tmp: tempfile::TempDir,
}

impl LiveDownload {
    /// Build the directory with `seed` (rows and files beside the live
    /// download), then start the core, which restores the live one.
    async fn with(seed: impl FnOnce(&DurableDownloadRepository, &Path)) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("downloads");
        std::fs::create_dir_all(&dir).unwrap();
        let store = open_durable_store(&tmp.path().join("data")).unwrap();
        let repo = DurableDownloadRepository::new(Arc::clone(&store));
        let link = file_link("live.bin", LIVE_BYTES);
        let paths = DownloadPaths::from_final_path(dir.join("live.bin"));
        let id = repo
            .create_download(&link, Some(&stub_server("127.0.0.1")), &paths)
            .unwrap()
            .id();
        ContentFileStore::write_verified_part(&paths, 0, LIVE_BYTES)
            .await
            .unwrap();
        repo.record_verified_part(
            id,
            VerifiedPartRecord {
                part_index: 0,
                offset: 0,
                len: LIVE_BYTES.len() as u64,
                part_hash: rmule_primitives::PartHash::from_bytes(*link.file_hash.as_bytes()),
            },
        )
        .unwrap();
        repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        seed(&repo, &dir);

        let mut core = Core::builder(
            CoreConfig {
                download_restore_pace: Duration::from_millis(10),
                ..CoreConfig::default()
            },
            Arc::clone(&store),
        )
        .settings(crate::fixture::attach_settings().await)
        .restore_at_attach()
        .build();
        next_expected(&mut core, "the live run holding its part file", |event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::WaitingForConnection { download_id })
                    if *download_id == id
            )
        })
        .await;
        let part = paths.part_path().to_path_buf();
        let meta = std::fs::metadata(&part).unwrap();
        Self {
            core,
            store,
            repo,
            dir,
            part,
            inode: (meta.dev(), meta.ino()),
            _tmp: tmp,
        }
    }

    /// The live part file is the same file with the same bytes, and nothing
    /// said it was lost.
    async fn assert_untouched(&mut self) {
        let meta = std::fs::metadata(&self.part).expect("the live part file is still there");
        assert_eq!((meta.dev(), meta.ino()), self.inode, "the same file");
        assert_eq!(std::fs::read(&self.part).unwrap(), LIVE_BYTES, "its bytes");
        let _ = timeout(Duration::from_millis(200), async {
            while let Some(event) = self.core.next_event().await {
                assert!(
                    !matches!(
                        event,
                        CoreEvent::Download(DownloadEvent::PartFileLost { .. })
                    ),
                    "the live run lost nothing: {event:?}"
                );
            }
        })
        .await;
    }
}

/// A download at rest beside the live one, its own part file in the same
/// directory.
fn paused_neighbour(repo: &DurableDownloadRepository, dir: &Path) -> (DownloadId, PathBuf) {
    let paths = DownloadPaths::from_final_path(dir.join("neighbour.bin"));
    let id = repo
        .create_download(
            &file_link("neighbour.bin", b"neighbour bytes"),
            Some(&stub_server("127.0.0.1")),
            &paths,
        )
        .unwrap()
        .id();
    std::fs::write(paths.part_path(), b"neighbour part").unwrap();
    repo.set_lifecycle(id, DownloadLifecycle::Paused).unwrap();
    (id, paths.part_path().to_path_buf())
}

#[tokio::test]
async fn cancelling_another_download_removes_its_part_file_and_leaves_the_live_one() {
    let mut neighbour = None;
    let mut live =
        LiveDownload::with(|repo, dir| neighbour = Some(paused_neighbour(repo, dir))).await;
    let (id, neighbour_part) = neighbour.unwrap();
    live.core
        .send(CoreCommand::Download(DownloadCommand::CancelDownload {
            download_id: id,
        }))
        .await
        .unwrap();
    next_expected(&mut live.core, "the neighbour cancelled", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCancelled { download_id }) if *download_id == id
        )
    })
    .await;
    assert!(
        !neighbour_part.exists(),
        "cancel removes the cancelled one's part file"
    );
    live.assert_untouched().await;
}

#[tokio::test]
async fn a_restart_refuses_a_running_download_and_touches_nothing() {
    let mut live = LiveDownload::with(|_, _| {}).await;
    let id = live.repo.listed_downloads().unwrap()[0].id();
    live.core
        .send(CoreCommand::Download(DownloadCommand::ResumeDownload {
            download_id: id,
        }))
        .await
        .unwrap();
    next_expected(&mut live.core, "the refusal", |event| {
        matches!(
            event,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::DownloadAlreadyActive
            }
        )
    })
    .await;
    live.assert_untouched().await;
}

#[tokio::test]
async fn clearing_completed_downloads_leaves_the_live_part_file() {
    let mut completed = None;
    let mut live = LiveDownload::with(|repo, dir| {
        let paths = DownloadPaths::from_final_path(dir.join("done.bin"));
        let id = repo
            .create_download(
                &file_link("done.bin", b"done bytes"),
                Some(&stub_server("127.0.0.1")),
                &paths,
            )
            .unwrap()
            .id();
        std::fs::write(paths.final_path(), b"done bytes").unwrap();
        repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        repo.set_lifecycle(id, DownloadLifecycle::Completed)
            .unwrap();
        completed = Some((id, paths.final_path().to_path_buf()));
    })
    .await;
    let (id, final_path) = completed.unwrap();
    live.core
        .send(CoreCommand::Download(
            DownloadCommand::ClearCompletedDownloads,
        ))
        .await
        .unwrap();
    next_expected(&mut live.core, "the completed one cleared", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCleared { download_id }) if *download_id == id
        )
    })
    .await;
    assert!(final_path.exists(), "clearing never touches a file");
    live.assert_untouched().await;
}

#[tokio::test]
async fn the_download_directory_scan_and_its_watch_leave_the_live_part_file() {
    let mut live = LiveDownload::with(|_, dir| {
        std::fs::write(dir.join("shared.bin"), b"a finished file").unwrap();
    })
    .await;
    let dir = live.dir.clone();
    live.core
        .settings()
        .set(rmule_core::Setting::DownloadDir {
            dir: dir.clone(),
            share_confirmed: true,
        })
        .unwrap();
    let finished = next_expected(&mut live.core, "the scan's first pass", |event| {
        matches!(event, CoreEvent::Scan(ScanEvent::Finished { .. }))
    })
    .await;
    let CoreEvent::Scan(ScanEvent::Finished { summary, .. }) = finished else {
        unreachable!("the predicate admits only Finished")
    };
    assert_eq!(
        summary.hashed, 1,
        "the finished file, and not the live part file"
    );
    // The watch sees the directory change around the live part file.
    // The live part file's stamp changes under the watch, as a running
    // download's writes do. The watch shares the new file only after it has
    // held still, so its share proves the watch ran over the directory; a
    // lost part file in any event before it fails the wait.
    std::fs::File::options()
        .write(true)
        .open(&live.part)
        .unwrap()
        .set_modified(std::time::SystemTime::now())
        .unwrap();
    std::fs::write(dir.join("another.bin"), b"another finished file").unwrap();
    let another = FileHashSummary::digest_bytes(b"another finished file").file_hash();
    timeout(Duration::from_secs(30), async {
        loop {
            match live.core.next_event().await.expect("stream open") {
                CoreEvent::Serve(ServeEvent::FileShared { file_hash }) if file_hash == another => {
                    return;
                }
                event @ CoreEvent::Download(DownloadEvent::PartFileLost { .. }) => {
                    panic!("the live run lost its part file: {event:?}");
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the watch shared the file dropped in beside the live part file");
    let registry = rmule_core::DurableSharedFileRegistry::new(Arc::clone(&live.store));
    assert!(
        rmule_core::SharedFileRegistry::list(&registry)
            .unwrap()
            .iter()
            .all(|row| row.path != live.part),
        "the live part file is never shared"
    );
    live.assert_untouched().await;
}
