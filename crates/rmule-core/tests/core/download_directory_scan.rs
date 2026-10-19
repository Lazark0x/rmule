//! The **Download Directory Scan** end to end over a real temporary
//! directory (ADR-0102): the disclosure guard, the first pass hashing what
//! lies under it, a restart trusting every row unread, a later pass
//! dropping what changed or vanished, and the real watch sharing a file
//! dropped in after the pass.

use rmule_testkit::HANG_GUARD;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime};

use rmule_core::diagnostics::DiagnosticsSnapshot;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DirectoryOffer, DirectoryRole, DirectoryState,
    DownloadPaths, DownloadRepository, DurableDownloadRepository, DurableSharedFileRegistry,
    DurableStore, ScanCommand, ScanEvent, ScanPhase, ScanSummary, ShareSource, SharedFileRegistry,
};

use crate::fixture::{stub_link, stub_server};
use rmule_primitives::FileHashSummary;
use tokio::time::{Duration, timeout};

fn core(store: Arc<DurableStore>) -> Core {
    Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings::default())
        .build()
}

async fn next_scan_event(core: &mut Core) -> ScanEvent {
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted a scan event")
            .expect("core event stream stayed open");
        if let CoreEvent::Scan(scan) = event {
            return scan;
        }
    }
}

/// The download directory's scan phase, when its scan runs.
fn scan_phase(snapshot: DiagnosticsSnapshot) -> Option<ScanPhase> {
    snapshot
        .shared_directories
        .into_iter()
        .find(|entry| entry.role == DirectoryRole::DownloadDirectory)
        .and_then(|entry| match entry.state {
            DirectoryState::Scan(phase) => Some(phase),
            _ => None,
        })
}

async fn diagnostics(core: &mut Core) -> DiagnosticsSnapshot {
    core.send(CoreCommand::DumpDiagnostics).await.unwrap();
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("a snapshot")
            .expect("stream open");
        if let CoreEvent::DiagnosticsSnapshot { snapshot } = event {
            return snapshot;
        }
    }
}

/// Name `dir` the download directory on the running core, as Settings do:
/// core scans it, asking with no answer on record.
fn name_download_dir(core: &Core, dir: &Path) {
    core.settings()
        .set(rmule_core::Setting::DownloadDir {
            dir: dir.to_path_buf(),
            share_confirmed: false,
        })
        .unwrap();
}

async fn answer(core: &Core, dir: &Path, share: bool) {
    core.send(CoreCommand::Scan(ScanCommand::Answer {
        dir: dir.to_path_buf(),
        share,
    }))
    .await
    .unwrap();
}

fn write(path: &Path, bytes: &[u8], modified_secs: u64) {
    std::fs::write(path, bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + StdDuration::from_secs(modified_secs))
        .unwrap();
}

/// A download directory with two shareable files, one nested, and three
/// things the scan must leave alone: a dot-directory, a symlink, and the part
/// file of a live download [`own_part`] records.
fn populate(root: &Path) -> (PathBuf, PathBuf) {
    let top = root.join("album.flac");
    let nested = root.join("films").join("clip.mkv");
    std::fs::create_dir(root.join("films")).unwrap();
    std::fs::create_dir(root.join(".trash")).unwrap();
    write(&top, b"top-level bytes", 1_000);
    write(&nested, b"nested bytes", 2_000);
    write(&root.join(".trash").join("hidden.bin"), b"hidden", 1);
    write(&root.join("pending.iso.part"), b"partial", 1);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&top, root.join("link.flac")).unwrap();
    (top, nested)
}

/// Record the live download whose part file [`populate`] wrote, so the scan
/// knows `pending.iso.part` as rmule's own by its path.
fn own_part(store: &Arc<DurableStore>, root: &Path) {
    DurableDownloadRepository::new(Arc::clone(store))
        .create_download(
            &stub_link("pending.iso", 7, 0x42),
            Some(&stub_server("example.org")),
            &DownloadPaths::from_final_path(root.join("pending.iso")),
            None,
        )
        .unwrap();
}

#[tokio::test]
async fn a_download_directory_is_asked_about_hashed_trusted_and_diffed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let (top, nested) = populate(&root);
    let store = rmule_testkit::memory_store();
    own_part(&store, &root);
    let registry = DurableSharedFileRegistry::new(store.clone());

    // First start: the guard asks, and nothing is shared while it waits.
    let mut first = core(store.clone());
    name_download_dir(&first, &root);
    assert_eq!(
        next_scan_event(&mut first).await,
        ScanEvent::ConsentRequested {
            dir: root.clone(),
            offer: DirectoryOffer {
                files: 2,
                bytes: 27,
                unread: 0
            },
            adding: false,
            replaces: Vec::new()
        }
    );
    let waiting = scan_phase(diagnostics(&mut first).await).expect("a scan");
    assert!(matches!(waiting, ScanPhase::AwaitingConsent { offer } if offer.files == 2));
    assert!(registry.list().unwrap().is_empty());
    answer(&first, &root, true).await;
    assert_eq!(
        next_scan_event(&mut first).await,
        ScanEvent::Finished {
            dir: root.clone(),
            summary: ScanSummary {
                hashed: 2,
                ..ScanSummary::default()
            }
        }
    );
    // The scan lives on past its first pass, into its watch; the pass's
    // report does not wait for the watch to hold.
    let phase = scan_phase(diagnostics(&mut first).await).expect("the scan lives on");
    assert!(
        matches!(
            phase,
            ScanPhase::StartingWatch | ScanPhase::Watching { settling: 0 }
        ),
        "{phase:?}"
    );
    let mut rows = registry.list().unwrap();
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    assert_eq!(
        rows.iter().map(|row| row.path.clone()).collect::<Vec<_>>(),
        [top.clone(), nested.clone()]
    );
    assert_eq!(
        rows[0].file_hash,
        FileHashSummary::digest_bytes(b"top-level bytes").file_hash()
    );
    assert_eq!(rows[0].source, ShareSource::DownloadDirectory);
    assert!(rows.iter().all(|row| row.modified.is_some()));
    first.shutdown().await;

    // Restart: the answer is on record and every row is trusted unread.
    let mut second = core(store.clone());
    name_download_dir(&second, &root);
    assert_eq!(
        next_scan_event(&mut second).await,
        ScanEvent::Finished {
            dir: root.clone(),
            summary: ScanSummary {
                trusted: 2,
                ..ScanSummary::default()
            }
        }
    );
    second.shutdown().await;

    // One file rewritten, one removed, one added.
    write(&top, b"re-encoded bytes", 3_000);
    std::fs::remove_file(&nested).unwrap();
    write(&root.join("films").join("new.mkv"), b"new bytes", 4_000);
    let mut third = core(store);
    name_download_dir(&third, &root);
    assert_eq!(
        next_scan_event(&mut third).await,
        ScanEvent::Finished {
            dir: root.clone(),
            summary: ScanSummary {
                hashed: 2,
                dropped: 2,
                ..ScanSummary::default()
            }
        }
    );
    let hashes: Vec<_> = registry
        .list()
        .unwrap()
        .iter()
        .map(|r| r.file_hash)
        .collect();
    assert_eq!(hashes.len(), 2);
    assert!(hashes.contains(&FileHashSummary::digest_bytes(b"re-encoded bytes").file_hash()));
    assert!(hashes.contains(&FileHashSummary::digest_bytes(b"new bytes").file_hash()));
    // The removed file is Had; the rewritten one's old content is not.
    let had: Vec<_> = registry
        .had_set()
        .list()
        .unwrap()
        .into_iter()
        .map(|file| (file.identity.file_hash, file.name))
        .collect();
    assert_eq!(
        had,
        [(
            FileHashSummary::digest_bytes(b"nested bytes").file_hash(),
            "clip.mkv".to_string()
        )]
    );
    third.shutdown().await;
}

#[tokio::test]
async fn a_declined_directory_is_never_shared_and_not_asked_again() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    populate(&root);
    let store = rmule_testkit::memory_store();
    own_part(&store, &root);
    let registry = DurableSharedFileRegistry::new(store.clone());

    let mut first = core(store.clone());
    name_download_dir(&first, &root);
    assert!(matches!(
        next_scan_event(&mut first).await,
        ScanEvent::ConsentRequested { .. }
    ));
    answer(&first, &root, false).await;
    assert_eq!(
        next_scan_event(&mut first).await,
        ScanEvent::Declined { dir: root.clone() }
    );
    first.shutdown().await;

    let mut second = core(store);
    name_download_dir(&second, &root);
    assert_eq!(
        next_scan_event(&mut second).await,
        ScanEvent::Declined { dir: root.clone() }
    );
    assert!(registry.list().unwrap().is_empty());
    second.shutdown().await;
}

#[tokio::test]
async fn an_answer_sent_before_the_start_spares_the_question() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    populate(&root);
    let store = rmule_testkit::memory_store();
    own_part(&store, &root);
    let mut core = core(store);
    // The Settings path: the warning was confirmed, then the scan starts.
    answer(&core, &root, true).await;
    name_download_dir(&core, &root);
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { summary, .. } if summary.hashed == 2
    ));
    core.shutdown().await;
}

/// The Settings path through Core Settings (ADR-0069): the confirmed
/// directory set on the running core is persisted, and core starts its scan
/// at once without a question.
#[tokio::test]
async fn a_confirmed_download_dir_set_on_the_running_core_is_scanned_at_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    populate(&root);
    let store = rmule_testkit::memory_store();
    own_part(&store, &root);
    let mut core = core(store);
    assert_eq!(
        core.settings().set(rmule_core::Setting::DownloadDir {
            dir: root.clone(),
            share_confirmed: true,
        }),
        Ok(rmule_core::TakesEffect::Now)
    );
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { summary, .. } if summary.hashed == 2
    ));
    assert_eq!(core.settings().read().unwrap().download_dir, Some(root));
    core.shutdown().await;
}

/// A core scans the download directory its Core Settings name from attach,
/// with no command, and asks from the answer recorded for it: one the
/// operator confirmed asks nothing, one they declined is not scanned.
#[tokio::test]
async fn a_core_scans_its_configured_download_dir_from_attach_under_the_recorded_answer() {
    for confirmed in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        populate(&root);
        let store = rmule_testkit::memory_store();
        own_part(&store, &root);
        DurableSharedFileRegistry::new(store.clone())
            .record_directory_answer(&root, confirmed)
            .unwrap();
        let mut core = Core::builder(CoreConfig::default(), store)
            .settings(rmule_core::CoreSettings {
                download_dir: Some(root.clone()),
                ..rmule_core::CoreSettings::default()
            })
            .build();
        let scan = next_scan_event(&mut core).await;
        if confirmed {
            assert!(
                matches!(&scan, ScanEvent::Finished { summary, .. } if summary.hashed == 2),
                "{scan:?}"
            );
        } else {
            assert_eq!(scan, ScanEvent::Declined { dir: root });
        }
        core.shutdown().await;
    }
}

#[tokio::test]
async fn quit_while_the_guard_waits_ends_the_scan_and_shares_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    populate(&root);
    let store = rmule_testkit::memory_store();
    own_part(&store, &root);
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = core(store);
    name_download_dir(&core, &root);
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::ConsentRequested { .. }
    ));
    timeout(Duration::from_secs(3), core.shutdown())
        .await
        .expect("quit frees the waiting worker");
    assert!(registry.list().unwrap().is_empty());
    assert_eq!(
        registry.directory_answer(&root).unwrap(),
        None,
        "a quit is no answer"
    );
}

/// The real watch (`notify` over FSEvents or inotify): a file dropped into
/// a watched directory becomes a registry row once it has held still.
#[tokio::test]
async fn a_file_dropped_into_a_watched_directory_becomes_a_registry_row() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = core(store);
    answer(&core, &root, true).await;
    name_download_dir(&core, &root);
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { summary, .. } if summary == ScanSummary::default()
    ));
    let dropped = root.join("dropped.bin");
    std::fs::write(&dropped, b"dropped in later").unwrap();
    let file_hash = FileHashSummary::digest_bytes(b"dropped in later").file_hash();
    // Five still seconds, one quiet second, and the backend's own latency.
    timeout(Duration::from_secs(30), async {
        loop {
            match core.next_event().await.expect("stream open") {
                CoreEvent::Serve(rmule_core::ServeEvent::FileShared { file_hash: shared })
                    if shared == file_hash =>
                {
                    return;
                }
                CoreEvent::Scan(ScanEvent::WatchUnavailable { reason, .. }) => {
                    panic!("the watch did not start: {reason:?}");
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the dropped file was shared");
    let row = registry.get(file_hash).unwrap().expect("a registry row");
    assert_eq!(row.path, dropped);
    assert_eq!(row.source, ShareSource::DownloadDirectory);
    core.shutdown().await;
}

/// A rename between two starts, on a real filesystem (ADR-0100, "A rename
/// carries its hash when the file's identity proves it"). macOS temporary
/// directories are APFS, whose identities rmule trusts, so the hash is
/// carried there; elsewhere the temporary directory may be tmpfs, which it
/// does not, and the file is read, as before.
#[tokio::test]
async fn a_file_renamed_between_starts_is_carried_where_its_identity_proves_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let before = root.join("draft.mkv");
    write(&before, b"a film, renamed later", 3_000);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());

    let mut first = core(store.clone());
    answer(&first, &root, true).await;
    name_download_dir(&first, &root);
    assert!(matches!(
        next_scan_event(&mut first).await,
        ScanEvent::Finished { summary, .. } if summary.hashed == 1
    ));
    first.shutdown().await;

    std::fs::create_dir(root.join("sorted")).unwrap();
    let after = root.join("sorted").join("final.mkv");
    std::fs::rename(&before, &after).unwrap();

    let mut second = core(store.clone());
    name_download_dir(&second, &root);
    let ScanEvent::Finished { summary, .. } = next_scan_event(&mut second).await else {
        panic!("the second pass finishes");
    };
    if cfg!(target_os = "macos") {
        assert_eq!(
            (summary.carried, summary.hashed),
            (1, 0),
            "carried, not read: {summary:?}"
        );
    } else {
        assert_eq!(summary.carried + summary.hashed, 1, "{summary:?}");
    }
    let rows = registry.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].path, after);
    assert_eq!(rows[0].name, "final.mkv");
    assert!(
        registry.had_set().list().unwrap().is_empty(),
        "a rename never passes through the Had Set"
    );
    second.shutdown().await;
}

/// Where the kernel keeps the inotify watch limit of the caller's user
/// namespace: the count every watch is charged against first.
#[cfg(target_os = "linux")]
const WATCH_LIMIT: &str = "/proc/sys/user/max_inotify_watches";

/// The real watch over inotify, past the per-user watch limit (ADR-0103,
/// "The inotify limit" and "Degrade"): a directory with more subdirectories
/// than the limit allows cannot be watched. The first pass still shares what
/// it found, the operator is told once, with the limit's own code, the
/// diagnostics keep saying so, and a fresh `Start` (the degrade's fallback)
/// still finds a file added afterwards.
///
/// Linux only, ignored, and skipped unless `RMULE_INOTIFY_LIMIT=1`: it needs a
/// limit low enough to reach, which a test cannot set for itself (a
/// multi-threaded process cannot enter a new user namespace). It runs inside
/// a user namespace whose limit is lowered, so nothing else on the host loses
/// a watch; `scripts/inotify-limit-run.sh` runs it so in a container.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a lowered inotify limit; set RMULE_INOTIFY_LIMIT=1"]
async fn past_the_inotify_limit_the_operator_is_told_once_and_a_fresh_pass_still_shares() {
    if std::env::var("RMULE_INOTIFY_LIMIT").as_deref() != Ok("1") {
        eprintln!("inotify limit run skipped: set RMULE_INOTIFY_LIMIT=1");
        return;
    }
    let limit: usize = std::fs::read_to_string(WATCH_LIMIT)
        .expect("the user namespace's inotify limit is readable")
        .trim()
        .parse()
        .expect("the limit is a number");
    assert!(
        limit <= 4096,
        "the limit is {limit}: lower it in a user namespace of the test's own (see this test's doc)"
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    // The root and every subdirectory take one watch each.
    for at in 0..limit + 8 {
        std::fs::create_dir(root.join(format!("d{at:05}"))).unwrap();
    }
    let first = root.join("first.bin");
    write(&first, b"shared by the first pass", 5_000);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = core(store);
    answer(&core, &root, true).await;
    name_download_dir(&core, &root);

    let mut finished = None;
    let mut unavailable = Vec::new();
    // The pass, then the watch's start; and a quiet spell after it, in which
    // nothing is said again.
    let _ = timeout(Duration::from_secs(20), async {
        loop {
            match core.next_event().await.expect("stream open") {
                CoreEvent::Scan(ScanEvent::Finished { summary, .. }) => finished = Some(summary),
                CoreEvent::Scan(ScanEvent::WatchUnavailable { reason, .. }) => {
                    unavailable.push(reason);
                }
                CoreEvent::Scan(
                    ScanEvent::WatchInterrupted { .. } | ScanEvent::WatchRestored { .. },
                ) => {
                    panic!("a watch that never started cannot be interrupted or restored");
                }
                _ => {}
            }
        }
    })
    .await;
    assert_eq!(finished.map(|summary| summary.hashed), Some(1));
    assert_eq!(unavailable, [rmule_core::WatchFault::Limit], "told once");
    assert!(
        registry
            .get(FileHashSummary::digest_bytes(b"shared by the first pass").file_hash())
            .unwrap()
            .is_some()
    );
    assert_eq!(
        scan_phase(diagnostics(&mut core).await),
        Some(ScanPhase::Unwatched {
            reason: rmule_core::WatchFault::Limit
        })
    );

    let later = root.join("later.bin");
    write(&later, b"added after the watch failed", 6_000);
    let file_hash = FileHashSummary::digest_bytes(b"added after the watch failed").file_hash();
    name_download_dir(&core, &root);
    timeout(HANG_GUARD, async {
        loop {
            if let CoreEvent::Serve(rmule_core::ServeEvent::FileShared { file_hash: shared }) =
                core.next_event().await.expect("stream open")
                && shared == file_hash
            {
                return;
            }
        }
    })
    .await
    .expect("the fresh pass shares the file added afterwards");
    assert_eq!(registry.get(file_hash).unwrap().expect("a row").path, later);
    core.shutdown().await;
}
