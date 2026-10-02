//! The **Shared Directory List** through a real core over real directories
//! (ADR-0101, "Shared Directories"): an add guarded, counted, confirmed and
//! scanned; a parent replacing its child; a remove that unshares at once and
//! sets the hashes aside, so the add again reads nothing; a no that stores
//! nothing; the list scanned again after a restart; and a directory taken
//! away while watched, whose files are withheld rather than Had.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmule_core::diagnostics::DiagnosticsSnapshot;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DirectoryOffer, DirectoryRefusal, DirectoryRole,
    DirectoryState, DurableSharedFileRegistry, DurableStore, ScanCommand, ScanEvent, ScanPhase,
    ServeEvent, ShareGuards, SharedFileRegistry,
};
use tokio::time::{Duration, timeout};

struct Machine {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Machine {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("rmule-data")).unwrap();
        Self {
            _tmp: tmp,
            root,
            home,
        }
    }

    /// A directory under the machine's root holding `files`.
    fn directory(&self, name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let dir = self.root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for (file, bytes) in files {
            std::fs::write(dir.join(file), bytes).unwrap();
        }
        dir
    }

    fn core(&self, store: Arc<DurableStore>) -> Core {
        Core::builder(CoreConfig::default(), store)
            .share_guards(ShareGuards {
                home: Some(self.home.clone()),
                data_dir: Some(self.home.join("rmule-data")),
            })
            .build()
    }
}

async fn next_scan_event(core: &mut Core) -> ScanEvent {
    loop {
        let event = timeout(Duration::from_secs(10), core.next_event())
            .await
            .expect("core emitted a scan event")
            .expect("core event stream stayed open");
        if let CoreEvent::Scan(scan) = event {
            return scan;
        }
    }
}

/// Every serve event until the next scan event, and that scan event.
async fn serve_events_until_scan(core: &mut Core) -> (Vec<ServeEvent>, ScanEvent) {
    let mut serve = Vec::new();
    loop {
        let event = timeout(Duration::from_secs(10), core.next_event())
            .await
            .expect("core emitted a scan event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Scan(scan) => return (serve, scan),
            CoreEvent::Serve(event) => serve.push(event),
            _ => {}
        }
    }
}

async fn send(core: &Core, command: ScanCommand) {
    core.send(CoreCommand::Scan(command)).await.unwrap();
}

async fn diagnostics(core: &mut Core) -> DiagnosticsSnapshot {
    core.send(CoreCommand::DumpDiagnostics).await.unwrap();
    loop {
        // A retire joins a worker whose watch may still be starting, which
        // can take the operating system seconds.
        let event = timeout(Duration::from_secs(10), core.next_event())
            .await
            .expect("a snapshot")
            .expect("stream open");
        if let CoreEvent::DiagnosticsSnapshot { snapshot } = event {
            return snapshot;
        }
    }
}

/// Add `dir` and answer the confirm with `share`; the offer it named.
async fn add(core: &mut Core, dir: &Path, share: bool) -> (DirectoryOffer, Vec<PathBuf>) {
    send(
        core,
        ScanCommand::AddSharedDirectory {
            path: dir.to_path_buf(),
        },
    )
    .await;
    let ScanEvent::ConsentRequested {
        dir: asked,
        offer,
        adding,
        replaces,
    } = next_scan_event(core).await
    else {
        panic!("the add asks first");
    };
    assert_eq!(asked, dir);
    assert!(adding);
    send(
        core,
        ScanCommand::Answer {
            dir: dir.to_path_buf(),
            share,
        },
    )
    .await;
    (offer, replaces)
}

async fn refused(core: &mut Core, path: &Path) -> DirectoryRefusal {
    send(
        core,
        ScanCommand::AddSharedDirectory {
            path: path.to_path_buf(),
        },
    )
    .await;
    match next_scan_event(core).await {
        ScanEvent::DirectoryRefused { reason, .. } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn an_add_is_guarded_counted_confirmed_and_shared() {
    let machine = Machine::new();
    let media = machine.directory(
        "media",
        &[("film.mkv", b"film bytes"), ("song.ogg", b"song")],
    );
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = machine.core(store);

    assert_eq!(
        refused(&mut core, &machine.home).await,
        DirectoryRefusal::HomeDirectory
    );
    assert_eq!(
        refused(&mut core, &machine.home.join("rmule-data")).await,
        DirectoryRefusal::DataDirectory
    );
    assert_eq!(
        refused(&mut core, Path::new("/")).await,
        DirectoryRefusal::FilesystemRoot
    );
    assert!(
        registry.list().unwrap().is_empty(),
        "nothing shared by a refusal"
    );

    let (offer, replaces) = add(&mut core, &media, true).await;
    assert_eq!(
        offer,
        DirectoryOffer {
            files: 2,
            bytes: 14,
            unread: 0
        }
    );
    assert!(replaces.is_empty());
    assert_eq!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded {
            dir: media.clone(),
            replaced: Vec::new()
        }
    );
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { summary, .. } if summary.hashed == 2
    ));
    assert_eq!(registry.list().unwrap().len(), 2);
    let listed = diagnostics(&mut core).await.shared_directories;
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].dir.clone(), listed[0].role),
        (media.clone(), DirectoryRole::Added)
    );
    assert!(matches!(listed[0].state, DirectoryState::Scan(_)));

    assert_eq!(
        refused(&mut core, &media.join(".")).await,
        DirectoryRefusal::AlreadyShared
    );
    std::fs::create_dir(media.join("films")).unwrap();
    assert_eq!(
        refused(&mut core, &media.join("films")).await,
        DirectoryRefusal::InsideShared { parent: media }
    );
    core.shutdown().await;
}

#[tokio::test]
async fn a_remove_unshares_at_once_and_the_add_again_reads_nothing() {
    let machine = Machine::new();
    let media = machine.directory(
        "media",
        &[("film.mkv", b"film bytes"), ("song.ogg", b"song")],
    );
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = machine.core(store);
    add(&mut core, &media, true).await;
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded { .. }
    ));
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { .. }
    ));

    send(
        &core,
        ScanCommand::RemoveSharedDirectory {
            path: media.clone(),
        },
    )
    .await;
    let (serve, removed) = serve_events_until_scan(&mut core).await;
    assert_eq!(
        removed,
        ScanEvent::DirectoryRemoved {
            dir: media.clone(),
            files: 2
        }
    );
    let unshared = serve
        .iter()
        .filter(|event| matches!(event, ServeEvent::FileUnshared { .. }))
        .count();
    assert_eq!(unshared, 2, "every file leaves the offer at once");
    assert!(registry.list().unwrap().is_empty());
    assert!(
        registry.had_set().list().unwrap().is_empty(),
        "files still on disk are not Had"
    );
    assert!(diagnostics(&mut core).await.shared_directories.is_empty());

    let (offer, _) = add(&mut core, &media, true).await;
    assert_eq!(offer.unread, 2, "both set aside, neither read again");
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded { .. }
    ));
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { summary, .. } if summary.hashed == 0 && summary.trusted == 2
    ));
    assert_eq!(registry.list().unwrap().len(), 2);
    core.shutdown().await;
}

#[tokio::test]
async fn a_no_stores_nothing_and_a_parent_replaces_its_child_after_its_confirm() {
    let machine = Machine::new();
    let films = machine.directory("media/films", &[("film.mkv", b"film bytes")]);
    let media = machine.root.join("media");
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = machine.core(store.clone());

    add(&mut core, &films, false).await;
    assert_eq!(
        next_scan_event(&mut core).await,
        ScanEvent::Declined { dir: films.clone() }
    );
    assert!(registry.list().unwrap().is_empty());
    assert!(diagnostics(&mut core).await.shared_directories.is_empty());

    add(&mut core, &films, true).await;
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded { .. }
    ));
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { .. }
    ));

    let (offer, replaces) = add(&mut core, &media, true).await;
    assert_eq!(replaces, std::slice::from_ref(&films));
    assert_eq!(offer.unread, 1, "the child's file is already hashed");
    assert_eq!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded {
            dir: media.clone(),
            replaced: vec![films]
        }
    );
    let listed: Vec<PathBuf> = diagnostics(&mut core)
        .await
        .shared_directories
        .into_iter()
        .map(|entry| entry.dir)
        .collect();
    assert_eq!(listed, std::slice::from_ref(&media));
    assert_eq!(
        registry.list().unwrap().len(),
        1,
        "the child's row stays, now the parent's"
    );
    core.shutdown().await;

    // The list outlives the core: a new one scans it without being asked.
    let mut again = machine.core(store);
    assert!(matches!(
        next_scan_event(&mut again).await,
        ScanEvent::Finished { dir, summary } if dir == media && summary.trusted == 1
    ));
    again.shutdown().await;
}

#[tokio::test]
async fn the_download_directory_under_an_added_one_is_covered_and_cannot_be_removed() {
    let machine = Machine::new();
    let downloads = machine.directory("files/rmule", &[]);
    let files = machine.root.join("files");
    let store = rmule_testkit::memory_store();
    let mut core = machine.core(store);
    send(
        &core,
        ScanCommand::Start {
            dir: downloads.clone(),
        },
    )
    .await;
    // The empty download directory needs no question; its pass finishes.
    assert!(
        matches!(next_scan_event(&mut core).await, ScanEvent::Finished { dir, .. } if dir == downloads)
    );
    add(&mut core, &files, true).await;
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded { .. }
    ));
    let listed = diagnostics(&mut core).await.shared_directories;
    assert_eq!(listed[0].role, DirectoryRole::DownloadDirectory);
    assert_eq!(
        listed[0].state,
        DirectoryState::Covered { by: files.clone() }
    );
    assert_eq!(listed[1].dir, files);

    send(
        &core,
        ScanCommand::RemoveSharedDirectory {
            path: downloads.clone(),
        },
    )
    .await;
    loop {
        match next_scan_event(&mut core).await {
            ScanEvent::DirectoryRefused { reason, .. } => {
                assert_eq!(reason, DirectoryRefusal::DownloadDirectory);
                break;
            }
            ScanEvent::Finished { .. } => {}
            other => panic!("{other:?}"),
        }
    }
    core.shutdown().await;
}

#[tokio::test]
async fn a_directory_taken_away_while_watched_is_missing_and_its_files_withheld() {
    let machine = Machine::new();
    let media = machine.directory("media", &[("film.mkv", b"film bytes")]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = machine.core(store);
    add(&mut core, &media, true).await;
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded { .. }
    ));
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { .. }
    ));
    // Let the watch hold before the directory goes.
    timeout(Duration::from_secs(10), async {
        loop {
            let watching = diagnostics(&mut core)
                .await
                .shared_directories
                .iter()
                .any(|entry| {
                    matches!(
                        entry.state,
                        DirectoryState::Scan(ScanPhase::Watching { .. })
                    )
                });
            if watching {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the watch holds");

    std::fs::rename(&media, machine.root.join("media, moved away")).unwrap();
    let (serve, missing) = timeout(Duration::from_secs(20), async {
        loop {
            let (serve, scan) = serve_events_until_scan(&mut core).await;
            if matches!(scan, ScanEvent::DirectoryMissing { .. }) {
                return (serve, scan);
            }
        }
    })
    .await
    .expect("the directory is found missing");
    assert!(matches!(missing, ScanEvent::DirectoryMissing { dir, .. } if dir == media));
    assert!(
        serve
            .iter()
            .any(|event| matches!(event, ServeEvent::FileWithheld { .. })),
        "{serve:?}"
    );
    assert_eq!(registry.list().unwrap().len(), 1, "the row stays");
    assert!(registry.had_set().list().unwrap().is_empty(), "never Had");
    let listed = diagnostics(&mut core).await.shared_directories;
    assert!(matches!(
        listed[0].state,
        DirectoryState::Scan(ScanPhase::Missing { .. })
    ));
    core.shutdown().await;
}
