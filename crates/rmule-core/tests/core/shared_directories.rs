//! The **Shared Directory List** through a real core over real directories
//! (ADR-0101, "Shared Directories"): an add guarded, counted, confirmed and
//! scanned; a parent replacing its child; a remove that unshares at once and
//! sets the hashes aside, so the add again reads nothing; a no that stores
//! nothing; the list scanned again after a restart; and a directory taken
//! away while watched, whose files are withheld rather than Had.

use rmule_testkit::HANG_GUARD;
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
        self.core_with(
            store,
            CoreConfig::default(),
            rmule_core::CoreSettings::default(),
        )
    }

    fn core_with(
        &self,
        store: Arc<DurableStore>,
        config: CoreConfig,
        settings: rmule_core::CoreSettings,
    ) -> Core {
        Core::builder(config, store)
            .settings(settings)
            .share_guards(ShareGuards {
                home: Some(self.home.clone()),
                data_dir: Some(self.home.join("rmule-data")),
            })
            .build()
    }
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

/// Every serve event until the next scan event, and that scan event.
async fn serve_events_until_scan(core: &mut Core) -> (Vec<ServeEvent>, ScanEvent) {
    let mut serve = Vec::new();
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
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
        let event = timeout(HANG_GUARD, core.next_event())
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

/// Wait until the scan of every entry of the list watches its directory.
async fn watch_holds(core: &mut Core) {
    timeout(HANG_GUARD, async {
        loop {
            let listed = diagnostics(core).await.shared_directories;
            let watching = !listed.is_empty()
                && listed.iter().all(|entry| {
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
}

/// Take `dir` away and wait until core finds it missing; the serve events
/// on the way.
async fn take_away(core: &mut Core, dir: &Path, to: &Path) -> Vec<ServeEvent> {
    std::fs::rename(dir, to).unwrap();
    timeout(HANG_GUARD, async {
        loop {
            let (serve, scan) = serve_events_until_scan(core).await;
            if matches!(&scan, ScanEvent::DirectoryMissing { dir: missing, .. } if missing == dir) {
                return serve;
            }
        }
    })
    .await
    .expect("the directory is found missing")
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

/// A download directory the guards refuse — the operator's home, named where
/// no guard was asked — is refused at attach like an add of it: listed as
/// refused, never scanned, and covering nothing — a directory added inside it
/// is its own entry, scanned, and its remove unshares its files. Moving it on
/// the running core onto rmule's data directory is refused at the set, with
/// the guard's reason.
#[tokio::test]
async fn a_refused_download_directory_is_not_scanned_and_covers_nothing() {
    let machine = Machine::new();
    let music = machine.directory("home/music", &[("song.ogg", b"song")]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = machine.core_with(
        store,
        CoreConfig::default(),
        rmule_core::CoreSettings {
            download_dir: Some(machine.home.clone()),
            ..rmule_core::CoreSettings::default()
        },
    );
    assert_eq!(
        next_scan_event(&mut core).await,
        ScanEvent::DownloadDirectoryRefused {
            dir: machine.home.clone(),
            reason: DirectoryRefusal::HomeDirectory
        }
    );
    assert_eq!(
        core.settings().set(rmule_core::Setting::DownloadDir {
            dir: machine.home.join("rmule-data"),
            share_confirmed: true,
        }),
        Err(rmule_core::SettingError::Refused(
            rmule_core::SettingRefusal::DownloadDirRefused(DirectoryRefusal::DataDirectory)
        ))
    );

    add(&mut core, &music, true).await;
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded { dir, .. } if dir == music
    ));
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { dir, summary } if dir == music && summary.hashed == 1
    ));
    let listed = diagnostics(&mut core).await.shared_directories;
    assert_eq!(
        (&listed[0].dir, &listed[0].state),
        (
            &machine.home,
            &DirectoryState::Refused(DirectoryRefusal::HomeDirectory)
        )
    );
    assert_eq!(listed[1].dir, music);
    assert!(matches!(listed[1].state, DirectoryState::Scan(_)));

    send(
        &core,
        ScanCommand::RemoveSharedDirectory {
            path: music.clone(),
        },
    )
    .await;
    let (_, removed) = serve_events_until_scan(&mut core).await;
    assert_eq!(
        removed,
        ScanEvent::DirectoryRemoved {
            dir: music,
            files: 1
        }
    );
    assert!(registry.list().unwrap().is_empty());
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
    core.settings()
        .set(rmule_core::Setting::DownloadDir {
            dir: downloads.clone(),
            share_confirmed: false,
        })
        .unwrap();
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
    watch_holds(&mut core).await;
    let serve = take_away(&mut core, &media, &machine.root.join("media, moved away")).await;
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

/// An added directory that comes back where the guards refuse it — a link
/// to the operator's home where the directory was — is judged as it appears,
/// before its pass reads anything: refused, said, listed as refused, and never
/// scanned, so nothing in the home is shared. The next start judges it again
/// and refuses it at attach.
#[cfg(unix)]
#[tokio::test]
async fn an_added_directory_that_returns_where_the_guards_refuse_it_is_not_scanned() {
    let machine = Machine::new();
    let media = machine.directory("media", &[("film.mkv", b"film bytes")]);
    std::fs::write(machine.home.join("letter.txt"), b"private").unwrap();
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let config = CoreConfig {
        missing_directory_look: Duration::from_millis(100),
        ..CoreConfig::default()
    };
    let mut core = machine.core_with(store.clone(), config, rmule_core::CoreSettings::default());
    add(&mut core, &media, true).await;
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::DirectoryAdded { .. }
    ));
    assert!(matches!(
        next_scan_event(&mut core).await,
        ScanEvent::Finished { .. }
    ));
    watch_holds(&mut core).await;
    take_away(&mut core, &media, &machine.root.join("media, moved away")).await;

    std::os::unix::fs::symlink(&machine.home, &media).unwrap();
    let refusal = ScanEvent::DirectoryRefused {
        dir: media.clone(),
        reason: DirectoryRefusal::HomeDirectory,
    };
    timeout(HANG_GUARD, async {
        loop {
            match next_scan_event(&mut core).await {
                event if event == refusal => return,
                event @ (ScanEvent::DirectoryReturned { .. }
                | ScanEvent::Finished { .. }
                | ScanEvent::ConsentRequested { .. }) => panic!("scanned: {event:?}"),
                _ => {}
            }
        }
    })
    .await
    .expect("the refusal is said as the directory appears");
    let listed = diagnostics(&mut core).await.shared_directories;
    assert_eq!(
        (&listed[0].dir, listed[0].role, &listed[0].state),
        (
            &media,
            DirectoryRole::Added,
            &DirectoryState::Refused(DirectoryRefusal::HomeDirectory)
        )
    );
    assert!(
        registry
            .list()
            .unwrap()
            .iter()
            .all(|row| row.path.file_name() != Some("letter.txt".as_ref())),
        "nothing in the home is shared"
    );
    core.shutdown().await;

    let mut again = machine.core(store);
    assert_eq!(next_scan_event(&mut again).await, refusal);
    let listed = diagnostics(&mut again).await.shared_directories;
    assert_eq!(
        listed[0].state,
        DirectoryState::Refused(DirectoryRefusal::HomeDirectory)
    );
    again.shutdown().await;
}

/// A withheld file under an added directory that returns where the guards
/// refuse it is withheld as refused, and stays so though it opens again: a
/// recheck of the withheld rows — the one another directory's return asks
/// for — offers that directory's file and not this one.
#[cfg(unix)]
#[tokio::test]
async fn a_withheld_file_under_a_refused_directory_is_not_offered_when_it_opens_again() {
    let machine = Machine::new();
    let media = machine.directory("media", &[("film.mkv", b"film bytes")]);
    let music = machine.directory("music", &[("song.mp3", b"song bytes")]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let config = CoreConfig {
        missing_directory_look: Duration::from_millis(100),
        ..CoreConfig::default()
    };
    let mut core = machine.core_with(store, config, rmule_core::CoreSettings::default());
    for dir in [&media, &music] {
        add(&mut core, dir, true).await;
        assert!(matches!(
            next_scan_event(&mut core).await,
            ScanEvent::DirectoryAdded { .. }
        ));
        assert!(matches!(
            next_scan_event(&mut core).await,
            ScanEvent::Finished { .. }
        ));
    }
    let hash_of = |name: &str| {
        registry
            .list()
            .unwrap()
            .into_iter()
            .find(|row| row.path.file_name() == Some(name.as_ref()))
            .expect("the file is shared")
            .file_hash
    };
    let (film, song) = (hash_of("film.mkv"), hash_of("song.mp3"));
    watch_holds(&mut core).await;
    let moved = machine.root.join("media, moved away");
    take_away(&mut core, &media, &moved).await;

    // The file lands in the home with its stamp, and the directory returns
    // as a link to it: the row's path opens again, through the home.
    std::fs::rename(moved.join("film.mkv"), machine.home.join("film.mkv")).unwrap();
    std::os::unix::fs::symlink(&machine.home, &media).unwrap();
    timeout(HANG_GUARD, async {
        loop {
            match core.next_event().await.expect("stream open") {
                CoreEvent::Serve(ServeEvent::FileWithheld {
                    file_hash,
                    reason: rmule_core::WithheldReason::Refused,
                    ..
                }) if file_hash == film => return,
                CoreEvent::Serve(ServeEvent::FileOffered { file_hash }) if file_hash == film => {
                    panic!("offered under a refused directory")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the refusal withholds the row as refused");

    let music_moved = machine.root.join("music, moved away");
    take_away(&mut core, &music, &music_moved).await;
    std::fs::rename(&music_moved, &music).unwrap();
    timeout(HANG_GUARD, async {
        loop {
            match core.next_event().await.expect("stream open") {
                CoreEvent::Serve(ServeEvent::FileOffered { file_hash }) if file_hash == song => {
                    return;
                }
                CoreEvent::Serve(ServeEvent::FileOffered { file_hash }) if file_hash == film => {
                    panic!("offered under a refused directory")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the recheck the return asks for offers the returned file");
    // The recheck ruled on both rows in one pass: a ruling on the refused
    // one would land within moments of the other's.
    let late = timeout(Duration::from_secs(1), async {
        loop {
            if let CoreEvent::Serve(ServeEvent::FileOffered { file_hash }) =
                core.next_event().await.expect("stream open")
                && file_hash == film
            {
                return;
            }
        }
    })
    .await;
    assert!(late.is_err(), "offered under a refused directory");
    core.shutdown().await;
}
