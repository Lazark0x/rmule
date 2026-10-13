//! **Source Seeds** across Quit and attach (ADR-0109): the peers a run knew
//! are written at Quit and dialed first by the next process's attach, before
//! any lookup answers; a stale set is dropped unread; a finished download
//! keeps none; and the operator's count bounds the write.

use rmule_testkit::HANG_GUARD;
use std::net::Ipv4Addr;
use std::num::NonZeroU8;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadId,
    DownloadLifecycle, DownloadRepository, DownloadedPart, DurableDownloadRepository,
    PeerDownloadOutcome, PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent,
    RememberPeers, SeedRank, SourceLookupOutcome, SourceLookupService, SourceSeed,
    open_durable_store,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, Informant, Ipv4Endpoint, PeerEndpoint, PeerSource, ServerEndpoint,
    SourceLookupTarget, SourceSighting,
};
use rmule_testkit::{StaticPeerTransfer, StaticSourceLookup, file_link};

use crate::fixture::next_expected;

/// Two dialable sources at RFC 5737 addresses.
fn first_seed() -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 41), 4662))
}

fn second_seed() -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 73), 4672))
}

fn answering(sources: &[PeerEndpoint]) -> StaticSourceLookup {
    StaticSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0B00_A8C0),
            sources: sources
                .iter()
                .map(|peer| {
                    let v4 = peer.as_v4().expect("IPv4 test source");
                    SourceSighting::plain(PeerSource::HighId(v4), Informant::Own)
                })
                .collect(),
        },
    }
}

/// A server that never answers: a run that waits for its lookup dials
/// nothing.
#[derive(Clone)]
struct NeverAnswers;

impl SourceLookupService for NeverAnswers {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, rmule_core::DownloadFailure> {
        std::future::pending().await
    }
}

/// Workers that connect and wait, each dial written down; with `hellos`
/// each reads the peer's hello first, and the dial at `hangs_up` ends before
/// any.
#[derive(Clone, Default)]
struct DialLog {
    dials: Arc<Mutex<Vec<PeerEndpoint>>>,
    hellos: bool,
    hangs_up: Option<PeerEndpoint>,
}

impl PeerTransferService for DialLog {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, rmule_core::DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        self.dials.lock().unwrap().push(peer);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(8);
        let (hello, hangs_up) = (self.hellos, self.hangs_up == Some(peer));
        tokio::spawn(async move {
            if hangs_up {
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return;
            }
            if hello {
                let _ = event_tx.send(hello_of(peer)).await;
            }
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                if matches!(command, PeerWorkerCommand::Shutdown { .. }) {
                    break;
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

fn link(name: &str) -> Ed2kFileLink {
    file_link(name, name.repeat(40).as_bytes())
}

async fn start(core: &mut Core, file: Ed2kFileLink) -> DownloadId {
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        name: rmule_primitives::SafeFileName::of_link(&file),
        file,
        source_hint: Some(ServerEndpoint::new("203.0.113.9", 4661).unwrap()),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();
    match next_expected(core, "the download queued", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
        )
    })
    .await
    {
        CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) => download_id,
        _ => unreachable!("matcher only returns queued events"),
    }
}

async fn part_assigned(core: &mut Core, id: DownloadId) {
    next_expected(core, "a part assigned", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartAssigned { download_id, .. }) if *download_id == id
        )
    })
    .await;
}

/// A first process runs `file` against `sources` until a part is assigned,
/// then quits; returns the download's id.
async fn run_then_quit(
    dir: &std::path::Path,
    settings: rmule_core::CoreSettings,
    file: Ed2kFileLink,
    sources: &[PeerEndpoint],
) -> DownloadId {
    let store = open_durable_store(dir).unwrap();
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_testkit::in_download_dir(settings, dir))
        .source_lookup(answering(sources))
        .peer_transfer(DialLog::default())
        .build();
    let id = start(&mut core, file).await;
    part_assigned(&mut core, id).await;
    core.shutdown().await;
    id
}

/// The next process's attach on the same store, whose server never answers.
fn attach(dir: &std::path::Path, dials: DialLog) -> impl std::future::Future<Output = Core> {
    let dir = dir.to_path_buf();
    async move {
        Core::builder(
            CoreConfig {
                download_restore_pace: Duration::from_millis(10),
                ..CoreConfig::default()
            },
            open_durable_store(&dir).expect("the last process released the store"),
        )
        .settings(crate::fixture::attach_settings().await)
        .source_lookup(NeverAnswers)
        .peer_transfer(dials)
        .restore_at_attach()
        .build()
    }
}

/// Quit writes the peers the run knew; the next attach dials them, marked
/// `remembered`, while its server has answered nothing, and says how many
/// answered once each has.
#[tokio::test]
async fn a_restart_dials_the_remembered_peers_before_any_lookup_answers() {
    let dir = tempfile::tempdir().unwrap();
    let id = run_then_quit(
        dir.path(),
        rmule_core::CoreSettings::default(),
        link("kept"),
        &[first_seed(), second_seed()],
    )
    .await;

    let dials = DialLog {
        hellos: true,
        hangs_up: Some(second_seed()),
        ..DialLog::default()
    };
    let mut core = attach(dir.path(), dials.clone()).await;
    let loaded = next_expected(&mut core, "attach loaded the seeds", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SeedsLoaded { .. })
        )
    })
    .await;
    assert!(matches!(
        loaded,
        CoreEvent::Download(DownloadEvent::SeedsLoaded {
            downloads: 1,
            seeds: 2,
            expired: 0
        })
    ));
    let dialled = next_expected(&mut core, "the run dialled its seeds", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SeedsDialled { .. })
        )
    })
    .await;
    assert!(matches!(
        dialled,
        CoreEvent::Download(DownloadEvent::SeedsDialled {
            download_id,
            written: 2,
            dialled: 2,
            answered: 1,
        }) if download_id == id
    ));

    let mut dialed = dials.dials.lock().unwrap().clone();
    dialed.sort();
    assert_eq!(dialed, [first_seed(), second_seed()]);
    let snapshot = core.diagnostics_snapshot();
    let workers = &snapshot
        .downloads
        .get(&id)
        .expect("the restored run")
        .workers;
    assert!(!workers.is_empty());
    for worker in workers.values() {
        assert!(
            worker.remembered(),
            "{:?} is not marked",
            worker.peer_endpoint()
        );
    }
    core.shutdown().await;
}

/// A set written more than a day ago is dropped at load and nothing of it is
/// dialed.
#[tokio::test]
async fn a_seed_written_twenty_five_hours_ago_is_dropped_unread() {
    let dir = tempfile::tempdir().unwrap();
    let id = {
        let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
        let paths = rmule_core::DownloadPaths::from_final_path(dir.path().join("stale"));
        let id = repo
            .create_download(&link("stale"), None, &paths)
            .unwrap()
            .id();
        repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        let seed = SourceSeed {
            endpoint: first_seed(),
            user_hash: None,
            crypt: None,
            rank: SeedRank::Received,
        };
        let written = SystemTime::now() - Duration::from_secs(25 * 60 * 60);
        assert!(repo.write_source_seeds(id, &[seed], written).unwrap());
        id
    };

    let dials = DialLog::default();
    let mut core = attach(dir.path(), dials.clone()).await;
    let loaded = next_expected(&mut core, "attach dropped the stale seed", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SeedsLoaded { .. })
        )
    })
    .await;
    assert!(matches!(
        loaded,
        CoreEvent::Download(DownloadEvent::SeedsLoaded {
            downloads: 0,
            seeds: 0,
            expired: 1
        })
    ));
    next_expected(&mut core, "the download resumed", |event| {
        matches!(event, CoreEvent::Download(DownloadEvent::DownloadResumed { download_id }) if *download_id == id)
    })
    .await;
    // The run waits on a server that never answers: nothing is dialed.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(dials.dials.lock().unwrap().is_empty());
    core.shutdown().await;
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    assert!(repo.source_seeds(id).unwrap().is_empty());
}

/// Attach leaves a paused download at rest; the operator's resume dials its
/// seeds first, as attach's restore would have.
#[tokio::test]
async fn a_paused_download_resumed_by_hand_dials_its_seeds() {
    let dir = tempfile::tempdir().unwrap();
    let id = {
        let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
        let paths = rmule_core::DownloadPaths::from_final_path(dir.path().join("paused"));
        let id = repo
            .create_download(&link("paused"), None, &paths)
            .unwrap()
            .id();
        repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        let seed = SourceSeed {
            endpoint: first_seed(),
            user_hash: None,
            crypt: None,
            rank: SeedRank::Ranked,
        };
        assert!(
            repo.write_source_seeds(id, &[seed], SystemTime::now())
                .unwrap()
        );
        repo.set_lifecycle(id, DownloadLifecycle::Paused).unwrap();
        id
    };

    let dials = DialLog {
        hellos: true,
        ..DialLog::default()
    };
    let mut core = attach(dir.path(), dials.clone()).await;
    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id: id,
    }))
    .await
    .unwrap();
    let dialled = next_expected(&mut core, "the resumed run dialled its seed", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SeedsDialled { .. })
        )
    })
    .await;
    assert!(matches!(
        dialled,
        CoreEvent::Download(DownloadEvent::SeedsDialled {
            download_id,
            written: 1,
            dialled: 1,
            answered: 1,
        }) if download_id == id
    ));
    assert_eq!(*dials.dials.lock().unwrap(), [first_seed()]);
    core.shutdown().await;
}

/// A download that completes leaves no seeds behind.
#[tokio::test]
async fn a_completed_download_keeps_no_seeds() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let bytes = b"seeds go with the download".to_vec();
    let file = file_link("done.bin", &bytes);
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(answering(&[first_seed()]))
        .peer_transfer(StaticPeerTransfer {
            expected_plan_count: 1,
            outcome: PeerDownloadOutcome {
                peer_hashes: Vec::new(),
                parts: vec![DownloadedPart {
                    part_index: 0,
                    offset: 0,
                    bytes,
                }],
            },
        })
        .build();
    let id = start(&mut core, file).await;
    let seed = SourceSeed {
        endpoint: first_seed(),
        user_hash: None,
        crypt: None,
        rank: SeedRank::Received,
    };
    repo.write_source_seeds(id, &[seed], SystemTime::now())
        .unwrap();
    next_expected(&mut core, "the download completed", |event| {
        matches!(event, CoreEvent::Download(DownloadEvent::DownloadCompleted { download_id, .. }) if *download_id == id)
    })
    .await;
    core.shutdown().await;
    assert_eq!(
        repo.load_download(id).unwrap().lifecycle(),
        DownloadLifecycle::Completed
    );
    assert!(repo.source_seeds(id).unwrap().is_empty());
}

/// `Remember peers` at one keeps one peer of the two the run knew.
#[tokio::test]
async fn the_remember_peers_count_bounds_the_write() {
    let dir = tempfile::tempdir().unwrap();
    let id = run_then_quit(
        dir.path(),
        rmule_core::CoreSettings {
            remember_peers: RememberPeers::new(NonZeroU8::MIN),
            ..rmule_core::CoreSettings::default()
        },
        link("one"),
        &[first_seed(), second_seed()],
    )
    .await;
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let seeds = repo.source_seeds(id).unwrap();
    assert_eq!(seeds.len(), 1, "{seeds:?}");
    assert_eq!(seeds[0].rank, SeedRank::Known);
}

/// `Remember peers` changed on the running core bounds the next write: core
/// takes it up at once (ADR-0069), with no restart between.
#[tokio::test]
async fn a_remember_peers_change_on_the_running_core_bounds_the_next_write() {
    let dir = tempfile::tempdir().unwrap();
    let mut core = Core::builder(
        CoreConfig::default(),
        open_durable_store(dir.path()).unwrap(),
    )
    .settings(rmule_testkit::in_download_dir(
        rmule_core::CoreSettings::default(),
        dir.path(),
    ))
    .source_lookup(answering(&[first_seed(), second_seed()]))
    .peer_transfer(DialLog::default())
    .build();
    let id = start(&mut core, link("live")).await;
    part_assigned(&mut core, id).await;
    assert_eq!(
        core.settings()
            .set(rmule_core::Setting::RememberPeers(RememberPeers::new(
                NonZeroU8::MIN
            ))),
        Ok(rmule_core::TakesEffect::Now)
    );
    core.shutdown().await;
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    assert_eq!(repo.source_seeds(id).unwrap().len(), 1);
}

/// The real fleet and the real dial, no server session and Kad off: attach
/// dials the remembered peer and the file arrives whole.
#[tokio::test]
async fn a_remembered_peer_serves_the_file_with_no_server_and_no_kad() {
    let bytes = b"a remembered peer needs nobody to name it".to_vec();
    let file = file_link("remembered.bin", &bytes);
    let peer = rmule_testkit::FakePeer::bind().await;
    let at = peer.addr();
    let peer_task = peer.spawn(rmule_testkit::PeerScript::serving(
        file.file_hash,
        bytes.clone(),
    ));
    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("remembered.bin");
    let id = {
        let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
        let paths = rmule_core::DownloadPaths::from_final_path(output_path.clone());
        let id = repo.create_download(&file, None, &paths).unwrap().id();
        repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        let seed = SourceSeed {
            endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(*at.ip(), at.port())),
            user_hash: Some(rmule_primitives::UserHash::from_bytes([
                0x3C, 0x91, 0x07, 0xE2, 0x5A, 0x48, 0xB6, 0x1F, 0xD3, 0x6E, 0x29, 0x84, 0xC0, 0x7B,
                0x15, 0xFA,
            ])),
            crypt: None,
            rank: SeedRank::Received,
        };
        assert!(
            repo.write_source_seeds(id, &[seed], SystemTime::now())
                .unwrap()
        );
        id
    };
    let mut core = Core::builder(
        CoreConfig {
            download_restore_pace: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        open_durable_store(dir.path()).unwrap(),
    )
    .settings(crate::fixture::attach_settings().await)
    .restore_at_attach()
    .build();
    loop {
        let event = tokio::time::timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted an event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { download_id, .. })
                if download_id == id =>
            {
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert_eq!(std::fs::read(&output_path).unwrap(), bytes);
    core.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), peer_task).await;
}

/// A peer's hello: its hash — the last byte of its address, so each peer's is
/// its own — and a stance that supports and requests obfuscation.
fn hello_hash(peer: PeerEndpoint) -> rmule_primitives::UserHash {
    let last = peer.ip().to_string().len() as u8;
    rmule_primitives::UserHash::from_bytes([
        0x6A,
        last,
        0x2F,
        0x93,
        0x0C,
        0xD8,
        0x41,
        0xB7,
        0x5E,
        0x12,
        0xA9,
        0x77,
        0xF0,
        0x38,
        0xC4,
        peer.port() as u8,
    ])
}

/// The peer's hello: its hash and a crypt-capable stance.
fn hello_of(peer: PeerEndpoint) -> PeerWorkerEvent {
    PeerWorkerEvent::Identity(crate::fixture::peer_identity(
        hello_hash(peer),
        rmule_primitives::CryptStance::new(true, true, false),
    ))
}

/// Workers whose hello names the peer's hash and a crypt-capable stance.
#[derive(Clone, Default)]
struct HelloStating;

impl PeerTransferService for HelloStating {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, rmule_core::DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let _ = event_tx.send(hello_of(peer)).await;
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                if matches!(command, PeerWorkerCommand::Shutdown { .. }) {
                    break;
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// Every dial's crypt side, as the runner briefed it.
#[derive(Clone, Default)]
struct BriefLog(Arc<Mutex<Vec<(PeerEndpoint, rmule_primitives::PeerCrypt)>>>);

impl PeerTransferService for BriefLog {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, rmule_core::DownloadFailure> {
        DialLog::default().start_peer_worker(peer, ctx, file).await
    }

    async fn start_download_worker(
        &mut self,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
        brief: rmule_core::WorkerBrief,
    ) -> Result<PeerWorker, rmule_core::DownloadFailure> {
        self.0.lock().unwrap().push((peer, brief.peer_crypt));
        self.start_peer_worker(peer, ctx, file).await
    }
}

/// Under a `required` policy, no session and Kad off, a remembered peer is
/// dialed obfuscated toward the hash its hello named: the seed kept the
/// stance, so the one outbound rule does not refuse it before the socket.
#[tokio::test]
async fn a_required_policy_dials_a_remembered_peer_with_the_stance_it_stated() {
    let dir = tempfile::tempdir().unwrap();
    let id = {
        let mut core = Core::builder(
            CoreConfig::default(),
            open_durable_store(dir.path()).unwrap(),
        )
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(answering(&[first_seed(), second_seed()]))
        .peer_transfer(HelloStating)
        .build();
        let id = start(&mut core, link("stated")).await;
        part_assigned(&mut core, id).await;
        core.shutdown().await;
        id
    };

    let briefs = BriefLog::default();
    let mut core = Core::builder(
        CoreConfig {
            download_restore_pace: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        open_durable_store(dir.path()).unwrap(),
    )
    .settings(rmule_core::CoreSettings {
        obfuscation: Some(rmule_core::ObfuscationPolicy::Required),
        ..crate::fixture::attach_settings().await
    })
    .source_lookup(NeverAnswers)
    .peer_transfer(briefs.clone())
    .restore_at_attach()
    .build();
    part_assigned(&mut core, id).await;
    let briefs = briefs.0.lock().unwrap().clone();
    assert_eq!(briefs.len(), 2, "{briefs:?}");
    let ours = rmule_primitives::CryptStance::new(true, true, true);
    for (peer, crypt) in briefs {
        assert_eq!(
            crypt.outbound(ours),
            rmule_primitives::OutboundCrypt::Obfuscated {
                toward: hello_hash(peer)
            },
            "{peer}"
        );
    }
    core.shutdown().await;
}
