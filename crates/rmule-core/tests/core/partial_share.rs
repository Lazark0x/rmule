//! A download offers its verified parts (ADR-0113): from its first part
//! verified against the whole part hash set, through a pause, until its
//! completion hands the file to its one registry row or a cancel ends it —
//! and never while its folder is one rmule will not share.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rmule_core::{
    ContentFileStore, Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent,
    DownloadLifecycle, DownloadPaths, DownloadRepository, DurableDownloadRepository,
    DurableSharedFileRegistry, DurableStore, PartialEnd, PeerTransferService, PeerWorker,
    PeerWorkerCommand, PeerWorkerEvent, ServeEvent, ShareGuards, SharedFileRegistry,
    VerifiedPartRecord, WithheldReason,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, FileHash, PeerEndpoint, ServerEndpoint};
use rmule_testkit::{file_link, next_event, source_with_high_id};
use tokio::sync::watch;

/// Two parts: one whole, and a tail.
fn content() -> Vec<u8> {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.extend_from_slice(b"tail");
    bytes
}

fn part(bytes: &[u8], part_index: u32) -> Vec<u8> {
    let start = part_index as usize * ED2K_PART_SIZE as usize;
    let end = (start + ED2K_PART_SIZE as usize).min(bytes.len());
    bytes[start..end].to_vec()
}

/// Serves the first part any worker is asked for at once, and every later
/// one only once the test opens the gate.
#[derive(Clone)]
struct Gated {
    bytes: Arc<Vec<u8>>,
    first_served: Arc<AtomicBool>,
    gate: watch::Receiver<bool>,
}

impl Gated {
    fn new(bytes: &[u8]) -> (Self, watch::Sender<bool>) {
        let (open, gate) = watch::channel(false);
        let gated = Self {
            bytes: Arc::new(bytes.to_vec()),
            first_served: Arc::default(),
            gate,
        };
        (gated, open)
    }
}

impl PeerTransferService for Gated {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, rmule_core::DownloadFailure> {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let this = self.clone();
        tokio::spawn(async move {
            let mut gate = this.gate.clone();
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let mut held = Vec::new();
            loop {
                tokio::select! {
                    command = command_rx.recv() => match command {
                        Some(PeerWorkerCommand::RequestPart { plan, .. }) => {
                            if this.first_served.swap(true, Ordering::SeqCst) {
                                held.push(plan.part_index);
                            } else {
                                serve(&event_tx, &this.bytes, plan.part_index).await;
                            }
                        }
                        Some(PeerWorkerCommand::Shutdown { .. }) | None => break,
                        Some(_) => {}
                    },
                    opened = async { gate.wait_for(|open| *open).await.is_ok() }, if !held.is_empty() => {
                        if !opened {
                            break;
                        }
                        for part_index in std::mem::take(&mut held) {
                            serve(&event_tx, &this.bytes, part_index).await;
                        }
                    }
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

async fn serve(
    event_tx: &tokio::sync::mpsc::Sender<PeerWorkerEvent>,
    bytes: &[u8],
    part_index: u32,
) {
    let _ = event_tx
        .send(PeerWorkerEvent::BlockReceived {
            part_index,
            offset: u64::from(part_index) * ED2K_PART_SIZE,
            bytes: part(bytes, part_index),
        })
        .await;
    let _ = event_tx
        .send(PeerWorkerEvent::PartStreamed { part_index })
        .await;
}

fn core(store: Arc<DurableStore>, dir: &Path, peer: Gated) -> Core {
    Core::builder(CoreConfig::default(), store)
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir,
        ))
        .source_lookup(source_with_high_id())
        .peer_transfer(peer)
        .build()
}

async fn start(core: &Core, link: &Ed2kFileLink) {
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link.clone(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("partial.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();
}

async fn send(core: &Core, command: DownloadCommand) {
    core.send(CoreCommand::Download(command)).await.unwrap();
}

/// Every event up to and including the first `until` matches; a failed
/// download fails the test.
async fn events_until(core: &mut Core, until: impl Fn(&CoreEvent) -> bool) -> Vec<CoreEvent> {
    let mut events = Vec::new();
    loop {
        let event = next_event(core).await;
        if let CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) = &event {
            panic!("download failed: {reason:?}");
        }
        let done = until(&event);
        events.push(event);
        if done {
            return events;
        }
    }
}

fn offered(file: FileHash) -> impl Fn(&CoreEvent) -> bool {
    move |event| matches!(event, CoreEvent::Serve(ServeEvent::PartialOffered { file_hash }) if *file_hash == file)
}

fn withdrawals(events: &[CoreEvent]) -> Vec<PartialEnd> {
    events
        .iter()
        .filter_map(|event| match event {
            CoreEvent::Serve(ServeEvent::PartialWithdrawn { cause, .. }) => Some(*cause),
            _ => None,
        })
        .collect()
}

fn position(events: &[CoreEvent], wanted: impl Fn(&CoreEvent) -> bool) -> usize {
    events.iter().position(wanted).expect("the event was said")
}

#[tokio::test]
async fn the_first_verified_part_offers_the_download_and_completion_hands_it_to_its_row() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = content();
    let link = file_link("partial.bin", &bytes);
    let store = rmule_testkit::memory_store();
    let (peer, gate) = Gated::new(&bytes);
    let mut core = core(Arc::clone(&store), dir.path(), peer);
    start(&core, &link).await;

    let before = events_until(&mut core, offered(link.file_hash)).await;
    assert!(
        before.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartVerified { .. })
        )),
        "offered once its first part verified"
    );
    gate.send(true).unwrap();
    let file = link.file_hash;
    let after = events_until(&mut core, |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::PartialWithdrawn { file_hash, .. }) if *file_hash == file)
    })
    .await;

    // The row is written before the Partial Share ends: through the step,
    // the file is offered as one or the other.
    let shared = position(
        &after,
        |event| matches!(event, CoreEvent::Serve(ServeEvent::FileShared { file_hash }) if *file_hash == file),
    );
    let completed = position(&after, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        )
    });
    assert!(completed < shared);
    assert_eq!(withdrawals(&after), [PartialEnd::Completed]);
    assert!(shared < after.len() - 1, "the withdrawal follows the row");

    // The row carries the finished file's stamp, so the next scan pass
    // trusts it unread (ADR-0102).
    let row = DurableSharedFileRegistry::new(store)
        .get(file)
        .unwrap()
        .expect("the completed download's row");
    let meta = std::fs::metadata(&row.path).unwrap();
    assert_eq!(row.file_size, meta.len());
    assert_eq!(row.modified, Some(meta.modified().unwrap()));
}

#[tokio::test]
async fn a_paused_download_keeps_its_offer_and_a_cancel_ends_it_once() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = content();
    let link = file_link("partial.bin", &bytes);
    let (peer, _gate) = Gated::new(&bytes);
    let mut core = core(rmule_testkit::memory_store(), dir.path(), peer);
    start(&core, &link).await;
    let queued = events_until(&mut core, offered(link.file_hash)).await;
    let download_id = queued
        .iter()
        .find_map(|event| match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) => {
                Some(*download_id)
            }
            _ => None,
        })
        .expect("queued");

    send(&core, DownloadCommand::PauseDownload { download_id }).await;
    let paused = events_until(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadPaused { .. })
        )
    })
    .await;
    send(&core, DownloadCommand::ResumeDownload { download_id }).await;
    let resumed = events_until(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadResumed { .. })
        )
    })
    .await;
    assert!(withdrawals(&paused).is_empty(), "a pause keeps the offer");
    assert!(withdrawals(&resumed).is_empty());

    send(&core, DownloadCommand::CancelDownload { download_id }).await;
    let file = link.file_hash;
    let cancelled = events_until(&mut core, |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::PartialWithdrawn { file_hash, .. }) if *file_hash == file)
    })
    .await;
    assert_eq!(withdrawals(&cancelled), [PartialEnd::Ended]);
    assert!(cancelled.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::DownloadCancelled { .. })
    )));
}

/// A download paused with its first part recorded, resumed by a core whose
/// download directory is `download_dir`, its guards refusing `home`: the
/// events up to its completion.
async fn resume_recorded(download_dir: &Path, home: Option<&Path>) -> (Vec<CoreEvent>, FileHash) {
    let bytes = content();
    let link = file_link("resumed.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let store = rmule_testkit::memory_store();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let paths = DownloadPaths::from_final_path(download_dir.join("resumed.bin"));
    let record = repo.create_download(&link, None, &paths).unwrap();
    repo.record_verified_part(
        record.id(),
        VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: ED2K_PART_SIZE,
            part_hash: hashes[0],
        },
    )
    .unwrap();
    repo.set_lifecycle(record.id(), DownloadLifecycle::Paused)
        .unwrap();
    ContentFileStore::write_verified_part(&paths, 0, &part(&bytes, 0))
        .await
        .unwrap();
    let (peer, gate) = Gated::new(&bytes);
    gate.send(true).unwrap();
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings {
            download_dir: Some(download_dir.to_path_buf()),
            ..rmule_core::CoreSettings::default()
        })
        .share_guards(ShareGuards {
            home: home.map(Path::to_path_buf),
            data_dir: None,
        })
        .source_lookup(source_with_high_id())
        .peer_transfer(peer)
        .build();
    send(
        &core,
        DownloadCommand::ResumeDownload {
            download_id: record.id(),
        },
    )
    .await;
    let file = link.file_hash;
    let events = events_until(&mut core, |event| match event {
        CoreEvent::Serve(
            ServeEvent::FileShared { file_hash } | ServeEvent::FileWithheld { file_hash, .. },
        ) => *file_hash == file,
        _ => false,
    })
    .await;
    (events, file)
}

#[tokio::test]
async fn a_resumed_download_offers_the_part_it_recorded_unless_its_folder_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(tmp.path()).unwrap();

    let (events, file) = resume_recorded(&dir, None).await;
    assert!(
        events.iter().any(offered(file)),
        "the resumed run's lease rules the range it recorded"
    );

    let tmp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(tmp.path()).unwrap();
    let (events, file) = resume_recorded(&home, Some(&home)).await;
    assert!(
        !events.iter().any(offered(file)),
        "a destination under a refused folder is held back"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Serve(ServeEvent::FileWithheld {
            reason: WithheldReason::Refused,
            ..
        })
    )));
}
