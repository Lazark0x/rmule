//! What arrived survives its run (ADR-0117 §4): a Pause and a Quit cost no
//! block, and a forged byte a checkpoint claims fails its part and refetches,
//! through a real core, a real store and a real part file.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadId, PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent,
    SourceLookupOutcome, SourceLookupService, open_durable_store,
};
use rmule_peer::{PartIndex, PeerHandshakeContext};
use rmule_primitives::{
    ClientId, ED2K_PART_SIZE, EMBLOCKSIZE, Ed2kFileLink, PartHash, PeerEndpoint, PeerSource,
    SourceLookupTarget,
};
use rmule_testkit::{file_link, next_event};

/// What the fake swarm did, and what it does next.
#[derive(Default)]
struct Script {
    /// Blocks it delivers before it goes silent; `None` serves every ask.
    delivers: Option<usize>,
    /// Blocks delivered so far.
    delivered: usize,
    /// The first block it delivers has a flipped byte.
    forges: bool,
    /// Every block asked of it since the script last began a run.
    asked: Vec<(u64, u64)>,
}

/// Peers serving `bytes`, as [`Script`] says.
struct Swarm {
    bytes: Arc<Vec<u8>>,
    hashes: Vec<PartHash>,
    script: Arc<Mutex<Script>>,
}

impl PeerTransferService for Swarm {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size());
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(64);
        let (bytes, hashes) = (Arc::clone(&self.bytes), self.hashes.clone());
        let script = Arc::clone(&self.script);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        let mut silent = false;
                        for block in blocks {
                            let event = {
                                let mut script = script.lock().unwrap();
                                script.asked.push((block.start, block.end));
                                delivery(&mut script, &bytes, block.start, block.end)
                            };
                            match event {
                                Some(event) => {
                                    let _ = event_tx.send(event).await;
                                }
                                None => silent = true,
                            }
                        }
                        // Behind every block it delivered, so the brain has
                        // merged them by the time the test reads this.
                        let told = if silent {
                            PeerWorkerEvent::HashSetReceived {
                                part_hashes: hashes.clone(),
                            }
                        } else {
                            PeerWorkerEvent::BlocksWanted {
                                room: 3,
                                drained: true,
                                handout,
                            }
                        };
                        let _ = event_tx.send(told).await;
                    }
                    PeerWorkerCommand::Shutdown { .. } => break,
                    _ => {}
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// The block `start..end` of `bytes` as `script` delivers it, if it does.
fn delivery(script: &mut Script, bytes: &[u8], start: u64, end: u64) -> Option<PeerWorkerEvent> {
    if script.delivers.is_some_and(|most| script.delivered >= most) {
        return None;
    }
    script.delivered += 1;
    let mut block = bytes[start as usize..end as usize].to_vec();
    if script.forges {
        script.forges = false;
        block[0] ^= 0xFF;
    }
    Some(PeerWorkerEvent::BlockReceived {
        part_index: PartIndex::new((start / ED2K_PART_SIZE) as u32),
        offset: start,
        bytes: block,
    })
}

/// A file of one whole part and a byte, and a core downloading it from the
/// swarm until `script` goes silent.
struct Download {
    core: Core,
    id: DownloadId,
    bytes: Arc<Vec<u8>>,
    link: Ed2kFileLink,
    script: Arc<Mutex<Script>>,
    dir: tempfile::TempDir,
}

/// Two fresh sources at every lookup: a source a run just left is spared its
/// reask clock, and these runs follow one another at once.
#[derive(Clone, Default)]
struct FreshSources {
    lookups: Arc<AtomicU16>,
}

impl SourceLookupService for FreshSources {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        let lookup = self.lookups.fetch_add(1, Ordering::Relaxed);
        let ports = [4662 + lookup * 2, 4663 + lookup * 2];
        Ok(SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: rmule_testkit::plain_sources(
                ports
                    .map(|port| PeerSource::new(ClientId::from_u32(0x0100_007F), port))
                    .to_vec(),
            ),
        })
    }
}

fn core_at(dir: &std::path::Path, swarm: Swarm) -> Core {
    let store = open_durable_store(dir).unwrap();
    let config = CoreConfig {
        download_restore_pace: Duration::from_millis(10),
        ..CoreConfig::default()
    };
    Core::builder(config, store)
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir,
        ))
        .source_lookup(FreshSources::default())
        .peer_transfer(swarm)
        .restore_at_attach()
        .build()
}

async fn started(delivers: usize, forges: bool) -> Download {
    let mut bytes: Vec<u8> = (0..ED2K_PART_SIZE).map(|at| (at % 251) as u8).collect();
    bytes.push(0xCD);
    let link = file_link("arrived.bin", &bytes);
    let script = Arc::new(Mutex::new(Script {
        delivers: Some(delivers),
        forges,
        ..Script::default()
    }));
    let dir = tempfile::tempdir().unwrap();
    let bytes = Arc::new(bytes);
    let mut core = core_at(dir.path(), swarm(&bytes, &link, &script));
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link.clone(),
        source_hint: None,
        name: rmule_testkit::file_name("arrived.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();
    let mut id = None;
    let mut told = 0;
    // The run says its set once; the silent swarm's says the blocks are in.
    while told < 2 {
        match next_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) => {
                id = Some(download_id)
            }
            CoreEvent::Download(DownloadEvent::HashSetReceived { .. }) => told += 1,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("the first run failed: {reason:?}")
            }
            _ => {}
        }
    }
    Download {
        core,
        id: id.expect("queued before its first block"),
        bytes,
        link,
        script,
        dir,
    }
}

fn swarm(bytes: &Arc<Vec<u8>>, link: &Ed2kFileLink, script: &Arc<Mutex<Script>>) -> Swarm {
    Swarm {
        bytes: Arc::clone(bytes),
        hashes: link.part_hash_set.as_ref().unwrap().hashes().to_vec(),
        script: Arc::clone(script),
    }
}

/// The swarm serves again, and its asks are counted from here.
fn serve_everything(script: &Mutex<Script>) -> Vec<(u64, u64)> {
    let mut script = script.lock().unwrap();
    script.delivers = None;
    std::mem::take(&mut script.asked)
}

async fn paused(core: &mut Core, id: DownloadId) {
    core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
        download_id: id,
    }))
    .await
    .unwrap();
    loop {
        if let CoreEvent::Download(DownloadEvent::DownloadPaused { download_id }) =
            next_event(core).await
            && download_id == id
        {
            return;
        }
    }
}

async fn resumed(core: &mut Core, id: DownloadId) {
    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id: id,
    }))
    .await
    .unwrap();
}

/// Every event up to the download's end, its corrupt parts counted.
async fn completed(core: &mut Core) -> usize {
    let mut corrupt = 0;
    loop {
        match next_event(core).await {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => return corrupt,
            CoreEvent::Download(DownloadEvent::PartCorrupt { .. }) => corrupt += 1,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("the run failed: {reason:?}")
            }
            _ => {}
        }
    }
}

/// Whether any of `asked` touches a byte below `end`.
fn asks_below(asked: &[(u64, u64)], end: u64) -> bool {
    asked.iter().any(|&(start, _)| start < end)
}

/// Blocks a run held are not asked again after a Pause, and the file that
/// lands is the file: the bytes came from the first run's part file.
#[tokio::test]
async fn a_paused_download_refetches_no_block_it_had() {
    let mut download = started(3, false).await;
    paused(&mut download.core, download.id).await;
    let first = serve_everything(&download.script);
    assert!(first.len() >= 3, "{first:?}");

    resumed(&mut download.core, download.id).await;
    assert_eq!(completed(&mut download.core).await, 0);

    let asked = serve_everything(&download.script);
    assert!(!asks_below(&asked, 3 * EMBLOCKSIZE), "{asked:?}");
    let landed = std::fs::read(download.dir.path().join("arrived.bin")).unwrap();
    assert!(landed == *download.bytes, "the file is the file");
}

/// A Quit commits what arrived, and a new core over the same store resumes it:
/// the one path every run starts from.
#[tokio::test]
async fn a_restarted_download_refetches_no_block_it_had() {
    let Download {
        core,
        bytes,
        link,
        script,
        dir,
        ..
    } = started(3, false).await;
    core.shutdown().await;
    serve_everything(&script);

    let mut core = core_at(dir.path(), swarm(&bytes, &link, &script));
    assert_eq!(completed(&mut core).await, 0);

    let asked = serve_everything(&script);
    assert!(!asks_below(&asked, 3 * EMBLOCKSIZE), "{asked:?}");
    let landed = std::fs::read(dir.path().join("arrived.bin")).unwrap();
    assert!(landed == *bytes, "the file is the file");
}

/// A forged byte survives its Pause as any other: the part's check, read from
/// the file, fails it, and the refetch puts the file right.
#[tokio::test]
async fn a_forged_cell_fails_its_part_across_a_pause_and_the_refetch_mends_it() {
    let mut download = started(3, true).await;
    paused(&mut download.core, download.id).await;
    serve_everything(&download.script);

    resumed(&mut download.core, download.id).await;
    assert_eq!(completed(&mut download.core).await, 1, "one failed check");

    let asked = serve_everything(&download.script);
    assert!(
        asks_below(&asked, EMBLOCKSIZE),
        "the bad cell is fetched again"
    );
    let landed = std::fs::read(download.dir.path().join("arrived.bin")).unwrap();
    assert!(landed == *download.bytes, "the file is the file");
}
