//! Fleet-end Peer Roster consistency: `CancelDownload` must not
//! leak the Download relation for a worker the fleet never gets to see a
//! `Disconnected` fact for — whether that fact never arrives at all (an
//! aborted task) or is already racing into `fact_rx` when the stop signal
//! fires.

use std::sync::Arc;

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, FileHashSummary, Informant, PeerEndpoint, PeerSource,
    ServerEndpoint, SourceSighting,
};
use tokio::sync::Notify;
use tokio::time::{Duration, timeout};

use crate::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, SourceLookupOutcome,
};

use super::*;

mod dial_ends;

/// A `SourceLookupService` that answers every lookup with the same single
/// High-ID source — `PEER_CLIENT_ID` decodes to 127.0.0.1 (a High ID *is* the
/// client's IPv4 address as a little-endian `u32`).
const PEER_CLIENT_ID: u32 = 0x0100_007F;

#[derive(Clone)]
struct FixedSourceLookup;

impl SourceLookupService for FixedSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: rmule_primitives::SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(SourceLookupOutcome {
            client_id: ClientId::from_u32(PEER_CLIENT_ID),
            sources: vec![SourceSighting::plain(
                PeerSource::new(ClientId::from_u32(PEER_CLIENT_ID), 4663),
                Informant::Own,
            )],
        })
    }
}

/// A worker that connects and then absorbs every command — including
/// `Shutdown` — without ever answering with its own `Disconnected`: the
/// aborted-task case, where the fleet's stop path cannot depend on the
/// worker's own fact stream to forget the roster.
struct StuckPeerTransfer;

impl PeerTransferService for StuckPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = PeerWorkerEvent::every_part(file.size);
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            // An uploader with a free slot grants it at once (ADR-0026).
            let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
            while command_rx.recv().await.is_some() {}
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// A worker that connects, then sends its own `Disconnected` the moment
/// `disconnect` is notified — used to race that fact against a `CancelDownload`
/// dispatched around the same instant.
struct DisconnectOnCuePeerTransfer {
    disconnect: Arc<Notify>,
}

impl PeerTransferService for DisconnectOnCuePeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = PeerWorkerEvent::every_part(file.size);
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(8);
        let disconnect = self.disconnect.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            // An uploader with a free slot grants it at once (ADR-0026).
            let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
            disconnect.notified().await;
            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
            while command_rx.recv().await.is_some() {}
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

fn example_file() -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("example.bin"),
        size: 11,
        file_hash: FileHash::from_bytes([0xAB; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// Await the next fact from `core`, bounded so a stalled fixture times out
/// instead of hanging the suite.
async fn next_core_event(core: &mut Core) -> CoreEvent {
    timeout(Duration::from_secs(2), core.next_event())
        .await
        .expect("core emitted next event within 2s")
        .expect("core event stream stayed open")
}

#[tokio::test]
async fn cancelling_a_download_forgets_a_still_connected_workers_roster_ip() {
    let out_dir = tempfile::tempdir().unwrap();
    let peer_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let store = crate::open_durable_store_in_memory().expect("in-memory store opens");
    let builder = Core::builder(CoreConfig::default(), store)
        .settings(crate::CoreSettings {
            download_dir: Some(out_dir.path().to_path_buf()),
            ..crate::CoreSettings::default()
        })
        .source_lookup(FixedSourceLookup)
        .peer_transfer(StuckPeerTransfer);
    let roster = builder.shared_peer_roster();
    let mut core = builder.build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: example_file(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_primitives::SafeFileName::clean(
            "roster-stop-leak.bin",
            &rmule_primitives::FileHash::from_bytes([0; 16]),
        ),
        if_taken: crate::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    let mut download_id = None;
    loop {
        match next_core_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => {
                download_id = Some(id);
            }
            CoreEvent::Download(DownloadEvent::PartAssigned { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed before a part was assigned: {reason:?}")
            }
            _ => {}
        }
    }
    let download_id = download_id.expect("DownloadQueued emitted before PartAssigned");
    assert!(
        roster.knows(peer_ip),
        "the fleet marked the connected peer's IP known"
    );

    // The worker never sends its own `Disconnected` — it absorbs `Shutdown`
    // and stops replying. Only the stop path's own forget-from-`command_channels`
    // write can retire the roster's mark here.
    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id,
    }))
    .await
    .unwrap();
    loop {
        match next_core_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::DownloadCancelled { download_id: id })
                if id == download_id =>
            {
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                panic!("the sole worker never delivered a part — nothing to complete")
            }
            _ => {}
        }
    }
    assert!(
        !roster.knows(peer_ip),
        "cancelling forgot the still-connected worker's IP even though it never sent its own Disconnected"
    );
}

#[tokio::test]
async fn a_disconnect_already_racing_into_fact_rx_at_stop_is_not_lost() {
    let out_dir = tempfile::tempdir().unwrap();
    let peer_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let store = crate::open_durable_store_in_memory().expect("in-memory store opens");
    let disconnect = Arc::new(Notify::new());
    let builder = Core::builder(CoreConfig::default(), store)
        .settings(crate::CoreSettings {
            download_dir: Some(out_dir.path().to_path_buf()),
            ..crate::CoreSettings::default()
        })
        .source_lookup(FixedSourceLookup)
        .peer_transfer(DisconnectOnCuePeerTransfer {
            disconnect: disconnect.clone(),
        });
    let roster = builder.shared_peer_roster();
    let mut core = builder.build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: example_file(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_primitives::SafeFileName::clean(
            "roster-stop-race.bin",
            &rmule_primitives::FileHash::from_bytes([0; 16]),
        ),
        if_taken: crate::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    let mut download_id = None;
    loop {
        match next_core_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => {
                download_id = Some(id);
            }
            CoreEvent::Download(DownloadEvent::PartAssigned { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed before a part was assigned: {reason:?}")
            }
            _ => {}
        }
    }
    let download_id = download_id.expect("DownloadQueued emitted before PartAssigned");
    assert!(
        roster.knows(peer_ip),
        "the fleet marked the connected peer's IP known"
    );

    // Fire the worker's own `Disconnected` and the operator's `CancelDownload`
    // back to back, with no await between them: whichever the fleet's `select!`
    // observes first — the normal per-iteration match, or the stop path's own
    // forget-and-drain — the roster must end up forgotten either way.
    disconnect.notify_one();
    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id,
    }))
    .await
    .unwrap();
    loop {
        match next_core_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::DownloadCancelled { download_id: id })
                if id == download_id =>
            {
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                panic!("the sole worker never delivered a part — nothing to complete")
            }
            _ => {}
        }
    }
    assert!(
        !roster.knows(peer_ip),
        "a Disconnected racing into fact_rx right at stop is not lost — the roster still forgets"
    );
}

/// The bytes the completing worker below serves — one short part, so the
/// file hash is the MD4 of the data and one block completes the download.
const SERVED: &[u8] = b"hello world";

/// A worker that connects, streams the whole part it is asked for once
/// `deliver` is notified, then absorbs `Shutdown` without ever answering
/// with its own `Disconnected`. The gate holds the download short of
/// completion while the test reads the roster.
struct CompletingPeerTransfer {
    deliver: Arc<Notify>,
}

impl PeerTransferService for CompletingPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = PeerWorkerEvent::every_part(file.size);
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(8);
        let deliver = Arc::clone(&self.deliver);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            // An uploader with a free slot grants it at once (ADR-0026).
            let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
            while let Some(command) = command_rx.recv().await {
                if let crate::PeerWorkerCommand::RequestBlocks { blocks, handout } = command {
                    deliver.notified().await;
                    let _ = event_tx
                        .send(PeerWorkerEvent::BlockReceived {
                            part_index: blocks[0].part_index,
                            offset: blocks[0].start,
                            bytes: SERVED.to_vec(),
                        })
                        .await;
                    let _ = event_tx
                        .send(PeerWorkerEvent::BlocksWanted {
                            room: 3,
                            drained: true,
                            handout,
                        })
                        .await;
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// A completing download ends its fleet through `Finalize`, which
/// passes no `EndWorker` — the whole-fleet shutdown is the Download
/// relation's terminal, whether or not the worker ever sends `Disconnected`.
#[tokio::test]
async fn a_completed_download_forgets_its_still_connected_workers_roster_ip() {
    let out_dir = tempfile::tempdir().unwrap();
    let peer_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let store = crate::open_durable_store_in_memory().expect("in-memory store opens");
    let deliver = Arc::new(Notify::new());
    let builder = Core::builder(CoreConfig::default(), store)
        .settings(crate::CoreSettings {
            download_dir: Some(out_dir.path().to_path_buf()),
            ..crate::CoreSettings::default()
        })
        .source_lookup(FixedSourceLookup)
        .peer_transfer(CompletingPeerTransfer {
            deliver: Arc::clone(&deliver),
        });
    let roster = builder.shared_peer_roster();
    let mut core = builder.build();

    let summary = FileHashSummary::digest_bytes(SERVED);
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: Ed2kFileLink {
            size: summary.file_size(),
            file_hash: summary.file_hash(),
            ..example_file()
        },
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_primitives::SafeFileName::clean(
            "roster-complete.bin",
            &rmule_primitives::FileHash::from_bytes([0; 16]),
        ),
        if_taken: crate::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    let mut marked = false;
    loop {
        match next_core_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::PartAssigned { .. }) => {
                marked |= roster.knows(peer_ip);
                deliver.notify_one();
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("the sole worker served the whole file: {reason:?}")
            }
            _ => {}
        }
    }
    assert!(marked, "the fleet marked the connected peer's IP known");
    assert!(
        !roster.knows(peer_ip),
        "completion forgot the worker's Download relation without its Disconnected"
    );
}

/// A worker that connects, is queued, then hangs up — the source a download
/// pools on the reask heartbeat (ADR-0057).
struct QueuedThenHangUpPeerTransfer;

impl PeerTransferService for QueuedThenHangUpPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = PeerWorkerEvent::every_part(file.size);
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            let _ = event_tx.send(PeerWorkerEvent::Queued { rank: 5 }).await;
            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
            while command_rx.recv().await.is_some() {}
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// Per ADR-0059 "Roster relations", a source that queued us
/// and hung up stays known to the UDP self-check after its worker retires —
/// the Remote-Queued Pool holds a `Queued` relation, aMule's `DS_ONQUEUE`
/// client — and leaves the roster when the download ends. Before, the
/// Download relation ended at retirement and nothing held the pooled peer.
#[tokio::test]
async fn a_remote_queued_peer_stays_known_after_its_worker_retires() {
    let out_dir = tempfile::tempdir().unwrap();
    let peer_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let store = crate::open_durable_store_in_memory().expect("in-memory store opens");
    let builder = Core::builder(CoreConfig::default(), store)
        .settings(crate::CoreSettings {
            download_dir: Some(out_dir.path().to_path_buf()),
            ..crate::CoreSettings::default()
        })
        .source_lookup(FixedSourceLookup)
        .peer_transfer(QueuedThenHangUpPeerTransfer);
    let roster = builder.shared_peer_roster();
    let mut core = builder.build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: example_file(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_primitives::SafeFileName::clean(
            "roster-queued.bin",
            &rmule_primitives::FileHash::from_bytes([0; 16]),
        ),
        if_taken: crate::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();
    let download_id = loop {
        if let CoreEvent::Download(DownloadEvent::SourceRemoteQueued { download_id, .. }) =
            next_core_event(&mut core).await
        {
            break download_id;
        }
    };
    // The brain's release of the retired worker — and with it the Download
    // relation's forget — follows the pooling on the same fleet turn; let it
    // land before reading the roster.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        roster.knows(peer_ip),
        "a remote-queued source stays known after its worker retired"
    );

    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id,
    }))
    .await
    .unwrap();
    loop {
        if let CoreEvent::Download(DownloadEvent::DownloadCancelled { .. }) =
            next_core_event(&mut core).await
        {
            break;
        }
    }
    assert!(
        !roster.knows(peer_ip),
        "the download's end ends its Queued relations"
    );
}
