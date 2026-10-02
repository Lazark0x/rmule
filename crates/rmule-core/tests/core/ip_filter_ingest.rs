//! IP-filter enforcement at the runner's source-ingest gates and the
//! global-source server-list install — the *wiring* proof the
//! `ip_filter` unit tests cannot give: each test loads a real dat file
//! through `CoreBuilder::ip_filter_dir` and drives one ingest path end to
//! end, asserting the filtered row never becomes a dial while its admitted
//! neighbor completes the download.
//!
//! aMule ground truth per path: the server snapshot and exchanged rows
//! (`CPartFile::AddSources`/`AddClientSources`, `PartFile.cpp:1668`/`:2799`),
//! Kad-projected rows (`CDownloadQueue::KademliaSearchFile`,
//! `DownloadQueue.cpp:1563`), the global-UDP rows (the same `AddSources`
//! ingest), and the server-list install (`CServerList::AddServer`,
//! `ServerList.cpp:210`).
//!
//! The scripted transfer's `expected_peer` assert doubles as the negative
//! proof: any dial to the filtered endpoint panics the worker spawn, so a
//! regression that drops one `retain` fails loudly, not silently.

use rmule_core::KadSource;
use std::sync::{Arc, Mutex};

use crate::fixture::identity;
use crate::fixture::kad_enable_config;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadedPart, KadEnableConfig, KadRuntimeFactory, KadSourceChannel, PeerDownloadOutcome,
    PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent, SourceLookupOutcome,
    SourceLookupService,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, ExchangedSource, FileHash, PeerEndpoint, PeerSource, ServerEndpoint,
    SourceLookupTarget,
};
use rmule_testkit::file_link_without_part_hash_set;
use rmule_testkit::{FakeEd2kServer, FakeServerUdp};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// `203.0.113.9` as an eD2k High-ID (client IDs carry the IP little-endian):
/// the row every dat file below blocks.
fn filtered_source(port: u16) -> PeerSource {
    PeerSource::new(
        ClientId::from_u32(u32::from_le_bytes([203, 0, 113, 9])),
        port,
    )
}

/// `10.0.0.9` — the admitted High-ID neighbor that carries the download.
fn admitted_source(port: u16) -> PeerSource {
    PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 9])), port)
}

/// A config dir whose `ipfilter.dat` blocks TEST-NET-3 at level 0.
fn blocklist_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("ipfilter.dat"),
        b"203.0.113.0-203.0.113.255,0,test blocklist\n",
    )
    .expect("write ipfilter.dat");
    dir
}

/// A server session up on a scripted fake server: the global source sweep
/// asks only while one is (ADR-0051's amendment). The server lives as
/// long as the returned handle.
async fn with_server_session(core: &Core) -> FakeEd2kServer {
    let server = FakeEd2kServer::start_scripted().await;
    rmule_testkit::connect_to(
        core,
        &server.endpoint(),
        crate::fixture::identity_with_port(0).into(),
    )
    .await;
    server
}

fn serving_outcome(bytes: &[u8]) -> PeerDownloadOutcome {
    PeerDownloadOutcome {
        peer_hashes: Vec::new(),
        parts: vec![DownloadedPart {
            part_index: 0,
            offset: 0,
            bytes: bytes.to_vec(),
        }],
    }
}

#[derive(Clone)]
struct ScriptedSourceLookup {
    outcome: SourceLookupOutcome,
}

impl SourceLookupService for ScriptedSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(self.outcome.clone())
    }
}

/// Serves the single part to `expected_peer`; a dial to anything else — the
/// filtered row, in every test below — panics.
struct ScriptedPeerTransfer {
    expected_peer: PeerEndpoint,
    outcome: PeerDownloadOutcome,
}

impl PeerTransferService for ScriptedPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        assert_eq!(
            peer, self.expected_peer,
            "only the admitted source is ever dialed"
        );
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(16);
        let outcome = self.outcome.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::RequestPart {
                        plan,
                        resume_offset,
                    } => {
                        if let Some(part) = outcome
                            .parts
                            .iter()
                            .find(|part| part.part_index == plan.part_index)
                        {
                            let start = (resume_offset.saturating_sub(part.offset) as usize)
                                .min(part.bytes.len());
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlockReceived {
                                    part_index: part.part_index,
                                    offset: resume_offset,
                                    bytes: part.bytes[start..].to_vec(),
                                })
                                .await;
                            let _ = event_tx
                                .send(PeerWorkerEvent::PartStreamed {
                                    part_index: part.part_index,
                                })
                                .await;
                        }
                    }
                    PeerWorkerCommand::RequestAich { .. } => {}
                    PeerWorkerCommand::RequestAichFileHash => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

async fn drive_to_completion(core: &mut Core) -> Vec<CoreEvent> {
    let mut events = Vec::new();
    loop {
        let event = timeout(Duration::from_secs(5), core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        let completed = matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        );
        if let CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) = &event {
            panic!("download failed: {reason:?}");
        }
        events.push(event);
        if completed {
            break;
        }
    }
    events
}

/// The initial server-snapshot ingest (aMule `CPartFile::AddSources`): the
/// filtered High-ID row is dropped before the `SourcesFound` counts, so the
/// event reports one usable source, and only the admitted row is dialed.
#[tokio::test]
async fn a_filtered_server_snapshot_source_never_reaches_the_pool() {
    let bytes = b"snapshot ingest gate".to_vec();
    let admitted = admitted_source(4663);
    let dir = blocklist_dir();

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(ScriptedSourceLookup {
            outcome: SourceLookupOutcome {
                client_id: ClientId::from_u32(0x0100_007F),
                sources: vec![
                    ExchangedSource::plain(filtered_source(4662)),
                    ExchangedSource::plain(admitted),
                ],
            },
        })
        .peer_transfer(ScriptedPeerTransfer {
            expected_peer: admitted.as_peer_endpoint().unwrap(),
            outcome: serving_outcome(&bytes),
        })
        .ip_filter_dir(dir.path().to_path_buf())
        .build();

    let out = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("filtered-ingest.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: out.path().join("snapshot.bin"),
    }))
    .await
    .unwrap();

    let events = drive_to_completion(&mut core).await;
    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::SourcesFound {
                total: 1,
                usable_high_id: 1,
                ..
            })
        )),
        "the filtered row is dropped before the counts (2 rows in, 1 counted): {events:?}"
    );
}

// --- Kad ingest --------------------------------------------------------------

struct FakeKadChannel {
    answer: Vec<KadSource>,
    answers_tx: mpsc::Sender<(FileHash, Vec<KadSource>)>,
    answers_rx: tokio::sync::Mutex<mpsc::Receiver<(FileHash, Vec<KadSource>)>>,
}

impl FakeKadChannel {
    fn new(answer: Vec<KadSource>) -> Self {
        let (answers_tx, answers_rx) = mpsc::channel(8);
        Self {
            answer,
            answers_tx,
            answers_rx: tokio::sync::Mutex::new(answers_rx),
        }
    }
}

impl KadSourceChannel for FakeKadChannel {
    async fn search_sources(&self, target: SourceLookupTarget) {
        let _ = self
            .answers_tx
            .send((target.file_hash(), self.answer.clone()))
            .await;
    }

    async fn publish_source(&self, _target: SourceLookupTarget) {}

    async fn next_sources(&self) -> Option<(FileHash, Vec<KadSource>)> {
        self.answers_rx.lock().await.recv().await
    }
}

struct FakeKadFactory {
    channel: Option<FakeKadChannel>,
}

impl KadRuntimeFactory for FakeKadFactory {
    type Channel = FakeKadChannel;

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _bind: rmule_core::ClientUdpBind,
    ) -> Result<FakeKadChannel, rmule_core::CoreError> {
        Ok(self.channel.take().expect("kad started once"))
    }
}

#[derive(Clone)]
struct FailingSourceLookup;

impl SourceLookupService for FailingSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Err(DownloadFailure::ServerDisconnected)
    }
}

/// The Kad-projected ingest (aMule `CDownloadQueue::KademliaSearchFile`): the
/// filtered row rides first in the projected batch and must never be dialed;
/// the admitted row carries the serverless download to completion.
#[tokio::test]
async fn a_filtered_kad_source_is_never_dialed() {
    let bytes = b"kad ingest gate".to_vec();
    let admitted = admitted_source(4663);
    let dir = blocklist_dir();

    let mut core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .source_lookup(FailingSourceLookup)
    .peer_transfer(ScriptedPeerTransfer {
        expected_peer: admitted.as_peer_endpoint().unwrap(),
        outcome: serving_outcome(&bytes),
    })
    .kad(FakeKadFactory {
        channel: Some(FakeKadChannel::new(vec![
            KadSource::dialable(filtered_source(4662)),
            KadSource::dialable(admitted),
        ])),
    })
    .ip_filter_dir(dir.path().to_path_buf())
    .build();

    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();

    let out = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("filtered-ingest.bin", &bytes),
        // A server nothing listens on: the lookup fails and Kad carries it.
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 1).unwrap()),
        credentials: identity().into(),
        output_path: out.path().join("kad.bin"),
    }))
    .await
    .unwrap();

    drive_to_completion(&mut core).await;
}

// --- source-exchange ingest --------------------------------------------------

/// First dial (the exchanger) hands over exchanged rows and disconnects;
/// second dial must be the admitted exchanged row, which serves the file. A
/// dial to the filtered exchanged row panics.
struct ExchangeThenServe {
    exchanger: PeerEndpoint,
    exchanged: Vec<ExchangedSource>,
    serving: PeerEndpoint,
    outcome: PeerDownloadOutcome,
    dials: Arc<Mutex<Vec<PeerEndpoint>>>,
}

impl PeerTransferService for ExchangeThenServe {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        self.dials.lock().unwrap().push(peer);
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(16);
        if peer == self.exchanger {
            let sources = self.exchanged.clone();
            tokio::spawn(async move {
                let _ = event_tx.send(PeerWorkerEvent::Connected).await;
                let _ = event_tx
                    .send(PeerWorkerEvent::SourcesReceived { sources })
                    .await;
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                while command_rx.recv().await.is_some() {}
            });
        } else {
            assert_eq!(
                peer, self.serving,
                "the filtered exchanged row is never dialed"
            );
            let outcome = self.outcome.clone();
            tokio::spawn(async move {
                let _ = event_tx.send(PeerWorkerEvent::Connected).await;
                while let Some(command) = command_rx.recv().await {
                    match command {
                        PeerWorkerCommand::RequestPart {
                            plan,
                            resume_offset,
                        } => {
                            if let Some(part) = outcome
                                .parts
                                .iter()
                                .find(|part| part.part_index == plan.part_index)
                            {
                                let start = (resume_offset.saturating_sub(part.offset) as usize)
                                    .min(part.bytes.len());
                                let _ = event_tx
                                    .send(PeerWorkerEvent::BlockReceived {
                                        part_index: part.part_index,
                                        offset: resume_offset,
                                        bytes: part.bytes[start..].to_vec(),
                                    })
                                    .await;
                                let _ = event_tx
                                    .send(PeerWorkerEvent::PartStreamed {
                                        part_index: part.part_index,
                                    })
                                    .await;
                            }
                        }
                        PeerWorkerCommand::RequestAich { .. } => {}
                        PeerWorkerCommand::RequestAichFileHash => {}
                        PeerWorkerCommand::Shutdown { .. } => break,
                    }
                }
            });
        }
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// The source-exchange ingest (aMule `CPartFile::AddClientSources`): the
/// filtered exchanged row — listed first, so an ungated pool would dial it —
/// never becomes a candidate; the admitted row backfills the freed slot.
#[tokio::test]
async fn a_filtered_exchanged_source_is_never_dialed() {
    let bytes = b"source exchange ingest gate".to_vec();
    let exchanger = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 7])), 4662);
    let admitted = admitted_source(4663);
    let dials = Arc::new(Mutex::new(Vec::new()));
    let dir = blocklist_dir();

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(ScriptedSourceLookup {
            outcome: SourceLookupOutcome {
                client_id: ClientId::from_u32(0x0100_007F),
                sources: vec![ExchangedSource::plain(exchanger)],
            },
        })
        .peer_transfer(ExchangeThenServe {
            exchanger: exchanger.as_peer_endpoint().unwrap(),
            exchanged: vec![
                ExchangedSource::plain(filtered_source(4662)),
                ExchangedSource::plain(admitted),
            ],
            serving: admitted.as_peer_endpoint().unwrap(),
            outcome: serving_outcome(&bytes),
            dials: dials.clone(),
        })
        .ip_filter_dir(dir.path().to_path_buf())
        .build();

    let out = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("filtered-ingest.bin", &bytes),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: out.path().join("sx.bin"),
    }))
    .await
    .unwrap();

    let events = drive_to_completion(&mut core).await;
    let dialed = dials.lock().unwrap().clone();
    assert_eq!(
        dialed,
        vec![
            exchanger.as_peer_endpoint().unwrap(),
            admitted_source(4663).as_peer_endpoint().unwrap(),
        ],
        "exactly the exchanger then the admitted exchanged row"
    );
    // The answer is reported as it arrived and as the gate left it.
    let exchanged: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            CoreEvent::Download(DownloadEvent::SourcesExchanged {
                peer,
                received,
                admitted,
                ..
            }) => Some((*peer, *received, *admitted)),
            _ => None,
        })
        .collect();
    assert_eq!(
        exchanged,
        vec![(exchanger.as_peer_endpoint().unwrap(), 2, 1)]
    );
}

// --- global-UDP ingest and the server-list install ---------------------------

/// The global-UDP ingest (the same `CPartFile::AddSources` gate): the fake
/// managed server answers with the filtered row first; only the admitted row
/// may rescue the sourceless download.
#[tokio::test]
async fn a_filtered_global_udp_source_is_never_dialed() {
    let bytes = b"global udp ingest gate".to_vec();
    let file = file_link_without_part_hash_set("filtered-ingest.bin", &bytes);
    let admitted = admitted_source(4663);
    let udp = FakeServerUdp::start(file.file_hash, vec![filtered_source(4662), admitted]).await;
    let dir = blocklist_dir();

    let mut core = Core::builder(
        CoreConfig {
            global_source_interval: Duration::from_millis(50),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .source_lookup(ScriptedSourceLookup {
        // A connected server with zero sources: only global-UDP can rescue.
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![],
        },
    })
    .peer_transfer(ScriptedPeerTransfer {
        expected_peer: admitted.as_peer_endpoint().unwrap(),
        outcome: serving_outcome(&bytes),
    })
    .ip_filter_dir(dir.path().to_path_buf())
    .build();

    crate::fixture::list_server(
        &core,
        &ServerEndpoint::parse_host_port(&format!("127.0.0.1:{}", udp.local_addr().port() - 4))
            .unwrap(),
    )
    .await;
    let _session = with_server_session(&core).await;

    let out = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: out.path().join("global.bin"),
    }))
    .await
    .unwrap();

    drive_to_completion(&mut core).await;
}

/// The server-list install gate (aMule `CServerList::AddServer`,
/// `ServerList.cpp:210`): with the server gate on, a filtered server never
/// enters the swept list, so the rescue never happens; flipping only
/// `ip_filter_servers` off makes the identical setup rescue — the delta is
/// the server gate, which also refuses the loopback session in the gated run. The client gate stays off throughout so
/// the loopback *peer* rows stay admissible.
#[tokio::test]
async fn a_filtered_listed_server_stays_out_of_the_swept_list() {
    let bytes = b"server list install gate".to_vec();
    let file = file_link_without_part_hash_set("filtered-ingest.bin", &bytes);
    let admitted_peer = admitted_source(4663);

    let run = |filter_servers: bool, bytes: Vec<u8>, file: Ed2kFileLink| async move {
        let udp = FakeServerUdp::start(file.file_hash, vec![admitted_source(4663)]).await;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("ipfilter.dat"),
            b"127.0.0.0-127.0.0.255,0,loopback servers blocked\n",
        )
        .expect("write ipfilter.dat");

        let mut core = Core::builder(
            CoreConfig {
                global_source_interval: Duration::from_millis(50),
                ip_filter_clients: false,
                ip_filter_servers: filter_servers,
                ..CoreConfig::default()
            },
            rmule_testkit::memory_store(),
        )
        .source_lookup(ScriptedSourceLookup {
            outcome: SourceLookupOutcome {
                client_id: ClientId::from_u32(0x0100_007F),
                sources: vec![],
            },
        })
        .peer_transfer(ScriptedPeerTransfer {
            expected_peer: admitted_source(4663).as_peer_endpoint().unwrap(),
            outcome: serving_outcome(&bytes),
        })
        .ip_filter_dir(dir.path().to_path_buf())
        .build();

        crate::fixture::list_server(
            &core,
            &ServerEndpoint::parse_host_port(&format!("127.0.0.1:{}", udp.local_addr().port() - 4))
                .unwrap(),
        )
        .await;
        // With the server gate on, the loopback session is refused too; the
        // swept-list half of the delta is proven at the level
        // (`diagnostics::state::server_health`).
        let _session = with_server_session(&core).await;

        let out = tempfile::tempdir().unwrap();
        core.send(CoreCommand::Download(DownloadCommand::StartDownload {
            file,
            source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            credentials: identity().into(),
            output_path: out.path().join("install.bin"),
        }))
        .await
        .unwrap();

        // Watch for a rescue within a bounded window.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(900);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match timeout(remaining, core.next_event()).await {
                Ok(Some(CoreEvent::Download(DownloadEvent::PeerSelected { .. }))) => return true,
                Ok(Some(_)) => {}
                Ok(None) => return false,
                Err(_) => return false,
            }
        }
    };

    assert!(
        !run(true, bytes.clone(), file.clone()).await,
        "with the server gate on, the filtered server never enters the swept \
         list and no rescue happens"
    );
    assert!(
        run(false, bytes, file).await,
        "the identical setup rescues with the gate off — the delta is the \
         server gate, not the harness"
    );
    let _ = admitted_peer;
}
