//! Scenario wiring for the requester side, the mirror of [`crate::serve`]: the
//! scripted `PeerWorker`s and source-lookup fakes a download test drives a core
//! with, the link/peer/source builders those scenarios need, and a one-shot
//! driver that runs one download to its terminal event. Every counterparty here
//! is in-process — no socket, no timer beyond the driver's own event deadline —
//! so the scheduling, verification and lifecycle behaviours read as plain event
//! sequences. Socket-level loopback scenarios use [`crate::FakePeer`] instead.

use ed2k::digest::Digest;
use std::path::Path;

use rmule_core::{
    BlockPlan, Core, CoreCommand, CoreConfig, CoreEvent, CoreSettings, DownloadCommand,
    DownloadEvent, DownloadFailure, DownloadedPart, NameTaken, PeerDownloadOutcome,
    PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent, SourceLookupOutcome,
    SourceLookupService,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, Ed2kText, FileHash, FileHashSummary, Informant, Ipv4Endpoint,
    PeerEndpoint, PeerSource, SafeFileName, ServerEndpoint, SourceLookupTarget, SourceSighting,
};
use tokio::time::{Duration, timeout};

/// `name` as a start names its file, cleaned as a link's name is.
#[must_use]
pub fn file_name(name: &str) -> SafeFileName {
    SafeFileName::clean(name, &FileHash::from_bytes([0; 16]))
}

/// `settings` with `dir` as the download directory every start lands in.
#[must_use]
pub fn in_download_dir(settings: CoreSettings, dir: &Path) -> CoreSettings {
    CoreSettings {
        download_dir: Some(dir.to_path_buf()),
        ..settings
    }
}

/// The link a publisher of `bytes` would compute: file hash plus the **ED2K
/// Part Hash Set** when the content spans more than one part (a sub-part file
/// has none to carry).
pub fn file_link(name: &str, bytes: &[u8]) -> Ed2kFileLink {
    let summary = FileHashSummary::digest_bytes(bytes);
    Ed2kFileLink {
        name: Ed2kText::from_utf8(name),
        size: summary.file_size(),
        file_hash: summary.file_hash(),
        part_hash_set: summary.part_hash_set().cloned(),
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// A link that carries no `p=` hash set at all, so the first peer to answer
/// with one becomes the download's **verification authority**.
pub fn file_link_without_part_hash_set(name: &str, bytes: &[u8]) -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8(name),
        size: bytes.len() as u64,
        file_hash: FileHash::from_bytes(ed2k::Ed2kRed::digest(bytes).into()),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// The endpoint a fake source with `last_octet` resolves to, matching the
/// addresses [`source_with_high_id`] and [`two_high_id_sources`] hand out.
pub fn loopback_peer(last_octet: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(
        format!("127.0.0.{last_octet}").parse().unwrap(),
        4663 + u16::from(last_octet) - 1,
    ))
}

/// Wrap plain server-lookup sources as candidates: a `0x42` reply carries no
/// crypt provenance, so every source is `SourceSighting::plain` (ADR-0046).
/// A scripted lookup answer is the test's own word, so a loopback peer passes
/// the Reserved Range check (ADR-0085).
pub fn plain_sources(sources: Vec<PeerSource>) -> Vec<SourceSighting> {
    sources
        .into_iter()
        .map(|source| SourceSighting::plain(source, Informant::Own))
        .collect()
}

/// A `SourceLookupService` that answers every lookup with the same outcome.
#[derive(Clone)]
pub struct StaticSourceLookup {
    /// The snapshot every lookup returns.
    pub outcome: SourceLookupOutcome,
}

impl SourceLookupService for StaticSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(self.outcome.clone())
    }
}

/// One Low-ID source (unusable) and one High-ID source, so exactly one peer is
/// dialable.
pub fn source_with_high_id() -> StaticSourceLookup {
    StaticSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: plain_sources(vec![
                PeerSource::new(ClientId::from_u32(42), 4662),
                PeerSource::new(ClientId::from_u32(0x0100_007F), 4663),
            ]),
        },
    }
}

/// Two High-ID sources, the pair [`loopback_peer`] 1 and 2 resolve to — enough
/// for a race, a backfill, or a cross-peer handover.
pub fn two_high_id_sources() -> StaticSourceLookup {
    StaticSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: plain_sources(vec![
                PeerSource::new(ClientId::from_u32(0x0100_007F), 4663),
                PeerSource::new(ClientId::from_u32(0x0200_007F), 4664),
            ]),
        },
    }
}

/// A `PeerTransferService` whose every worker serves `outcome` and asserts, at
/// shutdown, that it was handed blocks of exactly `expected_plan_count` parts.
pub struct StaticPeerTransfer {
    /// How many distinct parts the worker must have been handed blocks of.
    pub expected_plan_count: usize,
    /// The hash set and parts every worker answers with.
    pub outcome: PeerDownloadOutcome,
}

impl PeerTransferService for StaticPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        Ok(scripted_worker(
            peer,
            file.size,
            self.outcome.clone(),
            PlanExpectation::Count(self.expected_plan_count),
        ))
    }
}

/// The stricter twin of [`StaticPeerTransfer`]: asserts *which* part indexes
/// were handed, in the order of each one's first block — the proof a resumed
/// download skips what it already verified.
pub struct PlanAssertingPeerTransfer {
    /// The exact part indexes, in order, the worker must have been handed.
    pub expected_plan_indexes: Vec<u32>,
    /// The hash set and parts every worker answers with.
    pub outcome: PeerDownloadOutcome,
}

impl PeerTransferService for PlanAssertingPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        Ok(scripted_worker(
            peer,
            file.size,
            self.outcome.clone(),
            PlanExpectation::Indexes(self.expected_plan_indexes.clone()),
        ))
    }
}

/// A `PeerTransferService` whose workers connect, are granted the slot they
/// ask and then stream nothing: the download holds blocks in flight until a
/// command moves them.
pub struct PendingPeerTransfer;

impl PeerTransferService for PendingPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = every_part(file.size);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::Shutdown { .. } => break,
                    _ => {}
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// A probe answer spelling out every part of a `file_size`-byte file — not
/// the complete-source sentinel, so the source-ask gate reads it as it reads
/// a source that never advertised (ADR-0108). What an in-process fake sends
/// after `Connected`, before its first part is assigned (ADR-0030, ADR-0112).
#[must_use]
pub fn every_part(file_size: u64) -> PeerWorkerEvent {
    PeerWorkerEvent::PartsAdvertised {
        parts: Some(rmule_peer::PartBitmap::all_present(
            rmule_primitives::part_count(file_size),
        )),
        complete: false,
    }
}

/// Deliver each block of handout number `handout` whose part `parts` hold,
/// then — when every one was — report the pipeline drained with room for three
/// more (ADR-0117 worker protocol): the download hands the next blocks, or
/// takes the slot back. A handout holding a block of a part it lacks leaves
/// the worker stalled on it.
pub async fn emit_blocks(
    event_tx: &tokio::sync::mpsc::Sender<PeerWorkerEvent>,
    parts: &[DownloadedPart],
    blocks: &[BlockPlan],
    handout: u32,
) {
    let mut whole = true;
    for block in blocks {
        let Some(part) = parts
            .iter()
            .find(|part| part.part_index == block.part_index)
        else {
            whole = false;
            continue;
        };
        let start = (block.start.saturating_sub(part.offset) as usize).min(part.bytes.len());
        let end = (block.end.saturating_sub(part.offset) as usize).min(part.bytes.len());
        let _ = event_tx
            .send(PeerWorkerEvent::BlockReceived {
                part_index: part.part_index,
                offset: block.start,
                bytes: part.bytes[start..end].to_vec(),
            })
            .await;
    }
    if whole {
        let _ = event_tx
            .send(PeerWorkerEvent::BlocksWanted {
                room: 3,
                drained: true,
                handout,
            })
            .await;
    }
}

/// What a [`scripted_worker`] asserts about the parts it was asked for.
enum PlanExpectation {
    Count(usize),
    Indexes(Vec<u32>),
}

/// A `PeerWorker` that connects, is granted its slot the moment it asks —
/// an uploader with a free slot — answers the hash-set ask, or else its first
/// `RequestBlocks`, with the outcome's hash set (when it has one), delivers
/// the handed blocks of the parts it holds, and asserts `expectation` once
/// the runner shuts it down.
fn scripted_worker(
    peer: PeerEndpoint,
    file_size: u64,
    outcome: PeerDownloadOutcome,
    expectation: PlanExpectation,
) -> PeerWorker {
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
    let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let _ = event_tx.send(PeerWorkerEvent::Connected).await;
        let _ = event_tx.send(every_part(file_size)).await;
        let mut requested = Vec::new();
        let mut sent_hashes = false;
        while let Some(command) = command_rx.recv().await {
            match command {
                PeerWorkerCommand::AskSlot => {
                    let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                }
                PeerWorkerCommand::RequestHashSet => {
                    if !sent_hashes && !outcome.peer_hashes.is_empty() {
                        sent_hashes = true;
                        let _ = event_tx
                            .send(PeerWorkerEvent::HashSetReceived {
                                part_hashes: outcome.peer_hashes.clone(),
                            })
                            .await;
                    }
                }
                PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                    for block in &blocks {
                        if !requested.contains(&block.part_index) {
                            requested.push(block.part_index);
                        }
                    }
                    if !sent_hashes && !outcome.peer_hashes.is_empty() {
                        sent_hashes = true;
                        let _ = event_tx
                            .send(PeerWorkerEvent::HashSetReceived {
                                part_hashes: outcome.peer_hashes.clone(),
                            })
                            .await;
                    }
                    emit_blocks(&event_tx, &outcome.parts, &blocks, handout).await;
                }
                PeerWorkerCommand::RequestAich { .. } => {}
                PeerWorkerCommand::RequestAichFileHash => {}
                PeerWorkerCommand::Shutdown { .. } => break,
            }
        }
        match expectation {
            PlanExpectation::Count(expected) => assert_eq!(requested.len(), expected),
            PlanExpectation::Indexes(expected) => assert_eq!(requested, expected),
        }
    });
    PeerWorker::new(peer, command_tx, event_rx)
}

/// Start `file` on a default core wired to `source` and `peer`, and collect
/// every event up to and including the terminal one (completed, failed or
/// cancelled). The rows live in a private in-memory Durable Store and the
/// bytes in a temp dir that dies with the call, so repeated runs never see
/// each other's output file.
pub async fn run_download<S, P>(file: Ed2kFileLink, source: S, peer: P) -> Vec<CoreEvent>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    run_download_with(CoreConfig::default(), file, source, peer).await
}

/// [`run_download`] on a core built with `config`, for a test whose subject
/// is a setting the default does not pin (the workers per download).
pub async fn run_download_with<S, P>(
    config: CoreConfig,
    file: Ed2kFileLink,
    source: S,
    peer: P,
) -> Vec<CoreEvent>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    let dir = tempfile::tempdir().unwrap();
    let identity = crate::test_identity(0x42, "rmule-core-test", 4662);
    let mut core = Core::builder(config, crate::memory_store())
        .settings(in_download_dir(CoreSettings::default(), dir.path()))
        .user_hash(identity.user_hash())
        .source_lookup(source)
        .peer_transfer(peer)
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: file_name("download-workflow.bin"),
        if_taken: NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut events = Vec::new();
    loop {
        let event = next_event(&mut core).await;
        let terminal = matches!(
            event,
            CoreEvent::Download(
                DownloadEvent::DownloadCompleted { .. }
                    | DownloadEvent::DownloadFailed { .. }
                    | DownloadEvent::DownloadCancelled { .. }
            )
        );
        events.push(event);
        if terminal {
            return events;
        }
    }
}

/// The core's next event, or a panic if none arrives within two seconds — the
/// deadline that turns a stalled scheduler into a failure instead of a hang.
pub async fn next_event(core: &mut Core) -> CoreEvent {
    timeout(Duration::from_secs(2), core.next_event())
        .await
        .expect("core emitted next event")
        .expect("core event stream stayed open")
}
