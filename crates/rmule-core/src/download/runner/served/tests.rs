//! The run's writes to its Served Download, driven through the enactor:
//! the range before the next decision, a set that arrives late or disproves
//! a part, and the identity a pause leaves.

use std::collections::{HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmule_peer::{PartBitmap, PartIndex, PeerHandshakeContext};
use rmule_primitives::{
    ED2K_PART_SIZE, Ed2kFileLink, Informant, Ipv4Endpoint, PartHash, PeerEndpoint, PeerSource,
    SourceSighting,
};

use super::super::enact::{LoopCtx, enact_drain};
use super::super::test_context::{Held, NeverLooksUp, NeverTransfers, loop_ctx, runner_context};
use super::*;
use crate::adapters::{PeerTransferService, PeerWorker, PeerWorkerEvent, WorkerBrief};
use crate::content::HeldPartFile;
use crate::diagnostics::{PartState, WorkerSlot};
use crate::download::source_book::Gate;
use crate::download::state::{
    CallbackCapability, Channel, ContentFacts, Decision, SourcingPosture, StartingFacts,
};
use crate::error::DownloadFailure;
use crate::hashing::ResolvedHashSet;
use crate::ip_filter::IpFilter;
use crate::served_downloads::{ServedDownloads, VerifiedRange};
use crate::service::DownloadEvent;
use crate::{DownloadPaths, DurableDownloadRecord, VerificationAuthority};

const SOURCE: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4662);
const OTHER: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 8), 4662);

/// Two parts: one whole, and a byte.
fn content() -> Vec<u8> {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.push(0xCD);
    bytes
}

fn part_bytes(bytes: &[u8], part_index: u32) -> &[u8] {
    let start = part_index as usize * ED2K_PART_SIZE as usize;
    let end = (start + ED2K_PART_SIZE as usize).min(bytes.len());
    &bytes[start..end]
}

/// Records, at every dial, the status the run would advertise and the
/// Verified Range the serve side would read, then refuses the dial.
struct RecordsAtDial {
    cell: ServedDownloads,
    file: rmule_primitives::FileHash,
    seen: Arc<Mutex<Vec<(PartBitmap, VerifiedRange)>>>,
}

impl PeerTransferService for RecordsAtDial {
    async fn start_peer_worker(
        &mut self,
        _peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        unreachable!("the run dials through the brief")
    }

    async fn start_download_worker(
        &mut self,
        _peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
        brief: WorkerBrief,
    ) -> Result<PeerWorker, DownloadFailure> {
        let range = self.cell.served(self.file).expect("an entry").range;
        self.seen.lock().unwrap().push((brief.own_status, range));
        Err(DownloadFailure::NoUsableSources)
    }
}

/// A run of `link`'s download over `transfer`, its part file held and its
/// lease taken from `cell`.
async fn run_of<P: PeerTransferService>(
    transfer: P,
    link: &Ed2kFileLink,
    cell: &ServedDownloads,
    dir: &Path,
) -> (RunnerContext<NeverLooksUp, P>, Held, DurableDownloadRecord) {
    let (mut runner, held) = runner_context(
        NeverLooksUp,
        transfer,
        crate::diagnostics::DiagnosticsState::default(),
    );
    let paths = DownloadPaths::from_final_path(dir.join("served.bin"));
    let record = runner.rt.store.create_download(link, None, &paths).unwrap();
    let set = link
        .part_hash_set
        .as_ref()
        .map(|set| set.hashes().to_vec())
        .unwrap_or_default();
    assert!(cell.install(&record, &set));
    runner.served = cell.hand_to_run(link.file_hash, crate::download::RunNumber::new(1));
    *runner.part_file.lock().await =
        Some(HeldPartFile::hold(paths.part_path(), 0).await.unwrap().0);
    (runner, held, record)
}

/// The brain of `link`'s download, its one source connected and working
/// the part this returns.
fn working(link: &Ed2kFileLink, record: &DurableDownloadRecord) -> (DownloadState, u32) {
    let resolved = match &link.part_hash_set {
        Some(set) => ResolvedHashSet {
            authority: VerificationAuthority::LinkPartHashSet,
            hashes: set.hashes().to_vec(),
        },
        None => ResolvedHashSet {
            authority: VerificationAuthority::FileHashOnly,
            hashes: Vec::new(),
        },
    };
    let mut state = DownloadState::new(
        record.id(),
        ContentFacts {
            file_hash: link.file_hash,
            file_size: link.size,
            link_part_hash_set: link.part_hash_set.clone(),
            resolved,
            trusted_aich_root: None,
            verified_parts: Vec::new(),
            order: crate::scheduler::PartOrder::Rarest,
        },
        StartingFacts {
            distrusted: HashSet::new(),
            seeds_written: 0,
        },
        SourcingPosture {
            callback_capability: CallbackCapability::server_high_id(),
            dial: crate::dialable::DialPosition::default(),
            discovery_active: false,
            client_udp: false,
        },
        Duration::from_secs(30),
        crate::download::connection_budget::BudgetSeat::ceiling(1),
    );
    let now = Instant::now();
    let _ = state.start(now);
    let filter = IpFilter::default();
    let gate = Gate {
        filter: &filter,
        dial: crate::dialable::DialPosition::default(),
    };
    let _ = state.on_sightings(
        now,
        Channel::Link,
        vec![SourceSighting::plain(
            PeerSource::HighId(SOURCE),
            Informant::Own,
        )],
        &gate,
    );
    let mut decisions =
        state.on_worker_event(now, PeerEndpoint::V4(SOURCE), PeerWorkerEvent::Connected);
    decisions.extend(state.on_worker_event(
        now,
        PeerEndpoint::V4(SOURCE),
        PeerWorkerEvent::every_part(link.size),
    ));
    decisions.extend(state.on_worker_event(
        now,
        PeerEndpoint::V4(SOURCE),
        PeerWorkerEvent::SlotGranted,
    ));
    let assigned = decisions
        .into_iter()
        .find_map(|decision| match decision {
            Decision::Emit(DownloadEvent::PartAssigned { part_index, .. }) => Some(part_index),
            _ => None,
        })
        .expect("the granted source is given a part");
    (state, assigned)
}

/// The loop context of `record`'s run.
fn ctx_of<'a, S, P>(
    runner: &'a RunnerContext<S, P>,
    link: &'a Ed2kFileLink,
    record: &DurableDownloadRecord,
    state: DownloadState,
) -> LoopCtx<'a, S, P> {
    let mut ctx = loop_ctx(runner, link, state);
    ctx.download_id = record.id();
    ctx
}

fn persist(bytes: &[u8], part_index: u32) -> Decision {
    Decision::PersistPart {
        part_index,
        peer: PeerEndpoint::V4(SOURCE),
        offset: u64::from(part_index) * ED2K_PART_SIZE,
        bytes: part_bytes(bytes, part_index).to_vec(),
    }
}

#[tokio::test]
async fn a_persisted_part_is_in_the_range_before_the_next_decision_is_enacted() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = content();
    let link = rmule_testkit::file_link("served.bin", &bytes);
    let cell = ServedDownloads::default();
    let seen = Arc::default();
    let transfer = RecordsAtDial {
        cell: cell.clone(),
        file: link.file_hash,
        seen: Arc::clone(&seen),
    };
    let (runner, _held, record) = run_of(transfer, &link, &cell, dir.path()).await;
    let (state, part) = working(&link, &record);
    let mut ctx = ctx_of(&runner, &link, &record, state);

    // The dial reads `our_part_status` for its brief as it is enacted.
    let mut queue = VecDeque::from([
        persist(&bytes, part),
        Decision::Spawn {
            peer: PeerEndpoint::V4(OTHER),
            slot: WorkerSlot::from_usize(1),
            want_sources: false,
        },
    ]);
    enact_drain(&mut queue, &mut ctx).await.unwrap();

    let seen = seen.lock().unwrap();
    let (status, range) = seen.first().expect("the dial was enacted");
    assert!(
        status.has(PartIndex::new(part)),
        "the status names the part"
    );
    assert!(range.holds(part), "and the serve side already holds it");
    assert_eq!(cell.offered(), [link.file_hash]);
}

#[tokio::test]
async fn the_offer_waits_for_a_whole_set_that_arrives_after_the_part() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = content();
    let with_set = rmule_testkit::file_link("served.bin", &bytes);
    let set = with_set.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let link = Ed2kFileLink {
        part_hash_set: None,
        ..with_set
    };
    let cell = ServedDownloads::default();
    let offers = cell.offer_changes();
    let (runner, _held, record) = run_of(NeverTransfers, &link, &cell, dir.path()).await;
    let (state, part) = working(&link, &record);
    let mut ctx = ctx_of(&runner, &link, &record, state);

    enact_drain(&mut VecDeque::from([persist(&bytes, part)]), &mut ctx)
        .await
        .unwrap();
    assert!(
        cell.offered().is_empty(),
        "a part no set checked is not offered"
    );
    assert!(!offers.has_changed().unwrap());

    let mut arrival = VecDeque::from([Decision::PersistProvisionalHashes(set)]);
    enact_drain(&mut arrival, &mut ctx).await.unwrap();
    assert_eq!(cell.offered(), [link.file_hash]);
    assert!(
        offers.has_changed().unwrap(),
        "the trigger fires when the set arrives"
    );
    assert!(cell.served(link.file_hash).unwrap().range.holds(part));
}

#[tokio::test]
async fn a_part_the_arriving_set_disproves_is_dropped_and_fetched_again() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = content();
    let with_set = rmule_testkit::file_link("served.bin", &bytes);
    let mut set = with_set.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let link = Ed2kFileLink {
        part_hash_set: None,
        ..with_set
    };
    let cell = ServedDownloads::default();
    let (runner, mut held, record) = run_of(NeverTransfers, &link, &cell, dir.path()).await;
    let (state, part) = working(&link, &record);
    let mut ctx = ctx_of(&runner, &link, &record, state);
    enact_drain(&mut VecDeque::from([persist(&bytes, part)]), &mut ctx)
        .await
        .unwrap();
    assert_eq!(ctx.file_hash_only_parts, [part]);

    set[part as usize] = PartHash::from_bytes([0xEE; 16]);
    let mut arrival = VecDeque::from([Decision::PersistProvisionalHashes(set)]);
    enact_drain(&mut arrival, &mut ctx).await.unwrap();

    assert!(
        runner
            .rt
            .store
            .verified_parts(record.id())
            .unwrap()
            .is_empty(),
        "its record is gone"
    );
    assert!(ctx.file_hash_only_parts.is_empty());
    assert!(!ctx.state.our_part_status().has(PartIndex::new(part)));
    assert_ne!(ctx.state.part_map().0[part as usize], PartState::Verified);
    assert!(cell.offered().is_empty());
    let said = std::iter::from_fn(|| held.evt_rx.try_recv().ok()).find_map(|event| match event {
        crate::service::CoreEvent::Download(DownloadEvent::PartsDisproved {
            parts, bytes, ..
        }) => Some((parts, bytes)),
        _ => None,
    });
    assert_eq!(
        said,
        Some((1, part_bytes(&bytes, part).len() as u64)),
        "the loss is said"
    );
}

#[tokio::test]
async fn a_pause_leaves_the_key_length_and_time_of_the_part_file_it_lets_go() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = content();
    let link = rmule_testkit::file_link("served.bin", &bytes);
    let cell = ServedDownloads::default();
    let (runner, _held, record) = run_of(NeverTransfers, &link, &cell, dir.path()).await;
    let part_path = record.paths().part_path().to_path_buf();

    lease_started(&runner, record.id()).await;
    let running = cell.served(link.file_hash).unwrap().identity.unwrap();
    assert_eq!(running.key, FileKey::at(&part_path).unwrap());
    assert_eq!(running.at_rest, None, "a run writes the file");

    runner
        .part_file
        .lock()
        .await
        .as_mut()
        .unwrap()
        .write_part(0, part_bytes(&bytes, 0))
        .await
        .unwrap();
    let_go(&runner).await;

    assert!(
        runner.part_file.lock().await.is_none(),
        "the handle is let go"
    );
    let meta = std::fs::metadata(&part_path).unwrap();
    let paused = cell.served(link.file_hash).unwrap().identity.unwrap();
    assert_eq!(paused.key, FileKey::at(&part_path).unwrap());
    let at_rest = paused.at_rest.expect("nobody writes a paused file");
    assert_eq!(at_rest.len, meta.len());
    assert_eq!(at_rest.modified, meta.modified().unwrap());
}
