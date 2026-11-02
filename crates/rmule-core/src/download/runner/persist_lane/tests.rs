//! A run's disk through its lane: a checkpoint stands behind the bytes it
//! claims, a refused write ends the lane before anything behind it runs, and
//! the Write Cache holds a drain until a write gives back, a stop excepted.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use rmule_peer::PartIndex;
use rmule_primitives::{Ed2kFileLink, Ed2kText, FileHash, Ipv4Endpoint, PeerEndpoint};

use super::{LaneFact, PersistLane};
use crate::DownloadPaths;
use crate::assembly::{ArrivedPart, ArrivedWriter};
use crate::content::HeldPartFile;
use crate::diagnostics::DiagnosticsState;
use crate::download::runner::enact::{enact_drain, end_lane};
use crate::download::runner::test_context::{
    Held, NeverLooksUp, NeverTransfers, loop_ctx, one_part_state, runner_context,
};
use crate::download::runner::{RunnerContext, StopReason};
use crate::download::state::Decision;
use crate::download::write_cache::{CachedBytes, WriteCache};
use crate::error::DownloadFailure;
use crate::service::{DownloadId, VolumeStop};
use crate::storage::DownloadRepository;

const SIZE: u64 = 64 * 1024;

fn link() -> Ed2kFileLink {
    Ed2kFileLink::new(
        Ed2kText::from_utf8("lane.bin"),
        SIZE,
        FileHash::from_bytes([1; 16]),
    )
    .expect("a size eD2k addresses")
}

fn row(ranges: Vec<(u64, u64)>) -> ArrivedPart {
    ArrivedPart {
        part_index: PartIndex::new(0),
        ranges,
        writers: vec![ArrivedWriter {
            endpoint: PeerEndpoint::V4(Ipv4Endpoint::new([10, 0, 0, 1].into(), 4662)),
            user_hash: None,
        }],
        cells: vec![vec![0]],
    }
}

type Runner = RunnerContext<NeverLooksUp, NeverTransfers>;

/// A run with a row in the store and its part file held, under `cache`.
async fn run_with(dir: &std::path::Path, cache: WriteCache) -> (Runner, Held, DownloadId) {
    let (runner, held) = runner_context(NeverLooksUp, NeverTransfers, DiagnosticsState::default());
    let mut runner = runner;
    std::sync::Arc::get_mut(&mut runner.rt)
        .expect("the one handle")
        .write_cache = cache;
    let paths = DownloadPaths::from_final_path(dir.join("lane.bin"));
    let record = runner
        .rt
        .store
        .create_download(&link(), None, &paths, None)
        .unwrap();
    *runner.part_file.lock().await =
        Some(HeldPartFile::hold(paths.part_path(), 0).await.unwrap().0);
    (runner, held, record.id())
}

async fn settle(lane: &mut PersistLane<'_>) -> Vec<LaneFact> {
    let mut facts = Vec::new();
    while lane.busy() {
        facts.push(lane.next_fact().await);
    }
    facts
}

/// The checkpoint reaches the store only once the bytes it claims reached the
/// file: the lane holds its order, so a claim stands behind its bytes.
#[tokio::test]
async fn a_checkpoint_stands_behind_the_bytes_it_claims() {
    let dir = tempfile::tempdir().unwrap();
    let (runner, _held, id) = run_with(dir.path(), WriteCache::default()).await;
    let link = link();
    let mut lane = PersistLane::new(&runner, id, &link);
    lane.gather(0, vec![7; 4096], CachedBytes::over_the_cap());
    lane.take_checkpoint(Instant::now(), vec![row(vec![(0, 4096)])]);
    assert!(
        runner.rt.store.arrived_parts(id).unwrap().is_empty(),
        "nothing committed yet"
    );
    assert_eq!(
        settle(&mut lane).await.len(),
        2,
        "the write, then the commit"
    );

    let on_disk = std::fs::read(dir.path().join("lane.bin.part")).unwrap();
    assert_eq!(on_disk.len(), 4096);
    let rows = runner.rt.store.arrived_parts(id).unwrap();
    assert_eq!(rows[0].ranges, vec![(0, 4096)]);
    assert_eq!(rows[0].writers, row(Vec::new()).writers);
}

/// A write the volume refuses reaches the run as a Volume Stop, nothing behind
/// it runs, and no checkpoint claims the bytes it lost.
#[tokio::test]
async fn a_refused_write_ends_the_lane_and_nothing_claims_it() {
    let dir = tempfile::tempdir().unwrap();
    let (runner, _held, id) = run_with(dir.path(), WriteCache::default()).await;
    let path = dir.path().join("lane.bin.part");
    *runner.part_file.lock().await = Some(HeldPartFile::refusing_writes(&path));
    let link = link();
    let mut lane = PersistLane::new(&runner, id, &link);
    lane.gather(0, vec![7; 4096], CachedBytes::over_the_cap());
    lane.take_checkpoint(Instant::now(), vec![row(vec![(0, 4096)])]);

    let facts = settle(&mut lane).await;
    assert!(
        matches!(facts[..], [LaneFact::Ended(DownloadFailure::Paused)]),
        "the checkpoint behind it did not run"
    );
    assert!(lane.ended());
    assert!(matches!(
        runner.take_volume_stop(),
        Some(VolumeStop::WriteRefused { os_code: Some(_) })
    ));
    assert!(runner.rt.store.arrived_parts(id).unwrap().is_empty());
}

/// A node with no room in its Write Cache holds the drain; the room coming back
/// lets it through, so a slow disk stops the sockets, not the heap.
#[tokio::test]
async fn a_full_cache_holds_the_drain_until_a_write_ends() {
    let dir = tempfile::tempdir().unwrap();
    let cache = WriteCache::of(4096);
    let (runner, _held, id) = run_with(dir.path(), cache.clone()).await;
    let link = link();
    let mut ctx = loop_ctx(&runner, &link, one_part_state());
    ctx.download_id = id;
    ctx.persist = PersistLane::new(&runner, id, &link);
    let elsewhere = cache.try_take(4096).expect("the whole cache");
    let mut queue = VecDeque::from([Decision::WriteBytes {
        offset: 0,
        bytes: vec![7; 4096],
    }]);

    let drain = tokio::time::timeout(Duration::from_millis(50), enact_drain(&mut queue, &mut ctx));
    assert!(drain.await.is_err(), "the drain waits for room");

    drop(elsewhere);
    let mut queue = VecDeque::from([Decision::WriteBytes {
        offset: 0,
        bytes: vec![7; 4096],
    }]);
    tokio::time::timeout(Duration::from_secs(5), enact_drain(&mut queue, &mut ctx))
        .await
        .expect("room came back")
        .unwrap();
    end_lane(&mut ctx, false, &mut VecDeque::new()).await;
    assert!(
        cache.try_take(4096).is_some(),
        "the write gave its room back"
    );
}

/// A stop passes a full cache: no volume stands between a run and its end, and
/// the bytes that passed go to the file with the rest.
#[tokio::test]
async fn a_stop_goes_through_a_full_cache() {
    let dir = tempfile::tempdir().unwrap();
    let cache = WriteCache::of(4096);
    let (runner, held, id) = run_with(dir.path(), cache.clone()).await;
    let link = link();
    let mut ctx = loop_ctx(&runner, &link, one_part_state());
    ctx.download_id = id;
    ctx.persist = PersistLane::new(&runner, id, &link);
    let _elsewhere = cache.try_take(4096).expect("the whole cache");
    held._stop_tx.send(StopReason::Pause).unwrap();

    let mut queue = VecDeque::from([Decision::WriteBytes {
        offset: 0,
        bytes: vec![7; 4096],
    }]);
    tokio::time::timeout(Duration::from_secs(5), enact_drain(&mut queue, &mut ctx))
        .await
        .expect("a stop waits for nothing")
        .unwrap();
    end_lane(&mut ctx, true, &mut VecDeque::new()).await;
    let on_disk = std::fs::read(dir.path().join("lane.bin.part")).unwrap();
    assert_eq!(on_disk.len(), 4096);
}
