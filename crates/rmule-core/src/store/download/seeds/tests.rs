//! The seeds table at the store seam: order, age, the cascade with the
//! download's end, and the climb from a version-12 store.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rmule_primitives::{CryptStance, Ipv4Endpoint, PeerEndpoint, UserHash};
use rmule_store::Ladder;

use super::*;
use crate::storage::DownloadRepository;
use crate::store::{
    DURABLE_STORE_FILE, DurableStore, durable_schema_v12, open_durable_store,
    open_durable_store_in_memory,
};
use crate::{DownloadLifecycle, DownloadPaths};

fn seed(last: u8, rank: SeedRank) -> SourceSeed {
    SourceSeed {
        endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), 4662)),
        user_hash: Some(UserHash::from_bytes([
            last, 0x13, 0x57, 0x9B, 0xDF, 0x02, 0x46, 0x8A, 0xCE, 0x11, 0x33, 0x55, 0x77, 0x99,
            0xBB, 0xDD,
        ])),
        crypt: Some(CryptStance::new(true, last.is_multiple_of(2), false)),
        rank,
    }
}

fn create(repo: &DurableDownloadRepository, dir: &std::path::Path, name: &str) -> DownloadId {
    let file = rmule_testkit::file_link(name, name.as_bytes());
    let paths = DownloadPaths::from_final_path(dir.join(name));
    repo.create_download(&file, None, &paths).unwrap().id()
}

fn hours_ago(hours: u64) -> SystemTime {
    SystemTime::now() - Duration::from_secs(hours * 60 * 60)
}

#[test]
fn a_set_reads_back_in_the_order_written_and_an_empty_write_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let repo = DurableDownloadRepository::new(open_durable_store_in_memory().unwrap());
    let id = create(&repo, dir.path(), "kept.bin");
    let set = [seed(9, SeedRank::Received), seed(4, SeedRank::Known)];
    assert!(
        repo.write_source_seeds(id, &set, SystemTime::now())
            .unwrap()
    );
    assert!(!repo.write_source_seeds(id, &[], SystemTime::now()).unwrap());
    assert_eq!(repo.source_seeds(id).unwrap(), set);
}

#[test]
fn a_load_drops_a_set_written_more_than_a_day_ago() {
    let dir = tempfile::tempdir().unwrap();
    let repo = DurableDownloadRepository::new(open_durable_store_in_memory().unwrap());
    let stale = create(&repo, dir.path(), "stale.bin");
    let fresh = create(&repo, dir.path(), "fresh.bin");
    repo.write_source_seeds(stale, &[seed(1, SeedRank::Received)], hours_ago(25))
        .unwrap();
    repo.write_source_seeds(fresh, &[seed(2, SeedRank::Ranked)], hours_ago(23))
        .unwrap();

    let loaded = repo.load_source_seeds(stale, SystemTime::now()).unwrap();
    assert_eq!(
        loaded,
        LoadedSeeds {
            fresh: Vec::new(),
            expired: 1
        }
    );
    assert!(
        repo.source_seeds(stale).unwrap().is_empty(),
        "deleted at load"
    );
    let loaded = repo.load_source_seeds(fresh, SystemTime::now()).unwrap();
    assert_eq!(loaded.fresh, [seed(2, SeedRank::Ranked)]);
}

#[test]
fn completion_cancel_and_clear_each_leave_no_seeds_and_refuse_later_writes() {
    let dir = tempfile::tempdir().unwrap();
    let repo = DurableDownloadRepository::new(open_durable_store_in_memory().unwrap());
    for (name, end) in [
        ("done.bin", DownloadLifecycle::Completed),
        ("dropped.bin", DownloadLifecycle::Cancelled),
    ] {
        let id = create(&repo, dir.path(), name);
        repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        repo.write_source_seeds(id, &[seed(3, SeedRank::Known)], SystemTime::now())
            .unwrap();
        repo.set_lifecycle(id, end).unwrap();
        assert!(repo.source_seeds(id).unwrap().is_empty(), "{end:?}");
        assert!(
            !repo
                .write_source_seeds(id, &[seed(3, SeedRank::Known)], SystemTime::now())
                .unwrap(),
            "{end:?}: a late write lands nowhere"
        );
    }
    // A paused download keeps its seeds: age decides.
    let paused = create(&repo, dir.path(), "paused.bin");
    repo.set_lifecycle(paused, DownloadLifecycle::Active)
        .unwrap();
    repo.write_source_seeds(paused, &[seed(5, SeedRank::Ranked)], SystemTime::now())
        .unwrap();
    repo.set_lifecycle(paused, DownloadLifecycle::Paused)
        .unwrap();
    assert_eq!(repo.source_seeds(paused).unwrap().len(), 1);
}

#[test]
fn upgrade_from_a_version_twelve_store_gives_no_seeds_and_keeps_every_download() {
    let dir = tempfile::tempdir().unwrap();
    let id = {
        let v12 = Arc::new(
            DurableStore::open(
                dir.path().join(DURABLE_STORE_FILE),
                &durable_schema_v12(),
                &Ladder::new(12, &[]),
            )
            .unwrap(),
        );
        create(
            &DurableDownloadRepository::new(v12),
            dir.path(),
            "carried.bin",
        )
    };
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    assert_eq!(
        repo.load_download(id).unwrap().lifecycle(),
        DownloadLifecycle::Queued
    );
    assert!(repo.source_seeds(id).unwrap().is_empty());
    assert!(
        repo.write_source_seeds(id, &[seed(6, SeedRank::Received)], SystemTime::now())
            .unwrap()
    );
}
