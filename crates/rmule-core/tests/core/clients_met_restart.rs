//! Restart continuity for the credit ring (ADR-0041): the credit
//! reciprocity a running node accrues survives a `clients.met` save + load
//! cycle at the persistence seam — the whole point of persisting the ring.
//!
//! The ring is the sans-I/O [`CreditStore`]; `snapshot` → [`save_clients_met`]
//! writes it, [`load_clients_met`] reads it back, and replaying the loaded
//! records into a fresh ring reconstructs the exact totals and bound SUI keys.
//! The durable ring snapshots through that one edge whichever backend it was
//! opened on.

use rmule_core::DurableCreditStore;
use rmule_core::{CreditRecord, CreditStore, EXPIRY_SECS, load_clients_met, save_clients_met};
use rmule_primitives::UserHash;

fn hash(seed: u8) -> UserHash {
    UserHash::from_bytes([seed; UserHash::BYTE_LEN])
}

/// Replay loaded records into a fresh ring — the startup seed path (aMule's
/// `LoadList` populating `m_mapClients`). `record_upload`/`record_download` are
/// additive, so a zeroed ring reconstructs the persisted totals exactly.
fn reseed(store: &mut impl CreditStore, records: &[CreditRecord]) {
    for record in records {
        store.record_upload(record.key, record.uploaded).unwrap();
        store
            .record_download(record.key, record.downloaded)
            .unwrap();
        if let Some(der) = record.public_key() {
            store.bind_public_key(record.key, der).unwrap();
        }
    }
}

#[test]
fn credit_ring_survives_a_clients_met_save_and_load_cycle() {
    let now = 2_000_000_000u32;
    let dir = tempfile::tempdir().unwrap();

    // A live ring: two peers with byte history, one with a bound SUI key. Peer
    // `0xB2`'s upload exceeds 4 GiB so the persisted u64 exercises its high word.
    let ring = DurableCreditStore::new(rmule_testkit::memory_store());
    ring.record_upload(hash(0xA1), 10 * 1024 * 1024).unwrap();
    ring.record_download(hash(0xA1), 3 * 1024 * 1024).unwrap();
    ring.record_upload(hash(0xB2), (6u64 << 32) + 42).unwrap();
    let der = vec![0x7Au8; 59];
    ring.bind_public_key(hash(0xA1), &der).unwrap();

    // Persist → forget → reload → reseed a brand-new ring.
    save_clients_met(dir.path(), &ring.snapshot().unwrap(), now).unwrap();
    let loaded = load_clients_met(dir.path(), now).unwrap();
    let mut restored = DurableCreditStore::new(rmule_testkit::memory_store());
    reseed(&mut restored, &loaded);

    // The reciprocity-bearing state is identical across the "restart".
    assert_eq!(
        restored.totals(hash(0xA1)).unwrap(),
        ring.totals(hash(0xA1)).unwrap(),
    );
    assert_eq!(
        restored.totals(hash(0xB2)).unwrap(),
        ring.totals(hash(0xB2)).unwrap(),
    );
    assert_eq!(restored.public_key(hash(0xA1)).unwrap(), Some(der));
    // A peer with no bound key stays unsecured through the round-trip.
    assert_eq!(restored.public_key(hash(0xB2)).unwrap(), None);
}

#[test]
fn a_ring_saved_long_ago_expires_on_load() {
    // The 150-day horizon at the load edge: a file whose records were stamped
    // more than EXPIRY_SECS before the load `now` comes back empty (aMule's
    // LoadList drop), so a stale credit file does not resurrect ancient peers.
    let dir = tempfile::tempdir().unwrap();
    let saved_at = 1_000_000_000u32;

    let ring = DurableCreditStore::new(rmule_testkit::memory_store());
    ring.record_upload(hash(0xD4), 123_456).unwrap();
    save_clients_met(dir.path(), &ring.snapshot().unwrap(), saved_at).unwrap();

    let just_within = load_clients_met(dir.path(), saved_at + EXPIRY_SECS).unwrap();
    assert_eq!(
        just_within.len(),
        1,
        "on the horizon the record still loads"
    );

    let past = load_clients_met(dir.path(), saved_at + EXPIRY_SECS + 1).unwrap();
    assert!(past.is_empty(), "one second past the horizon it is dropped");
}

#[test]
fn a_missing_clients_met_is_an_empty_ring_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        load_clients_met(dir.path(), 2_000_000_000)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_daemon_lifecycle_seeds_and_flushes_the_credit_ring() {
    // The production wiring: a Core built with
    // `persist_credit_in` seeds its ring from `clients.met` on spawn and
    // flushes the ring back on `shutdown` — no caller-side reseed/save
    // choreography. A record written by a prior run must survive one full
    // spawn → shutdown cycle through the live actor.
    use rmule_core::{Core, CoreConfig};

    let dir = tempfile::tempdir().unwrap();
    let now = 2_000_000_000u32;

    let prior = DurableCreditStore::new(rmule_testkit::memory_store());
    prior.record_upload(hash(0xA1), 4096).unwrap();
    prior.record_download(hash(0xA1), 8192).unwrap();
    let der = vec![0x7Au8; 59];
    prior.bind_public_key(hash(0xA1), &der).unwrap();
    save_clients_met(dir.path(), &prior.snapshot().unwrap(), now).unwrap();

    let core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .persist_credit_in(dir.path().to_path_buf())
        .build();
    core.shutdown().await;

    // The flush restamps `nLastSeen` with the actor's wall clock, so read the
    // file back under an expiry-neutral `now` (0 keeps every stamp inside the
    // 150-day horizon regardless of when this test runs).
    let records = load_clients_met(dir.path(), 0).unwrap();
    assert_eq!(
        records.len(),
        1,
        "the seeded peer survives the daemon cycle"
    );
    assert_eq!(records[0].key, hash(0xA1));
    assert_eq!(records[0].uploaded, 4096);
    assert_eq!(records[0].downloaded, 8192);
    assert_eq!(records[0].public_key(), Some(der.as_slice()));
}

#[test]
fn seeding_skips_peers_the_ring_already_knows() {
    // The double-count guard: a self-persisting store reloads its own peers
    // before the clients.met seed runs; replaying the file over them
    // would double their totals. Only never-met peers are seeded.
    let ring = DurableCreditStore::new(rmule_testkit::memory_store());
    ring.record_upload(hash(0xE5), 100).unwrap();

    let known = CreditRecord::from_peer_credit(
        &rmule_core::PeerCredit {
            key: hash(0xE5),
            totals: rmule_core::CreditTotals {
                uploaded: 100,
                downloaded: 0,
            },
            public_key: None,
        },
        1_900_000_000,
    );
    let fresh = CreditRecord::from_peer_credit(
        &rmule_core::PeerCredit {
            key: hash(0xF6),
            totals: rmule_core::CreditTotals {
                uploaded: 7,
                downloaded: 9,
            },
            public_key: None,
        },
        1_900_000_000,
    );

    let seeded = rmule_core::seed_credit_ring(&ring, &[known, fresh]).unwrap();
    assert_eq!(seeded, 1, "only the never-met peer is replayed");
    assert_eq!(
        ring.totals(hash(0xE5)).unwrap().uploaded,
        100,
        "known peer not double-counted"
    );
    assert_eq!(ring.totals(hash(0xF6)).unwrap().uploaded, 7);
    assert_eq!(ring.totals(hash(0xF6)).unwrap().downloaded, 9);
}
