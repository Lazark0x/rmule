//! The eMule score modifier and the credit store behind it — the durable one
//! on `rmule-store`, run on both backends. `up` = bytes we served the peer;
//! `down` = bytes the peer served us.
use rmule_core::open_durable_store;

use rmule_core::{
    CreditProof, CreditStore, CreditTotals, DurableCreditStore, KeyBinding, PeerCredit,
    credit_modifier,
};
use rmule_primitives::UserHash;
use std::net::IpAddr;
use std::time::Duration;

/// Everything the ledger owes a caller in one pass: both directions accrue,
/// an unknown peer is zeroed rather than an error, the first SUI key is
/// adopted and an impostor's is refused, and the ring snapshot carries the
/// peer's totals and bound key together.
fn accrues_both_directions_and_guards_the_bound_key(store: &mut DurableCreditStore) {
    let peer = UserHash::from_bytes([0x07; UserHash::BYTE_LEN]);
    let key_a = vec![0xAA; 59];
    let key_b = vec![0xBB; 59];

    store.record_download(peer, 9_728_000).unwrap();
    store.record_download(peer, 271_360).unwrap();
    store.record_upload(peer, 1_000_000).unwrap();
    assert_eq!(
        store.totals(peer).unwrap(),
        CreditTotals {
            uploaded: 1_000_000,
            downloaded: 9_999_360,
        }
    );

    assert_eq!(store.public_key(peer).unwrap(), None);
    assert_eq!(
        store.bind_public_key(peer, &key_a).unwrap(),
        KeyBinding::Adopted
    );
    assert_eq!(
        store.bind_public_key(peer, &key_a).unwrap(),
        KeyBinding::AlreadyBound
    );
    assert_eq!(
        store.bind_public_key(peer, &key_b).unwrap(),
        KeyBinding::Mismatch
    );
    assert_eq!(
        store.public_key(peer).unwrap(),
        Some(key_a.clone()),
        "an impostor must not overwrite the bound key"
    );

    // An unknown peer is zeroed and keyless, not an error.
    let stranger = UserHash::from_bytes([0x08; UserHash::BYTE_LEN]);
    assert_eq!(store.totals(stranger).unwrap(), CreditTotals::default());
    assert_eq!(store.public_key(stranger).unwrap(), None);

    assert_eq!(
        store.snapshot().unwrap(),
        vec![PeerCredit {
            key: peer,
            totals: CreditTotals {
                uploaded: 1,
                downloaded: 1,
            },
            public_key: Some(key_a),
        }]
    );
}

#[test]
fn store_ledger_on_the_in_memory_backend_accrues_and_guards_the_bound_key() {
    accrues_both_directions_and_guards_the_bound_key(&mut DurableCreditStore::new(
        rmule_testkit::memory_store(),
    ));
}

#[test]
fn store_ledger_on_a_file_accrues_and_guards_the_bound_key() {
    let dir = tempfile::tempdir().unwrap();
    accrues_both_directions_and_guards_the_bound_key(&mut DurableCreditStore::new(
        open_durable_store(dir.path()).unwrap(),
    ));
}

#[test]
fn store_totals_and_the_secured_key_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let peer = UserHash::from_bytes([0x09; UserHash::BYTE_LEN]);
    let key_a = vec![0x30, 0x59, 0x01, 0x02];
    let key_b = vec![0x30, 0x59, 0x0A, 0x0B];

    {
        let ledger = DurableCreditStore::new(open_durable_store(path).unwrap());
        assert_eq!(
            ledger.bind_public_key(peer, &key_a).unwrap(),
            KeyBinding::Adopted
        );
        ledger.record_download(peer, 5_000_000).unwrap();
    }

    let ledger = DurableCreditStore::new(open_durable_store(path).unwrap());
    assert_eq!(ledger.public_key(peer).unwrap(), Some(key_a.clone()));
    assert_eq!(ledger.totals(peer).unwrap().downloaded, 5_000_000);
    // Theft is rejected across the reopen; the secured key is unchanged.
    assert_eq!(
        ledger.bind_public_key(peer, &key_b).unwrap(),
        KeyBinding::Mismatch
    );
    assert_eq!(ledger.public_key(peer).unwrap(), Some(key_a));
}

/// aMule deletes what a row held when its first key is proved: the prover has
/// not shown it earned them (`ClientCredits.cpp:235-241`). The wipe reaches the
/// memory the queue ranks by and what the store holds, and a pending accrual is
/// not added back on top of it.
#[test]
fn a_first_key_over_received_bytes_wipes_them_durably() {
    let dir = tempfile::tempdir().unwrap();
    let peer = UserHash::from_bytes([0x0A; UserHash::BYTE_LEN]);
    let wiped = CreditTotals {
        uploaded: 1,
        downloaded: 1,
    };
    {
        let ledger = DurableCreditStore::new(open_durable_store(dir.path()).unwrap());
        ledger.record_download(peer, 5_000_000).unwrap();
        ledger.checkpoint().unwrap();
        ledger.record_download(peer, 7_000_000).unwrap();
        ledger.bind_public_key(peer, b"first key").unwrap();
        assert_eq!(ledger.totals(peer).unwrap(), wiped);
        assert_eq!(ledger.modifier(peer).unwrap(), 1.0);
    }
    let ledger = DurableCreditStore::new(open_durable_store(dir.path()).unwrap());
    assert_eq!(ledger.totals(peer).unwrap(), wiped);
}

/// A row with nothing received has nothing to steal: stock's test is the
/// downloaded total alone (`ClientCredits.cpp:236`).
#[test]
fn a_first_key_over_uploads_alone_keeps_them() {
    let ledger = DurableCreditStore::new(rmule_testkit::memory_store());
    let peer = UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]);
    ledger.record_upload(peer, 5_000_000).unwrap();
    ledger.bind_public_key(peer, b"first key").unwrap();
    assert_eq!(ledger.totals(peer).unwrap().uploaded, 5_000_000);
}

/// `GetCurrentIdentState` read at the three doors (`ClientCredits.cpp:68-131`):
/// a keyed row pays and accrues only where its key was proved, a thief naming
/// the hash neither takes the credit nor writes to the ledger, and a row with
/// no key stays open.
#[test]
fn a_keyed_row_pays_and_accrues_only_where_its_key_was_proved() {
    const MIB: u64 = 1 << 20;
    let ledger = DurableCreditStore::new(rmule_testkit::memory_store());
    let peer = UserHash::from_bytes([0x0C; UserHash::BYTE_LEN]);
    let (owner, thief): (IpAddr, IpAddr) = ("203.0.113.1".parse().unwrap(), "203.0.113.2".parse().unwrap());
    ledger.bind_public_key(peer, b"key").unwrap();
    ledger.record_download(peer, 100 * MIB).unwrap();
    let earned = ledger.modifier(peer).unwrap();
    assert!(earned > 1.0);

    assert_eq!(ledger.proof(peer, thief), CreditProof::Owed);
    assert_eq!(ledger.score_modifier(peer, thief).unwrap(), 1.0);
    ledger.credit_upload(peer, thief, 1).unwrap();
    ledger.credit_download(peer, thief, 1).unwrap();
    assert_eq!(ledger.totals(peer).unwrap().uploaded, 0);
    assert_eq!(ledger.totals(peer).unwrap().downloaded, 100 * MIB);

    ledger.prove(peer, owner);
    assert_eq!(ledger.proof(peer, owner), CreditProof::Proved);
    assert_eq!(ledger.score_modifier(peer, owner).unwrap(), earned);
    ledger.credit_upload(peer, owner, 7).unwrap();
    assert_eq!(ledger.totals(peer).unwrap().uploaded, 7);

    assert_eq!(ledger.proof(peer, thief), CreditProof::Elsewhere);
    assert_eq!(ledger.score_modifier(peer, thief).unwrap(), 0.0);

    let open = UserHash::from_bytes([0x0D; UserHash::BYTE_LEN]);
    assert_eq!(ledger.proof(open, thief), CreditProof::Open);
    ledger.credit_upload(open, thief, 3).unwrap();
    assert_eq!(ledger.totals(open).unwrap().uploaded, 3);
}

/// One client holds one address per family (ADR-0107): a proof over IPv6 is no
/// bad-guy mark on its IPv4 link.
#[test]
fn a_proof_in_one_family_leaves_the_other_alone() {
    let ledger = DurableCreditStore::new(rmule_testkit::memory_store());
    let peer = UserHash::from_bytes([0x0E; UserHash::BYTE_LEN]);
    let (v4, v6): (IpAddr, IpAddr) = ("203.0.113.1".parse().unwrap(), "2001:db8::1".parse().unwrap());
    ledger.bind_public_key(peer, b"key").unwrap();
    ledger.prove(peer, v4);
    ledger.prove(peer, v6);
    assert_eq!(ledger.proof(peer, v4), CreditProof::Proved);
    assert_eq!(ledger.proof(peer, v6), CreditProof::Proved);
}

/// Accrual is a memory step (ADR-0031, ADR-0083): a store whose one writer is
/// busy, as it is through any commit's device flush, holds no block's count.
#[test]
fn an_accrual_waits_for_no_store_writer() {
    let store = rmule_testkit::memory_store();
    let ledger = DurableCreditStore::new(store.clone());
    let peer = UserHash::from_bytes([0x12; UserHash::BYTE_LEN]);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let writer = std::thread::spawn(move || {
        store.write(|_| {
            held_tx.send(()).unwrap();
            done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok::<_, rmule_core::CoreError>(())
        })
    });
    held_rx.recv().unwrap();

    ledger.record_upload(peer, 184_320).unwrap();

    done_tx.send(()).unwrap();
    writer.join().unwrap().unwrap();
    assert_eq!(ledger.totals(peer).unwrap().uploaded, 184_320);
}

/// The checkpoint is what the store hears, once, and what moved after it is
/// not written over a key bound meanwhile.
#[test]
fn what_moved_reaches_the_store_at_the_checkpoint_and_keeps_a_bound_key() {
    let store = rmule_testkit::memory_store();
    let ledger = DurableCreditStore::new(store.clone());
    let peer = UserHash::from_bytes([0x13; UserHash::BYTE_LEN]);
    let key = vec![0x30, 0x59, 0x01];

    ledger.record_upload(peer, 7).unwrap();
    let stored = |store| DurableCreditStore::new(store).totals(peer).unwrap();
    assert_eq!(stored(store.clone()).uploaded, 0);

    ledger.checkpoint().unwrap();
    assert_eq!(
        ledger.bind_public_key(peer, &key).unwrap(),
        KeyBinding::Adopted
    );
    ledger.record_upload(peer, 3).unwrap();
    ledger.checkpoint().unwrap();

    assert_eq!(stored(store).uploaded, 10);
    assert_eq!(ledger.public_key(peer).unwrap(), Some(key));
}

/// Accrual lands in memory (ADR-0083), so the ring reaches the disk at
/// [`CreditStore::checkpoint`] — the call the core actor makes once a minute
/// and on shutdown. Bytes accrued and then checkpointed survive the reopen with
/// nothing else writing the store.
#[test]
fn accrued_bytes_are_durable_once_the_ring_is_checkpointed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let peer = UserHash::from_bytes([0x11; UserHash::BYTE_LEN]);

    {
        let ledger = DurableCreditStore::new(open_durable_store(path).unwrap());
        ledger.record_upload(peer, 180_224).unwrap();
        ledger.record_download(peer, 9_728_000).unwrap();
        ledger.checkpoint().unwrap();
    }

    let ledger = DurableCreditStore::new(open_durable_store(path).unwrap());
    assert_eq!(
        ledger.totals(peer).unwrap(),
        CreditTotals {
            uploaded: 180_224,
            downloaded: 9_728_000,
        }
    );
}

const MIB: u64 = 1024 * 1024;

#[test]
fn modifier_is_one_when_the_peer_never_uploaded_to_us() {
    // down == 0: no credit earned, regardless of how much we gave them.
    assert_eq!(credit_modifier(0, 0), 1.0);
    assert_eq!(credit_modifier(500 * MIB, 0), 1.0);
}

#[test]
fn modifier_caps_a_generous_peer_we_gave_nothing_back_at_the_volume_term() {
    // up == 0, down == 1 MiB: ratio term is 10.0 but the volume cap binds.
    let expected = ((1.0_f64) + 2.0).sqrt(); // sqrt(3) ~= 1.732
    assert!((credit_modifier(0, MIB) - expected).abs() < 1e-9);
}

#[test]
fn modifier_clamps_a_high_ratio_to_ten() {
    // up = 10 MiB, down = 100 MiB: ratio = 20.0, cap = sqrt(102) ~= 10.099,
    // min = 10.099, clamped to 10.0.
    assert_eq!(credit_modifier(10 * MIB, 100 * MIB), 10.0);
}

#[test]
fn modifier_is_the_ratio_when_below_the_cap() {
    // up = down = 50 MiB: ratio = 2.0, cap = sqrt(52) ~= 7.2, min = 2.0.
    assert!((credit_modifier(50 * MIB, 50 * MIB) - 2.0).abs() < 1e-9);
}

#[test]
fn modifier_floors_at_one_when_we_gave_more_than_we_got() {
    // up = 100 MiB, down = 10 MiB: ratio = 0.2, clamped up to the 1.0 floor.
    assert_eq!(credit_modifier(100 * MIB, 10 * MIB), 1.0);
}

/// The one thing the contract above does not touch: the defaulted
/// [`CreditStore::modifier`] reads the ledger's own totals rather than a
/// number the caller passed in.
#[test]
fn the_ledger_derives_the_modifier_from_its_totals() {
    let store = DurableCreditStore::new(rmule_testkit::memory_store());
    let peer = UserHash::from_bytes([0x01; UserHash::BYTE_LEN]);

    store.record_download(peer, 100).unwrap();
    store.record_download(peer, 50).unwrap();
    store.record_upload(peer, 30).unwrap();

    assert_eq!(
        store.totals(peer).unwrap(),
        CreditTotals {
            uploaded: 30,
            downloaded: 150,
        }
    );
    assert!((store.modifier(peer).unwrap() - credit_modifier(30, 150)).abs() < 1e-12);
}
