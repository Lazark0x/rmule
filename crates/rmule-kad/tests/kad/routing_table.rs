//! K-bucket routing-table behavior on the capture-proven distance ordering.
//!
//! The table is keyed by the node's own ID: each contact lands in the bucket
//! for the leading-zero count of its XOR distance (word_le_msw_first,
//! ADR-0043), buckets cap at `K`, and a full bucket only admits a new
//! contact by replacing a `Failed` one — long-lived contacts win, the classic
//! Kademlia insertion policy.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_kad::{
    KadContact, KadContactState, KadId, KadNodeEndpoint, KadRoutingTable, KadRoutingUpdate,
    KadUdpKey,
};
use rmule_testkit::kad_node::{OWN_IP, T0, host_ip, id};

/// An ID landing in bucket 0 of an all-zero own ID: byte 3 is the MSB of the
/// most-significant distance word (word_le_msw_first), so setting its top bit
/// pins the leading-zero count to 0 while `salt` keeps the IDs distinct.
fn bucket0_id(salt: u8) -> KadId {
    let mut bytes = [0u8; KadId::BYTE_LEN];
    bytes[3] = 0x80;
    bytes[0] = salt;
    KadId::from_bytes(bytes)
}

fn endpoint(byte: u8, port: u16) -> KadNodeEndpoint {
    KadNodeEndpoint::new(host_ip(byte), port)
}

fn contact(id: KadId, endpoint_byte: u8) -> KadContact {
    KadContact::new(id, endpoint(endpoint_byte, 4672), 4662, 8)
}

fn table() -> KadRoutingTable {
    KadRoutingTable::new(id(0))
}

#[test]
fn a_new_contact_starts_unqueried_and_in_state_transitions_it() {
    let contact = contact(id(1), 1);
    assert_eq!(contact.state(), KadContactState::Unqueried);
    assert_eq!(
        contact.in_state(KadContactState::Responded).state(),
        KadContactState::Responded
    );
}

#[test]
fn upsert_rejects_the_tables_own_id() {
    let mut table = table();
    assert_eq!(
        table.upsert(T0, contact(id(0), 1)),
        KadRoutingUpdate::RejectedSelf
    );
    assert!(table.is_empty());
}

#[test]
fn upsert_adds_then_updates_in_place_without_duplicating() {
    let mut table = table();
    assert_eq!(table.upsert(T0, contact(id(1), 1)), KadRoutingUpdate::Added);
    assert_eq!(
        table.upsert(
            T0,
            KadContact::new(id(1), endpoint(1, 5000), 4662, 8).in_state(KadContactState::Responded)
        ),
        KadRoutingUpdate::Updated
    );

    assert_eq!(table.len(), 1);
    let stored = table.get(id(1)).expect("contact stays present");
    assert_eq!(stored.endpoint(), endpoint(1, 5000));
    assert_eq!(stored.state(), KadContactState::Responded);
}

#[test]
fn contacts_iterate_in_bucket_then_insertion_order() {
    let mut table = table();
    // id(1) has a smaller distance word than any bucket-0 ID, so it lives in a
    // later (more-zeros) bucket; bucket iteration puts bucket 0 first.
    table.upsert(T0, contact(id(1), 1));
    table.upsert(T0, contact(bucket0_id(2), 2));
    table.upsert(T0, contact(bucket0_id(1), 3));

    let ids: Vec<KadId> = table.contacts().map(KadContact::id).collect();
    assert_eq!(ids, vec![bucket0_id(2), bucket0_id(1), id(1)]);
}

#[test]
fn a_full_bucket_rejects_new_contacts_while_all_are_live() {
    let mut table = table();
    for salt in 0..KadRoutingTable::K {
        assert_eq!(
            table.upsert(T0, contact(bucket0_id(salt as u8), salt as u8)),
            KadRoutingUpdate::Added
        );
    }

    let overflow = bucket0_id(KadRoutingTable::K as u8);
    assert_eq!(
        table.upsert(T0, contact(overflow, 99)),
        KadRoutingUpdate::RejectedBucketFull
    );
    assert_eq!(table.len(), KadRoutingTable::K);
    assert!(table.get(overflow).is_none());
}

#[test]
fn a_full_bucket_admits_a_new_contact_by_replacing_a_failed_one() {
    let mut table = table();
    for salt in 0..KadRoutingTable::K {
        table.upsert(T0, contact(bucket0_id(salt as u8), salt as u8));
    }
    let failed = bucket0_id(3);
    table.upsert(T0, contact(failed, 3).in_state(KadContactState::Failed));

    let newcomer = bucket0_id(KadRoutingTable::K as u8);
    assert_eq!(
        table.upsert(T0, contact(newcomer, 99)),
        KadRoutingUpdate::AddedEvictingFailed { evicted: failed }
    );
    assert!(table.get(failed).is_none());
    assert!(table.get(newcomer).is_some());
    assert_eq!(table.len(), KadRoutingTable::K);
}

#[test]
fn evict_removes_the_contact_and_reports_whether_it_existed() {
    let mut table = table();
    table.upsert(T0, contact(id(1), 1));

    assert!(table.evict(id(1)));
    assert!(table.get(id(1)).is_none());
    assert!(table.is_empty());
    assert!(!table.evict(id(1)), "second evict finds nothing");
}

#[test]
fn select_nearest_returns_the_xor_closest_contact() {
    // With all-equal-byte ids the XOR distance to a target reduces to the
    // plain per-byte difference, so the id closest in value is nearest.
    let mut table = KadRoutingTable::new(id(0xFF));
    table.upsert(T0, contact(id(0x10), 1));
    table.upsert(T0, contact(id(0x40), 2));
    table.upsert(T0, contact(id(0x12), 3));

    let nearest = table.select_nearest(id(0x11)).expect("non-empty table");
    assert_eq!(nearest.id(), id(0x10), "0x10 is XOR-closest to 0x11");
}

#[test]
fn select_nearest_on_empty_table_is_none() {
    assert!(table().select_nearest(id(9)).is_none());
}

#[test]
fn select_closest_servable_ranks_filters_and_caps_on_the_responded_interim() {
    // With no contact verified, the servable set is the Responded set (the
    // ADR-0064 two-stage interim): closest-first, Responded-only, capped.
    let mut table = KadRoutingTable::new(id(0xFF));
    for (byte, state) in [
        (0x10, KadContactState::Responded),
        (0x12, KadContactState::Unqueried), // closer than 0x40 but not Responded
        (0x20, KadContactState::Responded),
        (0x40, KadContactState::Responded),
        (0x42, KadContactState::Failed),
    ] {
        table.upsert(T0, contact(id(byte), byte).in_state(state));
    }

    let closest: Vec<KadId> = table
        .select_closest_servable(id(0x11), 2)
        .into_iter()
        .map(KadContact::id)
        .collect();
    assert_eq!(
        closest,
        vec![id(0x10), id(0x20)],
        "closest-first, Responded only, capped at the requested count"
    );

    assert_eq!(
        table.select_closest_servable(id(0x11), 99).len(),
        3,
        "a large request returns every Responded contact, never other states"
    );
}

#[test]
fn verify_contact_gates_on_id_presence_and_ip_match() {
    // aMule VerifyContact(id, ip): the ID must name a stored contact and the ACK
    // must arrive from that contact's IP — an ACK from elsewhere proves nothing.
    let mut table = table();
    let ep = endpoint(7, 4672);
    table.upsert(
        T0,
        KadContact::new(id(1), ep, 4662, 8).in_state(KadContactState::Responded),
    );

    assert!(
        !table.verify_contact(id(2), ep.ip()),
        "absent ID: nothing to verify"
    );
    assert!(
        !table.verify_contact(id(1), endpoint(9, 4672).ip()),
        "right ID but wrong IP does not verify"
    );
    assert!(!table.get(id(1)).expect("still present").verified());

    assert!(
        table.verify_contact(id(1), ep.ip()),
        "matching ID and IP verifies"
    );
    assert!(table.get(id(1)).expect("present").verified());
    assert!(table.verify_contact(id(1), ep.ip()), "idempotent");
}

#[test]
fn verification_persists_across_an_ordinary_update() {
    let mut table = table();
    let ep = endpoint(7, 4672);
    table.upsert(
        T0,
        KadContact::new(id(1), ep, 4662, 8).in_state(KadContactState::Responded),
    );
    assert!(table.verify_contact(id(1), ep.ip()));

    // A later hello from the same endpoint arrives unverified; the update must
    // not clear the proven flag (liveness and identity are independent axes).
    table.upsert(
        T0,
        KadContact::new(id(1), ep, 4663, 8).in_state(KadContactState::Responded),
    );
    let stored = table.get(id(1)).expect("present");
    assert!(stored.verified(), "an ordinary update never un-verifies");
    assert_eq!(stored.tcp_port(), 4663, "but the update still applied");
}

#[test]
fn a_verified_contact_is_not_hijacked_to_a_new_endpoint() {
    let mut proven = table();
    let ep = endpoint(7, 4672);
    proven.upsert(
        T0,
        KadContact::new(id(1), ep, 4662, 8).in_state(KadContactState::Responded),
    );
    assert!(proven.verify_contact(id(1), ep.ip()));

    // A claimant of the same ID from a different endpoint is rejected outright.
    let hijacker = KadContact::new(id(1), endpoint(9, 4672), 4662, 8);
    assert_eq!(
        proven.upsert(T0, hijacker),
        KadRoutingUpdate::RejectedHijack { id: id(1) }
    );
    assert_eq!(
        proven.get(id(1)).expect("unmoved").endpoint(),
        ep,
        "the proven contact keeps its endpoint"
    );

    // An UNVERIFIED incumbent, by contrast, is replaced in place — no anti-hijack.
    let mut unproven = table();
    unproven.upsert(T0, KadContact::new(id(2), ep, 4662, 8));
    assert_eq!(
        unproven.upsert(T0, KadContact::new(id(2), endpoint(9, 4672), 4662, 8)),
        KadRoutingUpdate::Updated
    );
}

#[test]
fn servable_gate_never_empties_and_narrows_to_verified_once_any_verifies() {
    // The zero-servable-cliff invariant (ADR-0064 two-stage activation): gating
    // must never empty a non-empty servable set, and the moment any contact is
    // verified, unverified contacts stop being served.
    let mut table = KadRoutingTable::new(id(0xFF));
    for byte in [0x10u8, 0x20, 0x40] {
        table.upsert(
            T0,
            contact(id(byte), byte).in_state(KadContactState::Responded),
        );
    }

    // Interim (nothing verified): the whole Responded set is servable — the set
    // is never emptied just because verification has not happened yet.
    assert_eq!(
        table.select_closest_servable(id(0x11), 9).len(),
        3,
        "with no verified contact the Responded set is served (the interim)"
    );

    // Verify the middle contact: now only it is served, and the set stays
    // non-empty — the interim disengaged the instant a verified contact existed.
    assert!(table.verify_contact(id(0x20), endpoint(0x20, 4672).ip()));
    let served: Vec<KadId> = table
        .select_closest_servable(id(0x11), 9)
        .into_iter()
        .map(KadContact::id)
        .collect();
    assert_eq!(
        served,
        vec![id(0x20)],
        "only the verified contact is served"
    );
    assert!(
        !served.is_empty(),
        "gating never empties a non-empty servable set"
    );
}

#[test]
fn stalest_bucket_tracks_the_oldest_touched_bucket_for_refresh() {
    let mut table = table();
    let t1 = T0 + Duration::from_millis(1_000);
    let t2 = T0 + Duration::from_millis(2_000);
    let t3 = T0 + Duration::from_millis(3_000);

    table.upsert(t1, contact(bucket0_id(1), 1));
    table.upsert(t2, contact(id(1), 2)); // a different bucket
    let (stale_bucket, stale_at) = table.stalest_bucket().expect("two touched buckets");
    assert_eq!(stale_at, t1, "bucket 0 has the oldest activity");

    table.upsert(t3, contact(bucket0_id(2), 3)); // re-touch bucket 0
    let (refreshed_bucket, refreshed_at) = table.stalest_bucket().expect("still two buckets");
    assert_ne!(
        refreshed_bucket, stale_bucket,
        "after re-touching bucket 0 the other bucket is stalest"
    );
    assert_eq!(refreshed_at, t2);
}

#[test]
fn empty_table_has_no_stalest_bucket() {
    assert!(table().stalest_bucket().is_none());
}

// --- the UDP verify-key gate on updates (aMule `RoutingZone.cpp#L442`) -------

fn keyed_table() -> KadRoutingTable {
    let mut table = table();
    table.set_own_public_ip(OWN_IP);
    table
}

fn keyed(contact: KadContact, key: u32) -> KadContact {
    contact.with_udp_key(KadUdpKey::new(key, OWN_IP))
}

#[test]
fn a_keyed_entry_denies_an_update_that_cannot_present_its_key() {
    let mut table = keyed_table();
    let ep = endpoint(7, 4672);
    table.upsert(
        T0,
        keyed(
            KadContact::new(id(1), ep, 4662, 8).in_state(KadContactState::Responded),
            0xABCD_0001,
        ),
    );

    // No key at all, and a wrong key, are both denied — nothing changes.
    for claimant in [
        KadContact::new(id(1), endpoint(9, 4672), 4663, 8),
        keyed(
            KadContact::new(id(1), endpoint(9, 4672), 4663, 8),
            0xBADB_AD01,
        ),
    ] {
        assert_eq!(
            table.upsert(T0, claimant),
            KadRoutingUpdate::RejectedKeyMismatch { id: id(1) }
        );
        let stored = table.get(id(1)).expect("unmoved");
        assert_eq!(stored.endpoint(), ep);
        assert_eq!(stored.tcp_port(), 4662, "not even a field is touched");
    }

    // The genuine node presents the key and updates freely.
    assert_eq!(
        table.upsert(T0, keyed(KadContact::new(id(1), ep, 4663, 8), 0xABCD_0001)),
        KadRoutingUpdate::Updated
    );
    assert_eq!(table.get(id(1)).expect("present").tcp_port(), 4663);
}

#[test]
fn a_key_learned_under_another_public_ip_no_longer_guards_the_entry() {
    // The `(key, ip)` binding: aMule evaluates `GetKeyValue(myIP)`, which is 0
    // once our own IP moves — the entry falls back to keyless rules rather than
    // becoming permanently un-updatable behind a key nobody can reproduce.
    let mut table = keyed_table();
    let ep = endpoint(7, 4672);
    table.upsert(
        T0,
        keyed(
            KadContact::new(id(1), ep, 4662, 8).in_state(KadContactState::Responded),
            0xABCD_0001,
        ),
    );
    table.set_own_public_ip(Ipv4Addr::new(198, 51, 100, 55));

    assert_eq!(
        table.upsert(T0, KadContact::new(id(1), ep, 4663, 8)),
        KadRoutingUpdate::Updated,
        "a retired key cannot deny the update"
    );
}

#[test]
fn a_key_proven_endpoint_move_is_allowed_but_drops_verification() {
    // aMule `CContact::SetIPAddress`: moving a contact clears its verified flag,
    // because the proof was about the OLD address. The genuine node re-earns it
    // at the new one (a hello with a valid receiver key, or a fresh 0x22).
    let mut table = keyed_table();
    let old = endpoint(7, 4672);
    let new = endpoint(9, 4672);
    table.upsert(
        T0,
        keyed(
            KadContact::new(id(1), old, 4662, 8).in_state(KadContactState::Responded),
            0xABCD_0001,
        ),
    );
    assert!(table.verify_contact(id(1), old.ip()));

    assert_eq!(
        table.upsert(
            T0,
            keyed(
                KadContact::new(id(1), new, 4662, 8).in_state(KadContactState::Responded),
                0xABCD_0001,
            )
        ),
        KadRoutingUpdate::Updated,
        "the key proves this is the same node moving"
    );
    let stored = table.get(id(1)).expect("present");
    assert_eq!(stored.endpoint(), new);
    assert!(
        !stored.verified(),
        "the new address is unproven until it is verified there"
    );
}
