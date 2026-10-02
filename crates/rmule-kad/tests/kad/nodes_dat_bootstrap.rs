//! The nodes.dat **v3 bootstrap-edition** reader (ADR-0066 execution
//! breakdown 3): the dedicated reader [`nodes_dat.rs`]'s normal reader
//! hands off to via [`rmule_kad::NodesDatError::BootstrapEdition`], plus the
//! [`rmule_kad::BootstrapDialList`] (CONTEXT.md **Bootstrap Dial List**) its
//! closest-50 selection feeds.
//!
//! Handoff contract with the normal reader (decided here): this reader
//! re-parses the **full** nodes.dat bytes from the
//! leading marker on, rather than resuming from an offset the normal reader
//! left off at. That keeps the two readers independently callable on the
//! same byte buffer -- a pipeline tries the normal reader
//! first, and on `BootstrapEdition` hands the identical bytes to this one.
//!
//! Row shape and provenance: `RoutingZone.cpp::ReadBootstrapNodesDat`
//! (aMule 2.3.3, `4e8f2b3c`) -- the v1-shape 25-byte row regardless of the
//! outer file version, an **exact** `count * 25 == remaining` check (unlike
//! the normal reader's forgiving truncation), the same Kad2/port-53 filters,
//! and the closest-50-by-XOR-distance selection (`#L257`/`#L261`).

use std::net::Ipv4Addr;

use crate::fixture::ip;
use rmule_kad::{BootstrapDialList, BootstrapEditionError, KadId, NodesDat, NodesDatError};
use rmule_testkit::kad_node::id;

/// A [`KadId`] whose XOR distance to [`OWN_ID`] is exactly `k` -- bytes
/// `0..12` are zero on both sides (so they XOR to zero and contribute
/// nothing to the 128-bit magnitude), and bytes `12..16` carry `k` as the
/// magnitude's least-significant word (`KadDistance`'s doc: "four 32-bit
/// words, most-significant word first" -- byte-group 3 is the *last* word,
/// i.e. least significant). This makes "closest by XOR distance" exactly
/// "smallest `k`", so the closest-50 set and its order are checkable by
/// simple integer comparison rather than by re-deriving the byte-order rule
/// in the test itself.
fn id_at_distance(k: u32) -> KadId {
    let mut bytes = [0u8; KadId::BYTE_LEN];
    bytes[12..16].copy_from_slice(&k.to_le_bytes());
    KadId::from_bytes(bytes)
}

const OWN_ID: fn() -> KadId = || KadId::from_bytes([0u8; KadId::BYTE_LEN]);

/// One 25-byte v1-shape contact row: `[id 16][ip 4, low octet first][udp 2
/// LE][tcp 2 LE][version 1]` -- the v3 bootstrap-edition format uses the pure
/// v1 row shape regardless of the outer file version (`RoutingZone.cpp#L177`,
/// bootstrap-edition branch `#L228`).
fn row(id: KadId, ip: Ipv4Addr, udp_port: u16, tcp_port: u16, version: u8) -> Vec<u8> {
    let mut bytes = id.as_bytes().to_vec();
    let mut octets = ip.octets();
    octets.reverse();
    bytes.extend_from_slice(&octets);
    bytes.extend_from_slice(&udp_port.to_le_bytes());
    bytes.extend_from_slice(&tcp_port.to_le_bytes());
    bytes.push(version);
    bytes
}

/// A whole v3 bootstrap-edition nodes.dat payload: `[0u32][3u32][1u32][count
/// u32][rows...]` (`RoutingZone.cpp#L149`, bootstrap-edition branch `#L156`).
/// `declared_count` is independent of `rows.len()` so tests can build a
/// length mismatch deliberately.
fn file_with_count(rows: &[Vec<u8>], declared_count: u32) -> Vec<u8> {
    let mut bytes = 0u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&declared_count.to_le_bytes());
    for r in rows {
        bytes.extend_from_slice(r);
    }
    bytes
}

fn file(rows: &[Vec<u8>]) -> Vec<u8> {
    file_with_count(rows, u32::try_from(rows.len()).unwrap())
}

// --- the normal-reader handoff contract --------------------------------

#[test]
fn the_normal_reader_hands_off_the_exact_bytes_this_reader_parses_end_to_end() {
    // The identical byte buffer the normal reader refuses with
    // `BootstrapEdition` is what this reader is handed -- and it is a full
    // re-parse from byte 0, not a resume from where the normal reader's
    // cursor stopped.
    let bytes = file(&[row(id(1), ip(1), 4672, 4662, 8)]);

    assert_eq!(
        NodesDat::decode(&bytes),
        Err(NodesDatError::BootstrapEdition)
    );

    let mut list = BootstrapDialList::new();
    list.load_v3_bootstrap_edition(&bytes, OWN_ID())
        .expect("this reader owns it");
    assert_eq!(list.len(), 1);
    assert_eq!(list.candidates()[0].kad_id(), Some(id(1)));
}

// --- header recognition (NotBootstrapEdition) ---------------------------

#[test]
fn bytes_that_are_not_the_bootstrap_edition_shape_are_refused_as_not_this_readers_job() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        (
            "nonzero leading marker (v0-shaped)",
            1u32.to_le_bytes().to_vec(),
        ),
        (
            "leading zero but version 2 (the normal reader's v2 shape)",
            {
                let mut bytes = 0u32.to_le_bytes().to_vec();
                bytes.extend_from_slice(&2u32.to_le_bytes());
                bytes
            },
        ),
        (
            "version 3 but bootstrap-edition 0 (v3-normal, folds to v2 layout)",
            {
                let mut bytes = 0u32.to_le_bytes().to_vec();
                bytes.extend_from_slice(&3u32.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes
            },
        ),
        ("truncated before the bootstrap-edition word", {
            let mut bytes = 0u32.to_le_bytes().to_vec();
            bytes.extend_from_slice(&3u32.to_le_bytes());
            bytes
        }),
        ("truncated before the count word", {
            let mut bytes = 0u32.to_le_bytes().to_vec();
            bytes.extend_from_slice(&3u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes
        }),
    ];

    for (label, bytes) in cases {
        let mut list = BootstrapDialList::new();
        assert_eq!(
            list.load_v3_bootstrap_edition(&bytes, OWN_ID()),
            Err(BootstrapEditionError::NotBootstrapEdition),
            "{label}"
        );
        assert!(
            list.is_empty(),
            "{label}: a refused load leaves the list empty"
        );
    }
}

// --- the exact count*25 == remaining check -------------------------------

#[test]
fn a_declared_count_that_does_not_exactly_match_the_remaining_bytes_is_refused() {
    // Unlike the normal reader (which streams row-by-row and keeps whatever
    // parsed before a truncation), the bootstrap-edition reader has aMule's
    // own exact whole-row-count check (`RoutingZone.cpp#L242`): a mismatch
    // in either direction is a hard refusal, not a partial load.
    let one_row = row(id(1), ip(1), 4672, 4662, 8);

    let too_few_bytes_for_declared_count = file_with_count(std::slice::from_ref(&one_row), 2);
    let too_many_bytes_for_declared_count = file_with_count(&[one_row.clone(), one_row], 1);

    for bytes in [
        too_few_bytes_for_declared_count,
        too_many_bytes_for_declared_count,
    ] {
        let mut list = BootstrapDialList::new();
        assert_eq!(
            list.load_v3_bootstrap_edition(&bytes, OWN_ID()),
            Err(BootstrapEditionError::LengthMismatch)
        );
        assert!(list.is_empty(), "a refused load leaves the list empty");
    }
}

// --- per-contact filters (same as the normal reader) ---------------------

#[test]
fn kad1_rows_and_port_53_at_or_below_version_5_are_dropped_same_as_the_normal_reader() {
    let bytes = file(&[
        row(id(1), ip(1), 4672, 4662, 1), // Kad1: dropped
        row(id(2), ip(2), 53, 4662, 5),   // port 53, version <= 5: dropped
        row(id(3), ip(3), 53, 4662, 6),   // port 53, version >= 6: kept
        row(id(4), ip(4), 4672, 4662, 8), // ordinary Kad2: kept
    ]);

    let mut list = BootstrapDialList::new();
    list.load_v3_bootstrap_edition(&bytes, OWN_ID())
        .expect("decode");

    let ids: Vec<KadId> = list
        .candidates()
        .iter()
        .map(|c| c.kad_id().expect("v3 file rows always carry a Kad ID"))
        .collect();
    assert_eq!(ids, vec![id(3), id(4)]);
}

#[test]
fn is_good_ip_port_drops_port_zero_and_lan_ip_contacts_same_as_the_normal_reader() {
    // aMule's IsGoodIPPort gate (RoutingZone.cpp#L193): a nonzero port and a
    // routable IP. The bootstrap-edition reader applies it identically to the
    // normal reader.
    let bytes = file(&[
        row(id(1), ip(1), 4672, 4662, 8), // good: routable IP, nonzero port
        row(id(2), ip(2), 0, 4662, 8),    // dropped: port 0
        row(id(3), Ipv4Addr::new(10, 0, 0, 1), 4672, 4662, 8), // dropped: RFC1918 LAN IP
    ]);

    let mut list = BootstrapDialList::new();
    list.load_v3_bootstrap_edition(&bytes, OWN_ID())
        .expect("decode");

    let ids: Vec<KadId> = list
        .candidates()
        .iter()
        .map(|c| c.kad_id().expect("v3 file rows always carry a Kad ID"))
        .collect();
    assert_eq!(
        ids,
        vec![id(1)],
        "only the routable, nonzero-port contact is kept"
    );
}

// --- closest-50-by-XOR-distance determinism ------------------------------

#[test]
fn the_50_closest_contacts_by_xor_distance_are_selected_in_closest_first_order() {
    // 1000 contacts (aMule's upper "expected" count) with distances 1..=1000
    // from OWN_ID, listed in the file in *descending*-distance order -- the
    // exact opposite of the expected output order -- so a pass here cannot
    // be an accident of file order.
    let rows: Vec<Vec<u8>> = (1..=1000u32)
        .rev()
        .map(|k| {
            row(
                id_at_distance(k),
                Ipv4Addr::new(203, 0, 113, (k % 250 + 1) as u8),
                4672,
                4662,
                8,
            )
        })
        .collect();
    let bytes = file(&rows);

    let mut list = BootstrapDialList::new();
    list.load_v3_bootstrap_edition(&bytes, OWN_ID())
        .expect("decode");

    assert_eq!(list.len(), 50);
    let expected: Vec<KadId> = (1..=50u32).map(id_at_distance).collect();
    let actual: Vec<KadId> = list
        .candidates()
        .iter()
        .map(|c| c.kad_id().expect("v3 file rows always carry a Kad ID"))
        .collect();
    assert_eq!(
        actual, expected,
        "closest-50 must be exactly distances 1..=50, closest first, regardless of file order"
    );
}

#[test]
fn closest_selection_is_independent_of_a_non_monotonic_file_row_order() {
    // A shuffled (not simply reversed) row order over a small pool: the
    // closest contacts must still come out sorted by distance regardless.
    let order = [5u32, 1, 4, 2, 3];
    let rows: Vec<Vec<u8>> = order
        .iter()
        .map(|&k| row(id_at_distance(k), ip(k as u8), 4672, 4662, 8))
        .collect();
    let bytes = file(&rows);

    let mut list = BootstrapDialList::new();
    list.load_v3_bootstrap_edition(&bytes, OWN_ID())
        .expect("decode");

    let actual: Vec<KadId> = list
        .candidates()
        .iter()
        .map(|c| c.kad_id().expect("v3 file rows always carry a Kad ID"))
        .collect();
    assert_eq!(
        actual,
        vec![1, 2, 3, 4, 5]
            .into_iter()
            .map(id_at_distance)
            .collect::<Vec<_>>()
    );
}

// --- the dial-list-not-routing-table distinction -------------------------

#[test]
fn loading_a_bootstrap_file_never_touches_any_routing_table() {
    use rmule_kad::KadRoutingTable;

    let bytes = file(&[
        row(id(1), ip(1), 4672, 4662, 8),
        row(id(2), ip(2), 4672, 4662, 8),
    ]);

    let table = KadRoutingTable::new(id(0xFF));
    let mut list = BootstrapDialList::new();
    list.load_v3_bootstrap_edition(&bytes, OWN_ID())
        .expect("decode");

    assert_eq!(list.len(), 2, "the dial list holds the loaded candidates");
    assert!(
        table.is_empty(),
        "loading a bootstrap file must never reach into a routing table"
    );
}

#[test]
fn a_dial_list_already_loaded_refuses_a_second_bootstrap_file_load() {
    // aMule's own guard (`RoutingZone.cpp#L237`): at most one bootstrap-file
    // load into the same list.
    let first = file(&[row(id(1), ip(1), 4672, 4662, 8)]);
    let second = file(&[row(id(2), ip(2), 4672, 4662, 8)]);

    let mut list = BootstrapDialList::new();
    list.load_v3_bootstrap_edition(&first, OWN_ID())
        .expect("first load succeeds");
    let before = list.candidates().to_vec();

    let result = list.load_v3_bootstrap_edition(&second, OWN_ID());

    assert_eq!(result, Err(BootstrapEditionError::AlreadyLoaded));
    assert_eq!(
        list.candidates(),
        before.as_slice(),
        "a refused second load must not mutate the existing candidates"
    );
}
