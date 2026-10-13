//! The nodes.dat **normal** reader (ADR-0066 execution breakdown 2):
//! the file-version matrix, the per-contact Kad2/port-53 filters, and the
//! verified-bit-or-heuristic mapping into the ADR-0064 `Verified Contact`
//! seam ([`KadContact::verified`]).
//!
//! Out of scope here (and untested): the v3 **bootstrap-edition** reader
//! (different file shape entirely — exact-count rows, closest-50 dial-list
//! selection) and the pipeline that would inject these contacts into a live
//! `KadRoutingTable`. This file only proves the standalone
//! decoder and, for the servable-cliff test, how its output composes with
//! the *already-landed* `KadRoutingTable`.
//!
//! Row shape and provenance: `RoutingZone.cpp::ReadFile` (aMule 2.3.3,
//! `4e8f2b3c`), `kademlia/utils/KadUDPKey.h` for the 8-byte v2 key trailer.

use std::net::Ipv4Addr;

use crate::fixture::ip;
use rmule_kad::{
    KadContact, KadContactState, KadId, KadInstant, KadNodeEndpoint, KadRoutingTable, KadUdpKey,
    NodesDat, NodesDatError,
};
use rmule_testkit::kad_node::id;

/// One 25-byte v1-shape contact row: `[id 16][ip 4, low octet first][udp 2
/// LE][tcp 2 LE][version 1]` (`RoutingZone.cpp#L177`).
fn row_v1(id: KadId, ip: Ipv4Addr, udp_port: u16, tcp_port: u16, version: u8) -> Vec<u8> {
    let mut bytes = id.as_bytes().to_vec();
    let mut octets = ip.octets();
    octets.reverse();
    bytes.extend_from_slice(&octets);
    bytes.extend_from_slice(&udp_port.to_le_bytes());
    bytes.extend_from_slice(&tcp_port.to_le_bytes());
    bytes.push(version);
    bytes
}

/// A v2/v3-folded row: the v1 row plus the 9-byte extension — `CKadUDPKey`
/// (`udp_key` = `(key, ip)`, each `u32` LE, `KadUDPKey.h`'s `ReadFromFile`)
/// and the `verified` byte (`RoutingZone.cpp#L185`).
fn row_v2(
    id: KadId,
    ip: Ipv4Addr,
    udp_port: u16,
    tcp_port: u16,
    version: u8,
    udp_key: (u32, u32),
    verified: bool,
) -> Vec<u8> {
    let mut bytes = row_v1(id, ip, udp_port, tcp_port, version);
    bytes.extend_from_slice(&udp_key.0.to_le_bytes());
    bytes.extend_from_slice(&udp_key.1.to_le_bytes());
    bytes.push(u8::from(verified));
    bytes
}

/// A whole nodes.dat normal-format payload: `[0u32][fileVersion
/// u32]([bootstrapEdition u32])[count u32][rows...]` (`RoutingZone.cpp#L149`).
fn file(file_version: u32, bootstrap_edition: Option<u32>, rows: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = 0u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&file_version.to_le_bytes());
    if let Some(edition) = bootstrap_edition {
        bytes.extend_from_slice(&edition.to_le_bytes());
    }
    bytes.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
    for row in rows {
        bytes.extend_from_slice(row);
    }
    bytes
}

// --- version matrix ----------------------------------------------------

#[test]
fn a_nonzero_leading_marker_is_refused_as_too_old() {
    let bytes = 1u32.to_le_bytes().to_vec();
    assert_eq!(NodesDat::decode(&bytes), Err(NodesDatError::TooOld));
}

#[test]
fn version_3_with_bootstrap_edition_1_is_recognized_but_not_parsed_here() {
    let bytes = file(3, Some(1), &[row_v1(id(1), ip(1), 4672, 4662, 8)]);
    assert_eq!(
        NodesDat::decode(&bytes),
        Err(NodesDatError::BootstrapEdition)
    );
}

#[test]
fn version_3_without_bootstrap_edition_folds_into_the_v2_row_layout() {
    let bytes = file(
        3,
        Some(0), // bootstrapEdition present but not 1: still a "normal" v3 file
        &[row_v2(
            id(1),
            ip(1),
            4672,
            4662,
            8,
            (0xAAAA_AAAA, 0xBBBB_BBBB),
            true,
        )],
    );
    let parsed = NodesDat::decode(&bytes).expect("v3-normal parses via the v2 layout");
    assert_eq!(parsed.contacts().len(), 1);
    assert!(
        parsed.contacts()[0].verified(),
        "the v2-shape verified byte must still be read for a v3-normal file"
    );
}

#[test]
fn incomplete_or_out_of_range_version_markers_yield_zero_contacts_not_an_error() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "only the leading zero marker, no version word",
            0u32.to_le_bytes().to_vec(),
        ),
        ("version 0 after the marker", file(0, None, &[])),
        ("version past the supported 1..=3 range", file(7, None, &[])),
        ("version 3 truncated before the bootstrap-edition word", {
            let mut bytes = 0u32.to_le_bytes().to_vec();
            bytes.extend_from_slice(&3u32.to_le_bytes());
            bytes
        }),
    ];
    for (label, bytes) in cases {
        let parsed = NodesDat::decode(&bytes).unwrap_or_else(|err| panic!("{label}: {err:?}"));
        assert!(
            parsed.contacts().is_empty(),
            "{label}: expected zero contacts"
        );
    }
}

#[test]
fn truncation_mid_row_keeps_contacts_parsed_so_far() {
    let good_a = row_v1(id(1), ip(1), 4672, 4662, 8);
    let good_b = row_v1(id(2), ip(2), 4672, 4662, 8);
    let partial = row_v1(id(3), ip(3), 4672, 4662, 8)[..10].to_vec();
    // Declares 3 rows but only two are complete.
    let bytes = file(1, None, &[good_a, good_b, partial]);

    let parsed = NodesDat::decode(&bytes).expect("truncation is not a hard error");
    assert_eq!(
        parsed
            .contacts()
            .iter()
            .map(KadContact::id)
            .collect::<Vec<_>>(),
        vec![id(1), id(2)]
    );
}

// --- per-contact filters -------------------------------------------------

#[test]
fn kad1_rows_are_skipped_and_counted_while_kad2_rows_are_kept() {
    let bytes = file(
        1,
        None,
        &[
            row_v1(id(1), ip(1), 4672, 4662, 1), // Kad1: skipped
            row_v1(id(2), ip(2), 4672, 4662, 0), // Kad1 (version 0): skipped
            row_v1(id(3), ip(3), 4672, 4662, 8), // Kad2: kept
        ],
    );

    let parsed = NodesDat::decode(&bytes).expect("decode");
    assert_eq!(
        parsed
            .contacts()
            .iter()
            .map(KadContact::id)
            .collect::<Vec<_>>(),
        vec![id(3)]
    );
    assert_eq!(parsed.kad1_skipped(), 2);
}

#[test]
fn port_53_is_dropped_at_or_below_version_5_but_kept_from_version_6() {
    let bytes = file(
        1,
        None,
        &[
            row_v1(id(1), ip(1), 53, 4662, 5), // dropped: port 53, version <= 5
            row_v1(id(2), ip(2), 53, 4662, 6), // kept: crypt-capable v6+ on port 53
            row_v1(id(3), ip(3), 4672, 4662, 2), // kept: not port 53
        ],
    );

    let parsed = NodesDat::decode(&bytes).expect("decode");
    assert_eq!(
        parsed
            .contacts()
            .iter()
            .map(KadContact::id)
            .collect::<Vec<_>>(),
        vec![id(2), id(3)]
    );
}

#[test]
fn is_good_ip_port_drops_port_zero_and_lan_ip_contacts_keeping_only_the_good_one() {
    // aMule's IsGoodIPPort gate (RoutingZone.cpp#L193, between the Kad2 and
    // port-53 filters): a contact is loadable only with a nonzero port and a
    // routable IP. A port-0 row, a private/LAN-IP row and a row in a
    // Reserved Range (aMule's `reserved_ranges`, `NetworkFunctions.cpp:101`)
    // are all dropped.
    let bytes = file(
        1,
        None,
        &[
            row_v1(id(1), ip(1), 4672, 4662, 8), // good: routable IP, nonzero port
            row_v1(id(2), ip(2), 0, 4662, 8),    // dropped: port 0
            row_v1(id(3), Ipv4Addr::new(10, 0, 0, 1), 4672, 4662, 8), // dropped: RFC1918 LAN IP
            row_v1(id(4), Ipv4Addr::new(224, 0, 0, 1), 4672, 4662, 8), // dropped: multicast
            row_v1(id(5), Ipv4Addr::new(0, 0, 0, 5), 4672, 4662, 8), // dropped: this network
        ],
    );

    let parsed = NodesDat::decode(&bytes).expect("decode");
    assert_eq!(
        parsed
            .contacts()
            .iter()
            .map(KadContact::id)
            .collect::<Vec<_>>(),
        vec![id(1)],
        "only the routable, nonzero-port contact loads"
    );
}

// --- verified-bit / v1-heuristic mapping into the ADR-0064 seam ---------

#[test]
fn a_v1_file_has_no_verified_bits_so_every_surviving_contact_is_marked_verified() {
    // The all-verified heuristic (RoutingZone.cpp#L215): a v1 file structurally
    // carries no verified bit at all, so aMule marks every loaded contact
    // verified rather than leave Kad bootstrapping with zero servable contacts.
    let bytes = file(
        1,
        None,
        &[
            row_v1(id(1), ip(1), 4672, 4662, 8),
            row_v1(id(2), ip(2), 4672, 4662, 8),
        ],
    );

    let parsed = NodesDat::decode(&bytes).expect("decode");
    assert_eq!(parsed.contacts().len(), 2);
    assert!(
        parsed.contacts().iter().all(KadContact::verified),
        "every v1-loaded contact must be pre-verified"
    );
}

#[test]
fn a_v2_file_with_any_verified_bit_keeps_each_survivors_own_bit() {
    // Once at least one row in the file carries verified=1, the all-verified
    // fallback does not fire: survivors keep their own individual bit.
    let bytes = file(
        2,
        None,
        &[
            row_v2(id(1), ip(1), 4672, 4662, 8, (1, 1), true),
            row_v2(id(2), ip(2), 4672, 4662, 8, (0, 0), false),
        ],
    );

    let parsed = NodesDat::decode(&bytes).expect("decode");
    let verified: Vec<(KadId, bool)> = parsed
        .contacts()
        .iter()
        .map(|c| (c.id(), c.verified()))
        .collect();
    assert_eq!(verified, vec![(id(1), true), (id(2), false)]);
}

#[test]
fn a_verified_bit_on_a_row_the_filters_reject_still_suppresses_the_fallback() {
    // aMule sets `doHaveVerifiedContacts` while decoding each row, before the
    // per-contact filters run (RoutingZone.cpp#L185 precedes #L193's filter
    // block). A verified=1 row that is later dropped (here: Kad1) must still
    // block the all-verified fallback for whichever *unverified* rows survive.
    let bytes = file(
        2,
        None,
        &[
            row_v2(id(1), ip(1), 4672, 4662, 1, (1, 1), true), // Kad1: dropped, but verified=1
            row_v2(id(2), ip(2), 4672, 4662, 8, (0, 0), false), // Kad2: kept, unverified
        ],
    );

    let parsed = NodesDat::decode(&bytes).expect("decode");
    assert_eq!(parsed.contacts().len(), 1);
    assert!(
        !parsed.contacts()[0].verified(),
        "the fallback must not fire just because a dropped row happened to be verified"
    );
}

// --- the zero-servable-cliff consequence (ties into the verified seam) ---

#[test]
fn v1_loaded_contacts_stay_servable_after_another_contact_verifies_elsewhere() {
    // The real-world payoff of the all-verified heuristic: once *any* contact
    // in the table is verified, `select_closest_servable`'s interim disengages
    // and unverified contacts stop being served. Without the heuristic,
    // bootstrap-file contacts loaded from a v1 nodes.dat would silently fall
    // off the servable set the instant a single other contact verified. With
    // it, they never do -- this is the cliff ADR-0066 names as the reason the
    // heuristic exists.
    let bytes = file(
        1,
        None,
        &[
            row_v1(id(0x10), ip(0x10), 4672, 4662, 8),
            row_v1(id(0x20), ip(0x20), 4672, 4662, 8),
        ],
    );
    let loaded = NodesDat::decode(&bytes).expect("decode").into_contacts();
    assert!(
        loaded.iter().all(KadContact::verified),
        "loaded contacts start pre-verified"
    );

    let mut table = KadRoutingTable::new(id(0xFF));
    let t0 = KadInstant::EPOCH;
    for contact in loaded {
        table.upsert(t0, contact.in_state(KadContactState::Responded));
    }
    // A third, independently-verified contact appears (e.g. via a live 0x22
    // handshake) -- this is what narrows `select_closest_servable` to
    // verified-only and would strand any still-unverified contact.
    let other = KadContact::new(id(0x30), KadNodeEndpoint::new(ip(0x30), 4672), 4662, 8)
        .in_state(KadContactState::Responded)
        .into_verified();
    table.upsert(t0, other);

    let served: Vec<KadId> = table
        .select_closest_servable(id(0x11), 10)
        .into_iter()
        .map(KadContact::id)
        .collect();
    assert_eq!(
        served.len(),
        3,
        "the bootstrap-loaded contacts must still be served, not stranded by the narrowing gate"
    );
    assert!(served.contains(&id(0x10)));
    assert!(served.contains(&id(0x20)));
}

// --- v2 writer --------------------------------------------

/// A verified contact rebuilt exactly as the reader would surface it from a v2
/// row: verified, in file order.
fn verified_contact(id: KadId, ip: Ipv4Addr, udp: u16, tcp: u16, version: u8) -> KadContact {
    KadContact::new(id, KadNodeEndpoint::new(ip, udp), tcp, version).into_verified()
}

#[test]
fn v2_writer_is_the_exact_inverse_of_the_reader() {
    // A v2 file whose rows carry a zero UDP key and a set verified bit — the
    // shape aMule's own WriteFile emits for a bootstrap-loaded table (the v2
    // golden). Decoding it and re-encoding must reproduce the bytes verbatim,
    // proving `encode_v2` is `decode`'s inverse over exactly the rows a real
    // writer produces.
    let original = file(
        2,
        None,
        &[
            row_v2(id(0x10), ip(10), 4672, 4662, 8, (0, 0), true),
            row_v2(id(0x20), ip(20), 5000, 4662, 8, (0, 0), true),
            row_v2(id(0x30), ip(30), 4672, 5001, 9, (0, 0), true),
        ],
    );

    let decoded = NodesDat::decode(&original).expect("valid v2 file");
    assert_eq!(decoded.contacts().len(), 3);
    let reencoded = NodesDat::encode_v2(decoded.contacts());
    assert_eq!(
        reencoded, original,
        "decode → encode_v2 must reproduce a real writer's v2 bytes byte-for-byte"
    );
}

#[test]
fn the_v2_udp_key_round_trips_through_the_reader_and_writer() {
    // aMule persists each contact's `CKadUDPKey` (`key ‖ ip`, the sender key it
    // earned and the own-IP binding that keeps it honest). Losing it across a
    // restart would force every contact to re-handshake, so the key must
    // survive read → surface → write. The binding IP sits on disk in NATURAL
    // `a.b.c.d` order — `m_ip` is a network-order u32 (`GetPublicIP`,
    // `amule.cpp#L1455`), so aMule's LE `WriteUInt32` emits its octets as-is —
    // unlike the reversed contact IP in the same row. A round-trip alone is
    // order-blind (both slips cancel), so the on-disk bytes are pinned
    // explicitly too.
    let key_ip = Ipv4Addr::new(203, 0, 113, 9);
    let key_ip_wire = u32::from_le_bytes(key_ip.octets());
    let original = file(
        2,
        None,
        &[row_v2(
            id(0x10),
            ip(10),
            4672,
            4662,
            8,
            (0xABCD_0001, key_ip_wire),
            true,
        )],
    );
    // 12-byte header + `id(16) ip(4) udp(2) tcp(2) ver(1) key(4)` = offset 41.
    assert_eq!(
        &original[41..45],
        &[0xCB, 0x00, 0x71, 0x09],
        "203.0.113.9 at the binding-IP offset, natural octet order"
    );

    let decoded = NodesDat::decode(&original).expect("valid v2 file");
    let [contact] = decoded.contacts() else {
        panic!("one contact");
    };
    assert_eq!(
        contact.udp_key(),
        KadUdpKey::new(0xABCD_0001, key_ip),
        "the reader surfaces the persisted key and its binding IP"
    );
    assert_eq!(
        NodesDat::encode_v2(decoded.contacts()),
        original,
        "and the writer puts the same bytes back"
    );
}

#[test]
fn v2_writer_round_trips_contact_state() {
    // rmule-state → write → read → same state: the routing-continuity property.
    let contacts = vec![
        verified_contact(id(0xA1), ip(1), 4672, 4662, 8),
        verified_contact(id(0xB2), ip(2), 12000, 4661, 8),
        verified_contact(id(0xC3), ip(3), 4672, 4662, 9),
    ];

    let bytes = NodesDat::encode_v2(&contacts);
    let decoded = NodesDat::decode(&bytes).expect("our own v2 output must decode");

    assert_eq!(decoded.contacts(), contacts.as_slice());
}

#[test]
fn v2_writer_emits_the_v2_header_and_34_byte_rows() {
    let bytes = NodesDat::encode_v2(&[verified_contact(
        id(0x77),
        Ipv4Addr::new(45, 55, 12, 2),
        4672,
        4662,
        8,
    )]);

    assert_eq!(bytes.len(), 12 + 34, "12-byte header + one 34-byte v2 row");
    assert_eq!(&bytes[0..4], &[0, 0, 0, 0], "old-client guard");
    assert_eq!(&bytes[4..8], &2u32.to_le_bytes(), "version 2");
    assert_eq!(&bytes[8..12], &1u32.to_le_bytes(), "contact count");
    assert_eq!(&bytes[12..28], &[0x77; 16], "verbatim Kad ID");
    assert_eq!(
        &bytes[28..32],
        &[2, 12, 55, 45],
        "45.55.12.2 octets reversed"
    );
    assert_eq!(&bytes[32..34], &4672u16.to_le_bytes(), "udp port LE");
    assert_eq!(&bytes[34..36], &4662u16.to_le_bytes(), "tcp port LE");
    assert_eq!(bytes[36], 8, "contact version");
    assert_eq!(
        &bytes[37..45],
        &[0u8; 8],
        "zero UDP key (rmule models none)"
    );
    assert_eq!(bytes[45], 1, "verified bit");
}

#[test]
fn v2_writer_caps_at_the_contact_file_limit() {
    // aMule's `std::min(numContacts, CONTACT_FILE_LIMIT)` safety cap: an
    // oversized table writes exactly CONTACT_FILE_LIMIT rows, no more.
    let contacts: Vec<KadContact> = (0..(rmule_kad::CONTACT_FILE_LIMIT + 50))
        .map(|i| {
            let id = KadId::from_bytes(std::array::from_fn(|b| (i >> (b % 4 * 8)) as u8));
            verified_contact(
                id,
                Ipv4Addr::new(45, 55, (i % 250 + 1) as u8, 2),
                4672,
                4662,
                8,
            )
        })
        .collect();

    let bytes = NodesDat::encode_v2(&contacts);
    let expected_count = u32::try_from(rmule_kad::CONTACT_FILE_LIMIT).unwrap();
    assert_eq!(&bytes[8..12], &expected_count.to_le_bytes());
    assert_eq!(bytes.len(), 12 + rmule_kad::CONTACT_FILE_LIMIT * 34);
}
