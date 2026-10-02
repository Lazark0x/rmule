//! Documentation-provenance `KADEMLIA2_SEARCH_RES` (`0x3B`) decoder tests.
//!
//! These exercise [`decode_source_result`] against a handwritten fixture built
//! strictly from the DOCUMENTED eMule Kad2 layout (Wireshark
//! `epan/dissectors/packet-edonkey.c`, the ETH Mysicka thesis, and
//! `a-pavlov/jed2k` — three agreeing clean-room sources, plus aMule's own
//! `Search.cpp` source-type handling). No production encoder builds these
//! bytes: [`handwritten_fixture`] lays each field as explicit byte literals
//! with the spec mapping in comments, and the committed `result_0x3b_high_id.bin`
//! must match it byte-for-byte. The decoder is then driven over the *file* and
//! asserted to project the direct High ID row to an exact `PeerSource`, and the
//! Low ID / buddy / missing-port / deprecated rows to their diagnostics.

use std::net::Ipv4Addr;

use rmule_kad::opcode::KADEMLIA2_SEARCH_RES;
use rmule_kad::{
    KadDecoded, KadSourceCandidate, KadSourceDiagnostic, KadSourceResultDecodeError, decode_exact,
    decode_source_result,
};
use rmule_primitives::{ClientId, PeerEndpoint, PeerSource};

const FIXTURE: &[u8] = include_bytes!(
    "../fixtures/source_lookup/documentation/0x3b-high-id-documented/result_0x3b_high_id.bin"
);

/// Hand-lay the documented `0x3B` payload (the bytes AFTER the `0xE4 0x3B` that
/// `KadEnvelope` strips) as explicit literals. Each line maps a field to the
/// documented eMule Kad2 layout. This is deliberately NOT the production tag
/// encoder — the committed fixture must equal these literals, so the test
/// proves the decoder reads an independently authored documented layout, not
/// its own output.
fn handwritten_fixture() -> Vec<u8> {
    let mut p = Vec::new();

    // [16B sender Kad ID] — 4 LE 32-bit words; not load-bearing for projection.
    p.extend_from_slice(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ]);
    // [16B target] — the searched file hash (the recipe's synthetic file hash).
    p.extend_from_slice(&[
        0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62,
        0xD2,
    ]);
    // [2B result count, LE u16] = 5.
    p.extend_from_slice(&[0x05, 0x00]);

    // --- Row 0: direct High ID -> PeerSource 198.51.100.10:4662 ---
    p.extend_from_slice(&[0x01; 16]); // [16B source/result ID]
    p.push(0x03); // [1B tag count]
    // SOURCETYPE (UINT8 0x09, name 0xFF) = 1 (HighID direct).
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x01]);
    // SOURCEIP (UINT32 0x03, name 0xFE): IP 198.51.100.10, wire = d c b a.
    p.extend_from_slice(&[0x03, 0x01, 0x00, 0xFE, 0x0A, 0x64, 0x33, 0xC6]);
    // SOURCEPORT (UINT16 0x08, name 0xFD) = 4662 (0x1236) LE.
    p.extend_from_slice(&[0x08, 0x01, 0x00, 0xFD, 0x36, 0x12]);

    // --- Row 1: Low ID (direct type, IP resolves below threshold) ---
    p.extend_from_slice(&[0x02; 16]);
    p.push(0x03);
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x01]); // SOURCETYPE = 1
    // SOURCEIP wire d c b a = 00 01 02 03 -> ClientId 0x00010203 (< Low ID threshold).
    p.extend_from_slice(&[0x03, 0x01, 0x00, 0xFE, 0x00, 0x01, 0x02, 0x03]);
    p.extend_from_slice(&[0x08, 0x01, 0x00, 0xFD, 0x36, 0x12]); // SOURCEPORT = 4662

    // --- Row 2: buddy/firewalled (type 3) -> BuddyCallback; ignored SERVER* tags ---
    p.extend_from_slice(&[0x03; 16]);
    p.push(0x03);
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x03]); // SOURCETYPE = 3 (firewalled, buddy)
    // SERVERIP (name 0xFB) + SERVERPORT (name 0xFA) — recognized by aMule, ignored here.
    p.extend_from_slice(&[0x03, 0x01, 0x00, 0xFB, 0xAA, 0xBB, 0xCC, 0xDD]);
    p.extend_from_slice(&[0x08, 0x01, 0x00, 0xFA, 0x11, 0x22]);

    // --- Row 3: direct (type 1) but MISSING SOURCEPORT -> MissingEndpoint ---
    p.extend_from_slice(&[0x04; 16]);
    p.push(0x02);
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x01]); // SOURCETYPE = 1
    p.extend_from_slice(&[0x03, 0x01, 0x00, 0xFE, 0x0A, 0x64, 0x33, 0xC6]); // SOURCEIP, no port

    // --- Row 4: deprecated type 2 -> UnsupportedSourceType(2) ---
    p.extend_from_slice(&[0x05; 16]);
    p.push(0x01);
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x02]); // SOURCETYPE = 2 (deprecated)

    p
}

fn decode_fixture() -> Vec<KadSourceCandidate> {
    let KadDecoded::Plain(envelope) = decode_exact(&prepend_envelope(FIXTURE)).expect("plain 0xE4")
    else {
        panic!("documented fixture must decode as a plain 0xE4 envelope");
    };
    assert_eq!(envelope.opcode(), KADEMLIA2_SEARCH_RES);
    decode_source_result(&envelope).expect("documented row shape decodes")
}

fn prepend_envelope(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xE4, KADEMLIA2_SEARCH_RES];
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn committed_fixture_is_the_handwritten_documented_layout() {
    // If the committed `.bin` ever drifts from the spec-mapped literals (or were
    // regenerated from the production encoder), this fails. The fixture's
    // provenance is the handwritten layout, asserted here.
    assert_eq!(
        FIXTURE,
        handwritten_fixture().as_slice(),
        "committed fixture must equal the hand-laid documented layout byte-for-byte"
    );
}

#[test]
fn direct_high_id_row_projects_to_exact_peer_source() {
    let candidates = decode_fixture();
    let source = candidates[0]
        .peer_source()
        .expect("row 0 is a direct-connectable High ID source");

    assert_eq!(
        source,
        PeerSource::new(ClientId::from_u32(0x0A64_33C6), 4662),
        "SOURCEIP 198.51.100.10 + SOURCEPORT 4662 -> this PeerSource"
    );
    assert_eq!(
        source.as_peer_endpoint(),
        Some(PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
            Ipv4Addr::new(198, 51, 100, 10),
            4662
        ))),
        "the reconstructed endpoint must be the documented 198.51.100.10:4662"
    );
}

#[test]
fn low_id_row_is_a_low_id_diagnostic() {
    let candidates = decode_fixture();
    assert_eq!(candidates[1].peer_source(), None);
    assert_eq!(
        candidates[1].refusal(),
        Some(KadSourceDiagnostic::LowId {
            client_id: ClientId::from_u32(0x0001_0203),
            tcp_port: 4662,
        }),
        "a direct-type row whose IP resolves below the Low ID threshold stays a LowId diagnostic"
    );
}

#[test]
fn buddy_firewalled_row_is_a_buddy_callback_diagnostic() {
    let candidates = decode_fixture();
    // The widened reader keeps this verdict: the documented
    // fixture's type-3 row carries no `TAG_SERVERIP`/`TAG_SERVERPORT`/
    // `TAG_BUDDYHASH`, so there is nowhere to address a callback and the row
    // is still a refusal, not a buddy candidate.
    assert_eq!(
        candidates[2].refusal(),
        Some(KadSourceDiagnostic::BuddyCallback),
        "source type 3 with no buddy tags stays a BuddyCallback diagnostic"
    );
    assert_eq!(candidates[2].peer_source(), None);
    assert_eq!(candidates[2].buddy(), None);
}

#[test]
fn direct_row_missing_tcp_port_is_missing_endpoint() {
    let candidates = decode_fixture();
    assert_eq!(
        candidates[3].refusal(),
        Some(KadSourceDiagnostic::MissingEndpoint),
        "a direct row with a SOURCEIP but no SOURCEPORT cannot become a PeerSource"
    );
}

#[test]
fn deprecated_source_type_is_unsupported() {
    let candidates = decode_fixture();
    assert_eq!(
        candidates[4].refusal(),
        Some(KadSourceDiagnostic::UnsupportedSourceType(2)),
        "the deprecated source type 2 is preserved as an unsupported diagnostic"
    );
}

#[test]
fn only_the_one_direct_high_id_row_yields_a_peer_source() {
    let candidates = decode_fixture();
    let sources: Vec<PeerSource> = candidates.iter().filter_map(|c| c.peer_source()).collect();
    assert_eq!(
        sources,
        vec![PeerSource::new(ClientId::from_u32(0x0A64_33C6), 4662)],
        "exactly one direct-connectable High ID source is projected; the rest stay diagnostics"
    );
}

#[test]
fn packed_envelope_decodes_to_the_same_candidates_as_plain() {
    // A packed 0xE5 twin of the fixture (payload zlib-deflated) must inflate to
    // the identical logical envelope and project the identical candidates.
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(FIXTURE).expect("in-memory deflate");
    let mut packed = vec![0xE5u8, KADEMLIA2_SEARCH_RES];
    packed.extend_from_slice(&encoder.finish().expect("in-memory deflate"));

    let KadDecoded::Packed(envelope) = decode_exact(&packed).expect("packed decodes") else {
        panic!("expected a packed Kad envelope");
    };
    assert_eq!(
        decode_source_result(&envelope).expect("packed twin projects"),
        decode_fixture(),
        "packed and plain twins must project identical candidates"
    );
}

#[test]
fn truncated_payload_errors_without_panicking() {
    // Cut the payload off mid-row (after the header + part of row 0). The
    // decoder must return a typed MalformedPayload, never panic.
    let truncated = &FIXTURE[..40];
    let KadDecoded::Plain(envelope) =
        decode_exact(&prepend_envelope(truncated)).expect("still a plain envelope")
    else {
        panic!("truncated payload is still a plain envelope");
    };
    assert!(
        matches!(
            decode_source_result(&envelope),
            Err(KadSourceResultDecodeError::MalformedPayload { .. })
        ),
        "a truncated payload must be a typed decode error"
    );
}

#[test]
fn count_overstating_rows_errors() {
    // Same header but claim 6 rows while only 5 are present: the decoder runs
    // off the end parsing the 6th row and reports MalformedPayload.
    let mut overstated = handwritten_fixture();
    overstated[32] = 0x06; // result count u16 LE low byte 5 -> 6
    let KadDecoded::Plain(envelope) =
        decode_exact(&prepend_envelope(&overstated)).expect("plain envelope")
    else {
        panic!("plain envelope");
    };
    assert!(
        matches!(
            decode_source_result(&envelope),
            Err(KadSourceResultDecodeError::MalformedPayload { .. })
        ),
        "an overstated result count must error, not silently truncate"
    );
}
