//! Captured-provenance `KADEMLIA2_SEARCH_RES` (`0x3B`) decoder tests (ADR-0043):
//! the genuine aMule bytes that break the `0x3B` wall.
//!
//! rmule ran as a **Kad Stimulus Node** against a real aMule storer in the
//! private Docker mesh: rmule published a synthetic file's source (`0x44`),
//! aMule accepted and acked it (`0x4B`), rmule searched (`0x34`), and aMule
//! answered with the `0x3B` whose payload is committed here. rmule's `0x44`/
//! `0x34` are stimulus context; **these bytes are aMule-authored** — aMule
//! re-serialized the entry from parsed tags (not a byte echo), which is what
//! makes them evidence.
//!
//! The capture proves the two facts the documentation fixture could only
//! assert (`KadEvidence::SourceIpTagByteOrder`, `KadEvidence::SourceIdMeaning`)
//! and records one correction: aMule *does* re-emit a `FILESIZE` tag in the
//! source row (from the entry's `m_uSize` via `CEntry::WriteTagListInc`,
//! aMule `Entry.cpp`), which the handoff had predicted absent. rmule's decoder
//! ignores it (an unrecognized tag name) and still projects the direct source.

use std::net::Ipv4Addr;

use rmule_kad::opcode::KADEMLIA2_SEARCH_RES;
use rmule_kad::{KadDecoded, KadSourceCandidate, decode_exact, decode_source_result};
use rmule_primitives::{ClientId, Ipv4Endpoint, PeerEndpoint, PeerSource, kad_wire_id};

/// The User Hash of the publisher in the captured `0x3B` row — the value the
/// row's source id is the word-swap of.
const PUBLISHER_USER_HASH: [u8; 16] = [
    0x0b, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef, 0x0b, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef,
];

/// The `0x3B` payload aMule sent rmule, with the `0xE4 0x3B` envelope bytes
/// stripped (what `KadEnvelope` exposes). Captured 2026-07-07.
const CAPTURED: &[u8] = include_bytes!(
    "../fixtures/source_lookup/captured/private-amule-kad-source-result-20260707/result_0x3b_high_id.bin"
);

/// The publisher's mesh IP (rmule's container address) and ports the harness
/// gave the stimulus node. aMule observed the IP from the publish datagram's
/// sender and authored a `SOURCEIP` tag from it — the publisher sent none.
const PUBLISHER_IP: Ipv4Addr = Ipv4Addr::new(172, 30, 0, 9);
const PUBLISHER_TCP_PORT: u16 = 4662;

fn decode_captured() -> Vec<KadSourceCandidate> {
    let mut datagram = vec![0xE4, KADEMLIA2_SEARCH_RES];
    datagram.extend_from_slice(CAPTURED);
    let KadDecoded::Plain(envelope) = decode_exact(&datagram).expect("plain 0xE4 envelope") else {
        panic!("captured 0x3B must decode as a plain 0xE4 envelope");
    };
    assert_eq!(envelope.opcode(), KADEMLIA2_SEARCH_RES);
    decode_source_result(&envelope).expect("captured aMule row shape decodes")
}

#[test]
fn captured_amule_row_projects_to_the_published_high_id_source() {
    let candidates = decode_captured();
    assert_eq!(
        candidates.len(),
        1,
        "aMule answered with exactly the one source rmule published"
    );

    let source = candidates[0]
        .peer_source()
        .expect("the single row is a direct-connectable High ID source");
    assert_eq!(
        source,
        PeerSource::new(ClientId::from_u32(0x0900_1EAC), PUBLISHER_TCP_PORT),
        "aMule's SOURCEIP (172.30.0.9) + SOURCEPORT (4662) project to this PeerSource"
    );
    assert_eq!(
        source.as_peer_endpoint(),
        Some(PeerEndpoint::V4(Ipv4Endpoint::new(
            PUBLISHER_IP,
            PUBLISHER_TCP_PORT
        ))),
        "the reconstructed endpoint is the publisher's own mesh contact"
    );
}

/// `KadEvidence::SourceIpTagByteOrder`, capture-proven: aMule's `SOURCEIP` tag
/// value is the host-order u32 `(a<<24)|(b<<16)|(c<<8)|d` of `a.b.c.d`, written
/// little-endian on the wire — so the raw four bytes are `d c b a`. Decoding
/// under exactly that convention reconstructs the publisher's real IP.
#[test]
fn captured_source_ip_tag_byte_order_reconstructs_the_publisher_ip() {
    // The SOURCEIP tag value bytes in the captured payload, located after the
    // `[type 0x03][01 00][name 0xFE]` header: 172.30.0.9 as `d c b a`.
    assert_eq!(
        find_tag_value(CAPTURED, 0xFE),
        Some(vec![0x09, 0x00, 0x1E, 0xAC]),
        "SOURCEIP wire bytes are the host-order u32 of 172.30.0.9, little-endian (d c b a)"
    );
    // And the decoder, applying that byte order, yields the true endpoint.
    let endpoint = decode_captured()[0]
        .peer_source()
        .and_then(PeerSource::as_peer_endpoint)
        .expect("direct source");
    assert_eq!(endpoint.as_v4().expect("an IPv4 source").ip, PUBLISHER_IP);
}

/// `KadEvidence::SourceIdMeaning`, capture-proven: the 16-byte per-row source
/// ID aMule stored and re-serialized equals the publisher's **User Hash**
/// word-swapped per 32-bit word (the same transform as a Kad key), not the
/// publisher's Kad ID. The publisher's Kad ID was `0x5E…`; the row carries the
/// User Hash instead.
#[test]
fn captured_source_id_is_the_publisher_user_hash_word_swapped() {
    let source_id = captured_source_id(CAPTURED);
    assert_eq!(
        source_id,
        kad_wire_id(PUBLISHER_USER_HASH),
        "the stored source ID is the publisher User Hash word-swapped"
    );
    assert_ne!(
        source_id, [0x5E; 16],
        "it is NOT the publisher's Kad ID — the identities are independent"
    );
}

/// The IP-substitution finding, capture-proven: the publisher's `0x44` carried
/// no `SOURCEIP` (rmule's publisher never sends one — test-proven in
/// `publisher_storer`), so the `SOURCEIP` present in aMule's answer is
/// aMule-authored from its observed sender. Its value equals the publisher's
/// real IP, i.e. aMule substituted what it saw.
#[test]
fn amule_authored_the_source_ip_from_its_observed_sender() {
    assert!(
        find_tag_value(CAPTURED, 0xFE).is_some(),
        "aMule authored a SOURCEIP tag the publisher never sent"
    );
    // The one row's decoded IP is the publisher's real mesh IP (what aMule saw).
    assert_eq!(
        decode_captured()[0]
            .peer_source()
            .and_then(PeerSource::as_peer_endpoint)
            .and_then(PeerEndpoint::as_v4)
            .map(|e| e.ip),
        Some(PUBLISHER_IP)
    );
}

/// The captured row's tag list opens with a `FILESIZE` tag (name `0x02`) the
/// documentation fixture and the pre-capture notes predicted absent — aMule
/// re-emits it from the entry's size. The decoder must ignore the unrecognized
/// name and still project the source (regression against a stricter loop).
#[test]
fn captured_filesize_tag_is_tolerated_and_ignored() {
    let file_size_tag = find_tag_value(CAPTURED, 0x02);
    assert_eq!(
        file_size_tag,
        Some(vec![0x00, 0x00, 0x01, 0x00]),
        "aMule re-emitted a FILESIZE tag = 65536 (the 64 KiB synthetic file), little-endian"
    );
    // Despite the extra leading tag, the row still projects to the direct source.
    assert!(decode_captured()[0].peer_source().is_some());
}

// --- byte-poking helpers over the raw captured payload (not the decoder) ---

/// The 16-byte source ID: after `[16B sender][16B target][2B count]`.
fn captured_source_id(payload: &[u8]) -> [u8; 16] {
    payload[34..50]
        .try_into()
        .expect("payload carries a full source ID")
}

/// Scan the single row's tag list for the length-prefixed tag with single-byte
/// `name`, returning its value bytes. Tags are `[type][01 00][name][value…]`
/// with value width fixed by type (uint8 0x09, uint16 0x08, uint32 0x03).
fn find_tag_value(payload: &[u8], name: u8) -> Option<Vec<u8>> {
    let tag_count = payload[50] as usize;
    let mut off = 51;
    for _ in 0..tag_count {
        let tag_type = payload[off];
        let name_len = u16::from_le_bytes([payload[off + 1], payload[off + 2]]) as usize;
        let tag_name = payload[off + 3];
        let value_off = off + 3 + name_len;
        let value_len = match tag_type {
            0x09 => 1,
            0x08 => 2,
            0x03 => 4,
            other => panic!("unexpected captured tag type 0x{other:02x}"),
        };
        if tag_name == name {
            return Some(payload[value_off..value_off + value_len].to_vec());
        }
        off = value_off + value_len;
    }
    None
}
