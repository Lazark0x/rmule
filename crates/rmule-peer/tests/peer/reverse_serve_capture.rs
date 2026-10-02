//! Reverse-harness serve-consume capture (genuine stock aMule 2.3.3, run
//! `1785029762`, interop flow C `rmule-serves-amule-downloads`). These are the
//! counterparty's own wire frames, observed by rmule's serve side while a live
//! aMule downloaded a 64 KiB file from rmule — the reverse-harness evidence for
//! the peer-TCP multipacket-request, inbound-SX-ask and cancel-consume rows.
//! Each frame is re-decoded through the public API to prove
//! rmule reads real aMule bytes byte-exact; the `0xA4` also round-trips on
//! re-encode. Provenance + per-frame notes live alongside in `meta.toml`.
//!
//! The same direction again after rmule began claiming extended-requests 1
//! AMule's bundle to a v1 claimant carries its part status in
//! the name sub, phantom part included (run `1790228582`).

use crate::fixture::load;
use rmule_peer::{ExtendedRequests, MultiPacketRequest, PartBitmap, PeerPacket, RequestItem};
use rmule_primitives::{ED2K_PART_SIZE, FileHash, Packet};

const FIXTURE_DIR: &str = "fixtures/reverse_serve/captured/amule-233-serve-consume-20260726/";

/// The synthetic file both sides shared this run.
const FILE_HASH: [u8; 16] = [
    0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62, 0xD2,
];

fn decode_single(name: &str) -> PeerPacket {
    let bytes = load(FIXTURE_DIR, name);
    let (packet, consumed) = Packet::decode(&bytes).expect("fixture frame decodes");
    assert_eq!(consumed, bytes.len(), "{name} is exactly one frame");
    PeerPacket::decode(&packet).expect("peer packet decodes")
}

/// Multipacket reverse leg: aMule's bundled file request is the EXT (`0xA4`) form —
/// `file_size` present, walked into [Name, Sources2 v4, AichRoot]. aMule never
/// sends the base `0x92` toward an ext peer (ADR-0054). Re-encode round-trips.
#[test]
fn amule_reverse_multipacket_ext_request_walks_and_roundtrips() {
    let bytes = load(FIXTURE_DIR, "request_multipacket_ext_0xa4.bin");
    let (packet, _) = Packet::decode(&bytes).unwrap();
    let request =
        MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE).expect("0xA4 decodes");

    assert_eq!(request.file_hash, FileHash::from_bytes(FILE_HASH));
    assert_eq!(
        request.file_size,
        Some(65_536),
        "the EXT form carries the file size — proof aMule chose 0xA4 not 0x92",
    );
    assert_eq!(
        request.items,
        vec![
            RequestItem::Name { part_status: None },
            RequestItem::Sources2 {
                version: 4,
                options: 0
            },
            RequestItem::AichRoot,
        ],
    );
    assert!(
        request.unknown_sub.is_none(),
        "walker consumed every sub-item"
    );

    // Byte-exact re-encode: our encoder reproduces aMule's own frame.
    assert_eq!(
        request.encode_packet().encode(),
        bytes,
        "re-encoded 0xA4 must match aMule's captured bytes",
    );
}

/// Multipacket reverse leg: after the `0x93` answer aMule requests parts — a 3-slot u32
/// `0x47` with one live range (0..65536). Its upload-start proves the answer
/// was accepted.
#[test]
fn amule_reverse_request_parts_is_three_slot_u32() {
    match decode_single("request_parts_0x47.bin") {
        PeerPacket::RequestParts(parts) => {
            assert_eq!(parts.file_hash, FileHash::from_bytes(FILE_HASH));
            assert_eq!(parts.ranges.as_array(), &[(0, 65_536), (0, 0), (0, 0)]);
        }
        other => panic!("expected RequestParts, got {other:?}"),
    }
}

/// Cancel consume: aMule emits `OP_CANCELTRANSFER` (payload-less) once it has the
/// whole part; rmule consumes it as a cancel and releases the slot.
#[test]
fn amule_reverse_cancel_transfer_is_payloadless_0x56() {
    let bytes = load(FIXTURE_DIR, "cancel_transfer_0x56.bin");
    assert_eq!(
        bytes,
        [0xE3, 0x01, 0x00, 0x00, 0x00, 0x56],
        "1-byte payload-less body"
    );
    match decode_single("cancel_transfer_0x56.bin") {
        PeerPacket::CancelTransfer(_) => {}
        other => panic!("expected CancelTransfer, got {other:?}"),
    }
}

const V1_FIXTURE_DIR: &str =
    "fixtures/multipacket/captured/amule-233-multipacket-v1-status-20260924/";

/// The one-part-plus-phantom file of run `1790228582`: exactly `PARTSIZE`.
const V1_FILE_HASH: [u8; 16] = [
    0x22, 0x15, 0x52, 0x55, 0xA2, 0xED, 0x92, 0x71, 0x2C, 0xCD, 0x01, 0xAD, 0x0E, 0xB9, 0xE8, 0xCB,
];

/// Stock aMule's own `0xA4` to an rmule claiming extended-requests 1.
/// aMule claims 2, so the session speaks 1 and `SendFileRequest` writes
/// `WritePartStatus` into the name sub: `GetED2KPartCount()` =
/// `size / PARTSIZE + 1` = 2 for a file of exactly `PARTSIZE`, and a fresh
/// partfile holding nothing still reads the phantom part complete — bitmap
/// `0x02`. That is rmule's own writer rule, now checked against aMule's bytes.
/// No `OP_SETREQFILEID`: `GetPartCount()` is 1.
#[test]
fn amule_writes_its_status_with_the_phantom_part_to_a_v1_claimant() {
    let bytes = load(V1_FIXTURE_DIR, "request_multipacket_ext_0xa4.bin");
    let (packet, consumed) = Packet::decode(&bytes).expect("fixture frame decodes");
    assert_eq!(consumed, bytes.len(), "fixture is exactly one frame");
    let request = MultiPacketRequest::decode_packet(&packet, ExtendedRequests::negotiated(1, 2))
        .expect("the bundle decodes at level 1");

    assert_eq!(request.file_hash, FileHash::from_bytes(V1_FILE_HASH));
    assert_eq!(request.file_size, Some(ED2K_PART_SIZE));
    let status = PartBitmap::downloader_empty(ED2K_PART_SIZE);
    assert_eq!(status.part_count(), 2, "size / PARTSIZE + 1");
    assert_eq!(status.encode(), [0x02], "the phantom part reads held");
    assert_eq!(
        request.items,
        vec![
            RequestItem::Name {
                part_status: Some(status),
            },
            RequestItem::Sources2 {
                version: 4,
                options: 0,
            },
            RequestItem::AichRoot,
        ],
    );
    assert!(request.unknown_sub.is_none());
    assert_eq!(request.encode_packet().encode(), bytes);
}
