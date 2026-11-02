//! Publish-family codecs (`0x44`/`0x4B`), the storer-side `0x34` decode, and
//! the storer's `0x3B` re-encoder.
//!
//! Every vector here is **handwritten from the documented layouts** in
//! `docs/reference/notes/kad-packet-framing.md` ("Source-publish layouts",
//! documentation provenance — link-only aMule source, NOT captured bytes).
//! A real aMule storer's answers are captured beside them
//! (`captured_source_result.rs`, `captured_keyword_answers.rs`); these tests
//! pin rmule to the documented shape and to round-trip consistency with the
//! sealed `decode_source_result` projection. The one exception is the publish
//! past 4 GiB, which is a stock aMule's captured frame.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, Kad2MessageDecodeError, KadDecoded, KadId, KadPublishedSource, KadSourceRow,
    decode_exact, decode_source_result, encode_source_result,
};
use rmule_primitives::{ClientId, PeerSource};
use rmule_testkit::kad_source::FILE_KEY;

const SOURCE_ID: [u8; 16] = [
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
];
const SENDER_ID: [u8; 16] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
];

fn decode(datagram: &[u8]) -> Result<Kad2Message, Kad2MessageDecodeError> {
    let KadDecoded::Plain(envelope) = decode_exact(datagram).expect("test vector envelope") else {
        panic!("all publish vectors are plain 0xE4");
    };
    Kad2Message::decode(&envelope)
}

/// The documented `0x44` payload: `[file key][source ID][tag count][tags]`,
/// tags in aMule's publisher order (SOURCETYPE, SOURCEPORT, SOURCEUPORT,
/// FILESIZE, ENCRYPTION), each in the explicit length-prefixed name form.
fn documented_publish_source_req() -> Vec<u8> {
    let mut datagram = vec![0xE4, 0x44];
    datagram.extend_from_slice(&FILE_KEY);
    datagram.extend_from_slice(&SOURCE_ID);
    datagram.push(5); // tag count
    // TAG_SOURCETYPE (0xFF) u8 = 1 (HighID direct source)
    datagram.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x01]);
    // TAG_SOURCEPORT (0xFD) u16 = 4662
    datagram.extend_from_slice(&[0x08, 0x01, 0x00, 0xFD, 0x36, 0x12]);
    // TAG_SOURCEUPORT (0xFC) u16 = 4672
    datagram.extend_from_slice(&[0x08, 0x01, 0x00, 0xFC, 0x40, 0x12]);
    // TAG_FILESIZE (0x02) u32 = 987_654
    datagram.extend_from_slice(&[0x03, 0x01, 0x00, 0x02, 0x06, 0x12, 0x0F, 0x00]);
    // TAG_ENCRYPTION (0xF3) u8 = 0x0B
    datagram.extend_from_slice(&[0x09, 0x01, 0x00, 0xF3, 0x0B]);
    datagram
}

fn full_published_source() -> KadPublishedSource {
    KadPublishedSource {
        source_type: Some(1),
        tcp_port: Some(4662),
        udp_port_tag: Some(4672),
        file_size: Some(987_654),
        encryption: Some(0x0B),
        ..KadPublishedSource::default()
    }
}

#[test]
fn publish_source_req_encodes_the_documented_layout() {
    let message = Kad2Message::PublishSourceReq {
        file: KadId::from_bytes(FILE_KEY),
        source_id: SOURCE_ID,
        source: full_published_source(),
    };
    assert_eq!(message.encode().encode(), documented_publish_source_req());
}

#[test]
fn publish_source_req_decodes_back_to_the_projected_fields() {
    assert_eq!(
        decode(&documented_publish_source_req()),
        Ok(Kad2Message::PublishSourceReq {
            file: KadId::from_bytes(FILE_KEY),
            source_id: SOURCE_ID,
            source: full_published_source(),
        })
    );
}

/// A stock aMule 2.3.3's own `0x44` for a 5,000,000,000-byte file, shared as
/// one sparse hole by a firewalled node holding rmule as its buddy (interop
/// flow M `kad-core-buddy --publish-source --file-content sparse`, run
/// `1792364377`; provenance in `meta.toml` beside the frame). Past
/// `OLD_MAX_FILE_SIZE` the buddy row is type 5 (`Search.cpp:613`), and
/// `CTagVarInt` widens `TAG_FILESIZE` to `UINT64` above `u32::MAX`
/// (`Tag.h:176-182`).
const LARGE_PUBLISH_DIR: &str =
    "fixtures/buddy/captured/amule-233-publish-source-req-large-20261019/";
const LARGE_FILE_SIZE: u64 = 5_000_000_000;

#[test]
fn publish_source_req_widens_filesize_to_uint64_past_4_gib() {
    let frame = crate::fixture::captured(LARGE_PUBLISH_DIR, "publish_source_req_0x44.bin");
    let message = decode(&frame).expect("rmule reads aMule's large-file publish");
    let Kad2Message::PublishSourceReq { source, .. } = &message else {
        panic!("0x44 decodes to a publish");
    };
    assert_eq!(source.source_type, Some(5), "the large-file buddy row");
    assert_eq!(source.file_size, Some(LARGE_FILE_SIZE));
    let filesize = frame
        .windows(4)
        .position(|tag| tag == [0x0B, 0x01, 0x00, 0x02])
        .expect("TAG_FILESIZE rides as UINT64");
    assert_eq!(
        frame[filesize + 4..filesize + 12],
        LARGE_FILE_SIZE.to_le_bytes(),
    );
    assert_eq!(
        message.encode().encode(),
        frame,
        "rmule writes the row back byte for byte",
    );
}

#[test]
fn publish_source_req_skips_unknown_tags_and_keeps_first_duplicate() {
    let mut datagram = vec![0xE4, 0x44];
    datagram.extend_from_slice(&FILE_KEY);
    datagram.extend_from_slice(&SOURCE_ID);
    datagram.push(4);
    // TAG_SOURCETYPE = 3 (buddy) — first wins.
    datagram.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x03]);
    // Unknown tag (TAG_SERVERPORT 0xFA) — skipped, not an error.
    datagram.extend_from_slice(&[0x08, 0x01, 0x00, 0xFA, 0x12, 0x34]);
    // Duplicate TAG_SOURCETYPE = 1 — ignored (first wins, aMule posture).
    datagram.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x01]);
    // TAG_SOURCEPORT = 4662
    datagram.extend_from_slice(&[0x08, 0x01, 0x00, 0xFD, 0x36, 0x12]);

    assert_eq!(
        decode(&datagram),
        Ok(Kad2Message::PublishSourceReq {
            file: KadId::from_bytes(FILE_KEY),
            source_id: SOURCE_ID,
            source: KadPublishedSource {
                source_type: Some(3),
                tcp_port: Some(4662),
                udp_port_tag: None,
                file_size: None,
                encryption: None,
                ..KadPublishedSource::default()
            },
        })
    );
}

/// A `0x44` publish carrying one string IPv6 tag (`ip6` or `bi6`) beside the
/// single source-type tag, in the documented 40-byte string-tag shape — and,
/// when `buddy_named`, a `TAG_BUDDYHASH` naming the buddy a `bi6` belongs to.
fn publish_source_req_with_ipv6_tag(
    name: &[u8; 3],
    address: std::net::Ipv6Addr,
    buddy_named: bool,
) -> Vec<u8> {
    let mut datagram = vec![0xE4, 0x44];
    datagram.extend_from_slice(&FILE_KEY);
    datagram.extend_from_slice(&SOURCE_ID);
    datagram.push(if buddy_named { 3 } else { 2 }); // tag count
    datagram.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x01]); // TAG_SOURCETYPE = 1
    if buddy_named {
        datagram.extend_from_slice(&[0x02, 0x01, 0x00, 0xF8, 0x20, 0x00]); // TAG_BUDDYHASH
        datagram.extend_from_slice(&[b'C'; 32]);
    }
    datagram.extend_from_slice(&[0x02, 0x03, 0x00]);
    datagram.extend_from_slice(name);
    datagram.extend_from_slice(&[0x20, 0x00]);
    datagram.extend_from_slice(rmule_kad::ipv6_tags::encode_ipv6_hex(address).as_bytes());
    datagram
}

/// The publish reader gates `ip6` and `bi6` on `IsUsableTagIdentity`, exactly
/// as the source-result row reader does: only global unicast is stored. A
/// mapped or link-local claim leaves the field `None` rather than seeding the
/// index with an address that cannot be dialed or told apart from another
/// peer's.
#[test]
fn a_publish_admits_only_a_global_unicast_ipv6_claim() {
    let global: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let mapped: std::net::Ipv6Addr = "::ffff:1.2.3.4".parse().unwrap();
    let link_local: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let buddy_ipv6 = |source: &KadPublishedSource| source.buddy.and_then(|b| b.buddy_ipv6);

    let admitted = decode(&publish_source_req_with_ipv6_tag(b"ip6", global, false));
    let Ok(Kad2Message::PublishSourceReq { source, .. }) = admitted else {
        panic!("a well-formed publish decodes");
    };
    assert_eq!(source.ipv6, Some(global));

    // Unique-local, loopback and unspecified are refused alike.
    let unique_local: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    for refused in [
        mapped,
        link_local,
        unique_local,
        std::net::Ipv6Addr::LOCALHOST,
        std::net::Ipv6Addr::UNSPECIFIED,
    ] {
        let Ok(Kad2Message::PublishSourceReq { source, .. }) =
            decode(&publish_source_req_with_ipv6_tag(b"ip6", refused, false))
        else {
            panic!("a refused tag does not fail the message");
        };
        assert_eq!(
            source.ipv6, None,
            "{refused} is not a usable tag identity and must not be stored"
        );
        assert_eq!(
            source.source_type,
            Some(1),
            "the rest of the publish stands"
        );

        let Ok(Kad2Message::PublishSourceReq { source, .. }) =
            decode(&publish_source_req_with_ipv6_tag(b"bi6", refused, true))
        else {
            panic!("a refused buddy tag does not fail the message");
        };
        assert!(source.buddy.is_some(), "the buddy the hash named stands");
        assert_eq!(buddy_ipv6(&source), None, "the buddy claim is gated alike");
    }

    let Ok(Kad2Message::PublishSourceReq { source, .. }) =
        decode(&publish_source_req_with_ipv6_tag(b"bi6", global, true))
    else {
        panic!("a well-formed buddy publish decodes");
    };
    assert_eq!(buddy_ipv6(&source), Some(global));
}

/// `bi6` is the v6 half of a buddy contact, so a row that names no buddy —
/// no `TAG_BUDDYHASH`, nothing a callback could be verified against — drops
/// it with the rest of the contact, as the IPv4 half's `SERVERIP`/`SERVERPORT`
/// are dropped.
#[test]
fn a_bi6_with_no_buddy_named_is_dropped_with_the_contact() {
    let global: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let Ok(Kad2Message::PublishSourceReq { source, .. }) =
        decode(&publish_source_req_with_ipv6_tag(b"bi6", global, false))
    else {
        panic!("a well-formed publish decodes");
    };
    assert_eq!(source.buddy, None);
    assert_eq!(
        source.ipv6, None,
        "a bi6 is never read as the source's own ip6"
    );
}

#[test]
fn publish_source_req_rejects_truncation_and_tag_overrun() {
    // Truncated inside the source ID.
    let mut truncated = vec![0xE4, 0x44];
    truncated.extend_from_slice(&FILE_KEY);
    truncated.extend_from_slice(&SOURCE_ID[..8]);
    assert!(matches!(
        decode(&truncated),
        Err(Kad2MessageDecodeError::Malformed { opcode: 0x44, .. })
    ));

    // Tag count promises more tags than the payload carries.
    let mut overrun = vec![0xE4, 0x44];
    overrun.extend_from_slice(&FILE_KEY);
    overrun.extend_from_slice(&SOURCE_ID);
    overrun.push(2);
    overrun.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x01]);
    assert!(matches!(
        decode(&overrun),
        Err(Kad2MessageDecodeError::Malformed { opcode: 0x44, .. })
    ));
}

fn documented_publish_res() -> Vec<u8> {
    let mut datagram = vec![0xE4, 0x4B];
    datagram.extend_from_slice(&FILE_KEY);
    datagram.push(0x32); // load = 50
    datagram
}

#[test]
fn publish_res_round_trips_the_17_byte_documented_layout() {
    let message = Kad2Message::PublishRes {
        file: KadId::from_bytes(FILE_KEY),
        load: 0x32,
        options: 0,
    };
    // options == 0 emits no trailing byte: byte-identical to aMule 2.3.3.
    assert_eq!(message.encode().encode(), documented_publish_res());
    assert_eq!(decode(&documented_publish_res()), Ok(message));
}

#[test]
fn publish_res_captures_and_round_trips_the_future_use_options_byte() {
    // The trailing options byte (bit 0 requests the dormant 0x4C ACK under an
    // obfuscation key, ADR-0062) is surfaced, not dropped: decode captures
    // it and encode re-emits it, so a 0x4B carrying it round-trips.
    let mut datagram = documented_publish_res();
    datagram.push(0x01);
    let message = Kad2Message::PublishRes {
        file: KadId::from_bytes(FILE_KEY),
        load: 0x32,
        options: 0x01,
    };
    assert_eq!(decode(&datagram), Ok(message.clone()));
    assert_eq!(message.encode().encode(), datagram);
}

#[test]
fn search_source_req_decodes_and_masks_the_start_position_top_bit() {
    // `[target][start u16 LE][size u64 LE]`; receivers mask start & 0x7FFF.
    let mut datagram = vec![0xE4, 0x34];
    datagram.extend_from_slice(&FILE_KEY);
    datagram.extend_from_slice(&0x8001u16.to_le_bytes());
    datagram.extend_from_slice(&987_654u64.to_le_bytes());

    assert_eq!(
        decode(&datagram),
        Ok(Kad2Message::SearchSourceReq {
            target: KadId::from_bytes(FILE_KEY),
            start_position: 1,
            file_size: 987_654,
        })
    );
}

#[test]
fn search_source_req_rejects_trailing_bytes() {
    let mut datagram = vec![0xE4, 0x34];
    datagram.extend_from_slice(&FILE_KEY);
    datagram.extend_from_slice(&0u16.to_le_bytes());
    datagram.extend_from_slice(&987_654u64.to_le_bytes());
    datagram.push(0xEE);
    assert!(matches!(
        decode(&datagram),
        Err(Kad2MessageDecodeError::Malformed { opcode: 0x34, .. })
    ));
}

fn direct_row(last_ip_octet: u8) -> KadSourceRow {
    KadSourceRow {
        source_id: SOURCE_ID,
        source_type: 1,
        ip: Ipv4Addr::new(83, 44, 21, last_ip_octet),
        tcp_port: 4662,
        udp_port: 4672,
        encryption: Some(0x0B),
        buddy: None,
        ipv6: None,
    }
}

/// One documented `0x3B` row: `[source ID][tag count][tags]`, tags in the
/// stored-entry order (SOURCEIP, SOURCETYPE, SOURCEPORT, SOURCEUPORT,
/// ENCRYPTION), SOURCEIP as the host-order u32 of `a.b.c.d`.
fn documented_search_res_single_row() -> Vec<u8> {
    let mut datagram = vec![0xE4, 0x3B];
    datagram.extend_from_slice(&SENDER_ID);
    datagram.extend_from_slice(&FILE_KEY);
    datagram.extend_from_slice(&1u16.to_le_bytes());
    datagram.extend_from_slice(&SOURCE_ID);
    datagram.push(5);
    // TAG_SOURCEIP (0xFE) u32 = 83.44.21.9 host-order
    let host_order = u32::from_be_bytes([83, 44, 21, 9]);
    datagram.extend_from_slice(&[0x03, 0x01, 0x00, 0xFE]);
    datagram.extend_from_slice(&host_order.to_le_bytes());
    // TAG_SOURCETYPE (0xFF) u8 = 1
    datagram.extend_from_slice(&[0x09, 0x01, 0x00, 0xFF, 0x01]);
    // TAG_SOURCEPORT (0xFD) u16 = 4662
    datagram.extend_from_slice(&[0x08, 0x01, 0x00, 0xFD, 0x36, 0x12]);
    // TAG_SOURCEUPORT (0xFC) u16 = 4672
    datagram.extend_from_slice(&[0x08, 0x01, 0x00, 0xFC, 0x40, 0x12]);
    // TAG_ENCRYPTION (0xF3) u8 = 0x0B
    datagram.extend_from_slice(&[0x09, 0x01, 0x00, 0xF3, 0x0B]);
    datagram
}

#[test]
fn search_res_encoder_emits_the_documented_row_layout() {
    let batches = encode_source_result(
        KadId::from_bytes(SENDER_ID),
        KadId::from_bytes(FILE_KEY),
        &[direct_row(9)],
    );
    let encoded: Vec<Vec<u8>> = batches.iter().map(|e| e.encode()).collect();
    assert_eq!(encoded, vec![documented_search_res_single_row()]);
}

#[test]
fn search_res_encoder_round_trips_through_the_sealed_projection() {
    let batches = encode_source_result(
        KadId::from_bytes(SENDER_ID),
        KadId::from_bytes(FILE_KEY),
        &[direct_row(9)],
    );
    assert_eq!(batches.len(), 1);
    let candidates = decode_source_result(&batches[0]).expect("re-encoded rows must decode");
    let expected_client_id = ClientId::from_u32(u32::from_be_bytes([83, 44, 21, 9]).swap_bytes());
    // The sealed projection is the only constructor of a Direct candidate, so
    // the round-trip is observed through `peer_source()`, never rebuilt.
    let sources: Vec<_> = candidates
        .iter()
        .map(|candidate| candidate.peer_source())
        .collect();
    assert_eq!(
        sources,
        vec![Some(PeerSource::new(expected_client_id, 4662))]
    );
}

#[test]
fn search_res_encoder_batches_fifty_rows_per_datagram() {
    let rows: Vec<KadSourceRow> = (0..120)
        .map(|i| direct_row(u8::try_from(i % 200).unwrap()))
        .collect();
    let batches = encode_source_result(
        KadId::from_bytes(SENDER_ID),
        KadId::from_bytes(FILE_KEY),
        &rows,
    );
    assert_eq!(batches.len(), 3);

    let counts: Vec<usize> = batches
        .iter()
        .map(|envelope| decode_source_result(envelope).expect("batch decodes").len())
        .collect();
    assert_eq!(counts, vec![50, 50, 20]);
}

#[test]
fn search_res_encoder_emits_nothing_for_zero_rows() {
    let batches = encode_source_result(
        KadId::from_bytes(SENDER_ID),
        KadId::from_bytes(FILE_KEY),
        &[],
    );
    assert!(batches.is_empty());
}
