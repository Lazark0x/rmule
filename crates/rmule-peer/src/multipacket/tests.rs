//! Unit tests of the bundled file negotiation codec: request and answer walkers, error policy, and the hostile-size guards.

use super::*;
use rmule_primitives::{ED2K_PART_SIZE, PacketProtocol};

fn hash() -> FileHash {
    FileHash::from_bytes([0x11; FileHash::BYTE_LEN])
}

fn request_packet(opcode: PeerOpcode, payload: Vec<u8>) -> Packet {
    Packet::new(opcode.protocol(), opcode.as_u8(), payload)
}

#[test]
fn request_decodes_every_known_sub_item_in_order() {
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0x58); // Name
    payload.push(0x4F); // SetReqId
    payload.push(0x81); // Sources (v1)
    payload.push(0x83); // Sources2 (v2)
    payload.push(7); // version
    payload.extend_from_slice(&0x1234u16.to_le_bytes()); // options
    payload.push(0x9E); // AichRoot

    let packet = request_packet(PeerOpcode::MultiPacket, payload);
    let req =
        MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE).expect("full decode");
    assert_eq!(req.file_hash, hash());
    assert_eq!(req.file_size, None);
    assert_eq!(
        req.items,
        vec![
            RequestItem::Name { part_status: None },
            RequestItem::SetReqId,
            RequestItem::Sources,
            RequestItem::Sources2 {
                version: 7,
                options: 0x1234
            },
            RequestItem::AichRoot,
        ]
    );
    assert!(req.unknown_sub.is_none());
}

#[test]
fn ext_request_carries_file_size_and_reencodes_as_0xa4() {
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&123_456_789u64.to_le_bytes());
    payload.push(0x58);

    let packet = request_packet(PeerOpcode::MultiPacketExt, payload);
    let req =
        MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE).expect("ext decode");
    assert_eq!(req.file_size, Some(123_456_789));

    let reencoded = req.encode_packet();
    assert_eq!(reencoded.opcode(), 0xA4);
    assert_eq!(reencoded.protocol(), PacketProtocol::Emule);
}

#[test]
fn request_rejects_truncated_header() {
    let short_hash = vec![0u8; FileHash::BYTE_LEN - 1];
    let packet = request_packet(PeerOpcode::MultiPacket, short_hash);
    assert!(matches!(
        MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE),
        Err(MultiPacketDecodeError::Truncated { .. })
    ));
}

#[test]
fn ext_request_rejects_truncated_size_field() {
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&[0u8; 4]); // only 4 of the 8 size bytes
    let packet = request_packet(PeerOpcode::MultiPacketExt, payload);
    assert!(matches!(
        MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE),
        Err(MultiPacketDecodeError::Truncated { .. })
    ));
}

#[test]
fn request_reports_a_sub_cut_short_instead_of_failing_the_packet() {
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&[0x4F, 0x83, 1]); // version only, no u16 options
    let packet = request_packet(PeerOpcode::MultiPacket, payload);
    let req = MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE).unwrap();
    assert_eq!(req.items, vec![RequestItem::SetReqId]);
    assert_eq!(req.cut, Some(BundleCut::Sources2));
}

/// An `OP_MULTIPACKET_EXT` name sub's status is read by the size the
/// frame carries, as aMule's `ProcessExtendedInfo` reads it by the file
/// (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:414-446`): a count that is
/// not that size's clears the status after its two bytes and the walk
/// carries on from there — the bundle is not failed for the bitmap its
/// wire count would have needed.
#[test]
fn an_ext_bundles_name_status_is_read_by_the_size_it_carries() {
    let bundle = |sub: &[u8]| {
        let mut payload = hash().as_bytes().to_vec();
        payload.extend_from_slice(&4096u64.to_le_bytes()); // one part, count 1
        payload.extend_from_slice(sub);
        let packet = request_packet(PeerOpcode::MultiPacketExt, payload);
        MultiPacketRequest::decode_packet(&packet, ExtendedRequests::negotiated(1, 2)).unwrap()
    };
    // Count 32 wants four bitmap bytes by the wire; by the file it is
    // simply the wrong count, cleared, and `0x4F` is the next sub.
    let cleared = bundle(&[0x58, 0x20, 0x00, 0x4F]);
    assert_eq!(
        cleared.items,
        vec![
            RequestItem::Name { part_status: None },
            RequestItem::SetReqId
        ]
    );
    assert_eq!(cleared.cut, None);
    // The file's own count reads one bitmap byte and the walk goes on.
    let read = bundle(&[0x58, 0x01, 0x00, 0x01, 0x4F]);
    assert_eq!(
        read.items,
        vec![
            RequestItem::Name {
                part_status: Some(PartBitmap::decode(1, &[0x01]).unwrap())
            },
            RequestItem::SetReqId
        ]
    );
    // The file's count with its bitmap missing is cut, nothing read.
    assert_eq!(
        bundle(&[0x58, 0x01, 0x00]).cut,
        Some(BundleCut::NameStatus(Some(
            PartBitmap::decode(1, &[0x00]).unwrap()
        )))
    );
}

#[test]
fn request_stops_at_unknown_sub_and_reports_it() {
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0x58); // Name — parsed
    payload.push(0x4F); // SetReqId — parsed
    payload.push(0xFF); // unknown
    payload.extend_from_slice(&[0xAA, 0xBB]); // unparseable tail

    let packet = request_packet(PeerOpcode::MultiPacket, payload);
    let req =
        MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE).expect("stays open");
    assert_eq!(
        req.items,
        vec![
            RequestItem::Name { part_status: None },
            RequestItem::SetReqId
        ]
    );
    assert_eq!(
        req.unknown_sub,
        Some(UnknownSub {
            opcode: 0xFF,
            remaining: 2
        })
    );
}

#[test]
fn request_unknown_sub_as_final_byte_reports_zero_remaining() {
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0xFF);
    let packet = request_packet(PeerOpcode::MultiPacket, payload);
    let req =
        MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE).expect("stays open");
    assert!(req.items.is_empty());
    assert_eq!(
        req.unknown_sub,
        Some(UnknownSub {
            opcode: 0xFF,
            remaining: 0
        })
    );
}

#[test]
fn request_round_trips_through_encode_and_decode() {
    let req = MultiPacketRequest {
        file_hash: hash(),
        file_size: None,
        items: vec![
            RequestItem::Name { part_status: None },
            RequestItem::Sources2 {
                version: 1,
                options: 0,
            },
            RequestItem::AichRoot,
        ],
        unknown_sub: None,
        cut: None,
    };
    let decoded =
        MultiPacketRequest::decode_packet(&req.encode_packet(), ExtendedRequests::NONE).unwrap();
    assert_eq!(decoded, req);
}

fn answer_packet(payload: Vec<u8>) -> Packet {
    Packet::new(
        PeerOpcode::MultiPacketAnswer.protocol(),
        PeerOpcode::MultiPacketAnswer.as_u8(),
        payload,
    )
}

#[test]
fn answer_decodes_every_known_sub_item_in_order() {
    let name = b"movie.avi";
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0x59);
    payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
    payload.extend_from_slice(name);
    payload.push(0x50);
    payload.extend_from_slice(&10u16.to_le_bytes());
    payload.extend_from_slice(&[0b1010_1010, 0b0000_0011]);
    payload.push(0x9D);
    payload.extend_from_slice(&[0x22; AichRootHash::BYTE_LEN]);

    let ans = MultiPacketAnswer::decode_packet(&answer_packet(payload)).expect("full decode");
    assert_eq!(ans.file_hash, hash());
    assert_eq!(
        ans.items,
        vec![
            AnswerItem::Name(Ed2kText::from_bytes(name.to_vec())),
            AnswerItem::Status(PartBitmap::decode(10, &[0b1010_1010, 0b0000_0011]).unwrap()),
            AnswerItem::AichRoot(AichRootHash::from_bytes([0x22; AichRootHash::BYTE_LEN])),
        ]
    );
    assert!(ans.unknown_sub.is_none());
}

#[test]
fn answer_rejects_truncated_header() {
    let packet = answer_packet(vec![0u8; FileHash::BYTE_LEN - 1]);
    assert!(matches!(
        MultiPacketAnswer::decode_packet(&packet),
        Err(MultiPacketDecodeError::Truncated { .. })
    ));
}

#[test]
fn answer_rejects_truncated_name_length_prefix() {
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0x59);
    payload.push(0x00); // only one length byte
    assert!(matches!(
        MultiPacketAnswer::decode_packet(&answer_packet(payload)),
        Err(MultiPacketDecodeError::Truncated { .. })
    ));
}

#[test]
fn answer_rejects_name_length_overrun() {
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0x59);
    payload.extend_from_slice(&100u16.to_le_bytes());
    payload.extend_from_slice(b"only-3");
    assert!(matches!(
        MultiPacketAnswer::decode_packet(&answer_packet(payload)),
        Err(MultiPacketDecodeError::Truncated { .. })
    ));
}

#[test]
fn answer_rejects_truncated_status_bitmap() {
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0x50);
    payload.extend_from_slice(&10u16.to_le_bytes()); // needs 2 bitmap bytes
    payload.push(0xFF); // only 1 given
    assert!(matches!(
        MultiPacketAnswer::decode_packet(&answer_packet(payload)),
        Err(MultiPacketDecodeError::Truncated { .. })
    ));
}

#[test]
fn answer_stops_at_unknown_sub_and_reports_it() {
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0x59);
    payload.extend_from_slice(&0u16.to_le_bytes()); // empty name, parsed
    payload.push(0xEE); // unknown
    payload.push(0xCC); // unparseable tail

    let ans = MultiPacketAnswer::decode_packet(&answer_packet(payload)).expect("stays open");
    assert_eq!(
        ans.items,
        vec![AnswerItem::Name(Ed2kText::from_bytes(vec![]))]
    );
    assert_eq!(
        ans.unknown_sub,
        Some(UnknownSub {
            opcode: 0xEE,
            remaining: 1
        })
    );
}

#[test]
fn answer_round_trips_through_encode_and_decode() {
    let ans = MultiPacketAnswer {
        file_hash: hash(),
        items: vec![
            AnswerItem::Name(Ed2kText::from_utf8("clip.mkv")),
            AnswerItem::Status(PartBitmap::decode(3, &[0b0000_0101]).unwrap()),
            AnswerItem::AichRoot(AichRootHash::from_bytes([0x33; AichRootHash::BYTE_LEN])),
        ],
        unknown_sub: None,
    };
    let decoded = MultiPacketAnswer::decode_packet(&ans.encode_packet()).unwrap();
    assert_eq!(decoded, ans);
}

/// The quickest of `runs` calls: the minimum, so a scheduler hiccup on a
/// loaded machine cannot fail a bound the work itself is far inside.
fn fastest(runs: usize, mut work: impl FnMut()) -> std::time::Duration {
    (0..runs)
        .map(|_| {
            let started = std::time::Instant::now();
            work();
            started.elapsed()
        })
        .min()
        .expect("at least one run")
}

/// An `OP_MULTIPACKET_EXT` size is the peer's
/// claim, and it sized a bitmap before any gate. `u64::MAX / 2` cost about
/// 1.35 s of release CPU and half a GiB per `0x58` sub, every sub again.
#[test]
fn a_hostile_ext_size_is_refused_before_any_status_read() {
    let hostile = u64::MAX / 2;
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&hostile.to_le_bytes());
    for _ in 0..3 {
        payload.extend_from_slice(&[0x58, 0x01, 0x00]);
    }
    let packet = request_packet(PeerOpcode::MultiPacketExt, payload);
    let mut result = None;
    let took = fastest(5, || {
        result = Some(MultiPacketRequest::decode_packet(
            &packet,
            ExtendedRequests::negotiated(1, 2),
        ));
    });
    assert_eq!(
        result.expect("ran"),
        Err(MultiPacketDecodeError::FileSizeOutOfRange { size: hostile })
    );
    assert!(took < std::time::Duration::from_millis(1), "took {took:?}");

    // The ceiling itself names a file and is walked.
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&MAX_ED2K_FILE_SIZE.to_le_bytes());
    payload.extend_from_slice(&[0x58, 0x01, 0x00, 0x4F]);
    let packet = request_packet(PeerOpcode::MultiPacketExt, payload);
    let walked = MultiPacketRequest::decode_packet(&packet, ExtendedRequests::negotiated(1, 2))
        .expect("a 256 GiB file is an eD2k file");
    assert_eq!(
        walked.items,
        vec![
            RequestItem::Name { part_status: None },
            RequestItem::SetReqId
        ]
    );
}

/// The count check itself allocates nothing, whatever size it is handed:
/// a mismatch is `Cleared` after its two bytes, at the same cost for
/// `u64::MAX` as for one part.
#[test]
fn a_status_count_is_checked_against_any_size_without_a_bitmap() {
    let mut outcome = None;
    let took = fastest(5, || {
        outcome = Some(read_file_sized_status(&[0x01, 0x00, 0xFF], u64::MAX));
    });
    assert_eq!(outcome, Some(FileSizedStatus::Cleared));
    assert!(took < std::time::Duration::from_millis(1), "took {took:?}");

    // Same verdict as the bitmap's own count, `size / PARTSIZE + 1`.
    for size in [1, ED2K_PART_SIZE, ED2K_PART_SIZE + 1, 5 << 30] {
        let own = PartBitmap::downloader_empty(size).part_count();
        let count = u16::try_from(own).expect("small file").to_le_bytes();
        let bitmap = vec![0u8; usize::from(u16::from_le_bytes(count)).div_ceil(8)];
        let tail = [count.as_slice(), &bitmap].concat();
        assert!(
            matches!(
                read_file_sized_status(&tail, size),
                FileSizedStatus::Read { .. }
            ),
            "size {size}: the file's own count reads"
        );
    }
}
