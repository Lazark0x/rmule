//! Codec golden vectors: each frame's shape across the UDP versions that
//! decide its optional fields, the header and trailing-byte refusals, and the
//! callback frames that share the reask header.

use super::*;

fn hash() -> FileHash {
    FileHash::from_bytes([0xAB; FileHash::BYTE_LEN])
}

/// A complete two-part file's `WritePartStatus`: count 2, one all-present
/// byte (`0b0000_0011`).
fn full_two_parts() -> PartBitmap {
    PartBitmap::decode(2, &[0b0000_0011]).unwrap()
}

#[test]
fn reask_ping_golden_bytes_across_udp_versions() {
    // v4 (> 3): hash + WritePartStatus + complete-source count.
    let v4 = ReaskFilePing {
        file_hash: hash(),
        part_status: Some(full_two_parts()),
        complete_sources: Some(5),
    };
    let mut expected = vec![0xC5, 0x90];
    expected.extend_from_slice(&[0xAB; 16]);
    expected.extend_from_slice(&[0x02, 0x00, 0x03]); // <count=2><status 0x03>
    expected.extend_from_slice(&[0x05, 0x00]); // complete sources
    assert_eq!(v4.encode_udp(), expected);
    assert_eq!(ReaskFilePing::decode_udp(&expected, 4), Ok(v4));

    // v3 (> 2, not > 3): hash + complete-source count only.
    let v3 = ReaskFilePing {
        file_hash: hash(),
        part_status: None,
        complete_sources: Some(5),
    };
    let mut expected = vec![0xC5, 0x90];
    expected.extend_from_slice(&[0xAB; 16]);
    expected.extend_from_slice(&[0x05, 0x00]);
    assert_eq!(v3.encode_udp(), expected);
    assert_eq!(ReaskFilePing::decode_udp(&expected, 3), Ok(v3));

    // v2 (not > 2): the bare hash.
    let v2 = ReaskFilePing {
        file_hash: hash(),
        part_status: None,
        complete_sources: None,
    };
    let mut expected = vec![0xC5, 0x90];
    expected.extend_from_slice(&[0xAB; 16]);
    assert_eq!(v2.encode_udp(), expected);
    assert_eq!(ReaskFilePing::decode_udp(&expected, 2), Ok(v2));
}

#[test]
fn reask_ping_large_file_golden_spans_a_multi_byte_part_status() {
    // The "large form": a file whose part count needs a multi-byte
    // `WritePartStatus` bitfield, proving the 0x90 body carries the full
    // `ceil(parts/8)`-byte status verbatim (aMule `CPartFile::WritePartStatus`
    // loops the whole part count) — the two-part golden above only exercises
    // a single status byte. Twenty parts: 0–15 present (two 0xFF bytes),
    // 16–19 missing (a trailing 0x00 byte the ceil rounding still emits), and
    // a complete-source count large enough to prove its LE u16 (258 = 0x0102).
    let status = PartBitmap::decode(20, &[0xFF, 0xFF, 0x00]).unwrap();
    let large = ReaskFilePing {
        file_hash: hash(),
        part_status: Some(status),
        complete_sources: Some(258),
    };
    let mut expected = vec![0xC5, 0x90];
    expected.extend_from_slice(&[0xAB; 16]);
    expected.extend_from_slice(&[0x14, 0x00]); // <part count = 20>
    expected.extend_from_slice(&[0xFF, 0xFF, 0x00]); // ceil(20/8) = 3 status bytes
    expected.extend_from_slice(&[0x02, 0x01]); // <complete sources = 258>
    assert_eq!(large.encode_udp(), expected);
    assert_eq!(ReaskFilePing::decode_udp(&expected, 4), Ok(large));
}

#[test]
fn reask_ack_golden_bytes_gate_part_status_on_the_waiters_version() {
    // Waiter UDP v4: our part status rides ahead of the rank.
    let v4 = ReaskAck {
        part_status: Some(full_two_parts()),
        rank: 7,
    };
    let expected = vec![0xC5, 0x91, 0x02, 0x00, 0x03, 0x07, 0x00];
    assert_eq!(v4.encode_udp(), expected);
    assert_eq!(ReaskAck::decode_udp(&expected, 4), Ok(v4));

    // Waiter UDP v3: rank only.
    let v3 = ReaskAck {
        part_status: None,
        rank: 7,
    };
    let expected = vec![0xC5, 0x91, 0x07, 0x00];
    assert_eq!(v3.encode_udp(), expected);
    assert_eq!(ReaskAck::decode_udp(&expected, 3), Ok(v3));
}

#[test]
fn empty_body_replies_are_two_byte_datagrams() {
    assert_eq!(file_not_found_datagram(), vec![0xC5, 0x92]);
    assert_eq!(queue_full_datagram(), vec![0xC5, 0x93]);
}

#[test]
fn decode_rejects_wrong_frame_and_trailing_bytes() {
    let ping = ReaskFilePing {
        file_hash: hash(),
        part_status: None,
        complete_sources: None,
    };
    // Wrong protocol byte (a server-UDP `0xE3`, never on this socket).
    let mut wrong_proto = ping.encode_udp();
    wrong_proto[0] = 0xE3;
    assert_eq!(
        ReaskFilePing::decode_udp(&wrong_proto, 2),
        Err(ReaskDecodeError::WrongProtocol { protocol: 0xE3 }),
    );
    // Wrong opcode.
    assert_eq!(
        ReaskAck::decode_udp(&ping.encode_udp(), 2),
        Err(ReaskDecodeError::WrongOpcode { opcode: 0x90 }),
    );
    // Trailing bytes past the declared body (a v2 ping with junk appended).
    let mut trailing = ping.encode_udp();
    trailing.push(0xFF);
    assert_eq!(
        ReaskFilePing::decode_udp(&trailing, 2),
        Err(ReaskDecodeError::TrailingBytes { trailing: 1 }),
    );
}

#[test]
fn direct_callback_req_golden_bytes_and_round_trip() {
    // ADR-0061 route 2 emit: `[0xC5][0x95]<our TCP port LE><our user hash
    // 16><connect options>`. 0x4CE2 = 19_682, our advertised TCP port;
    // connect options 0x03 = supports+requests crypt (bits 0,1).
    let req = DirectCallbackReq {
        our_tcp_port: 0x4CE2,
        our_user_hash: UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
        connect_options: 0x03,
    };
    let mut expected = vec![0xC5, 0x95, 0xE2, 0x4C];
    expected.extend_from_slice(&[0x5A; 16]);
    expected.push(0x03);
    assert_eq!(req.encode_udp(), expected);
    assert_eq!(DirectCallbackReq::decode_udp(&expected), Ok(req));
    // The body is fixed-width — 2 + 16 + 1 = 19 bytes under the 2-byte
    // header — so a short datagram is truncated, not silently accepted.
    assert_eq!(
        DirectCallbackReq::decode_udp(&expected[..expected.len() - 1]),
        Err(ReaskDecodeError::Truncated {
            needed: 19,
            actual: 18
        }),
    );
    // Trailing bytes past the fixed body are rejected (an over-long junk
    // datagram is not a callback request).
    let mut trailing = expected.clone();
    trailing.push(0xFF);
    assert_eq!(
        DirectCallbackReq::decode_udp(&trailing),
        Err(ReaskDecodeError::TrailingBytes { trailing: 1 }),
    );
    // A reask opcode is not a direct-callback request.
    assert_eq!(
        DirectCallbackReq::decode_udp(&queue_full_datagram()),
        Err(ReaskDecodeError::WrongOpcode { opcode: 0x93 }),
    );
}

#[test]
fn reask_callback_udp_splits_the_verified_buddy_id_from_the_forwarded_tail() {
    // The 0x94 relay input: `[0xC5][0x94]<buddyID 16><forwarded…>`. The
    // leading 16 bytes are the buddy-ID the open node verifies against its
    // registered buddy; the rest is forwarded opaquely to the firewalled
    // client (aMule's `packet + 16, size - 16`).
    let msg = ReaskCallbackUdp {
        buddy_id: [0x7A; BUDDY_ID_LEN],
        forwarded: vec![0x01, 0x02, 0x03, 0x04],
    };
    let mut expected = vec![0xC5, 0x94];
    expected.extend_from_slice(&[0x7A; 16]);
    expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(msg.encode_udp(), expected);
    assert_eq!(ReaskCallbackUdp::decode_udp(&expected), Ok(msg));

    // An exactly-16-byte body is a valid relay with an empty forwarded tail.
    assert_eq!(
        ReaskCallbackUdp::decode_udp(&[vec![0xC5, 0x94], vec![0x11; 16]].concat()),
        Ok(ReaskCallbackUdp {
            buddy_id: [0x11; 16],
            forwarded: Vec::new(),
        })
    );
    // A body shorter than the 16-byte buddy-ID is truncated, never a partial id.
    assert_eq!(
        ReaskCallbackUdp::decode_udp(&[vec![0xC5, 0x94], vec![0x00; 15]].concat()),
        Err(ReaskDecodeError::Truncated {
            needed: 16,
            actual: 15
        }),
    );
    // A different opcode is not a reask-callback.
    assert_eq!(
        ReaskCallbackUdp::decode_udp(&queue_full_datagram()),
        Err(ReaskDecodeError::WrongOpcode { opcode: 0x93 }),
    );
}

#[test]
fn opcode_round_trips_including_the_callback_seams() {
    for (byte, opcode) in [
        (0x90, ClientUdpOpcode::ReaskFilePing),
        (0x91, ClientUdpOpcode::ReaskAck),
        (0x92, ClientUdpOpcode::FileNotFound),
        (0x93, ClientUdpOpcode::QueueFull),
        (0x94, ClientUdpOpcode::ReaskCallbackUdp),
        (0x95, ClientUdpOpcode::DirectCallbackReq),
    ] {
        assert_eq!(ClientUdpOpcode::try_from_u8(byte), Some(opcode));
        assert_eq!(opcode.as_u8(), byte);
    }
    assert_eq!(ClientUdpOpcode::try_from_u8(0x60), None);
}
