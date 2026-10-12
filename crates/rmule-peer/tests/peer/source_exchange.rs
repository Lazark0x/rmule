//! Source-exchange packet codec — SX1 (`0x81`/`0x82`, ADR-0055) and SX2
//! (`0x83`/`0x84`, ADR-0055), all under `OP_EMULEPROT`. Opcodes and wire
//! shapes per amule `4e8f2b3c`.

use rmule_peer::{
    AnswerSources, AnswerSources2, RequestSources2, RequestSourcesPacket, SourceExchangeEntry,
    SourceExchangeVersion,
};
use rmule_primitives::{
    ClientId, CryptStance, FileHash, OutboundCrypt, Packet, PacketProtocol, PeerSource,
    SourceCryptOptions, SourceSighting, UserHash,
};

/// Our own stance for these codec tests: supports and requests obfuscation
/// (the "someone has to ask" half of `PeerCrypt::outbound`), so the
/// assertions turn on the decoded peer's crypt side alone.
const OURS: CryptStance = CryptStance::new(true, true, false);

/// Build an `OP_ANSWERSOURCES` v1 payload: `[hash][count]` then per source
/// `[id u32][tcp u16][server ip u32][server port u16]` (server fields zeroed).
fn answer_sources_payload(fh: FileHash, sources: &[(u32, u16)]) -> Vec<u8> {
    let mut p = fh.as_bytes().to_vec();
    p.extend_from_slice(&(sources.len() as u16).to_le_bytes());
    for &(id, tcp) in sources {
        p.extend_from_slice(&id.to_le_bytes());
        p.extend_from_slice(&tcp.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes()); // server ip (ignored)
        p.extend_from_slice(&0u16.to_le_bytes()); // server port (ignored)
    }
    p
}

/// A single wider source-exchange source: the v1 quintet, then (v≥2) the target
/// `user_hash`, then (if `crypt` is `Some`) the v4 crypt-options byte. Stride is
/// 12 (v1), 28 (v2/3), or 29 (v4) depending on which tails are present. `id` is
/// whatever raw 4 bytes should land on the wire — callers wanting v3+ hybrid
/// order pass an already-swapped value (e.g. `ed2k_id.swap_bytes()`).
fn wide_source(p: &mut Vec<u8>, id: u32, tcp: u16, user_hash: Option<[u8; 16]>, crypt: Option<u8>) {
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(&tcp.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes()); // server ip (ignored)
    p.extend_from_slice(&0u16.to_le_bytes()); // server port (ignored)
    if let Some(hash) = user_hash {
        p.extend_from_slice(&hash);
    }
    if let Some(byte) = crypt {
        p.push(byte);
    }
}

fn answer_header(fh: FileHash, count: u16) -> Vec<u8> {
    let mut p = fh.as_bytes().to_vec();
    p.extend_from_slice(&count.to_le_bytes());
    p
}

#[test]
fn request_sources_encodes_op_requestsources() {
    let fh = FileHash::from_bytes([0x33; 16]);
    let packet = RequestSourcesPacket { file_hash: fh }.encode_packet();
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0x81);
    assert_eq!(packet.payload(), fh.as_bytes());
}

#[test]
fn answer_sources_decodes_v1_sources_keeping_id_and_tcp_port() {
    let fh = FileHash::from_bytes([0x44; 16]);
    let id = u32::from_le_bytes([1, 2, 3, 4]); // High-ID (IP 1.2.3.4)
    let packet = Packet::new(
        PacketProtocol::Emule,
        0x82,
        answer_sources_payload(fh, &[(id, 4662), (0x7F00_0001, 1234)]),
    );
    let ans = AnswerSources::decode_packet(&packet, 1).expect("answer decodes");
    assert_eq!(ans.file_hash, fh);
    assert_eq!(ans.sources.len(), 2);
    assert_eq!(ans.sources[0].client_id(), Some(ClientId::from_u32(id)));
    assert_eq!(ans.sources[0].tcp_port(), 4662);
    assert!(
        ans.sources[0].as_peer_endpoint().is_some(),
        "1.2.3.4 is High-ID and projects to a PeerEndpoint"
    );
}

#[test]
fn answer_sources_tolerates_zero_count() {
    let fh = FileHash::from_bytes([0x55; 16]);
    let packet = Packet::new(PacketProtocol::Emule, 0x82, answer_sources_payload(fh, &[]));
    let ans = AnswerSources::decode_packet(&packet, 1).expect("zero-count decodes");
    assert!(ans.sources.is_empty());
    assert_eq!(ans.file_hash, fh);
}

#[test]
fn answer_sources_zero_count_rejected_when_advertised_version_is_not_one() {
    // aMule's if/else-if chain resolves count=0 through the *first* (v1) arm
    // unconditionally (every stride's `count * stride == body` equation is
    // `0 == 0`), so an empty answer only decodes when the cross-check version
    // is exactly 1 — never inferred as "any version, since there's nothing to
    // disagree about."
    let fh = FileHash::from_bytes([0x58; 16]);
    let packet = Packet::new(PacketProtocol::Emule, 0x82, answer_sources_payload(fh, &[]));
    assert!(AnswerSources::decode_packet(&packet, 2).is_err());
}

#[test]
fn answer_sources_rejects_truncated_source_list() {
    let fh = FileHash::from_bytes([0x66; 16]);
    let mut payload = fh.as_bytes().to_vec();
    payload.extend_from_slice(&3u16.to_le_bytes()); // claims 3 sources, provides none
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);
    assert!(AnswerSources::decode_packet(&packet, 1).is_err());
}

#[test]
fn answer_sources_v4_decodes_user_hash_and_crypt_options() {
    // Exchange version 4: 29-byte stride adds a 16-byte User Hash (v≥2) and a
    // crypt-options byte (v4). Pinned from aMule `CPartFile::AddClientSources`
    // @4e8f2b3c; [pending] until a capture confirms it. v4 also implies
    // hybrid id order for a HighID, so the wire carries `id.swap_bytes()`.
    let fh = FileHash::from_bytes([0x44; 16]);
    let id = u32::from_le_bytes([1, 2, 3, 4]); // High-ID 1.2.3.4, ed2k order
    let hash = [0xAB; 16];
    let crypt = 0b0000_0101; // supports (bit 0) + requires (bit 2), not requests
    let mut payload = answer_header(fh, 1);
    wide_source(&mut payload, id.swap_bytes(), 4662, Some(hash), Some(crypt));
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);

    let ans = AnswerSources::decode_packet(&packet, 4).expect("v4 answer decodes");
    assert_eq!(ans.sources.len(), 1);
    let src = ans.sources[0];
    assert_eq!(src.client_id(), Some(ClientId::from_u32(id)));
    assert_eq!(src.tcp_port(), 4662);
    assert_eq!(src.user_hash(), Some(UserHash::from_bytes(hash)));
    let opts = src
        .crypt_options()
        .expect("v4 carries a crypt-options byte");
    assert!(opts.supports_crypt(), "bit 0 set");
    assert!(!opts.requests_crypt(), "bit 1 clear");
    assert!(opts.requires_crypt(), "bit 2 set");
    // Hash present + crypt supported, and our side asks for it ⇒
    // obfuscate-dialable — but not required: the raw requires bit reads
    // true, yet `PeerCrypt`'s ladder darkens it because the requests bit
    // beneath it is clear (mirroring aMule's own getter chain).
    assert_eq!(
        src.peer_crypt().outbound(OURS),
        OutboundCrypt::Obfuscated {
            toward: UserHash::from_bytes(hash),
        }
    );
}

#[test]
fn answer_sources_v4_geometry_rejects_non_exact_advertised_version() {
    // aMule requires `uClientSXVersion == 4` exactly for the 29-byte stride —
    // not `>= 4` the way the 28-byte stride accepts anything `> 2`.
    let fh = FileHash::from_bytes([0x57; 16]);
    let mut payload = answer_header(fh, 1);
    wide_source(&mut payload, 0x0102_0304, 4000, Some([0; 16]), Some(0b001));
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);

    assert!(AnswerSources::decode_packet(&packet, 3).is_err());
    assert!(AnswerSources::decode_packet(&packet, 5).is_err());
}

#[test]
fn answer_sources_v2_decodes_user_hash_without_crypt_options() {
    // Exchange version 2: 28-byte stride adds the User Hash but no crypt byte,
    // so there is no crypt hint — the source is not obfuscate-dialable.
    let fh = FileHash::from_bytes([0x45; 16]);
    let id = u32::from_le_bytes([5, 6, 7, 8]);
    let hash = [0xCD; 16];
    let mut payload = answer_header(fh, 1);
    wide_source(&mut payload, id, 5000, Some(hash), None);
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);

    let ans = AnswerSources::decode_packet(&packet, 2).expect("v2 answer decodes");
    let src = ans.sources[0];
    assert_eq!(
        src.client_id(),
        Some(ClientId::from_u32(id)),
        "v2 does not byte-swap the id"
    );
    assert_eq!(src.user_hash(), Some(UserHash::from_bytes(hash)));
    assert_eq!(src.crypt_options(), None);
    assert_eq!(
        src.peer_crypt().outbound(OURS),
        OutboundCrypt::Plaintext,
        "no crypt-options byte ⇒ no crypt hint ⇒ plaintext dial"
    );
}

#[test]
fn answer_sources_same_bytes_decode_differently_at_v2_vs_v3() {
    // v2 and v3 share the 28-byte stride and differ *only* in id byte order.
    // The same raw wire bytes must decode to different client ids depending
    // purely on the cross-check version — and aMule's `else if (>2)` resolves
    // v3 for *any* advertised version above 2, not just exactly 3.
    let fh = FileHash::from_bytes([0x55; 16]);
    let raw_id = u32::from_le_bytes([9, 8, 7, 6]); // arbitrary High-ID
    let mut payload = answer_header(fh, 1);
    wide_source(&mut payload, raw_id, 4000, Some([0; 16]), None);
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);

    let as_v2 = AnswerSources::decode_packet(&packet, 2).expect("resolves v2");
    assert_eq!(
        as_v2.sources[0].client_id(),
        Some(ClientId::from_u32(raw_id)),
        "v2 does not swap"
    );

    let as_v3 = AnswerSources::decode_packet(&packet, 3).expect("resolves v3");
    assert_eq!(
        as_v3.sources[0].client_id(),
        Some(ClientId::from_u32(raw_id.swap_bytes())),
        "v3 swaps the same raw bytes"
    );

    let as_v3_via_higher_advert = AnswerSources::decode_packet(&packet, 4)
        .expect("advertised_version > 2 also resolves v3, not just == 3");
    assert_eq!(
        as_v3_via_higher_advert.sources[0].client_id(),
        as_v3.sources[0].client_id()
    );
}

#[test]
fn answer_sources_stride28_rejected_when_advertised_version_below_two() {
    let fh = FileHash::from_bytes([0x56; 16]);
    let mut payload = answer_header(fh, 1);
    wide_source(&mut payload, 0x0102_0304, 4000, Some([0; 16]), None);
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);

    assert!(AnswerSources::decode_packet(&packet, 0).is_err());
    assert!(AnswerSources::decode_packet(&packet, 1).is_err());
}

#[test]
fn answer_sources_v3_decode_swaps_high_id_from_hybrid_wire_order() {
    // A real v3 sender puts a HighID's bytes on the wire in hybrid (network)
    // order; decode must swap them back to ed2k order.
    let fh = FileHash::from_bytes([0x53; 16]);
    let ed2k_id = u32::from_le_bytes([1, 2, 3, 4]); // HighID 1.2.3.4, ed2k order
    let wire_id = ed2k_id.swap_bytes(); // hybrid order, as landed on the wire
    let mut payload = answer_header(fh, 1);
    wide_source(&mut payload, wire_id, 4662, Some([0; 16]), None);
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);

    let ans = AnswerSources::decode_packet(&packet, 3).expect("v3 answer decodes");
    assert_eq!(
        ans.sources[0].client_id(),
        Some(ClientId::from_u32(ed2k_id))
    );
}

#[test]
fn answer_sources_v3_decode_does_not_swap_low_id() {
    // A LowID is a small server-assigned integer, not an IP — its magnitude
    // must survive v3 decode unchanged, or it would be corrupted into a
    // bogus HighID.
    let fh = FileHash::from_bytes([0x54; 16]);
    let mut payload = answer_header(fh, 1);
    wide_source(&mut payload, 5000, 4662, Some([0; 16]), None);
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);

    let ans = AnswerSources::decode_packet(&packet, 3).expect("v3 answer decodes");
    assert_eq!(ans.sources[0].client_id(), Some(ClientId::from_u32(5000)));
}

#[test]
fn answer_sources_v4_without_crypt_support_is_not_obfuscation_dialable() {
    // A v4 source whose crypt-options byte does not set bit 0 (supports) is
    // dialed plaintext even though it carries a User Hash.
    let fh = FileHash::from_bytes([0x46; 16]);
    let id = u32::from_le_bytes([9, 10, 11, 12]); // High-ID, ed2k order
    let mut payload = answer_header(fh, 1);
    wide_source(
        &mut payload,
        id.swap_bytes(),
        5001,
        Some([0xEE; 16]),
        Some(0b0000_0000),
    );
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);

    let src = AnswerSources::decode_packet(&packet, 4)
        .expect("decodes")
        .sources[0];
    assert_eq!(src.client_id(), Some(ClientId::from_u32(id)));
    assert!(src.user_hash().is_some());
    assert_eq!(src.peer_crypt().outbound(OURS), OutboundCrypt::Plaintext);
}

#[test]
fn answer_sources_v1_source_carries_no_crypt_material() {
    // Backward compatible: a v1 (12-byte stride) answer still decodes, yielding
    // a plaintext-only candidate with neither a User Hash nor crypt options.
    let fh = FileHash::from_bytes([0x47; 16]);
    let packet = Packet::new(
        PacketProtocol::Emule,
        0x82,
        answer_sources_payload(fh, &[(0x0100_0010, 4662)]),
    );
    let src = AnswerSources::decode_packet(&packet, 1)
        .expect("v1 answer decodes")
        .sources[0];
    assert_eq!(src.user_hash(), None);
    assert_eq!(src.crypt_options(), None);
    assert_eq!(src.peer_crypt().outbound(OURS), OutboundCrypt::Plaintext);
}

#[test]
fn answer_sources_rejects_trailing_bytes() {
    // aMule's `AddClientSources` requires the payload to be exactly
    // `count * stride + header`; a stray trailing byte is malformed (and would
    // signal a version mismatch) regardless of the cross-check version.
    let fh = FileHash::from_bytes([0x77; 16]);
    let mut payload = answer_sources_payload(fh, &[(0x0100_0010, 4662)]);
    payload.push(0xAB);
    let packet = Packet::new(PacketProtocol::Emule, 0x82, payload);
    assert!(AnswerSources::decode_packet(&packet, 1).is_err());
}

#[test]
fn answer_sources_encode_v3_swaps_high_id_on_the_wire() {
    let fh = FileHash::from_bytes([0x51; 16]);
    let id = u32::from_le_bytes([1, 2, 3, 4]); // HighID 1.2.3.4
    let source = SourceSighting::plain(PeerSource::new(ClientId::from_u32(id), 4662));
    let answer = AnswerSources {
        file_hash: fh,
        sources: vec![SourceExchangeEntry::plain(source)],
    };
    let packet = answer.encode_packet(SourceExchangeVersion::V3);
    let payload = packet.payload();
    let id_bytes: [u8; 4] = payload[18..22].try_into().expect("4 id bytes");
    assert_eq!(
        u32::from_le_bytes(id_bytes),
        id.swap_bytes(),
        "v3 HighID id is byte-swapped (hybrid order) on the wire"
    );
    assert_ne!(id_bytes, id.to_le_bytes());
}

#[test]
fn answer_sources_encode_v3_low_id_is_not_swapped() {
    let fh = FileHash::from_bytes([0x52; 16]);
    let source = SourceSighting::plain(PeerSource::new(ClientId::from_u32(5000), 4662));
    let answer = AnswerSources {
        file_hash: fh,
        sources: vec![SourceExchangeEntry::plain(source)],
    };
    let packet = answer.encode_packet(SourceExchangeVersion::V3);
    let payload = packet.payload();
    assert_eq!(
        &payload[18..22],
        &5000u32.to_le_bytes(),
        "LowID magnitude is scheme-invariant; never swapped"
    );
}

#[test]
fn answer_sources_round_trip_v3_preserves_high_id() {
    let fh = FileHash::from_bytes([0x59; 16]);
    let id = u32::from_le_bytes([11, 22, 33, 44]);
    let source = SourceSighting::plain(PeerSource::new(ClientId::from_u32(id), 4662));
    let answer = AnswerSources {
        file_hash: fh,
        sources: vec![SourceExchangeEntry::plain(source)],
    };
    let packet = answer.encode_packet(SourceExchangeVersion::V3);
    let decoded = AnswerSources::decode_packet(&packet, 3).expect("round trip decodes");
    assert_eq!(decoded.sources[0].client_id(), Some(ClientId::from_u32(id)));
}

#[test]
fn answer_sources_round_trip_v4_preserves_hash_and_crypt() {
    let fh = FileHash::from_bytes([0x5A; 16]);
    let id = u32::from_le_bytes([1, 2, 3, 4]);
    let hash = UserHash::from_bytes([0x77; 16]);
    let crypt = SourceCryptOptions::from_byte(0b101);
    let source = SourceSighting::new(
        PeerSource::new(ClientId::from_u32(id), 4662),
        Some(hash),
        Some(crypt),
    );
    let answer = AnswerSources {
        file_hash: fh,
        sources: vec![SourceExchangeEntry::plain(source)],
    };
    let packet = answer.encode_packet(SourceExchangeVersion::V4);
    let decoded = AnswerSources::decode_packet(&packet, 4).expect("round trip decodes");
    let decoded_src = decoded.sources[0];
    assert_eq!(decoded_src.client_id(), Some(ClientId::from_u32(id)));
    assert_eq!(decoded_src.user_hash(), Some(hash));
    assert_eq!(decoded_src.crypt_options(), Some(crypt));
}

#[test]
fn answer_sources2_round_trip_v1_plain_source() {
    let fh = FileHash::from_bytes([0x60; 16]);
    let id = u32::from_le_bytes([1, 2, 3, 4]);
    let source = SourceSighting::plain(PeerSource::new(ClientId::from_u32(id), 4662));
    let answer = AnswerSources2 {
        version: SourceExchangeVersion::V1,
        file_hash: fh,
        sources: vec![SourceExchangeEntry::plain(source)],
    };
    let packet = answer.encode_packet();
    assert_eq!(packet.opcode(), 0x84);
    assert_eq!(packet.protocol(), PacketProtocol::Emule);

    let decoded = AnswerSources2::decode_packet(&packet).expect("v1 SX2 answer decodes");
    assert_eq!(decoded.version, SourceExchangeVersion::V1);
    assert_eq!(decoded.file_hash, fh);
    assert_eq!(decoded.sources[0].client_id(), Some(ClientId::from_u32(id)));
    assert_eq!(decoded.sources[0].user_hash(), None);
}

#[test]
fn answer_sources2_round_trip_v4_mixes_high_and_low_id() {
    let fh = FileHash::from_bytes([0x61; 16]);
    let high_id = u32::from_le_bytes([5, 6, 7, 8]);
    let hash = UserHash::from_bytes([0x22; 16]);
    let crypt = SourceCryptOptions::from_byte(0b011);
    let high = SourceSighting::new(
        PeerSource::new(ClientId::from_u32(high_id), 111),
        Some(hash),
        Some(crypt),
    );
    let low = SourceSighting::new(
        PeerSource::new(ClientId::from_u32(42), 222),
        Some(hash),
        Some(crypt),
    );
    let answer = AnswerSources2 {
        version: SourceExchangeVersion::V4,
        file_hash: fh,
        sources: vec![
            SourceExchangeEntry::plain(high),
            SourceExchangeEntry::plain(low),
        ],
    };
    let packet = answer.encode_packet();
    let decoded = AnswerSources2::decode_packet(&packet).expect("v4 SX2 answer decodes");
    assert_eq!(
        decoded.sources[0].client_id(),
        Some(ClientId::from_u32(high_id))
    );
    assert_eq!(decoded.sources[1].client_id(), Some(ClientId::from_u32(42)));
    assert_eq!(decoded.sources[0].user_hash(), Some(hash));
    assert_eq!(decoded.sources[0].crypt_options(), Some(crypt));
}

#[test]
fn answer_sources2_encode_v4_pins_the_byte_exact_wire_with_hybrid_high_id() {
    // 0x84 v4 emit golden (ADR-0055): `[ver=4][hash16][count=1]` then the entry
    // `[id u32][tcp u16][srvIP u32=0][srvPort u16=0][userhash 16][crypt 1]`.
    // A HighID rides the wire in hybrid (byte-swapped) order for v>=4 — the
    // "uniform id rule" (aMule `CPartFile::AddClientSources` @4e8f2b3c).
    let fh = FileHash::from_bytes([0x65; 16]);
    let ed2k_id = u32::from_le_bytes([1, 2, 3, 4]); // HighID 1.2.3.4, ed2k order
    let user_hash = UserHash::from_bytes([0x9A; 16]);
    let crypt = SourceCryptOptions::from_byte(0b0000_0101); // supports + requires
    let source = SourceSighting::new(
        PeerSource::new(ClientId::from_u32(ed2k_id), 4662),
        Some(user_hash),
        Some(crypt),
    );
    let answer = AnswerSources2 {
        version: SourceExchangeVersion::V4,
        file_hash: fh,
        sources: vec![SourceExchangeEntry::plain(source)],
    };
    let packet = answer.encode_packet();
    assert_eq!(packet.opcode(), 0x84);
    assert_eq!(packet.protocol(), PacketProtocol::Emule);

    let mut expected = vec![4u8]; // version
    expected.extend_from_slice(fh.as_bytes());
    expected.extend_from_slice(&1u16.to_le_bytes()); // count
    expected.extend_from_slice(&ed2k_id.swap_bytes().to_le_bytes()); // hybrid HighID
    expected.extend_from_slice(&4662u16.to_le_bytes()); // tcp port
    expected.extend_from_slice(&0u32.to_le_bytes()); // server ip (untracked)
    expected.extend_from_slice(&0u16.to_le_bytes()); // server port (untracked)
    expected.extend_from_slice(user_hash.as_bytes());
    expected.push(0b0000_0101); // crypt options
    assert_eq!(packet.payload(), expected.as_slice());
}

#[test]
fn answer_sources2_rejects_version_zero() {
    let fh = FileHash::from_bytes([0x62; 16]);
    let mut payload = vec![0u8]; // version=0, aMule's explicit "== 0" rejection
    payload.extend_from_slice(fh.as_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    let packet = Packet::new(PacketProtocol::Emule, 0x84, payload);
    assert!(AnswerSources2::decode_packet(&packet).is_err());
}

#[test]
fn answer_sources2_rejects_version_above_sx2_ceiling() {
    let fh = FileHash::from_bytes([0x63; 16]);
    let mut payload = vec![5u8]; // above SOURCEEXCHANGE2_VERSION (4)
    payload.extend_from_slice(fh.as_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    let packet = Packet::new(PacketProtocol::Emule, 0x84, payload);
    assert!(AnswerSources2::decode_packet(&packet).is_err());
}

#[test]
fn answer_sources2_rejects_wrong_geometry_for_declared_version() {
    let fh = FileHash::from_bytes([0x64; 16]);
    let mut payload = vec![1u8]; // version=1 (12-byte stride)
    payload.extend_from_slice(fh.as_bytes());
    payload.extend_from_slice(&2u16.to_le_bytes()); // claims 2 sources
    payload.extend_from_slice(&[0u8; 12]); // only 1 source's worth of bytes
    let packet = Packet::new(PacketProtocol::Emule, 0x84, payload);
    assert!(AnswerSources2::decode_packet(&packet).is_err());
}

#[test]
fn answer_sources2_rejects_truncated_payload() {
    let version_byte_only = Packet::new(PacketProtocol::Emule, 0x84, vec![4u8]);
    assert!(AnswerSources2::decode_packet(&version_byte_only).is_err());
    let empty = Packet::new(PacketProtocol::Emule, 0x84, vec![]);
    assert!(AnswerSources2::decode_packet(&empty).is_err());
}

#[test]
fn request_sources2_encodes_standalone_wire_shape() {
    // aMule always sends `SOURCEEXCHANGE2_VERSION` (4) with reserved options 0
    // (`DownloadClient.cpp` @4e8f2b3c) — 19 bytes total.
    let fh = FileHash::from_bytes([0x70; 16]);
    let req = RequestSources2 {
        version: 4,
        options: 0,
        file_hash: fh,
    };
    let packet = req.encode_packet();
    assert_eq!(packet.opcode(), 0x83);
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    let mut expected = vec![4u8, 0, 0];
    expected.extend_from_slice(fh.as_bytes());
    assert_eq!(packet.payload(), expected.as_slice());
}

#[test]
fn request_sources2_round_trips_arbitrary_version_and_options() {
    let fh = FileHash::from_bytes([0x71; 16]);
    let req = RequestSources2 {
        version: 7,
        options: 0x1234,
        file_hash: fh,
    };
    let packet = req.encode_packet();
    let decoded = RequestSources2::decode_packet(&packet).expect("decodes");
    assert_eq!(decoded, req);
}

#[test]
fn request_sources2_rejects_wrong_size() {
    let fh = FileHash::from_bytes([0x72; 16]);
    // The legacy OP_REQUESTSOURCES shape (bare 16-byte hash) is not a valid
    // standalone OP_REQUESTSOURCES2 body.
    let too_short = Packet::new(PacketProtocol::Emule, 0x83, fh.as_bytes().to_vec());
    assert!(RequestSources2::decode_packet(&too_short).is_err());

    let mut too_long = vec![4u8, 0, 0];
    too_long.extend_from_slice(fh.as_bytes());
    too_long.push(0xFF);
    let too_long_packet = Packet::new(PacketProtocol::Emule, 0x83, too_long);
    assert!(RequestSources2::decode_packet(&too_long_packet).is_err());
}
