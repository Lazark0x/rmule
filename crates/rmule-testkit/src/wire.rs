//! The one home for the shared eD2k-peer wire-byte builders: the framed
//! packets the fakes and Protocol-Counterparty Tests hand straight to the
//! socket. Builders are parameterized by protocol primitives (hashes, byte
//! offsets, queue ranks, names); the *policy* that decides which frame to send
//! lives in the fakes, not here. Faithful to behaviour, not to captured bytes
//! (ADR-0040).

use rmule_peer::{
    AnswerSources, Hello, HelloAnswer, MiscOptions1, MiscOptions2, PeerHelloBody,
    SourceExchangeEntry, SourceExchangeVersion,
};
use rmule_primitives::{
    ClientId, Ed2kText, ExchangedSource, FileHash, Ipv4Endpoint, Packet, PacketProtocol, PartHash,
    Tag, TagName, TagValue, UserHash,
};

/// The peer hello body shared by the `OP_HELLO` and `OP_HELLOANSWER` builders:
/// a High-ID peer on 4662 advertising `nickname` under tag 0x01, plus a mule's
/// `CT_EMULE_VERSION` and `CT_EMULE_MISCOPTIONS1` advertising source-exchange
/// v2 — a real eMule/aMule peer always sends both tags. v2 is the lowest
/// nibble aMule asks for sources (stock 2.3.3 `DownloadClient.cpp:191`, ADR-0108), so a
/// fake that answers source asks must claim at least it; and
/// `OP_ANSWERSOURCES`'s geometry cross-check resolves against *this peer's*
/// claimed nibble (ADR-0055), not rmule's own.
fn hello_body(user_hash: UserHash, nickname: &str) -> PeerHelloBody {
    hello_body_advertising(user_hash, nickname, MiscOptions1::from_bits(2 << 12), None)
}

/// [`hello_body`] with explicit capability words. One `CT_EMULE_MISCOPTIONS1`
/// tag only: rmule's hello parser takes the *first* occurrence of each
/// capability tag, so an advertisement must ride the body's single word — a
/// second pushed tag is a dead advert.
fn hello_body_advertising(
    user_hash: UserHash,
    nickname: &str,
    misc1: MiscOptions1,
    misc2: Option<MiscOptions2>,
) -> PeerHelloBody {
    let mut tags = vec![
        Tag::new(
            TagName::length_prefixed_id(0x01),
            TagValue::String(Ed2kText::from_utf8(nickname)),
        ),
        crate::peer_session::mule_version_tag(),
        misc1.to_tag(),
    ];
    if let Some(misc2) = misc2 {
        tags.push(misc2.to_tag());
    }
    PeerHelloBody {
        user_hash,
        client_id: ClientId::from_u32(0x2000_0002),
        tcp_port: 4662,
        tags,
        connected_server: Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
    }
}

/// A framed `OP_HELLO` opening a conversation as `user_hash`/`nickname`.
pub fn hello_bytes(user_hash: UserHash, nickname: &str) -> Vec<u8> {
    Hello::new(hello_body(user_hash, nickname))
        .encode_packet()
        .encode()
}

/// A framed `OP_HELLOANSWER` replying as `user_hash`/`nickname`.
pub fn hello_answer_bytes(user_hash: UserHash, nickname: &str) -> Vec<u8> {
    HelloAnswer::new(hello_body(user_hash, nickname))
        .encode_packet()
        .encode()
}

/// [`hello_answer_bytes`] advertising the SX1 nibble `sx1` instead of `2`.
pub fn hello_answer_bytes_with_sx1(user_hash: UserHash, nickname: &str, sx1: u8) -> Vec<u8> {
    let misc1 = MiscOptions1::from_bits(u32::from(sx1) << 12);
    HelloAnswer::new(hello_body_advertising(user_hash, nickname, misc1, None))
        .encode_packet()
        .encode()
}

/// A framed `OP_HELLOANSWER` that additionally advertises MultiPacket
/// (`MiscOptions1` bit 1), ExtMultiPacket (`MiscOptions2` bit 5), and
/// SourceExchange2 (`MiscOptions2` bit 10) — the capabilities an uploader must
/// declare for rmule to fold its file request into one `OP_MULTIPACKET_EXT`
/// bundle carrying the SX2 sub (ADR-0054 emit; the reverse harness).
/// Uses the same honest advertisement rmule itself sends — and the same trio a
/// stock aMule 2.3.3 lights together — so the fixture looks like a real
/// multipacket client rather than one with a lone bit lit. The words ride the
/// body's single MiscOptions tags: rmule's parser reads the first occurrence,
/// so pushing extra tags would leave the capability dark (the old bug
/// that let the reverse harness negotiate standalone without noticing).
pub fn multipacket_hello_answer_bytes(user_hash: UserHash, nickname: &str) -> Vec<u8> {
    let body = hello_body_advertising(
        user_hash,
        nickname,
        MiscOptions1::rmule_advertised(),
        Some(
            MiscOptions2::rmule_advertised(false, false, false)
                .with_multipacket_ext()
                .with_source_exchange2(),
        ),
    );
    HelloAnswer::new(body).encode_packet().encode()
}

/// A pre-0.42 mule's framed `OP_HELLOANSWER`: its name and a `CT_VERSION`,
/// no mule tag — such a mule states what it supports only in an
/// `OP_EMULEINFO` ([`legacy_mule_info_bytes`]).
pub fn legacy_hello_answer_bytes(user_hash: UserHash, nickname: &str) -> Vec<u8> {
    let body = PeerHelloBody {
        user_hash,
        client_id: ClientId::from_u32(0x2000_0002),
        tcp_port: 4662,
        tags: vec![
            Tag::new(
                TagName::length_prefixed_id(0x01),
                TagValue::String(Ed2kText::from_utf8(nickname)),
            ),
            Tag::new(TagName::length_prefixed_id(0x11), TagValue::U32(0x3C)),
        ],
        connected_server: Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
    };
    HelloAnswer::new(body).encode_packet().encode()
}

/// A pre-0.42 mule's framed `OP_EMULEINFO` (`0xC5 0x01`) as eMule's
/// `SendMuleInfoPacket` writes one: mule version 0x30, protocol 1, then
/// old-format integer tags — compression 1 and `ET_SOURCEEXCHANGE` = `sx1`
/// (stock aMule 2.3.3 `BaseClient.cpp:918-921` reads it).
pub fn legacy_mule_info_bytes(sx1: u8) -> Vec<u8> {
    let tags = [(0x20_u8, 1_u32), (0x23, u32::from(sx1))];
    let mut payload = vec![0x30, 0x01];
    payload.extend_from_slice(&(tags.len() as u32).to_le_bytes());
    for (id, value) in tags {
        payload.extend_from_slice(
            &Tag::new(TagName::length_prefixed_id(id), TagValue::U32(value)).encode(),
        );
    }
    Packet::new(PacketProtocol::Emule, 0x01, payload).encode()
}

/// A framed file-name answer (opcode 0x59): the file hash and its name.
pub fn filename_answer_bytes(file_hash: FileHash, name: &str) -> Vec<u8> {
    let mut payload = file_hash.as_bytes().to_vec();
    payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    Packet::new(PacketProtocol::Edonkey, 0x59, payload).encode()
}

/// A framed file-status answer (opcode 0x50): a one-part bitmap present.
pub fn file_status_bytes(file_hash: FileHash) -> Vec<u8> {
    let mut payload = file_hash.as_bytes().to_vec();
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(0x01);
    Packet::new(PacketProtocol::Edonkey, 0x50, payload).encode()
}

/// A framed hash-set answer (opcode 0x52): `part_hashes` as the per-part hash
/// set — an empty slice is the zero-count single-chunk set.
pub fn hash_set_bytes(file_hash: FileHash, part_hashes: &[PartHash]) -> Vec<u8> {
    let mut payload = file_hash.as_bytes().to_vec();
    payload.extend_from_slice(&(part_hashes.len() as u16).to_le_bytes());
    for hash in part_hashes {
        payload.extend_from_slice(hash.as_bytes());
    }
    Packet::new(PacketProtocol::Edonkey, 0x52, payload).encode()
}

/// A framed accept-upload (opcode 0x55): the upload slot is granted.
pub fn accept_upload_bytes() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x55, Vec::new()).encode()
}

/// A framed queue-ranking (eMule opcode 0x60): the requester's current `rank`.
pub fn queueranking_bytes(rank: u16) -> Vec<u8> {
    let mut payload = rank.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0u8; 10]);
    Packet::new(PacketProtocol::Emule, 0x60, payload).encode()
}

/// A framed sending-part (opcode 0x46): `data` for the byte range beginning at
/// `start` (the end offset is `start + data.len()`).
pub fn sending_part_bytes(file_hash: FileHash, start: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = file_hash.as_bytes().to_vec();
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&(start + data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    Packet::new(PacketProtocol::Edonkey, 0x46, payload).encode()
}

/// A framed **packed** (`0xD4`) `OP_ANSWERSOURCES` answer (ADR-0053): the
/// v1 source list, zlib-compressed via the shared
/// [`rmule_primitives::pack_if_smaller`] mechanism — the peer-inbound-inflate
/// scenario. aMule always packs `OP_ANSWERSOURCES` regardless of size, so the
/// fixture asserts it actually packed rather than silently exercising the
/// plain path; callers must pick a `sources` list redundant/large enough to
/// compress smaller (a handful of repeated entries is enough).
pub fn packed_answer_sources_bytes(file_hash: FileHash, sources: &[ExchangedSource]) -> Vec<u8> {
    let plain = AnswerSources {
        file_hash,
        sources: sources
            .iter()
            .copied()
            .map(SourceExchangeEntry::plain)
            .collect(),
    }
    // V2 entries: the geometry matches the SX1 nibble the fake's hello
    // claims (`hello_body`), which the asker cross-checks the answer against.
    .encode_packet(SourceExchangeVersion::V2);
    let packed = rmule_primitives::pack_if_smaller(plain);
    assert_eq!(
        packed.protocol(),
        PacketProtocol::PackedEd2k,
        "fixture source list must compress smaller than plain — add more sources"
    );
    packed.encode()
}
