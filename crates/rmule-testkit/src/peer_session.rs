//! Session-level fixtures for the peer state machine: an identified
//! [`PeerSession`] with its handshake context, output drains, and the
//! peer-sent wire frames a requester's legs answer to.
//!
//! Namespaced because the vocabulary — `peer`, `ctx`, `writes`, `events` —
//! would collide at the crate root: a leg names the few builders it wants, or
//! globs the whole vocabulary in when peer sessions are its whole subject.
//! Faithful to behaviour, not to captured bytes (ADR-0040).

use std::net::Ipv4Addr;

use rmule_peer::{
    HelloAnswer, MiscOptions1, PeerEvent, PeerHandshakeContext, PeerHelloBody, PeerOutput,
    PeerSession,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    AichRootHash, ClientId, ClientIdentity, Ed2kText, FileHash, Ipv4Endpoint, Packet,
    PacketProtocol, PartHash, PeerEndpoint, Tag, TagName, TagValue, UserHash,
};

/// The peer this suite dials: `203.0.113.1:4662`, TEST-NET-3 and never routable.
pub fn peer() -> PeerEndpoint {
    peer_at(1)
}

/// The same peer reached over IPv6, in the never-routable documentation
/// prefix — the counterparty for anything the IPv6 dialect decides by the
/// session's own family (ADR-0087).
#[must_use]
pub fn peer_v6() -> PeerEndpoint {
    PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
        "2001:db8::1"
            .parse()
            .expect("a literal documentation address"),
        4662,
    ))
}

/// A second, third, ... peer in the same never-routable TEST-NET-3 block, so a
/// suite that needs two counterparties can tell their endpoints apart.
pub fn peer_at(last_octet: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::new(203, 0, 113, last_octet),
        4662,
    ))
}

/// Our own side of the handshake: High-ID `0x10000001` listening on 4662,
/// connected to a server at `192.0.2.1:4661`.
pub fn ctx() -> PeerHandshakeContext {
    ctx_with_server(Some(Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 1), 4661)))
}

/// The same side of the handshake, logged in to a server on loopback: what a
/// suite driving a real socket against its own fake server speaks from.
pub fn loopback_ctx() -> PeerHandshakeContext {
    ctx_with_server(Some(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661)))
}

/// The same side of the handshake with no server behind us: what a Kad
/// dial-back or a buddy relay speaks from, where no login is in the picture.
pub fn serverless_ctx() -> PeerHandshakeContext {
    ctx_with_server(None)
}

/// The same side of the handshake with the server we are logged in to chosen
/// by the caller: a loopback suite points it at its own `127.0.0.1` fake, and
/// a firewalled dial-back leg has no server at all.
pub fn ctx_with_server(connected_server: Option<Ipv4Endpoint>) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("rmule"),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0x10000001),
        ed2k_client_id: ClientId::from_u32(0x10000001),
        public_ip: None,
        connected_server,
    }
}

/// `CT_EMULE_VERSION` as stock aMule 2.3.3 writes it in every hello, the word
/// `0x0304_0D80`: the tag that makes a peer a mule, speaking the extended
/// protocol that source exchange and the queue rank ride on (aMule
/// `BaseClient.cpp:711`).
#[must_use]
pub fn mule_version_tag() -> Tag {
    Tag::new(
        TagName::length_prefixed_id(0xFB),
        TagValue::U32(0x0304_0D80),
    )
}

/// The peer's hello-answer body: a mule hello, `CT_EMULE_VERSION` beside
/// `CT_EMULE_MISCOPTIONS1` as every real eMule/aMule peer sends them, the
/// latter advertising source-exchange v1 — an answer's geometry cross-check
/// resolves against the peer's own claimed nibble (ADR-0055).
pub fn answer_body(user_hash: UserHash) -> PeerHelloBody {
    PeerHelloBody {
        user_hash,
        client_id: ClientId::from_u32(0x20000002),
        tcp_port: 4662,
        tags: vec![
            Tag::new(
                TagName::length_prefixed_id(0x01),
                TagValue::String(Ed2kText::from_utf8("remote")),
            ),
            mule_version_tag(),
            // A real eMule/aMule peer always advertises `CT_EMULE_MISCOPTIONS1`;
            // source-exchange v1 here is what lets an `OP_ANSWERSOURCES` v1
            // answer resolve its geometry cross-check (ADR-0055 threads
            // this peer's own claimed nibble, not rmule's).
            MiscOptions1::from_bits(1 << 12).to_tag(),
        ],
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    }
}

/// Every `Write` in `outputs`, decoded back into packets.
pub fn writes(outputs: &[PeerOutput]) -> Vec<Packet> {
    outputs
        .iter()
        .filter_map(|o| match o {
            PeerOutput::Write(bytes) => Packet::decode(bytes).ok().map(|(p, _)| p),
            _ => None,
        })
        .collect()
}

/// Every `Event` in `outputs`.
pub fn events(outputs: &[PeerOutput]) -> Vec<&PeerEvent> {
    outputs
        .iter()
        .filter_map(|o| match o {
            PeerOutput::Event(e) => Some(e),
            _ => None,
        })
        .collect()
}

/// The raw bytes of the last `Write` in `outputs`. Panics when there is none.
pub fn last_write_bytes(outputs: &[PeerOutput]) -> Vec<u8> {
    outputs
        .iter()
        .rev()
        .find_map(|o| match o {
            PeerOutput::Write(b) => Some(b.to_vec()),
            _ => None,
        })
        .expect("a Write output")
}

/// An outbound session past the hello exchange: started, the answer fed in,
/// and both output batches drained, so the peer is identified.
pub fn identified_session() -> PeerSession {
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    let answer = HelloAnswer::new(answer_body(UserHash::from_bytes([0x99; 16])))
        .encode_packet()
        .encode();
    session.handle_bytes(&answer);
    let _ = drain(|| session.poll_output());
    session
}

/// A file hash of sixteen repeated `seed` bytes.
pub fn file_hash(seed: u8) -> FileHash {
    FileHash::from_bytes([seed; 16])
}

// Peer-sent frames: what a counterparty answers a requester with.

/// `OP_REQFILENAMEANSWER` (0x59): `[hash][name len u16][name]`.
pub fn reqfilename_answer(hash: FileHash, name: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(name_bytes);
    Packet::new(PacketProtocol::Edonkey, 0x59, payload).encode()
}

/// `OP_FILESTATUS` (0x50): `[hash][part count u16][bitmap]`.
pub fn file_status(hash: FileHash, part_count: u16, bitmap: &[u8]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&part_count.to_le_bytes());
    payload.extend_from_slice(bitmap);
    Packet::new(PacketProtocol::Edonkey, 0x50, payload).encode()
}

/// `OP_FILEREQANSNOFIL` (0x48): the peer does not have the file.
pub fn filereqansnofil(hash: FileHash) -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x48, hash.as_bytes().to_vec()).encode()
}

/// `OP_HASHSETANSWER` (0x52): the file's part-hash set.
pub fn hashset_answer(hash: FileHash, part_hashes: &[PartHash]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&(part_hashes.len() as u16).to_le_bytes());
    for h in part_hashes {
        payload.extend_from_slice(h.as_bytes());
    }
    Packet::new(PacketProtocol::Edonkey, 0x52, payload).encode()
}

/// `OP_QUEUERANKING` (0x60, eMule): our place in the peer's upload queue.
pub fn queueranking(rank: u16) -> Vec<u8> {
    let mut payload = rank.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0u8; 10]);
    Packet::new(PacketProtocol::Emule, 0x60, payload).encode()
}

/// `OP_OUTOFPARTREQS` (0x57): the peer dropped us back into its queue.
pub fn outofpartreqs() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x57, Vec::new()).encode()
}

/// `OP_ACCEPTUPLOADREQ` (0x55): the peer granted the slot.
pub fn acceptuploadreq() -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, 0x55, Vec::new()).encode()
}

/// `OP_SENDINGPART` (0x46): one block under 32-bit offsets.
pub fn sendingpart(hash: FileHash, start: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&(start + data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    Packet::new(PacketProtocol::Edonkey, 0x46, payload).encode()
}

/// `OP_SENDINGPART_I64` (0xA2, eMule): one block under 64-bit offsets, the
/// form a file past 4 GiB needs.
pub fn sendingpart_i64(hash: FileHash, start: u64, data: &[u8]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&(start + data.len() as u64).to_le_bytes());
    payload.extend_from_slice(data);
    Packet::new(PacketProtocol::Emule, 0xA2, payload).encode()
}

/// A peer-sent `OP_COMPRESSEDPART`: the whole block in one packet
/// (`nBlockSize` == this packet's compressed length).
pub fn compressedpart(hash: FileHash, start: u32, plain: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(plain).unwrap();
    let compressed = enc.finish().unwrap();
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&(compressed.len() as u32).to_le_bytes()); // nBlockSize
    payload.extend_from_slice(&compressed);
    Packet::new(PacketProtocol::Emule, 0x40, payload).encode()
}

/// A raw `OP_COMPRESSEDPART` chunk with an explicit `nBlockSize`, for blocks
/// split across packets — or for hostile declared lengths.
pub fn compressedpart_chunk(hash: FileHash, start: u32, block_len: u32, chunk: &[u8]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&block_len.to_le_bytes());
    payload.extend_from_slice(chunk);
    Packet::new(PacketProtocol::Emule, 0x40, payload).encode()
}

/// A corrupt `OP_COMPRESSEDPART`: `nBlockSize` matches the chunk length but
/// the bytes are not a valid zlib stream.
pub fn corrupt_compressedpart(hash: FileHash, start: u32, junk: &[u8]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&(junk.len() as u32).to_le_bytes());
    payload.extend_from_slice(junk);
    Packet::new(PacketProtocol::Emule, 0x40, payload).encode()
}

/// A peer-sent `OP_ANSWERSOURCES` (v1): `[hash][count]` then per source
/// `[id u32][tcp u16][server ip u32][server port u16]`.
pub fn answer_sources_wire(hash: FileHash, sources: &[(u32, u16)]) -> Vec<u8> {
    let mut p = hash.as_bytes().to_vec();
    p.extend_from_slice(&(sources.len() as u16).to_le_bytes());
    for &(id, tcp) in sources {
        p.extend_from_slice(&id.to_le_bytes());
        p.extend_from_slice(&tcp.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
    }
    Packet::new(PacketProtocol::Emule, 0x82, p).encode()
}

/// `OP_AICHANSWER` (0x9C, eMule): a part's AICH root and its recovery hashes.
pub fn aich_answer_wire(hash: FileHash, part: u16, root: AichRootHash, recovery: &[u8]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&part.to_le_bytes());
    payload.extend_from_slice(root.as_bytes());
    payload.extend_from_slice(recovery);
    Packet::new(PacketProtocol::Emule, 0x9C, payload).encode()
}

/// `OP_AICHREQUEST` (0x9B, eMule): ask for one part's recovery data.
pub fn aich_request_wire(hash: FileHash, part: u16, root: AichRootHash) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&part.to_le_bytes());
    payload.extend_from_slice(root.as_bytes());
    Packet::new(PacketProtocol::Emule, 0x9B, payload).encode()
}
