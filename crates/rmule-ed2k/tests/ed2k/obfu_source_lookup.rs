//! `OP_GETSOURCES_OBFU` (`0x23`) / `OP_FOUNDSOURCES_OBFU` (`0x44`) codecs and
//! the crypt-provenance projection onto `Ed2kEvent::SourcesFound` (ADR-0046
//! s5). Wire layout from aMule `CPartFile::AddSources(..., bWithObfuscationAndHash)`
//! @ `377ec8d9`: each source is `[id 4][port 2][crypt-options 1]` and, iff
//! `crypt-options & 0x80`, a trailing `[user hash 16]`. `[pending]` on the
//! server-UDP-capable-eserver capture (ADR-0046 evidence).

use rmule_ed2k::{Ed2kEvent, FoundSources, FoundSourcesObfu, GetSourcesRequest, ServerPacket};
use rmule_primitives::{
    ClientId, CryptStance, ExchangedSource, FileHash, OutboundCrypt, Packet, PacketProtocol,
    PeerSource, SourceLookupTarget, UserHash,
};

const HAS_USER_HASH: u8 = 0x80;

/// Our own stance for these tests: supports and requests obfuscation (the
/// "someone has to ask" half of `PeerCrypt::outbound`).
const OURS: CryptStance = CryptStance::new(true, true, false);

fn user_hash(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
}

fn high_id() -> ClientId {
    ClientId::from_u32(ClientId::LOW_ID_THRESHOLD)
}

/// One `0x44` source item: id, port, crypt byte, and — iff `0x80` is set — a hash.
fn obfu_source_bytes(id: ClientId, port: u16, crypt: u8, hash: Option<UserHash>) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&id.as_u32().to_le_bytes());
    bytes.extend_from_slice(&port.to_le_bytes());
    bytes.push(crypt);
    if let Some(h) = hash {
        assert_eq!(crypt & HAS_USER_HASH, HAS_USER_HASH, "0x80 gates the hash");
        bytes.extend_from_slice(h.as_bytes());
    }
    bytes
}

fn obfu_packet(file_hash: FileHash, items: &[Vec<u8>]) -> Packet {
    let mut payload = Vec::new();
    payload.extend_from_slice(file_hash.as_bytes());
    payload.push(u8::try_from(items.len()).unwrap());
    for item in items {
        payload.extend_from_slice(item);
    }
    Packet::new(PacketProtocol::Edonkey, 0x44, payload)
}

#[test]
fn get_sources_obfu_swaps_only_the_opcode() {
    // `OP_GETSOURCES_OBFU` is the plaintext get-sources body under a different
    // opcode — it asks the server to answer with the obfuscation-aware `0x44`.
    let request = GetSourcesRequest::Normal {
        target: SourceLookupTarget::new(crate::fixture::hash(0x44), 4242),
    };
    let plain = request.encode_packet();
    let obfu = request.encode_obfu_packet();

    assert_eq!(plain.opcode(), 0x19);
    assert_eq!(obfu.opcode(), 0x23);
    assert_eq!(obfu.payload(), plain.payload());
}

#[test]
fn found_sources_obfu_decodes_crypt_bits_and_the_gated_hash() {
    // A: crypt-supporting High-ID source with a User Hash (0x80 | supports).
    // B: a plain source — no 0x80, so no hash, and no crypt support.
    let dial = user_hash(0xAB);
    let a = obfu_source_bytes(high_id(), 4662, HAS_USER_HASH | 0x01, Some(dial));
    let b = obfu_source_bytes(ClientId::from_u32(9), 4663, 0x00, None);
    let decoded =
        FoundSourcesObfu::decode_packet(&obfu_packet(crate::fixture::hash(0x77), &[a, b])).unwrap();

    assert_eq!(decoded.file_hash(), crate::fixture::hash(0x77));
    let sources = decoded.sources();
    assert_eq!(sources.len(), 2);

    assert_eq!(sources[0].peer_source(), PeerSource::new(high_id(), 4662));
    assert_eq!(sources[0].user_hash(), Some(dial));
    assert!(sources[0].crypt_options().unwrap().supports_crypt());
    // The unlock: a server-lookup source is now obfuscate-dialable.
    assert_eq!(
        sources[0].peer_crypt().outbound(OURS),
        OutboundCrypt::Obfuscated { toward: dial }
    );

    assert_eq!(sources[1].user_hash(), None);
    assert_eq!(
        sources[1].peer_crypt().outbound(OURS),
        OutboundCrypt::Plaintext
    );
}

#[test]
fn found_sources_obfu_supports_bit_without_hash_is_not_dialable() {
    // Crypt-supported but the server carried no hash (0x80 clear): rmule cannot
    // derive the peer key, so it must dial plaintext — never with a bogus key.
    let supports_no_hash = obfu_source_bytes(high_id(), 4662, 0x01, None);
    // A hash present but crypt unsupported (0x80 set, bit0 clear): also not
    // dialable — obfuscation is off for that source.
    let hash_no_support = obfu_source_bytes(high_id(), 4663, HAS_USER_HASH, Some(user_hash(0x05)));
    let decoded = FoundSourcesObfu::decode_packet(&obfu_packet(
        crate::fixture::hash(0x01),
        &[supports_no_hash, hash_no_support],
    ))
    .unwrap();

    assert_eq!(
        decoded.sources()[0].peer_crypt().outbound(OURS),
        OutboundCrypt::Plaintext
    );
    assert_eq!(
        decoded.sources()[1].peer_crypt().outbound(OURS),
        OutboundCrypt::Plaintext
    );
}

#[test]
fn found_sources_obfu_masks_the_transport_bit_out_of_crypt_options() {
    // 0x80 HAS_USER_HASH is wire framing (it gates the trailing hash), not a
    // crypt capability. A source that carries it and an otherwise-identical
    // source-exchange-style source that does not must decode to the SAME
    // `SourceCryptOptions`, or any `ExchangedSource`-keyed dedup would treat one
    // peer as two. aMule stores `byCryptOptions & 0x7F` for exactly this reason.
    let with_transport =
        obfu_source_bytes(high_id(), 4662, HAS_USER_HASH | 0x01, Some(user_hash(0x05)));
    let without_transport = obfu_source_bytes(high_id(), 4662, 0x01, None);
    let decoded = FoundSourcesObfu::decode_packet(&obfu_packet(
        crate::fixture::hash(0x55),
        &[with_transport, without_transport],
    ))
    .unwrap();

    assert_eq!(
        decoded.sources()[0].crypt_options(),
        decoded.sources()[1].crypt_options(),
        "the 0x80 transport bit must not leak into the stored crypt capability",
    );
}

#[test]
fn found_sources_obfu_round_trips_mixed_strides() {
    let with_hash = obfu_source_bytes(high_id(), 4662, HAS_USER_HASH | 0x07, Some(user_hash(0xCD)));
    let without = obfu_source_bytes(ClientId::from_u32(3), 5000, 0x01, None);
    let packet = obfu_packet(crate::fixture::hash(0x42), &[with_hash, without]);

    let decoded = FoundSourcesObfu::decode_packet(&packet).unwrap();
    assert_eq!(decoded.encode_packet().encode(), packet.encode());
}

#[test]
fn malformed_found_sources_obfu_rejects() {
    // Missing hash + count byte.
    let stub = Packet::new(PacketProtocol::Edonkey, 0x44, vec![0; 8]);
    assert!(FoundSourcesObfu::decode_packet(&stub).is_err());

    // Count claims one source, but the crypt byte is truncated.
    let mut short_crypt = Vec::new();
    short_crypt.extend_from_slice(crate::fixture::hash(0x11).as_bytes());
    short_crypt.push(1);
    short_crypt.extend_from_slice(&[1, 0, 0, 0, 0x36, 0x12]); // id + port, no crypt byte
    assert!(
        FoundSourcesObfu::decode_packet(&Packet::new(PacketProtocol::Edonkey, 0x44, short_crypt))
            .is_err()
    );

    // 0x80 promises a hash that is not there.
    let mut short_hash = Vec::new();
    short_hash.extend_from_slice(crate::fixture::hash(0x11).as_bytes());
    short_hash.push(1);
    short_hash.extend_from_slice(&obfu_source_bytes(high_id(), 4662, HAS_USER_HASH, None));
    assert!(
        FoundSourcesObfu::decode_packet(&Packet::new(PacketProtocol::Edonkey, 0x44, short_hash))
            .is_err()
    );

    // Trailing bytes past the declared count are a Malformed Tail diagnostic,
    // never a rejected packet (ADR-0085): the declared source still stands.
    let mut trailing = obfu_packet(
        crate::fixture::hash(0x11),
        &[obfu_source_bytes(high_id(), 4662, 0x00, None)],
    )
    .payload()
    .to_vec();
    trailing.push(0xFF);
    let decoded =
        FoundSourcesObfu::decode_packet(&Packet::new(PacketProtocol::Edonkey, 0x44, trailing))
            .expect("a source list is never rejected whole");
    assert_eq!(decoded.sources().len(), 1);
    assert!(decoded.tail().is_malformed());
}

#[test]
fn obfu_found_sources_projects_crypt_provenance_onto_the_event() {
    let dial = user_hash(0xAB);
    let a = obfu_source_bytes(high_id(), 4662, HAS_USER_HASH | 0x01, Some(dial));
    let b = obfu_source_bytes(ClientId::from_u32(9), 4663, 0x00, None);
    let obfu = ServerPacket::decode(&obfu_packet(crate::fixture::hash(0x77), &[a, b])).unwrap();

    let Ed2kEvent::SourcesFound {
        file_hash, sources, ..
    } = Ed2kEvent::from_server_packet(&obfu)
    else {
        panic!("expected SourcesFound");
    };
    assert_eq!(file_hash, crate::fixture::hash(0x77));
    assert_eq!(
        sources[0].peer_crypt().outbound(OURS),
        OutboundCrypt::Obfuscated { toward: dial }
    );
    assert_eq!(
        sources[1].peer_crypt().outbound(OURS),
        OutboundCrypt::Plaintext
    );
}

#[test]
fn plain_found_sources_projects_as_plaintext_only_candidates() {
    // The plain `0x42` path carries no crypt material, so every candidate is
    // `ExchangedSource::plain` — dialed plaintext.
    let source = PeerSource::new(high_id(), 4662);
    let plain = ServerPacket::FoundSources(
        FoundSources::new(crate::fixture::hash(0x33), vec![source]).unwrap(),
    );

    let Ed2kEvent::SourcesFound { sources, .. } = Ed2kEvent::from_server_packet(&plain) else {
        panic!("expected SourcesFound");
    };
    assert_eq!(sources, vec![ExchangedSource::plain(source)]);
    assert_eq!(
        sources[0].peer_crypt().outbound(OURS),
        OutboundCrypt::Plaintext
    );
}
