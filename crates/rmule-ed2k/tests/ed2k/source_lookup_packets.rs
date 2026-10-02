//! `OP_GETSOURCES` and `OP_FOUNDSOURCES` as packets: the legacy, normal and
//! large wire forms, and the obfuscated opcodes that dispatch to the same
//! typed codecs.

use rmule_ed2k::{ClientPacket, FoundSources, GetSourcesRequest, ServerPacket};
use rmule_primitives::{ClientId, Packet, PacketProtocol, PeerSource, SourceLookupTarget};

#[test]
fn get_sources_decodes_legacy_normal_and_large_wire_forms() {
    let legacy = Packet::new(PacketProtocol::Edonkey, 0x19, vec![0x11; 16]);
    assert_eq!(
        GetSourcesRequest::decode_packet(&legacy).unwrap(),
        GetSourcesRequest::Legacy {
            file_hash: crate::fixture::hash(0x11),
        }
    );

    let mut normal_payload = vec![0x22; 16];
    normal_payload.extend_from_slice(&1234u32.to_le_bytes());
    let normal = Packet::new(PacketProtocol::Edonkey, 0x19, normal_payload);
    assert_eq!(
        GetSourcesRequest::decode_packet(&normal).unwrap(),
        GetSourcesRequest::Normal {
            target: SourceLookupTarget::new(crate::fixture::hash(0x22), 1234),
        }
    );

    let mut large_payload = vec![0x33; 16];
    large_payload.extend_from_slice(&0u32.to_le_bytes());
    large_payload.extend_from_slice(&(u64::from(u32::MAX) + 1).to_le_bytes());
    let large = Packet::new(PacketProtocol::Edonkey, 0x19, large_payload);
    assert_eq!(
        GetSourcesRequest::decode_packet(&large).unwrap(),
        GetSourcesRequest::Large {
            target: SourceLookupTarget::new(crate::fixture::hash(0x33), u64::from(u32::MAX) + 1),
        }
    );
}

#[test]
fn get_sources_encodes_normal_and_large_requests() {
    let normal = GetSourcesRequest::Normal {
        target: SourceLookupTarget::new(crate::fixture::hash(0x44), 42),
    };
    assert_eq!(normal.encode_packet().payload().len(), 20);

    let large = GetSourcesRequest::Large {
        target: SourceLookupTarget::new(crate::fixture::hash(0x55), u64::from(u32::MAX) + 1),
    };
    let packet = large.encode_packet();
    assert_eq!(packet.payload().len(), 28);
    assert_eq!(&packet.payload()[16..20], &[0, 0, 0, 0]);
}

#[test]
fn malformed_get_sources_rejects() {
    let bad_len = Packet::new(PacketProtocol::Edonkey, 0x19, vec![0; 17]);
    assert!(GetSourcesRequest::decode_packet(&bad_len).is_err());

    let mut bad_sentinel = vec![0x66; 16];
    bad_sentinel.extend_from_slice(&1u32.to_le_bytes());
    bad_sentinel.extend_from_slice(&100u64.to_le_bytes());
    let bad = Packet::new(PacketProtocol::Edonkey, 0x19, bad_sentinel);
    assert!(GetSourcesRequest::decode_packet(&bad).is_err());
}

#[test]
fn found_sources_decodes_and_encodes_peer_sources() {
    let high = PeerSource::new(ClientId::from_u32(ClientId::LOW_ID_THRESHOLD), 4662);
    let low = PeerSource::new(ClientId::from_u32(7), 4663);
    let found = FoundSources::new(crate::fixture::hash(0x77), vec![high, low]).unwrap();

    let packet = found.encode_packet();
    let decoded = FoundSources::decode_packet(&packet).unwrap();

    assert_eq!(decoded.file_hash(), crate::fixture::hash(0x77));
    assert_eq!(decoded.sources(), &[high, low]);
    assert!(decoded.sources()[0].is_high_id());
    assert!(decoded.sources()[1].is_low_id());
}

#[test]
fn malformed_found_sources_rejects() {
    let missing_count = Packet::new(PacketProtocol::Edonkey, 0x42, vec![0; 16]);
    assert!(FoundSources::decode_packet(&missing_count).is_err());

    let mut count_mismatch = vec![0; 16];
    count_mismatch.push(2);
    count_mismatch.extend_from_slice(&[1, 0, 0, 0, 0x36, 0x12]);
    let packet = Packet::new(PacketProtocol::Edonkey, 0x42, count_mismatch);
    assert!(FoundSources::decode_packet(&packet).is_err());
}

#[test]
fn obfuscated_source_lookup_opcodes_dispatch_to_typed_codecs() {
    // ADR-0046: `0x23`/`0x44` are modelled, not preserved
    // as Unknown. A well-formed `0x23` decodes as a get-sources request (same
    // body as `0x19`); a well-formed `0x44` decodes as the obfuscation-aware
    // found-sources reply.
    let mut get_obfu_body = vec![0x11; 16];
    get_obfu_body.extend_from_slice(&99u32.to_le_bytes());
    let get_obfu = Packet::new(PacketProtocol::Edonkey, 0x23, get_obfu_body);
    assert!(matches!(
        ClientPacket::decode(&get_obfu).unwrap(),
        ClientPacket::GetSources(GetSourcesRequest::Normal { .. })
    ));

    let found_obfu = Packet::new(PacketProtocol::Edonkey, 0x44, {
        let mut payload = vec![0x22; 16];
        payload.push(0); // zero sources
        payload
    });
    assert!(matches!(
        ServerPacket::decode(&found_obfu).unwrap(),
        ServerPacket::FoundSourcesObfu(_)
    ));
}
