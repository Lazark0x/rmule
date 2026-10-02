//! The TCP-flags extension on `OP_IDCHANGE`: each progressive threshold
//! decodes and re-encodes, the facts projection applies aMule's consume rules,
//! and a High-ID is our public address with or without the extension.

use std::net::Ipv4Addr;

use rmule_ed2k::{IdChange, ServerAssignedFacts, ServerTcpFlags};
use rmule_primitives::{ClientId, Packet, PacketProtocol};

#[test]
fn id_change_decodes_typed_tcp_flags() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x40, vec![1, 0, 0, 0, 0, 1, 0, 0]);

    let id = IdChange::decode_packet(&packet).expect("decode id change");

    assert_eq!(id.client_id, ClientId::from_u32(1));
    assert_eq!(
        id.tcp_flags.expect("flags").bits(),
        ServerTcpFlags::LARGE_FILES
    );
}

/// A full 24-byte IDCHANGE payload: id 2, flags 0x100, standard port 4661,
/// public ip 171.25.158.106 (octets in wire order), obfuscation port 4671,
/// then 4 trailing bytes.
fn full_payload() -> Vec<u8> {
    let mut payload = 2_u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&0x100_u32.to_le_bytes());
    payload.extend_from_slice(&4661_u32.to_le_bytes());
    payload.extend_from_slice(&[171, 25, 158, 106]);
    payload.extend_from_slice(&4671_u32.to_le_bytes());
    payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    payload
}

#[test]
fn id_change_decodes_each_progressive_threshold_and_re_encodes() {
    // aMule ServerSocket.cpp's `size >=` ladder: 4 / 8 / 12 / 20. A
    // between-thresholds length (16) yields only what it clears, with the
    // residue preserved as trailing; bytes past 20 are trailing too.
    let cases: [(usize, bool, bool, bool, usize); 6] = [
        // (payload len, flags, standard port, ip+obf pair, trailing len)
        (4, false, false, false, 0),
        (8, true, false, false, 0),
        (12, true, true, false, 0),
        (16, true, true, false, 4),
        (20, true, true, true, 0),
        (24, true, true, true, 4),
    ];
    for (len, flags, standard, pair, trailing) in cases {
        let packet = Packet::new(
            PacketProtocol::Edonkey,
            0x40,
            full_payload()[..len].to_vec(),
        );
        let id = IdChange::decode_packet(&packet).expect("threshold decodes");
        assert_eq!(id.client_id.as_u32(), 2, "len {len}");
        assert_eq!(id.tcp_flags.is_some(), flags, "len {len}: flags");
        assert_eq!(
            id.standard_tcp_port,
            standard.then_some(4661),
            "len {len}: standard port"
        );
        assert_eq!(
            id.public_ip,
            pair.then_some(u32::from_le_bytes([171, 25, 158, 106])),
            "len {len}: public ip"
        );
        assert_eq!(
            id.obfuscation_tcp_port,
            pair.then_some(4671),
            "len {len}: obfuscation port"
        );
        assert_eq!(id.trailing.len(), trailing, "len {len}: trailing");
        assert_eq!(
            id.encode_packet().encode(),
            packet.encode(),
            "len {len}: byte-exact re-encode"
        );
    }
}

#[test]
fn facts_projection_applies_amules_consume_rules() {
    let decode = |payload: Vec<u8>| {
        IdChange::decode_packet(&Packet::new(PacketProtocol::Edonkey, 0x40, payload))
            .expect("decodes")
    };

    // The full extension projects: HighID-valued reported IP kept (rendered
    // from its wire octets), ports narrowed to u16.
    let facts = ServerAssignedFacts::project(&decode(full_payload()));
    assert_eq!(
        facts,
        ServerAssignedFacts {
            public_ip: Some(Ipv4Addr::new(171, 25, 158, 106)),
            standard_tcp_port: Some(4661),
            obfuscation_tcp_port: Some(4671),
        }
    );

    // A LowID-valued reported IP is discarded (aMule zeroes it), and a zero
    // obfuscation port means "not offered".
    let mut degenerate = full_payload()[..20].to_vec();
    degenerate[12..16].copy_from_slice(&(ClientId::LOW_ID_THRESHOLD - 1).to_le_bytes());
    degenerate[16..20].copy_from_slice(&0_u32.to_le_bytes());
    let facts = ServerAssignedFacts::project(&decode(degenerate));
    assert_eq!(
        facts,
        ServerAssignedFacts {
            public_ip: None,
            standard_tcp_port: Some(4661),
            obfuscation_tcp_port: None,
        }
    );

    // The 8-byte form asserts nothing — for a *Low* id. The High-ID case has
    // its own source; see below.
    assert_eq!(
        ServerAssignedFacts::project(&decode(full_payload()[..8].to_vec())),
        ServerAssignedFacts::default()
    );
}

#[test]
fn a_high_id_is_our_public_address_even_without_the_extension() {
    // The exact 8-byte IDCHANGE the interop Lugdunum sent during the server
    // crypt capture: id 0x030012AC (172.18.0.3, High), tcp_flags 0x17F9, and
    // no extension at all. aMule takes its address from the id here
    // (`CServerConnect::SetClientID` → `SetPublicIP(new_id)`); reading only the
    // extension leaves the UDP crypt send gates disarmed forever.
    let payload = vec![0xAC, 0x12, 0x00, 0x03, 0xF9, 0x17, 0x00, 0x00];
    let id = IdChange::decode_packet(&Packet::new(PacketProtocol::Edonkey, 0x40, payload))
        .expect("decodes");

    assert!(id.client_id.is_high_id());
    assert_eq!(id.public_ip, None, "the short form carries no extension");
    assert_eq!(
        ServerAssignedFacts::project(&id).public_ip,
        Some(Ipv4Addr::new(172, 18, 0, 3))
    );
}
