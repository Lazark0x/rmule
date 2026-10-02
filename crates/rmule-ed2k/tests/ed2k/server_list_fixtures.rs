//! `OP_SERVERLIST` against its recorded cases: round-trips byte-exact, accepts
//! zero entries, rejects a count that disagrees with the payload, and reads the
//! optional trailing IPv6 block (ADR-0087 §4.6).

use std::fs;
use std::net::Ipv4Addr;

use rmule_ed2k::{ServerList, ServerListTail};
use rmule_primitives::{Ipv4Endpoint, Ipv6Endpoint, Packet, PacketProtocol};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ServerListFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    // `[expected]` is intentionally not deserialised — per-entry
    // ip/port projection asserts would be tautological with the round
    // trip below.
}

#[test]
fn server_list_fixtures_round_trip_byte_exact() {
    for path in crate::fixture::case_paths_named("server", "server_list") {
        let raw = fs::read_to_string(&path).expect("read toml fixture");
        let fixture: ServerListFixture =
            toml::from_str(&raw).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        assert!(fixture.accepted, "{} accepted", fixture.name);
        assert!(
            !fixture.provenance.is_empty(),
            "{} provenance",
            fixture.name
        );
        assert!(
            !fixture.source_note.is_empty(),
            "{} source_note",
            fixture.name
        );

        let bytes = fs::read(path.with_extension("bin")).expect("read bin fixture");
        let packet = Packet::decode_exact(&bytes)
            .unwrap_or_else(|err| panic!("{} packet: {err}", fixture.name));
        let list = ServerList::decode_packet(&packet)
            .unwrap_or_else(|err| panic!("{} decode: {err}", fixture.name));
        assert_eq!(
            list.encode_packet().encode(),
            bytes,
            "{} re-encode",
            fixture.name
        );
    }
}

#[test]
fn server_list_rejects_count_mismatch() {
    // declares 2 entries but only supplies 6 bytes (one entry's worth)
    let payload = vec![0x02, 0x7f, 0x00, 0x00, 0x01, 0x35, 0x12];
    let packet = Packet::new(PacketProtocol::Edonkey, 0x32, payload);
    assert!(ServerList::decode_packet(&packet).is_err());
}

/// Bytes after the IPv4 array are no longer a rejection: ADR-0087 §4.6 makes
/// the first of them an IPv6 count, so a stray `0xFF` declares 255 entries and
/// carries none. That is a **malformed tail**, not a bad packet — rejecting the
/// frame would discard an IPv4 array the server sent correctly, which is the
/// opposite of the spec's "bounds-check before reading" rule.
///
/// This replaces the pre-ADR-0087 contract, which was that any trailing byte
/// failed the decode.
#[test]
fn a_stray_byte_after_the_v4_array_is_a_malformed_ipv6_block_not_a_bad_packet() {
    let payload = vec![0x01, 0x7f, 0x00, 0x00, 0x01, 0x35, 0x12, 0xff];
    let packet = Packet::new(PacketProtocol::Edonkey, 0x32, payload);
    let list = ServerList::decode_packet(&packet).expect("the IPv4 array still decodes");
    assert_eq!(
        list.servers(),
        &[Ipv4Endpoint::new(Ipv4Addr::new(127, 0, 0, 1), 0x1235)]
    );
    assert_eq!(list.tail(), ServerListTail::Malformed { trailing_len: 1 });
}

#[test]
fn server_list_rejects_empty_payload() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x32, Vec::new());
    assert!(ServerList::decode_packet(&packet).is_err());
}

#[test]
fn server_list_accepts_zero_entries() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x32, vec![0x00]);
    let list = ServerList::decode_packet(&packet).expect("zero entries decode");
    assert!(list.servers().is_empty());
    assert_eq!(list.encode_packet().encode(), packet.encode());
}

/// ADR-0087 §4.6's trailing IPv6 block: eighteen bytes per entry (sixteen
/// network-order address bytes plus the little-endian port), appended after the
/// self-terminating IPv4 array.
///
/// Evidence: **`single-oracle` (eNode-go) and un-captured** — the other server
/// implementing the dialect never mentions this block, so these are the spec's
/// bytes.
#[test]
fn a_trailing_ipv6_block_reads_after_the_self_terminating_v4_array() {
    let first: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let second: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
    let mut payload = vec![1u8];
    payload.extend_from_slice(&Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4661).encode());
    payload.push(2);
    payload.extend_from_slice(&first.octets());
    payload.extend_from_slice(&4661u16.to_le_bytes());
    payload.extend_from_slice(&second.octets());
    payload.extend_from_slice(&5661u16.to_le_bytes());

    let packet = Packet::new(PacketProtocol::Edonkey, 0x32, payload.clone());
    let list = ServerList::decode_packet(&packet).expect("decodes");
    assert_eq!(
        list.servers(),
        &[Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4661)]
    );
    assert_eq!(
        list.ipv6_servers(),
        &[
            Ipv6Endpoint::new(first, 4661),
            Ipv6Endpoint::new(second, 5661)
        ]
    );
    assert_eq!(list.tail(), ServerListTail::Read { count: 2 });
    assert_eq!(
        list.encode_packet().payload(),
        payload.as_slice(),
        "a read block is written back byte-exact"
    );
}

/// A legacy server sends **nothing** after the IPv4 array — not even a zero
/// byte — so "no bytes remain" reads as "no block", and the re-encode adds no
/// byte the wire has never carried.
#[test]
fn a_legacy_list_has_an_absent_tail_and_re_encodes_byte_exact() {
    let mut payload = vec![1u8];
    payload.extend_from_slice(&Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 20), 4661).encode());
    let packet = Packet::new(PacketProtocol::Edonkey, 0x32, payload.clone());
    let list = ServerList::decode_packet(&packet).expect("decodes");
    assert_eq!(list.tail(), ServerListTail::Absent);
    assert!(list.ipv6_servers().is_empty());
    assert_eq!(list.encode_packet().payload(), payload.as_slice());

    // A capable server with nothing to offer writes a zero byte, and that is a
    // different statement from silence.
    let empty_block = ServerList::new(Vec::new())
        .unwrap()
        .with_ipv6_servers(Vec::new())
        .unwrap();
    assert_eq!(empty_block.tail(), ServerListTail::Read { count: 0 });
    assert_eq!(empty_block.encode_packet().payload(), &[0u8, 0u8]);
}

/// A block whose declared count outruns the payload costs the IPv6 half and
/// nothing else: the IPv4 array was already parsed and is still valid, so the
/// packet is never rejected whole.
#[test]
fn a_block_that_outruns_its_payload_keeps_every_ipv4_entry() {
    let v4 = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4661);
    let mut payload = vec![1u8];
    payload.extend_from_slice(&v4.encode());
    payload.push(3); // claims three entries...
    payload.extend_from_slice(&[0xAA; 20]); // ...and carries one and a bit
    let packet = Packet::new(PacketProtocol::Edonkey, 0x32, payload);
    let list = ServerList::decode_packet(&packet).expect("the IPv4 half still decodes");
    assert_eq!(list.servers(), &[v4]);
    assert!(list.ipv6_servers().is_empty());
    assert_eq!(list.tail(), ServerListTail::Malformed { trailing_len: 21 });
}

/// A block that leaves bytes over is as malformed as one that runs short: the
/// frame is length-delimited, so nothing may follow the declared entries.
#[test]
fn a_block_with_bytes_past_its_entries_is_malformed() {
    let v4 = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4661);
    let mut payload = vec![1u8];
    payload.extend_from_slice(&v4.encode());
    payload.push(1);
    payload.extend_from_slice(
        &"2a01:4f8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    payload.extend_from_slice(&4661u16.to_le_bytes());
    payload.push(0xEE); // one byte the block does not account for
    let packet = Packet::new(PacketProtocol::Edonkey, 0x32, payload);
    let list = ServerList::decode_packet(&packet).expect("the IPv4 half still decodes");
    assert_eq!(list.servers(), &[v4]);
    assert!(list.ipv6_servers().is_empty());
    assert_eq!(list.tail(), ServerListTail::Malformed { trailing_len: 20 });
}
