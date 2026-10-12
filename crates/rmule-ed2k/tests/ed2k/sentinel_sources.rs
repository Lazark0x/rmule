//! Sentinel-safe source lists (ADR-0085): a record whose id is `0xFFFFFFFF`
//! names no IPv4 address — its real address is sixteen bytes carried inline as
//! the record's last field (emule-qt `docs/protocol/ipv6-spec.md:694-703`,
//! reader `src/core/transfer/DownloadQueue.cpp:786-797` @ `73fff714`). The
//! reader consumes them in place, so the record after a sentinel starts where
//! it really starts; a list that does not measure keeps only the records
//! before its first sentinel.
//!
//! The two one-source payload sizes are ed2k-server#12's documented pair: 23
//! bytes classic (`[hash 16][count 1][id 4][port 2]`) and 39 bytes with the
//! sentinel's address — identical in every layout, which is why they alone
//! could never tell an inline reader from a trailing one.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_ed2k::{FoundSources, FoundSourcesObfu, GlobFoundSources};
use rmule_primitives::{
    Ipv4Endpoint, Ipv6Endpoint, Packet, PacketProtocol, PeerSource, SourceCryptOptions,
    SourceListTail, SourceSighting, UserHash,
};

const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const SENTINEL: u32 = PeerSource::IPV6_SENTINEL;

/// One record in the spec layout: `[id 4][port 2]`, then the sentinel's
/// address inline.
fn record(out: &mut Vec<u8>, id: u32, port: u16, v6: Option<Ipv6Addr>) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&port.to_le_bytes());
    if let Some(address) = v6 {
        out.extend_from_slice(&address.octets());
    }
}

/// `[hash 16][count]`, the head every source list shares.
fn head(hash_byte: u8, count: u8) -> Vec<u8> {
    let mut payload = vec![hash_byte; 16];
    payload.push(count);
    payload
}

fn found(payload: Vec<u8>) -> FoundSources {
    FoundSources::decode_packet(&Packet::new(PacketProtocol::Edonkey, 0x42, payload))
        .expect("a source list is never rejected whole")
}

/// `10.0.0.9` as the id field carries it.
const HIGH_ID: u32 = u32::from_le_bytes([10, 0, 0, 9]);

fn high(a: u8, b: u8, c: u8, d: u8, port: u16) -> PeerSource {
    PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), port))
}

/// emule-qt's own sentinel vector, `tests/tst_DownloadQueue.cpp:614-645` @
/// `73fff714` (`addServerSources_parsesIPv6Sentinel`): count 2, the sentinel
/// FIRST with `2a01:4f8::11:2233` inline, then the High ID `88.77.66.55`, both
/// at port 4662 — "Sentinel FIRST so a mis-count desyncs the second".
fn emule_qt_vector() -> Vec<u8> {
    let hash = [40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
    let v6bytes = [
        0x2a, 0x01, 0x04, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22,
        0x33,
    ];
    let mut body = hash.to_vec();
    body.push(2);
    body.extend_from_slice(&SENTINEL.to_le_bytes());
    body.extend_from_slice(&4662u16.to_le_bytes());
    body.extend_from_slice(&v6bytes);
    // `Address::fromString("88.77.66.55").toNetworkUint32()` appended low byte
    // first: the octets in order.
    body.extend_from_slice(&[88, 77, 66, 55]);
    body.extend_from_slice(&4662u16.to_le_bytes());
    body
}

const EMULE_QT_V6: Ipv6Addr = Ipv6Addr::new(0x2a01, 0x4f8, 0, 0, 0, 0, 0x11, 0x2233);

#[test]
fn emule_qts_vector_reads_the_sentinel_inline_and_the_high_id_behind_it() {
    let payload = emule_qt_vector();
    let decoded = found(payload.clone());
    assert_eq!(
        decoded.sources(),
        [
            PeerSource::Ipv6(Ipv6Endpoint::new(EMULE_QT_V6, 4662)),
            high(88, 77, 66, 55, 4662),
        ],
        "both sources parsed, the second not desynced by the first's sixteen bytes"
    );
    assert_eq!(decoded.tail(), SourceListTail::Read { sentinels: 1 });
    assert_eq!(
        decoded.encode_packet().payload(),
        payload.as_slice(),
        "rmule writes the layout it reads"
    );
}

#[test]
fn emule_qts_vector_reads_the_same_on_the_packed_udp_form() {
    let mut datagram = vec![PacketProtocol::Edonkey.as_byte(), 0x9B];
    datagram.extend_from_slice(&emule_qt_vector());
    let (decoded, consumed) = GlobFoundSources::decode_udp(&datagram).expect("decodes");
    assert_eq!(consumed, datagram.len());
    assert_eq!(
        decoded.sources(),
        [
            PeerSource::Ipv6(Ipv6Endpoint::new(EMULE_QT_V6, 4662)),
            high(88, 77, 66, 55, 4662),
        ]
    );
}

#[test]
fn the_pre_fix_trailing_layout_never_yields_a_source_past_its_first_sentinel() {
    // The bytes rmule's own encoder used to write: records at a 6-byte
    // stride, the two addresses appended after the last one.
    let mut payload = head(0x22, 4);
    record(&mut payload, HIGH_ID, 4662, None);
    record(&mut payload, SENTINEL, 5000, None);
    record(&mut payload, u32::from_le_bytes([10, 0, 0, 10]), 4663, None);
    record(&mut payload, SENTINEL, 5001, None);
    payload.extend_from_slice(&V6.octets());
    payload.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());

    let decoded = found(payload);
    assert_eq!(
        decoded.sources(),
        [high(10, 0, 0, 9, 4662)],
        "the record before the first sentinel stands; nothing read off address bytes does"
    );
    assert!(decoded.tail().is_malformed());
}

#[test]
fn a_classic_one_source_payload_is_twenty_three_bytes_and_reads_ipv4() {
    let mut payload = head(0x11, 1);
    record(&mut payload, HIGH_ID, 4662, None);
    assert_eq!(payload.len(), 23, "ed2k-server#12's classic source payload");

    let decoded = found(payload);
    assert_eq!(decoded.sources(), [high(10, 0, 0, 9, 4662)]);
    assert_eq!(decoded.tail(), SourceListTail::Read { sentinels: 0 });
}

#[test]
fn a_sentinel_one_source_payload_is_thirty_nine_bytes_and_reads_ipv6() {
    let mut payload = head(0x11, 1);
    record(&mut payload, SENTINEL, 4662, Some(V6));
    assert_eq!(
        payload.len(),
        39,
        "ed2k-server#12's sentinel source payload"
    );

    let decoded = found(payload.clone());
    assert_eq!(
        decoded.sources(),
        [PeerSource::Ipv6(Ipv6Endpoint::new(V6, 4662))],
        "the sentinel's address comes from its inline bytes, never from its id"
    );
    assert_eq!(decoded.tail(), SourceListTail::Read { sentinels: 1 });
    assert_eq!(decoded.encode_packet().payload(), payload.as_slice());
}

#[test]
fn consecutive_sentinels_each_consume_their_own_address() {
    // emule-qt `tests/tst_DownloadQueue.cpp:698-707`
    // (`addServerSources_vetsIPv6LikeIPv4`): four sentinels in a row at 4662.
    // emule-qt's own isGoodIP/ban/filter vetting drops three of them; rmule's
    // codec gate is only `is_usable_tag_identity`, which all four pass.
    let addresses = [
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001),
        Ipv6Addr::new(0x2a01, 0x04f8, 0, 0, 0, 0, 0, 0xdead),
        Ipv6Addr::new(0x2a02, 0x26f0, 0, 0, 0, 0, 0, 0xbeef),
        Ipv6Addr::new(0x2a03, 0x2880, 0, 0, 0, 0, 0, 0x0001),
    ];
    let mut payload = vec![43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    payload.push(4);
    for address in addresses {
        record(&mut payload, SENTINEL, 4662, Some(address));
    }

    let decoded = found(payload);
    let expected: Vec<PeerSource> = addresses
        .iter()
        .map(|a| PeerSource::Ipv6(Ipv6Endpoint::new(*a, 4662)))
        .collect();
    assert_eq!(decoded.sources(), expected.as_slice());
    assert_eq!(decoded.tail(), SourceListTail::Read { sentinels: 4 });
}

#[test]
fn an_unusable_sentinel_address_costs_its_record_and_consumes_its_bytes() {
    for refused in [
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "fd00::1",
    ] {
        let address: Ipv6Addr = refused.parse().unwrap();
        let mut body = head(0x33, 2);
        record(&mut body, SENTINEL, 5000, Some(address));
        record(&mut body, HIGH_ID, 4662, None);

        let decoded = found(body.clone());
        assert_eq!(
            decoded.sources(),
            [high(10, 0, 0, 9, 4662)],
            "{refused}: no source, and the record behind it still in step"
        );
        assert_eq!(decoded.tail(), SourceListTail::Read { sentinels: 1 });

        let mut datagram = vec![PacketProtocol::Edonkey.as_byte(), 0x9B];
        datagram.extend_from_slice(&body);
        let (glob, _) = GlobFoundSources::decode_udp(&datagram).expect("decodes");
        assert_eq!(
            glob.sources(),
            [high(10, 0, 0, 9, 4662)],
            "{refused} on 0x9B"
        );
    }
}

#[test]
fn a_sentinel_cut_short_keeps_only_the_records_before_it() {
    let mut payload = head(0x33, 3);
    record(&mut payload, HIGH_ID, 4662, None);
    record(&mut payload, SENTINEL, 5000, None);
    payload.extend_from_slice(&V6.octets()[..10]);

    let decoded = found(payload);
    assert_eq!(decoded.sources(), [high(10, 0, 0, 9, 4662)]);
    assert_eq!(
        decoded.tail(),
        SourceListTail::Malformed {
            sentinels: 1,
            tail_len: 10
        }
    );
}

#[test]
fn a_sentinel_id_never_becomes_the_broadcast_address() {
    let mut payload = head(0x44, 1);
    record(&mut payload, SENTINEL, 4662, None);
    let decoded = found(payload);
    assert!(
        decoded.sources().is_empty(),
        "an unaccompanied sentinel is dropped, not read as 255.255.255.255"
    );
    assert!(decoded.tail().is_malformed());
}

#[test]
fn trailing_bytes_with_no_sentinel_cost_no_record() {
    let mut payload = head(0x55, 1);
    record(&mut payload, HIGH_ID, 4662, None);
    payload.extend_from_slice(b"unmodelled trailer");
    let decoded = found(payload);
    assert_eq!(
        decoded.sources(),
        [high(10, 0, 0, 9, 4662)],
        "an unexplained trailer is a diagnostic, never a rejected packet"
    );
    assert_eq!(
        decoded.tail(),
        SourceListTail::Malformed {
            sentinels: 0,
            tail_len: 18
        }
    );
}

#[test]
fn a_truncated_classic_record_array_is_still_a_rejected_frame() {
    let mut payload = head(0x66, 2);
    payload.extend_from_slice(&HIGH_ID.to_le_bytes());
    assert!(
        FoundSources::decode_packet(&Packet::new(PacketProtocol::Edonkey, 0x42, payload)).is_err()
    );
}

#[test]
fn a_high_id_that_packs_to_the_sentinel_is_refused_at_construction() {
    let broadcast = high(255, 255, 255, 255, 4662);
    assert!(FoundSources::new(crate::fixture::hash(0x01), vec![broadcast]).is_err());
}

#[test]
fn the_obfuscated_form_carries_the_address_after_the_crypt_fields() {
    // ipv6-spec.md:694-703: `[id][port][crypt][user hash iff crypt & 0x80]`,
    // then the sentinel's address ALWAYS LAST.
    let user_hash = UserHash::from_bytes([0xAB; 16]);
    let mut payload = head(0x77, 2);
    record(&mut payload, SENTINEL, 5000, None);
    payload.push(0x80 | 0x01);
    payload.extend_from_slice(user_hash.as_bytes());
    payload.extend_from_slice(&V6.octets());
    record(&mut payload, HIGH_ID, 4662, None);
    payload.push(0x00);

    let decoded = FoundSourcesObfu::decode_packet(&Packet::new(
        PacketProtocol::Edonkey,
        0x44,
        payload.clone(),
    ))
    .expect("decodes");
    let v6 = SourceSighting::new(
        PeerSource::Ipv6(Ipv6Endpoint::new(V6, 5000)),
        Some(user_hash),
        Some(SourceCryptOptions::from_byte(0x01)),
    );
    let v4 = SourceSighting::new(
        high(10, 0, 0, 9, 4662),
        None,
        Some(SourceCryptOptions::from_byte(0)),
    );
    assert_eq!(decoded.sources(), [v6, v4]);
    assert_eq!(decoded.tail(), SourceListTail::Read { sentinels: 1 });
    assert_eq!(decoded.encode_packet().payload(), payload.as_slice());
}

#[test]
fn a_packed_datagram_with_the_sentinel_body_last_reads_both() {
    // The legal shape (ipv6-spec.md §4.4): a sentinel-bearing `0x9B`
    // body is the last in its datagram.
    let mut datagram = vec![PacketProtocol::Edonkey.as_byte(), 0x9B];
    datagram.extend_from_slice(&head(0x99, 1));
    record(&mut datagram, HIGH_ID, 4663, None);
    let second_at = datagram.len();
    datagram.extend_from_slice(&[PacketProtocol::Edonkey.as_byte(), 0x9B]);
    datagram.extend_from_slice(&head(0x88, 1));
    record(&mut datagram, SENTINEL, 4662, Some(V6));

    let (first, consumed) = GlobFoundSources::decode_udp(&datagram).expect("first packet");
    assert_eq!(consumed, second_at);
    assert_eq!(first.sources(), [high(10, 0, 0, 9, 4663)]);
    let (second, rest) = GlobFoundSources::decode_udp(&datagram[consumed..]).expect("second");
    assert_eq!(rest, datagram.len() - consumed);
    assert_eq!(
        second.sources(),
        [PeerSource::Ipv6(Ipv6Endpoint::new(V6, 4662))]
    );
}

#[test]
fn tolerance_a_sentinel_body_ahead_of_another_packet_stays_in_step() {
    // A server must not send this shape; rmule still reads it, because the
    // inline address is part of the body the count delimits.
    let mut datagram = vec![PacketProtocol::Edonkey.as_byte(), 0x9B];
    datagram.extend_from_slice(&head(0x88, 1));
    record(&mut datagram, SENTINEL, 4662, Some(V6));
    let second_at = datagram.len();
    datagram.extend_from_slice(&[PacketProtocol::Edonkey.as_byte(), 0x9B]);
    datagram.extend_from_slice(&head(0x99, 1));
    record(&mut datagram, HIGH_ID, 4663, None);

    let (first, consumed) = GlobFoundSources::decode_udp(&datagram).expect("first packet");
    assert_eq!(consumed, second_at, "the address is part of this packet");
    assert_eq!(first.tail(), SourceListTail::Read { sentinels: 1 });
    let (second, _) = GlobFoundSources::decode_udp(&datagram[consumed..]).expect("second packet");
    assert_eq!(second.file_hash(), crate::fixture::hash(0x99));
    assert_eq!(second.sources(), [high(10, 0, 0, 9, 4663)]);
}

#[test]
fn a_packed_datagram_whose_sentinel_is_cut_short_ends_the_datagram() {
    let mut datagram = vec![PacketProtocol::Edonkey.as_byte(), 0x9B];
    datagram.extend_from_slice(&head(0xAA, 2));
    record(&mut datagram, HIGH_ID, 4662, None);
    record(&mut datagram, SENTINEL, 5000, None);
    datagram.extend_from_slice(&V6.octets()[..8]);

    let (packet, consumed) = GlobFoundSources::decode_udp(&datagram).expect("never rejected whole");
    assert_eq!(packet.sources(), [high(10, 0, 0, 9, 4662)]);
    assert_eq!(
        packet.tail(),
        SourceListTail::Malformed {
            sentinels: 1,
            tail_len: 8
        }
    );
    assert_eq!(
        consumed,
        datagram.len(),
        "nothing sane can follow a short list"
    );
}
