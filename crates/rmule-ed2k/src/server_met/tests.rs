//! `server.met` decode/encode against its recorded and handwritten cases:
//! the two accepted headers and the known.met trap, container unwrapping and
//! its size ceiling, the truncation posture, the three projected tags plus
//! ADR-0087's `ST_IPV6` row, and the duplicate-merge rule.
//!
//! Extracted from the parent when the pair crossed the file ceiling; the
//! production half is the contract, this is its evidence.

use std::io::Write;
use std::net::Ipv4Addr;

use flate2::Compression;
use flate2::write::GzEncoder;
use rmule_primitives::TagName;

use super::*;
fn name_tag(value: &str) -> Tag {
    Tag::new(
        TagName::compact_id(TAG_SERVERNAME),
        TagValue::String(Ed2kText::from_utf8(value)),
    )
}

fn description_tag(value: &str) -> Tag {
    Tag::new(
        TagName::compact_id(TAG_DESCRIPTION),
        TagValue::String(Ed2kText::from_utf8(value)),
    )
}

fn preference_tag(value: u32) -> Tag {
    Tag::new(TagName::compact_id(TAG_PREFERENCE), TagValue::U32(value))
}

fn encode_row(ip: Ipv4Addr, port: u16, tags: &[Tag]) -> Vec<u8> {
    let mut bytes = Ipv4Endpoint::new(ip, port).encode().to_vec();
    bytes.extend_from_slice(&u32::try_from(tags.len()).unwrap().to_le_bytes());
    for tag in tags {
        bytes.extend(tag.encode());
    }
    bytes
}

fn encode_file(header: u8, declared_count: u32, rows: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![header];
    bytes.extend_from_slice(&declared_count.to_le_bytes());
    for row in rows {
        bytes.extend_from_slice(row);
    }
    bytes
}

fn gzip_bytes(input: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn header_0xe0_and_0x0e_are_both_accepted() {
    for header in [HEADER_AMULE, HEADER_MET] {
        let bytes = encode_file(header, 0, &[]);
        let file =
            ServerMet::decode(&bytes).unwrap_or_else(|err| panic!("header 0x{header:02X}: {err}"));
        assert!(file.entries().is_empty());
    }
}

#[test]
fn header_0x0f_known_met_trap_is_rejected() {
    let bytes = encode_file(0x0F, 0, &[]);
    assert_eq!(
        ServerMet::decode(&bytes),
        Err(ServerMetError::InvalidHeader { byte: 0x0F })
    );
}

#[test]
fn arbitrary_invalid_header_is_rejected() {
    let bytes = encode_file(0x01, 0, &[]);
    assert_eq!(
        ServerMet::decode(&bytes),
        Err(ServerMetError::InvalidHeader { byte: 0x01 })
    );
}

#[test]
fn empty_input_is_missing_header() {
    assert_eq!(ServerMet::decode(&[]), Err(ServerMetError::MissingHeader));
}

#[test]
fn a_file_cut_inside_the_count_is_truncated_not_empty() {
    let full = [HEADER_AMULE, 0x00, 0x00, 0x00, 0x00];
    for cut in 1..full.len() {
        let file = ServerMet::decode(&full[..cut]).expect("valid header, short count");
        assert!(file.entries().is_empty());
        assert!(
            file.is_truncated(),
            "cut at {cut} bytes must read as truncated"
        );
    }
    assert!(!ServerMet::decode(&full).expect("empty list").is_truncated());
}

#[test]
fn truncation_mid_row_prefix_keeps_prior_complete_rows() {
    let row1 = encode_row(Ipv4Addr::new(1, 2, 3, 4), 4661, &[name_tag("Alpha")]);
    let row2 = encode_row(Ipv4Addr::new(5, 6, 7, 8), 4662, &[name_tag("Beta")]);
    let row3_partial =
        encode_row(Ipv4Addr::new(9, 9, 9, 9), 4663, &[name_tag("Gamma")])[..3].to_vec();
    // Declares 3 rows but only supplies 2 complete ones.
    let bytes = encode_file(HEADER_AMULE, 3, &[row1, row2, row3_partial]);

    let file = ServerMet::decode(&bytes).expect("decode");
    assert_eq!(file.entries().len(), 2);
    assert_eq!(file.entries()[0].name().to_display_string(), "Alpha");
    assert_eq!(file.entries()[1].name().to_display_string(), "Beta");
    // The short read is observable, not silent: the header declared 3.
    assert!(file.is_truncated());
    assert_eq!(file.declared_count(), 3);
}

#[test]
fn a_truncated_decode_reencodes_with_the_real_row_count() {
    // `encode` must count the rows it actually writes, not echo the
    // (larger) declared count a truncated download carried — else the
    // re-encoded file is self-inconsistent and reads as truncated forever.
    let row1 = encode_row(Ipv4Addr::new(1, 2, 3, 4), 4661, &[name_tag("Alpha")]);
    let bytes = encode_file(HEADER_AMULE, 3, &[row1]);
    let file = ServerMet::decode(&bytes).expect("decode");
    assert!(
        file.is_truncated(),
        "the input under-delivers its declared 3 rows"
    );

    let reencoded = file.encode();
    let count = u32::from_le_bytes(reencoded[1..5].try_into().unwrap());
    assert_eq!(count, 1, "the header must count the rows actually written");
    assert!(
        !ServerMet::decode(&reencoded)
            .expect("round-trip")
            .is_truncated(),
        "a re-encode of the salvaged rows is a well-formed, untruncated file"
    );
}

#[test]
fn truncation_mid_tag_list_keeps_prior_complete_rows() {
    let row1 = encode_row(Ipv4Addr::new(1, 2, 3, 4), 4661, &[name_tag("Alpha")]);
    // Declares 2 tags in its header but only supplies 1 tag's bytes.
    let mut row2_partial = Ipv4Endpoint::new(Ipv4Addr::new(5, 6, 7, 8), 4662)
        .encode()
        .to_vec();
    row2_partial.extend_from_slice(&2u32.to_le_bytes());
    row2_partial.extend(name_tag("Beta").encode());
    let bytes = encode_file(HEADER_AMULE, 2, &[row1, row2_partial]);

    let file = ServerMet::decode(&bytes).expect("decode");
    assert_eq!(file.entries().len(), 1);
    assert_eq!(file.entries()[0].name().to_display_string(), "Alpha");
}

#[test]
fn gzip_wrapped_payload_decodes_transparently() {
    let row = encode_row(Ipv4Addr::new(9, 9, 9, 9), 4661, &[name_tag("Gz Server")]);
    let plain = encode_file(HEADER_AMULE, 1, &[row]);
    let gzipped = gzip_bytes(&plain);

    let file = ServerMet::decode(&gzipped).expect("gzip decode");
    assert_eq!(file.entries()[0].name().to_display_string(), "Gz Server");
    assert!(!file.is_truncated(), "a complete file is not truncated");
    assert_eq!(file.declared_count(), 1);
}

#[test]
fn corrupt_gzip_body_is_rejected() {
    let bytes = vec![0x1F, 0x8B, 0xFF, 0xFF, 0xFF, 0xFF];
    assert_eq!(
        ServerMet::decode(&bytes),
        Err(ServerMetError::GzipInflateFailed)
    );
}

#[test]
fn gzip_inflating_past_the_cap_is_rejected() {
    // A gzip bomb: a stream that expands beyond the ceiling is refused
    // rather than allocated. Exercised through the helper with a tiny cap
    // so the test needs no multi-megabyte buffer.
    let plain = vec![0u8; 4096];
    let gzipped = gzip_bytes(&plain);
    assert_eq!(
        inflate_gzip_capped(&gzipped, 64),
        Err(ServerMetError::GzipInflatedTooLarge)
    );
    // A stream that fits exactly at the cap still inflates.
    assert_eq!(inflate_gzip_capped(&gzipped, 4096), Ok(plain));
}

#[test]
fn zip_container_is_rejected() {
    let bytes = vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
    assert_eq!(
        ServerMet::decode(&bytes),
        Err(ServerMetError::UnsupportedContainer)
    );
}

#[test]
fn preference_tag_maps_to_normal_high_low() {
    for (raw, expected) in [
        (0u32, ServerPriority::Normal),
        (1, ServerPriority::High),
        (2, ServerPriority::Low),
    ] {
        let row = encode_row(Ipv4Addr::new(1, 1, 1, 1), 1, &[preference_tag(raw)]);
        let bytes = encode_file(HEADER_AMULE, 1, &[row]);
        let file = ServerMet::decode(&bytes).expect("decode");
        assert_eq!(
            file.entries()[0].priority(),
            expected,
            "raw preference {raw}"
        );
    }
}

#[test]
fn out_of_range_preference_normalizes_to_normal() {
    let row = encode_row(Ipv4Addr::new(1, 1, 1, 1), 1, &[preference_tag(99)]);
    let bytes = encode_file(HEADER_AMULE, 1, &[row]);
    let file = ServerMet::decode(&bytes).expect("decode");
    assert_eq!(file.entries()[0].priority(), ServerPriority::Normal);
}

#[test]
fn name_and_description_tags_are_projected_from_bytes() {
    let row = encode_row(
        Ipv4Addr::new(1, 1, 1, 1),
        4661,
        &[name_tag("Alpha"), description_tag("A fine server")],
    );
    let bytes = encode_file(HEADER_AMULE, 1, &[row]);
    let file = ServerMet::decode(&bytes).expect("decode");
    assert_eq!(file.entries()[0].name().to_display_string(), "Alpha");
    assert_eq!(
        file.entries()[0].description().to_display_string(),
        "A fine server"
    );
}

#[test]
fn missing_name_tag_synthesizes_server_address_name() {
    let row = encode_row(Ipv4Addr::new(203, 0, 113, 5), 4661, &[]);
    let bytes = encode_file(HEADER_AMULE, 1, &[row]);
    let file = ServerMet::decode(&bytes).expect("decode");
    assert_eq!(
        file.entries()[0].name().to_display_string(),
        "Server 203.0.113.5:4661"
    );
}

#[test]
fn a_nameless_ipv6_only_row_is_named_by_its_ipv6_address() {
    let address: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let row = encode_row(
        Ipv4Addr::UNSPECIFIED,
        4661,
        &[ipv6_address_tag_compact(ST_IPV6, address)],
    );
    let file = ServerMet::decode(&encode_file(HEADER_AMULE, 1, &[row])).expect("decode");
    assert_eq!(
        file.entries()[0].name().to_display_string(),
        "Server [2a01:4f8::1]:4661",
        "never `Server 0.0.0.0:4661`"
    );
    assert_eq!(
        file.entries()[0].identity(),
        PeerEndpoint::V6(Ipv6Endpoint::new(address, 4661))
    );
}

/// ADR-0087 §4.8's worked bytes: `81 99` then sixteen raw network-order
/// address bytes, on a row whose header IP is `0` — the compatibility
/// trick that makes stock eMule *ignore* an IPv6 server instead of
/// mis-dialling one.
#[test]
fn an_ipv6_only_row_is_a_zero_header_ip_plus_an_st_ipv6_hash_tag() {
    let address: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let mut expected_tag = vec![0x81, ST_IPV6];
    expected_tag.extend_from_slice(&address.octets());

    let entry = ServerMetEntry::new(
        Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 4661),
        Ed2kText::from_utf8("v6 only"),
        Ed2kText::from_bytes(Vec::new()),
        ServerPriority::Normal,
    )
    .with_ipv6(address);
    let encoded = ServerMet::from_entries(vec![entry]).encode();
    assert!(
        encoded
            .windows(expected_tag.len())
            .any(|window| window == expected_tag),
        "the row carries ST_IPV6 as a 16-byte HASH, not a length-prefixed blob"
    );

    let decoded = ServerMet::decode(&encoded).expect("decode");
    let row = &decoded.entries()[0];
    assert_eq!(row.ipv6(), Some(address));
    assert_eq!(
        row.ipv6_endpoint(),
        Some(Ipv6Endpoint::new(address, 4661)),
        "the header's one port field serves both families"
    );
    assert!(row.is_ipv6_only());
    // The `u32` projection every classic validator reads is 0 — which is
    // exactly why routability must be judged on the 128 bits.
    assert!(row.endpoint().ip.is_unspecified());
}

#[test]
fn a_second_st_ipv6_never_overwrites_the_first_and_an_unusable_one_is_dropped() {
    let first: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let second: std::net::Ipv6Addr = "2a01:4f8::2".parse().unwrap();
    let row = encode_row(
        Ipv4Addr::UNSPECIFIED,
        4661,
        &[
            ipv6_address_tag_compact(ST_IPV6, first),
            ipv6_address_tag_compact(ST_IPV6, second),
        ],
    );
    let decoded = ServerMet::decode(&encode_file(HEADER_AMULE, 1, &[row])).expect("decode");
    assert_eq!(decoded.entries()[0].ipv6(), Some(first));

    // A link-local address names two hosts to two readers through a
    // scope-less tag, so the row keeps its (here empty) IPv4 half and
    // loses only the tag — it never becomes a server rmule would dial.
    let unusable = encode_row(
        Ipv4Addr::UNSPECIFIED,
        4661,
        &[ipv6_address_tag_compact(
            ST_IPV6,
            "fe80::1".parse().unwrap(),
        )],
    );
    let decoded = ServerMet::decode(&encode_file(HEADER_AMULE, 1, &[unusable])).expect("decode");
    assert_eq!(decoded.entries()[0].ipv6(), None);
    assert!(!decoded.entries()[0].is_ipv6_only());
}

fn sample_entry(name: &str, description: &str, priority: ServerPriority) -> ServerMetEntry {
    ServerMetEntry {
        endpoint: Ipv4Endpoint::new(Ipv4Addr::new(1, 1, 1, 1), 4661),
        ipv6: None,
        name: Ed2kText::from_utf8(name),
        description: Ed2kText::from_utf8(description),
        priority,
        figures: ServerMetFigures::NONE,
        obfuscation: ServerMetObfuscation::NONE,
        aux_ports: Vec::new(),
    }
}

/// The figures read from the tags aMule writes them in: `"users"` and
/// `"files"` named by text, the rest by id, a packed version as `hi.lo`, and
/// the first string version kept over a second.
#[test]
fn a_rows_figures_decode_from_their_tags_and_round_trip() {
    let named = |name: &str, value: u32| {
        Tag::new(
            TagName::text(name).expect("a tag name"),
            TagValue::U32(value),
        )
    };
    let row = encode_row(
        Ipv4Addr::new(1, 2, 3, 4),
        4661,
        &[
            name_tag("fig"),
            named("users", 1200),
            named("files", 340_000),
            Tag::new(TagName::compact_id(0x0C), TagValue::U16(87)),
            Tag::new(TagName::compact_id(0x90), TagValue::U32(1_700_000_000)),
            Tag::new(TagName::compact_id(0x88), TagValue::U32(1000)),
            Tag::new(TagName::compact_id(0x89), TagValue::U32(1500)),
            Tag::new(TagName::compact_id(0x91), TagValue::U32((17 << 16) | 15)),
        ],
    );
    let decoded = ServerMet::decode(&encode_file(HEADER_AMULE, 1, &[row])).expect("decode");
    let figures = decoded.entries()[0].figures().clone();
    assert_eq!(
        figures,
        ServerMetFigures {
            ping_ms: Some(87),
            users: Some(1200),
            files: Some(340_000),
            soft_files: Some(1000),
            hard_files: Some(1500),
            last_ping: Some(1_700_000_000),
            version: Some("17.15".to_string()),
        }
    );
    let again = ServerMet::decode(&decoded.encode()).expect("re-decode");
    assert_eq!(again.entries()[0].figures(), &figures);
}

/// aMule's `AddTagFromFile` reads `ST_UDPFLAGS` and `ST_TCPPORTOBFUSCATION`
/// (`Server.cpp:239-258`); a merge keeps a fact a fresh row is silent about,
/// and takes one it states even from a never-pinged row.
#[test]
fn a_rows_obfuscation_tags_decode_round_trip_and_merge() {
    let row = encode_row(
        Ipv4Addr::new(1, 2, 3, 4),
        4661,
        &[
            name_tag("obf"),
            Tag::new(TagName::compact_id(0x92), TagValue::U32(0x400)),
            Tag::new(TagName::compact_id(0x97), TagValue::U16(4674)),
        ],
    );
    let decoded = ServerMet::decode(&encode_file(HEADER_AMULE, 1, &[row])).expect("decode");
    let entry = decoded.entries()[0].clone();
    assert_eq!(
        entry.obfuscation(),
        ServerMetObfuscation {
            udp_flags: Some(0x400),
            tcp_port: Some(4674),
            ..ServerMetObfuscation::NONE
        }
    );
    let again = ServerMet::decode(&decoded.encode()).expect("re-decode");
    assert_eq!(again.entries()[0].obfuscation(), entry.obfuscation());

    let silent = entry.clone().with_obfuscation(ServerMetObfuscation::NONE);
    assert_eq!(
        entry.clone().merge(silent.clone()).obfuscation(),
        entry.obfuscation(),
        "a silent fresh row does not unlearn the port"
    );
    assert_eq!(
        silent.merge(entry.clone()).obfuscation(),
        entry.obfuscation(),
        "a stated port lands even without a last-ping time"
    );
}

/// aMule's `AddTagFromFile` reads the UDP half of the crypt facts too
/// (`Server.cpp:236-251`): the obfuscation UDP port, the `ServerUDPKey` and
/// the IPv4 it was learned under. The key IP is in the file's address byte
/// order, a zero key or address is "none", and the facts round-trip.
#[test]
fn a_rows_udp_crypt_tags_decode_round_trip_and_merge() {
    let row = encode_row(
        Ipv4Addr::new(1, 2, 3, 4),
        4661,
        &[
            name_tag("crypt"),
            Tag::new(TagName::compact_id(0x95), TagValue::U32(0xABCD_1234)),
            Tag::new(
                TagName::compact_id(0x96),
                TagValue::U32(u32::from_le_bytes([198, 51, 100, 7])),
            ),
            Tag::new(TagName::compact_id(0x98), TagValue::U16(4673)),
        ],
    );
    let decoded = ServerMet::decode(&encode_file(HEADER_AMULE, 1, &[row])).expect("decode");
    let entry = decoded.entries()[0].clone();
    let facts = entry.obfuscation();
    assert_eq!(facts.udp_key, Some(0xABCD_1234));
    assert_eq!(facts.udp_key_ip, Some(Ipv4Addr::new(198, 51, 100, 7)));
    assert_eq!(facts.udp_port, Some(4673));
    let again = ServerMet::decode(&decoded.encode()).expect("re-decode");
    assert_eq!(again.entries()[0].obfuscation(), facts);

    let zeroed = encode_row(
        Ipv4Addr::new(1, 2, 3, 4),
        4661,
        &[
            Tag::new(TagName::compact_id(0x95), TagValue::U32(0)),
            Tag::new(TagName::compact_id(0x96), TagValue::U32(0)),
        ],
    );
    let zeroed = ServerMet::decode(&encode_file(HEADER_AMULE, 1, &[zeroed])).expect("decode");
    assert_eq!(
        zeroed.entries()[0].obfuscation(),
        ServerMetObfuscation::NONE
    );

    let silent = entry.clone().with_obfuscation(ServerMetObfuscation::NONE);
    assert_eq!(
        entry.clone().merge(silent).obfuscation(),
        facts,
        "a silent fresh row does not unlearn the key"
    );
}

/// `ST_AUXPORTSLIST` (`Server.cpp:222-231`): the header port is the standard
/// port and the list starts with the port to dial. An empty tag, which some
/// server.mets carry, says nothing; the list round-trips; a row that holds
/// one keeps it against a mirror's.
#[test]
fn a_rows_aux_ports_list_decodes_round_trips_and_is_not_a_mirrors_to_change() {
    let aux = |list: &str| {
        Tag::new(
            TagName::compact_id(0x93),
            TagValue::String(Ed2kText::from_utf8(list)),
        )
    };
    let file = encode_file(
        HEADER_AMULE,
        2,
        &[
            encode_row(
                Ipv4Addr::new(1, 2, 3, 4),
                4661,
                &[name_tag("aux"), aux("4232, 4242")],
            ),
            encode_row(
                Ipv4Addr::new(5, 6, 7, 8),
                4661,
                &[name_tag("empty"), aux("")],
            ),
        ],
    );
    let decoded = ServerMet::decode(&file).expect("decode");
    assert_eq!(
        decoded.entries()[0].endpoint().port,
        4661,
        "the standard port"
    );
    assert_eq!(decoded.entries()[0].aux_ports(), &[4232, 4242]);
    assert!(decoded.entries()[1].aux_ports().is_empty());

    let again = ServerMet::decode(&decoded.encode()).expect("re-decode");
    assert_eq!(again.entries()[0].aux_ports(), &[4232, 4242]);
    assert!(again.entries()[1].aux_ports().is_empty());

    let held = decoded.entries()[0].clone();
    let mirror = held.clone().with_aux_ports(vec![9999]);
    assert_eq!(
        held.clone().merge(mirror.clone()).aux_ports(),
        &[4232, 4242]
    );
    let bare = held.clone().with_aux_ports(Vec::new());
    assert_eq!(bare.merge(mirror).aux_ports(), &[9999]);
}

/// A fresher row's figures replace older ones on a merge; an older or
/// timeless row's do not.
#[test]
fn merge_keeps_the_fresher_figures() {
    let at = |last_ping: u32, users: u32| {
        sample_entry("s", "", ServerPriority::Normal).with_figures(ServerMetFigures {
            last_ping: Some(last_ping),
            users: Some(users),
            ..ServerMetFigures::NONE
        })
    };
    assert_eq!(at(10, 1).merge(at(20, 2)).figures().users, Some(2));
    assert_eq!(at(20, 1).merge(at(10, 2)).figures().users, Some(1));
    assert_eq!(
        at(20, 1)
            .merge(sample_entry("s", "", ServerPriority::Normal))
            .figures()
            .users,
        Some(1)
    );
}

#[test]
fn merge_overwrites_name_unconditionally() {
    let existing = sample_entry("Old Name", "Old description", ServerPriority::Normal);
    let fresh = sample_entry("New Name", "", ServerPriority::Normal);

    let merged = existing.merge(fresh);
    assert_eq!(merged.name().to_display_string(), "New Name");
}

#[test]
fn merge_updates_description_only_when_fresh_is_non_empty() {
    let existing = sample_entry("Name", "Old description", ServerPriority::Normal);

    let kept = existing
        .clone()
        .merge(sample_entry("Name", "", ServerPriority::Normal));
    assert_eq!(kept.description().to_display_string(), "Old description");

    let updated = existing.merge(sample_entry(
        "Name",
        "New description",
        ServerPriority::Normal,
    ));
    assert_eq!(updated.description().to_display_string(), "New description");
}

#[test]
fn merge_leaves_priority_untouched() {
    let existing = sample_entry("Name", "Desc", ServerPriority::High);
    let fresh = sample_entry("Name", "Desc", ServerPriority::Low);

    let merged = existing.merge(fresh);
    assert_eq!(merged.priority(), ServerPriority::High);
}

#[test]
fn writer_state_round_trips_through_the_decoder() {
    // rmule-state → write → read → same state: a named server
    // with a description at High priority, and a nameless Low one whose
    // synthesised name must survive the round-trip.
    let entries = vec![
        ServerMetEntry::new(
            Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4661),
            Ed2kText::from_utf8("PEERATES"),
            Ed2kText::from_utf8("A community server"),
            ServerPriority::High,
        ),
        ServerMetEntry::new(
            Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 5000),
            Ed2kText::from_bytes(Vec::new()),
            Ed2kText::from_bytes(Vec::new()),
            ServerPriority::Low,
        ),
    ];

    let bytes = ServerMet::from_entries(entries).encode();
    assert_eq!(bytes[0], HEADER_AMULE, "aMule's own SaveServerMet marker");

    let decoded = ServerMet::decode(&bytes).expect("our own server.met decodes");
    assert_eq!(decoded.entries().len(), 2);
    assert!(!decoded.is_truncated());

    let named = &decoded.entries()[0];
    assert_eq!(named.name().to_display_string(), "PEERATES");
    assert_eq!(
        named.description().to_display_string(),
        "A community server"
    );
    assert_eq!(named.priority(), ServerPriority::High);

    let nameless = &decoded.entries()[1];
    assert_eq!(
        nameless.name().to_display_string(),
        "Server 198.51.100.9:5000"
    );
    assert!(nameless.description().as_bytes().is_empty());
    assert_eq!(nameless.priority(), ServerPriority::Low);

    // The re-encode is a fixed point: once names are materialised, decode →
    // encode reproduces the same bytes.
    let reencoded = ServerMet::from_entries(decoded.into_entries()).encode();
    assert_eq!(
        reencoded, bytes,
        "encode is stable across a decode round-trip"
    );
}
