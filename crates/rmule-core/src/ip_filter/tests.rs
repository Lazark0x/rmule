//! IP-filter unit tests: both dat line formats and the ambiguous row resolving
//! as PeerGuardian, malformed rows counted and skipped, a reversed range
//! accepted but inert, the level threshold applied at build time, a later file
//! punching an allow hole through an earlier block, boundary-exact lookups,
//! the per-surface config switches, directory loading tolerating absence and
//! non-UTF-8 descriptions, and source admission by client ID kind.

use super::*;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

fn filter_of(text: &str) -> IpFilter {
    let (filter, _) = IpFilter::from_texts(&[text.as_bytes()], 127, true, true);
    filter
}

#[test]
fn both_line_formats_parse_and_the_ambiguous_line_resolves_as_peer_guardian() {
    // The AntiP2P form blocks at level 0; the PeerGuardian form carries
    // its own level.
    let filter = filter_of(
        "Some Evil Corp:10.0.0.0-10.0.0.255\n\
         172.16.0.0 - 172.16.0.255 , 0 , spaced peer guardian\n",
    );
    assert!(filter.is_filtered_client(ip(10, 0, 0, 7)));
    assert!(filter.is_filtered_client(ip(172, 16, 0, 200)));
    assert!(!filter.is_filtered_client(ip(10, 0, 1, 0)));

    // The scanner's own headline ambiguity (`IPFilterScanner.l:31`):
    // a line matching both formats is PeerGuardian (flex rule order on a
    // whole-line tie). Read as PG it blocks 1.2.3.4-1.2.3.5 at level 100;
    // misread as AntiP2P it would block 2.3.4.5-2.3.4.6 at level 0.
    let ambiguous = filter_of("1.2.3.4-1.2.3.5,100,Duh:2.3.4.5-2.3.4.6\n");
    assert!(ambiguous.is_filtered_client(ip(1, 2, 3, 4)));
    assert!(!ambiguous.is_filtered_client(ip(2, 3, 4, 5)));

    // AntiP2P takes the rightmost shape-matching colon (flex longest
    // match): the description may itself contain colons and ranges.
    let nested = filter_of("desc:1.2.3.4-1.2.3.5 junk:20.0.0.0-20.0.0.9\n");
    assert!(nested.is_filtered_client(ip(20, 0, 0, 5)));
    assert!(!nested.is_filtered_client(ip(1, 2, 3, 4)));
}

#[test]
fn malformed_lines_are_counted_and_skipped_without_killing_the_load() {
    let text = b"# comment\n\
        \n\
        \t \r\n\
        999.0.0.1-1.0.0.2,0,octet over 255 in a matched shape\n\
        10.0.0.1-10.0.0.2,999,level over 255 in a matched shape\n\
        1.2.3.4-1.2.3.5\n\
        complete nonsense\n\
        bad:9999.1.2.3-1.2.3.4\n\
        10.1.0.0-10.1.0.255,0,good line still lands\n";
    let (filter, stats) = IpFilter::from_texts(&[text.as_slice()], 127, true, true);
    // Comments and blank/whitespace-only lines count nowhere; the bare
    // range line (no commas, no colon) matches neither format — aMule's
    // `^.` bad-line rule; `bad:9999...` has no shape-matching colon tail
    // (four-digit octet) so it is bad too, not an AntiP2P row.
    assert_eq!(
        stats[0],
        IpFilterLoadStats {
            accepted: 1,
            malformed: 5,
        }
    );
    assert!(filter.is_filtered_client(ip(10, 1, 0, 128)));
    assert!(!filter.is_filtered_client(ip(10, 0, 0, 1)));
}

#[test]
fn a_reversed_range_counts_as_accepted_but_never_blocks() {
    // aMule lexes it fine (`filtercount++`) and `AddIPRange` then drops it
    // on `IPStart > IPEnd` with the return value ignored.
    let (filter, stats) = IpFilter::from_texts(
        &[b"10.0.0.9-10.0.0.1,0,reversed\n".as_slice()],
        127,
        true,
        true,
    );
    assert_eq!(
        stats[0],
        IpFilterLoadStats {
            accepted: 1,
            malformed: 0,
        }
    );
    assert!(!filter.is_filtered_client(ip(10, 0, 0, 5)));
    assert_eq!(filter.blocked_range_count(), 0);
}

#[test]
fn the_level_threshold_blocks_strictly_below_and_is_applied_at_build_time() {
    let text = b"10.0.0.0-10.0.0.255,126,just below default\n\
        10.0.1.0-10.0.1.255,127,exactly the default threshold\n\
        10.0.2.0-10.0.2.255,128,above\n";
    let (at_default, _) = IpFilter::from_texts(&[text.as_slice()], 127, true, true);
    assert!(at_default.is_filtered_client(ip(10, 0, 0, 1)), "126 < 127");
    assert!(
        !at_default.is_filtered_client(ip(10, 0, 1, 1)),
        "127 is NOT below the threshold — aMule blocks strictly below"
    );
    assert!(!at_default.is_filtered_client(ip(10, 0, 2, 1)));

    // The threshold is applied when the table is built, so a different
    // threshold changes which rows exist at all (aMule reloads on a level
    // change for exactly this reason).
    let (at_129, _) = IpFilter::from_texts(&[text.as_slice()], 129, true, true);
    assert!(at_129.is_filtered_client(ip(10, 0, 1, 1)));
    assert!(at_129.is_filtered_client(ip(10, 0, 2, 1)), "128 < 129");
    let (at_zero, _) = IpFilter::from_texts(&[text.as_slice()], 0, true, true);
    assert!(
        !at_zero.is_filtered_client(ip(10, 0, 0, 1)),
        "threshold 0 blocks nothing — no level is strictly below it"
    );
}

#[test]
fn a_later_file_punches_an_allow_hole_through_an_earlier_blocked_range() {
    // The CRangeMap overwrite semantic that makes ipfilter_static.dat
    // (loaded second) take precedence: an allow-leveled sub-range REPLACES
    // the overlapped middle of a blocked range. An append-only store
    // would keep blocking 10.0.1.x and fail this test.
    let downloaded = b"10.0.0.0-10.0.2.255,0,blocked by the downloaded list\n";
    let static_dat = b"10.0.1.0-10.0.1.255,200,operator carve-out\n";
    let (filter, _) = IpFilter::from_texts(
        &[downloaded.as_slice(), static_dat.as_slice()],
        127,
        true,
        true,
    );
    assert!(filter.is_filtered_client(ip(10, 0, 0, 255)));
    assert!(
        !filter.is_filtered_client(ip(10, 0, 1, 128)),
        "the static file's higher-level range overwrote the overlap"
    );
    assert!(filter.is_filtered_client(ip(10, 0, 2, 0)));

    // And the reverse: the static file can also block what an earlier
    // line allowed — last write wins in both directions.
    let (reblocked, _) = IpFilter::from_texts(
        &[static_dat.as_slice(), downloaded.as_slice()],
        127,
        true,
        true,
    );
    assert!(reblocked.is_filtered_client(ip(10, 0, 1, 128)));
}

#[test]
fn lookup_hits_range_boundaries_exactly() {
    let filter = filter_of("50.0.0.10-50.0.0.20,0,a\n60.0.0.0-60.0.0.0,0,single\n");
    assert!(!filter.is_filtered_client(ip(50, 0, 0, 9)));
    assert!(filter.is_filtered_client(ip(50, 0, 0, 10)));
    assert!(filter.is_filtered_client(ip(50, 0, 0, 20)));
    assert!(!filter.is_filtered_client(ip(50, 0, 0, 21)));
    assert!(filter.is_filtered_client(ip(60, 0, 0, 0)));
    assert!(!filter.is_filtered_client(ip(59, 255, 255, 255)));

    // The address-space edges.
    let edges = filter_of("0.0.0.0-0.0.0.5,0,bottom\n255.255.255.250-255.255.255.255,0,top\n");
    assert!(edges.is_filtered_client(ip(0, 0, 0, 0)));
    assert!(edges.is_filtered_client(ip(255, 255, 255, 255)));
    assert!(!edges.is_filtered_client(ip(128, 0, 0, 1)));
}

#[test]
fn large_ranges_cover_exactly_what_amules_split_row_encoding_would() {
    // aMule splits a range longer than 0x8000 into u16-encoded rows
    // (`IPFilter.cpp:157-173`) that tile it exactly; rmule stores the
    // range whole. Equivalence is checked on the encoding's own boundary
    // values: a length of exactly 0x8000 (the last direct-encoded size),
    // 0x8001 (the first split size), and one beyond 0x08000000 (the
    // per-row cap).
    //
    // 1.0.0.0 + 0x8000 - 1 = 1.0.127.255; 10.0.0.0 + 0x08000000 = 18.0.0.0.
    let filter = filter_of(
        "1.0.0.0-1.0.127.255,0,len 0x8000\n\
         2.0.0.0-2.0.128.0,0,len 0x8001\n\
         10.0.0.0-18.0.0.0,0,len 0x08000001\n",
    );
    assert!(filter.is_filtered_client(ip(1, 0, 127, 255)));
    assert!(!filter.is_filtered_client(ip(1, 0, 128, 0)));
    assert!(
        filter.is_filtered_client(ip(2, 0, 128, 0)),
        "the split tail row"
    );
    assert!(!filter.is_filtered_client(ip(2, 0, 128, 1)));
    assert!(filter.is_filtered_client(ip(17, 255, 255, 255)));
    assert!(
        filter.is_filtered_client(ip(18, 0, 0, 0)),
        "the capped row's continuation"
    );
    assert!(!filter.is_filtered_client(ip(18, 0, 0, 1)));
}

#[test]
fn the_client_and_server_gates_obey_their_own_config_switch() {
    // aMule checks the matching pref before the table (IPFilter.cpp:421):
    // the same covered IP answers differently per surface when only one
    // gate is on.
    let text = b"10.0.0.0-10.0.0.255,0,covered\n";
    let (clients_only, _) = IpFilter::from_texts(&[text.as_slice()], 127, true, false);
    assert!(clients_only.is_filtered_client(ip(10, 0, 0, 1)));
    assert!(!clients_only.is_filtered_server(ip(10, 0, 0, 1)));
    let (servers_only, _) = IpFilter::from_texts(&[text.as_slice()], 127, false, true);
    assert!(!servers_only.is_filtered_client(ip(10, 0, 0, 1)));
    assert!(servers_only.is_filtered_server(ip(10, 0, 0, 1)));
}

#[test]
fn load_dir_reads_both_files_tolerating_absence_and_non_utf8_descriptions() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Nothing on disk: an empty filter, not an error (aMule's missing-file
    // `return 0`).
    let empty = IpFilter::load_dir(dir.path(), 127, true, true);
    assert!(!empty.is_filtered_client(ip(10, 0, 0, 1)));

    // Only the static file exists — it loads alone (aMule loads it
    // unconditionally, `IPFilter.cpp:130`). Its description bytes are
    // Latin-1, not UTF-8: real-world dat files carry those and the load
    // must not care.
    let mut static_line = b"10.0.0.0-10.0.0.255,0,caf\xe9 r\xe9seau\n".to_vec();
    static_line.extend_from_slice(b"# trailing comment\n");
    std::fs::write(dir.path().join("ipfilter_static.dat"), &static_line).expect("write");
    let loaded = IpFilter::load_dir(dir.path(), 127, true, true);
    assert!(loaded.is_filtered_client(ip(10, 0, 0, 128)));

    // Both exist: the static file overrides the downloaded one's overlap.
    std::fs::write(
        dir.path().join("ipfilter.dat"),
        b"10.0.0.0-10.0.0.255,200,downloaded says allow\n20.0.0.0-20.0.0.255,0,downloaded block\n",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("ipfilter_static.dat"),
        b"10.0.0.0-10.0.0.255,0,static says block\n",
    )
    .expect("write");
    let both = IpFilter::load_dir(dir.path(), 127, true, true);
    assert!(both.is_filtered_client(ip(10, 0, 0, 1)), "static wins");
    assert!(both.is_filtered_client(ip(20, 0, 0, 1)));
}

#[test]
fn admits_source_drops_filtered_high_id_rows_and_passes_low_id_rows() {
    use rmule_primitives::{ClientId, PeerSource};

    let filter = filter_of("203.0.113.0-203.0.113.255,0,blocked\n");
    let blocked = PeerSource::new(
        ClientId::from_u32(u32::from_le_bytes([203, 0, 113, 9])),
        4662,
    );
    let allowed = PeerSource::new(
        ClientId::from_u32(u32::from_le_bytes([198, 51, 100, 9])),
        4662,
    );
    let low_id = PeerSource::new(ClientId::from_u32(4242), 4662);
    assert!(!admits_source(&filter, blocked.as_peer_endpoint()));
    assert!(admits_source(&filter, allowed.as_peer_endpoint()));
    assert!(
        admits_source(&filter, low_id.as_peer_endpoint()),
        "a Low-ID row has no IP to test — aMule's !IsLowID guard"
    );
}

/// A peer claiming a mapped address (`::ffff:a.b.c.d`) hits the v4 table for
/// its embedded IPv4 — without the unmap, writing a blocked
/// address as a v6 literal was a bypass. A native v6 peer still passes
/// through unchecked (no v6 filter format exists), so the two verdicts must
/// differ even though both arrive through the same `V6` variant.
#[test]
fn a_mapped_peer_hits_the_v4_table_and_a_native_v6_peer_still_passes_through() {
    use rmule_primitives::{Ipv6Endpoint, PeerEndpoint};

    let filter = filter_of("203.0.113.0-203.0.113.255,0,blocked\n");

    let mapped_blocked = PeerEndpoint::V6(Ipv6Endpoint::new(
        "::ffff:203.0.113.9".parse().unwrap(),
        4662,
    ));
    assert!(
        filter.is_filtered_peer(mapped_blocked),
        "::ffff:203.0.113.9 is 203.0.113.9 wearing a v6 literal"
    );

    let mapped_allowed = PeerEndpoint::V6(Ipv6Endpoint::new(
        "::ffff:198.51.100.9".parse().unwrap(),
        4662,
    ));
    assert!(!filter.is_filtered_peer(mapped_allowed));

    let native = PeerEndpoint::V6(Ipv6Endpoint::new("2001:db8::1".parse().unwrap(), 4662));
    assert!(
        !filter.is_filtered_peer(native),
        "a native v6 peer still passes — no v6 filter format is defined yet"
    );
}
