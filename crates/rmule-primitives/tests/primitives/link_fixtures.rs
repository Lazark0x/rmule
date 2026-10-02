//! `ed2k://` link parsing against recorded cases: what each
//! `tests/fixtures/links` file says a link means, and that an accepted link's
//! canonical form parses back to an equal link.

use rmule_primitives::{Ed2kLink, LinkPeer, LinkSourceExpiry};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LinkFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    #[serde(default)]
    reject_reason: Option<String>,
    input: LinkInput,
    #[serde(default)]
    expected: ExpectedLink,
}

#[derive(Debug, Deserialize)]
struct LinkInput {
    link: String,
}

#[derive(Debug, Default, Deserialize)]
struct ExpectedLink {
    kind: Option<String>,
    canonical: Option<String>,
    name: Option<String>,
    size: Option<u64>,
    file_hash: Option<String>,
    #[serde(default)]
    part_hashes: Vec<String>,
    aich_root: Option<String>,
    #[serde(default)]
    ipv6_sources: Vec<String>,
    /// Each classic peer as `<host>:<port>[:<crypt>[:<hash>]][@YYYY-MM-DD]`.
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    web_sources: Vec<String>,
    host: Option<String>,
    port: Option<u16>,
    address: Option<String>,
    /// The names of the fields skipped as no client's, in link order.
    #[serde(default)]
    skipped_fields: Vec<String>,
}

#[test]
fn link_fixtures_match_expected_ed2k_behavior() {
    for fixture in crate::fixture::cases::<LinkFixture>("links") {
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

        let parsed = Ed2kLink::read(&fixture.input.link);
        if fixture.accepted {
            let read = parsed.unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
            assert_expected_link(&fixture.name, &fixture.expected, &read.link);
            assert_eq!(
                read.skipped_fields, fixture.expected.skipped_fields,
                "{} skipped fields",
                fixture.name
            );
        } else {
            assert!(parsed.is_err(), "{} should be rejected", fixture.name);
            assert!(
                fixture.reject_reason.is_some(),
                "{} should include reject_reason",
                fixture.name
            );
        }
    }
}

/// Round-trip property: every accepted fixture's canonical form must
/// re-parse to a link that's `Eq` to the first parse. Catches subtle
/// drift in `Display` emitting bytes that the parser would reject —
/// e.g. the historical `|/|` source-list sniffer's false positive on
/// canonical `…|p=…|h=…|/`, or any future change to `encode_file_name`
/// that produces a percent sequence the decoder doesn't accept. Covers
/// the `p=`-only, `h=`-only, and `p=` + `h=` combined forms in one
/// loop via the existing fixture set.
#[test]
fn accepted_link_fixtures_canonical_form_re_parses_to_an_equal_link() {
    for fixture in crate::fixture::cases::<LinkFixture>("links") {
        if !fixture.accepted {
            continue;
        }
        let first = Ed2kLink::parse(&fixture.input.link)
            .unwrap_or_else(|e| panic!("{}: first parse failed: {e}", fixture.name));
        let canonical = first.to_string();
        let second = Ed2kLink::parse(&canonical).unwrap_or_else(|e| {
            panic!(
                "{}: re-parse of canonical form failed: {e}\n  canonical: {canonical}",
                fixture.name
            )
        });
        assert_eq!(
            first, second,
            "{}: first parse != re-parsed canonical form",
            fixture.name
        );
        // And canonicalisation must be idempotent: second.to_string()
        // equals the first canonical form.
        assert_eq!(
            canonical,
            second.to_string(),
            "{}: canonicalisation is not idempotent",
            fixture.name
        );
    }
}

fn assert_expected_link(case_name: &str, expected: &ExpectedLink, link: &Ed2kLink) {
    assert_eq!(
        Some(link.kind()),
        expected.kind.as_deref(),
        "{case_name} kind"
    );
    assert_eq!(
        Some(link.to_string()),
        expected.canonical.clone(),
        "{case_name} canonical"
    );

    match link {
        Ed2kLink::File(file) => {
            assert_eq!(
                file.name.try_as_str().ok(),
                expected.name.as_deref(),
                "{case_name} name"
            );
            assert_eq!(Some(file.size), expected.size, "{case_name} size");
            assert_eq!(
                Some(file.file_hash.to_hex_upper()),
                expected.file_hash.clone(),
                "{case_name} file_hash"
            );
            let part_hashes: Vec<String> = file
                .part_hash_set
                .as_ref()
                .map(|set| {
                    set.hashes()
                        .iter()
                        .map(|hash| hash.to_hex_upper())
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(part_hashes, expected.part_hashes, "{case_name} part_hashes");
            assert_eq!(
                file.aich_root.map(|root| root.to_base32_upper()),
                expected.aich_root.clone(),
                "{case_name} aich_root"
            );
            let ipv6_sources: Vec<String> =
                file.ipv6_sources.iter().map(ToString::to_string).collect();
            assert_eq!(
                ipv6_sources, expected.ipv6_sources,
                "{case_name} ipv6_sources"
            );
            let sources: Vec<String> = file.sources.peers().iter().map(peer_text).collect();
            assert_eq!(sources, expected.sources, "{case_name} sources");
            assert_eq!(
                file.sources.web(),
                expected.web_sources,
                "{case_name} web_sources"
            );
        }
        Ed2kLink::Server(server) => {
            assert_eq!(
                Some(server.endpoint.host()),
                expected.host.as_deref(),
                "{case_name} host"
            );
            assert_eq!(
                Some(server.endpoint.port()),
                expected.port,
                "{case_name} port"
            );
        }
        Ed2kLink::ServerList(server_list) => {
            assert_eq!(
                Some(server_list.address.as_str()),
                expected.address.as_deref(),
                "{case_name} address"
            );
        }
    }
}

/// An `s6=` entry that names no dialable peer is
/// skipped like a malformed one — loopback, link-local, ULA, mapped,
/// unspecified, port 0 — and the hints stop at emule-qt's 64 across every
/// source token (`ED2KLink.h:29`).
#[test]
fn s6_skips_undialable_entries_and_caps_the_hints_across_tokens() {
    let hash = "0123456789ABCDEF0123456789ABCDEF";
    let refused =
        "[::1]:4662,[fe80::1]:4662,[fd00::1]:4662,[::ffff:10.0.0.1]:4662,[::]:4662,[2001:db8::9]:0";
    let link: Ed2kLink = format!("ed2k://|file|a.bin|1|{hash}|/|s6={refused},[2001:db8::1]:4662|/")
        .parse()
        .expect("the link stands");
    let Ed2kLink::File(file) = link else {
        panic!("a file link");
    };
    assert_eq!(
        file.ipv6_sources,
        ["[2001:db8::1]:4662".parse().unwrap()],
        "only the dialable hint survives"
    );

    let token = |base: u16| {
        (0..40)
            .map(|i| format!("[2001:db8::{:x}]:4662", base + i))
            .collect::<Vec<_>>()
            .join(",")
    };
    let link: Ed2kLink = format!(
        "ed2k://|file|a.bin|1|{hash}|/|s6={}|s6={}|/",
        token(0x100),
        token(0x200)
    )
    .parse()
    .expect("the link stands");
    let Ed2kLink::File(file) = link else {
        panic!("a file link");
    };
    assert_eq!(file.ipv6_sources.len(), 64);
}

fn peer_text(peer: &LinkPeer) -> String {
    let mut text = format!("{}:{}", peer.host, peer.port);
    if let Some(crypt) = peer.crypt {
        text.push_str(&format!(":{}", crypt.as_byte()));
    }
    if let Some(hash) = peer.user_hash {
        text.push_str(&format!(":{}", hash.to_hex_upper()));
    }
    if let Some(expires) = peer.expires {
        text.push_str(&format!("@{}", expiry_text(expires)));
    }
    text
}

fn expiry_text(expires: LinkSourceExpiry) -> String {
    format!(
        "{}-{:02}-{:02}",
        expires.year(),
        expires.month(),
        expires.day()
    )
}

/// The 64-hint cap is one budget across `s6=` and `sources,` (emule-qt's
/// `kMaxLinkSources`, ADR-0089): the classic peers get what
/// the IPv6 hints left.
#[test]
fn the_hint_cap_spans_the_ipv6_and_the_classic_tokens() {
    let hash = "AA010FBC1D14C795D86EF98C95479D17";
    let ipv6 = (0..40)
        .map(|i| format!("[2001:db8::{:x}]:4662", 0x100 + i))
        .collect::<Vec<_>>()
        .join(",");
    let classic = (1..=40)
        .map(|i| format!("198.51.100.{i}:4662"))
        .collect::<Vec<_>>()
        .join(",");
    let link: Ed2kLink = format!("ed2k://|file|a.bin|1|{hash}|/|s6={ipv6}|sources,{classic}|/")
        .parse()
        .expect("the link stands");
    let Ed2kLink::File(file) = link else {
        panic!("a file link");
    };
    assert_eq!(file.ipv6_sources.len(), 40);
    assert_eq!(file.sources.peers().len(), 24);
    assert_eq!(peer_text(&file.sources.peers()[23]), "198.51.100.24:4662");
}
