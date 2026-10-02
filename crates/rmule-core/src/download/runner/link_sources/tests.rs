//! A link's sources as the run's first candidates: named ones resolved,
//! dated ones expired, crypt facts carried, and the link's order ahead of the
//! server's answer.

use std::net::Ipv4Addr;

use rmule_primitives::{
    Ed2kFileLink, Ed2kLink, ExchangedSource, Ipv4Endpoint, PeerEndpoint, PeerSource,
    SourceCryptOptions, UserHash,
};

use super::{ahead_of, link_sources};
use crate::name_resolver::{FakeNameResolver, SharedNameResolver};

const HASH: &str = "AA010FBC1D14C795D86EF98C95479D17";

fn file(link: &str) -> Ed2kFileLink {
    match Ed2kLink::parse(link).expect("the link stands") {
        Ed2kLink::File(file) => file,
        other => panic!("a file link, not {other:?}"),
    }
}

fn endpoints(sources: &[ExchangedSource]) -> Vec<PeerEndpoint> {
    sources
        .iter()
        .filter_map(|source| source.as_peer_endpoint())
        .collect()
}

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> PeerEndpoint {
    PeerEndpoint::from(Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), port))
}

/// A named source is a candidate once it resolves, at the address it
/// resolved to; one that does not resolve is not a candidate, and costs
/// nothing else. The link's order stands, and its `s6=` hints follow.
#[tokio::test]
async fn a_named_source_is_resolved_and_one_that_does_not_resolve_is_left_out() {
    let resolver =
        FakeNameResolver::knowing(&[("peer.example.org", Ipv4Addr::new(203, 0, 113, 44))]);
    let shared: SharedNameResolver = resolver.clone();
    let link = file(&format!(
        "ed2k://|file|a.bin|11|{HASH}|/|s6=[2001:db8::5]:4662|sources,198.51.100.7:4662,\
         peer.example.org:5662,gone.example.org:4662|/"
    ));

    let sources = link_sources(&link, &shared, 0).await;

    assert_eq!(
        endpoints(&sources),
        [
            v4(198, 51, 100, 7, 4662),
            v4(203, 0, 113, 44, 5662),
            PeerEndpoint::from(rmule_primitives::Ipv6Endpoint::new(
                "2001:db8::5".parse().unwrap(),
                4662
            )),
        ]
    );
    let mut asked = resolver.asked();
    asked.sort();
    assert_eq!(asked, ["gone.example.org", "peer.example.org"]);
}

/// aMule's `:<crypt>:<hash>` entry reaches the candidate as the crypt side
/// its dial meets our policy with — the same record a `0x44` answer makes.
#[tokio::test]
async fn a_sources_crypt_byte_and_user_hash_ride_its_candidate() {
    let shared: SharedNameResolver = FakeNameResolver::knowing(&[]);
    let link = file(&format!(
        "ed2k://|file|a.bin|11|{HASH}|/|sources,198.51.100.7:4662:129:31D6CFE0D16AE931B73C59D7E0C089C0|/"
    ));

    let sources = link_sources(&link, &shared, 0).await;

    let expected = ExchangedSource::new(
        PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4662)),
        Some(UserHash::from_hex("31D6CFE0D16AE931B73C59D7E0C089C0").unwrap()),
        Some(SourceCryptOptions::from_byte(129)),
    );
    assert_eq!(sources, [expected]);
}

/// eMule's `sources@YYMMDD,` stops naming sources at the start of that day
/// (`ED2KLink.cpp:238-259`); an undated token beside it is unaffected.
#[tokio::test]
async fn a_dated_source_past_its_day_is_not_a_candidate() {
    let shared: SharedNameResolver = FakeNameResolver::knowing(&[]);
    let link = file(&format!(
        "ed2k://|file|a.bin|11|{HASH}|/|sources@260930,192.0.2.10:4662|sources,192.0.2.11:4662|/"
    ));
    let day_start = 1_790_726_400; // 2026-09-30 00:00 UTC

    let before = link_sources(&link, &shared, day_start - 1).await;
    let after = link_sources(&link, &shared, day_start).await;

    assert_eq!(
        endpoints(&before),
        [v4(192, 0, 2, 10, 4662), v4(192, 0, 2, 11, 4662)]
    );
    assert_eq!(endpoints(&after), [v4(192, 0, 2, 11, 4662)]);
}

/// The link's sources lead the pool; a peer the server also names keeps the
/// link's place but the server's record, and is pooled once.
#[test]
fn the_links_sources_lead_and_a_source_both_name_is_pooled_once() {
    let plain = |a, d| {
        ExchangedSource::plain(PeerSource::HighId(Ipv4Endpoint::new(
            Ipv4Addr::new(a, 0, 2, d),
            4662,
        )))
    };
    let answered = ExchangedSource::new(
        PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 20), 4662)),
        Some(UserHash::from_hex("5F3E9A0C71B2D4E6880A1C3E5F7092B4").unwrap()),
        Some(SourceCryptOptions::from_byte(0x03)),
    );
    let link = vec![plain(192, 20), plain(192, 21), plain(192, 20)];
    let server = vec![plain(192, 30), answered];

    let pool = ahead_of(link, server);

    assert_eq!(
        endpoints(&pool),
        [
            v4(192, 0, 2, 20, 4662),
            v4(192, 0, 2, 21, 4662),
            v4(192, 0, 2, 30, 4662)
        ]
    );
    assert_eq!(pool[0], answered);
}
