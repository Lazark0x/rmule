//! Serve-side source-exchange pool, filter and throttle tests.

use std::net::Ipv4Addr;

use rmule_primitives::{ClientId, Ipv4Endpoint, PeerSource};

use super::*;

fn high_id(octets: [u8; 4], port: u16) -> SourceSighting {
    SourceSighting::plain(PeerSource::new(
        ClientId::from_u32(u32::from_le_bytes(octets)),
        port,
    ))
}

fn low_id(id: u32) -> SourceSighting {
    SourceSighting::plain(PeerSource::new(ClientId::from_u32(id), 4662))
}

fn endpoint(octets: [u8; 4], port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::from(octets), port))
}

/// A bitmap of `parts` parts with exactly `present` set (LSB-first bytes).
fn bitmap(parts: u32, present: &[u32]) -> PartBitmap {
    let mut bytes = vec![0u8; (parts as usize).div_ceil(8)];
    for &i in present {
        bytes[(i / 8) as usize] |= 1 << (i % 8);
    }
    PartBitmap::decode(parts, &bytes).expect("bitmap of the exact length decodes")
}

fn requester(octets: [u8; 4], part_status: Option<PartBitmap>) -> SxRequester {
    SxRequester {
        endpoint: Some(endpoint(octets, 4662)),
        part_status,
    }
}

/// A requester with an endpoint that no candidate below collides with.
fn other_requester() -> SxRequester {
    requester([9, 9, 9, 9], None)
}

#[test]
fn low_id_candidates_and_the_requester_itself_are_skipped() {
    let candidates = vec![
        SxCandidate::unknown_status(low_id(5000)),
        SxCandidate::unknown_status(high_id([1, 2, 3, 4], 4662)),
        SxCandidate::unknown_status(high_id([9, 9, 9, 9], 4662)), // the requester
    ];
    let out = select_sources(
        ServedFileKind::Complete,
        &requester([9, 9, 9, 9], None),
        &candidates,
    );
    let ids: Vec<u32> = out
        .iter()
        .filter_map(|s| s.peer_source())
        .map(PeerSource::wire_id)
        .collect();
    assert_eq!(
        ids,
        vec![u32::from_le_bytes([1, 2, 3, 4])],
        "the LowID and the requester itself are dropped; the third HighID stays",
    );
}

#[test]
fn unknown_source_status_is_the_pool_asymmetry() {
    // The exact same unknown-status candidate is included for a complete
    // file and excluded for an in-progress one — aMule's KnownFile/PartFile
    // asymmetry, the whole reason the two pools differ.
    let candidates = vec![SxCandidate::unknown_status(high_id([1, 2, 3, 4], 4662))];
    assert_eq!(
        select_sources(ServedFileKind::Complete, &other_requester(), &candidates).len(),
        1,
        "a complete file includes an unknown-status source",
    );
    assert!(
        select_sources(ServedFileKind::InProgress, &other_requester(), &candidates).is_empty(),
        "an in-progress file excludes an unknown-status source",
    );
}

#[test]
fn the_needed_chunk_filter_keeps_only_sources_offering_a_missing_part() {
    // Requester has parts {0}. A candidate holding {0} offers nothing new
    // (dropped); one holding {1} offers a needed part (kept).
    let requester = requester([9, 9, 9, 9], Some(bitmap(2, &[0])));
    let has_part0 = SxCandidate {
        source: high_id([1, 2, 3, 4], 4662),
        part_status: Some(bitmap(2, &[0])),
    };
    let has_part1 = SxCandidate {
        source: high_id([5, 6, 7, 8], 4662),
        part_status: Some(bitmap(2, &[1])),
    };
    let out = select_sources(
        ServedFileKind::Complete,
        &requester,
        &[has_part0, has_part1],
    );
    let ids: Vec<u32> = out
        .iter()
        .filter_map(|s| s.peer_source())
        .map(PeerSource::wire_id)
        .collect();
    assert_eq!(
        ids,
        vec![u32::from_le_bytes([5, 6, 7, 8])],
        "only the source with a part the requester lacks is served",
    );
}

#[test]
fn an_unknown_requester_is_sent_sources_holding_a_part_and_the_unknowns() {
    // Requester status unknown (aMule's `!SupportsUploadChunksState` branch,
    // `KnownFile.cpp:1000-1024`; `PartFile.cpp`'s `!KnowNeededParts`): a known
    // source holding any part is sent, one known to hold nothing is not, and
    // an unknown source follows the pool's own asymmetry.
    let holds_part_2 = SxCandidate {
        source: high_id([1, 2, 3, 4], 4662),
        part_status: Some(bitmap(4, &[2])),
    };
    let holds_nothing = SxCandidate {
        source: high_id([5, 6, 7, 8], 4662),
        part_status: Some(bitmap(4, &[])),
    };
    let unknown = SxCandidate::unknown_status(high_id([6, 6, 6, 6], 4662));
    let candidates = [holds_part_2.clone(), holds_nothing, unknown.clone()];
    assert_eq!(
        select_sources(ServedFileKind::Complete, &other_requester(), &candidates),
        vec![holds_part_2.source, unknown.source],
    );
    assert_eq!(
        select_sources(ServedFileKind::InProgress, &other_requester(), &candidates),
        vec![holds_part_2.source],
    );
}

#[test]
fn the_answer_is_capped_at_five_hundred_entries() {
    // 600 distinct HighID candidates → only the first 500 are served.
    let candidates: Vec<_> = (0..600u32)
        .map(|i| {
            let octets = (0x0A00_0000u32 + i).to_le_bytes();
            SxCandidate::unknown_status(high_id(octets, 4662))
        })
        .collect();
    let out = select_sources(ServedFileKind::Complete, &other_requester(), &candidates);
    assert_eq!(out.len(), SOURCE_EXCHANGE_MAX_ENTRIES);
}

#[test]
fn the_throttle_grants_the_first_ask_then_gates_a_rare_file_at_forty_minutes() {
    let mut throttle = SourceExchangeThrottle::default();
    let peer = endpoint([1, 2, 3, 4], 4662);
    let t0 = Instant::now();
    // A rare file (10 known sources): first ask free.
    assert!(throttle.admit(peer, t0, 10), "first ask is always answered");
    // 39m59s later — still within the 40-minute rare gate.
    assert!(
        !throttle.admit(peer, t0 + Duration::from_secs(40 * 60 - 1), 10),
        "a rare-file re-ask before 40 minutes is throttled",
    );
    // Exactly 40 minutes after the *first* ask (the throttled one did not
    // re-stamp the clock): answered again.
    assert!(
        throttle.admit(peer, t0 + Duration::from_secs(40 * 60), 10),
        "at 40 minutes the rare-file gate opens",
    );
}

#[test]
fn a_common_file_gates_at_one_hundred_sixty_minutes() {
    let mut throttle = SourceExchangeThrottle::default();
    let peer = endpoint([1, 2, 3, 4], 4662);
    let t0 = Instant::now();
    // A common file (100 > 50 known sources): the longer gate applies.
    assert!(throttle.admit(peer, t0, 100));
    assert!(
        !throttle.admit(peer, t0 + Duration::from_secs(159 * 60), 100),
        "a common-file re-ask before 160 minutes is throttled",
    );
    assert!(
        throttle.admit(peer, t0 + Duration::from_secs(160 * 60), 100),
        "at 160 minutes the common-file gate opens",
    );
}

#[test]
fn forgetting_a_disconnected_peer_makes_its_next_first_ask_free() {
    let mut throttle = SourceExchangeThrottle::default();
    let peer = endpoint([1, 2, 3, 4], 4662);
    let t0 = Instant::now();
    assert!(throttle.admit(peer, t0, 100));
    assert!(!throttle.admit(peer, t0 + Duration::from_secs(60), 100));
    throttle.forget(peer);
    assert!(
        throttle.admit(peer, t0 + Duration::from_secs(60), 100),
        "after a disconnect the reconnecting peer's first ask is free again",
    );
}
