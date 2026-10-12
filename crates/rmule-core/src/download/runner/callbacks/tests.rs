//! The runner's half of the two-roads-one-key rule (ADR-0039 + ADR-0091): a
//! pending callback's registration is held under the brain's key, so ending
//! that callback drops both of its deadlines and releases both of its roads —
//! and ends no other callback's.
//!
//! No sockets and no clock; which connection a filed road takes is the
//! registry's own tests'.

use std::net::Ipv4Addr;

use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Ipv4Endpoint, PeerSource, SourceCryptOptions, SourceSighting,
    UserHash,
};
use tokio::sync::mpsc;

use crate::adapters::{InboundArrival, InboundVerdict};

use super::*;

fn hash(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
}

fn file() -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("claimed"),
        size: 4096,
        file_hash: FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// A connected-server Low-ID candidate whose obfuscation-aware `0x44` item
/// carried the target's User Hash — the one rung-1 fact a source channel
/// really names, and the only key a claim can be filed under.
fn candidate_with_hash(low_id: u32, user_hash: UserHash) -> LowIdCandidate {
    LowIdCandidate::from_sighting(
        SourceSighting::new(
            PeerSource::new(ClientId::from_u32(low_id), 4662),
            Some(user_hash),
            Some(SourceCryptOptions::from_byte(0x01)),
        ),
        None,
    )
    .expect("a Low-ID source is a candidate")
}

/// The same source as a plain `0x42` answer names it: an id and a port.
fn bare_candidate(low_id: u32) -> LowIdCandidate {
    LowIdCandidate::from_sighting(
        SourceSighting::plain(PeerSource::new(ClientId::from_u32(low_id), 4662)),
        None,
    )
    .expect("a Low-ID source is a candidate")
}

/// One download's callback state over `registry`, logged into the server a
/// brain-side `server: None` resolves against.
fn context(registry: &AwaitedInbound) -> CallbackContext {
    let own = crate::own_identity::SharedOwnIdentity::default();
    own.set_connected_session(Some(crate::own_identity::ConnectedSession {
        server: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661)),
        client_id: ClientId::from_u32(0x0A00_0001),
    }));
    CallbackContext::new(
        super::CallbackFacts {
            reach: crate::reachability::SharedSelfReach::new(
                crate::KadReachLevel::fixed(false),
                own,
                crate::natt::front::SharedNattFront::default(),
            ),
            our_tcp_port: 4662,
        },
        mpsc::channel(4).0,
        mpsc::channel(4).0,
        registry.clone(),
    )
}

fn brief() -> AdoptionBrief {
    AdoptionBrief {
        file: file(),
        own_status: PartBitmap::downloader_empty(0),
        want_sources: true,
    }
}

/// Whether a connection arriving by `arrival` with this hello would be
/// adopted — spending the registration when it would.
fn awaited(
    registry: &AwaitedInbound,
    arrival: InboundArrival,
    hello: UserHash,
    reported: CallbackKey,
) -> bool {
    matches!(
        registry.triage(arrival, hello, reported),
        InboundVerdict::Adopt(_)
    )
}

/// A callback is one pending thing with two ways in, so ending it drops both
/// of its roads.
#[test]
fn ending_a_callback_drops_both_roads() {
    let target = hash(0xAB);
    let candidate = candidate_with_hash(7, target);
    let key = candidate.key();
    let registry = AwaitedInbound::default();
    let mut ctx = context(&registry);
    ctx.await_callback(key, brief());
    assert!(
        ctx.claim_tunnel(&candidate, &file(), PartBitmap::downloader_empty(0), true),
        "a candidate carrying a User Hash claims its Tunnel"
    );

    ctx.end_callback(key);

    assert!(
        !awaited(
            &registry,
            InboundArrival::Accepted,
            target,
            ctx.routing_key(key)
        ),
        "the server-relayed road is released"
    );
    assert!(
        !awaited(
            &registry,
            InboundArrival::DialedToward(target),
            target,
            ctx.routing_key(key)
        ),
        "the punch's claim is released too, so no later Tunnel is adopted for it"
    );
}

/// A candidate no channel ever named a User Hash for claims nothing: there is
/// no key to file it under and no hello that could confirm one. Its fallback
/// is not cancelled — the server coordinator is asked by id — so what it
/// raises simply takes the serve road.
#[test]
fn a_candidate_without_a_user_hash_claims_no_tunnel() {
    let registry = AwaitedInbound::default();
    let mut ctx = context(&registry);
    assert!(
        !ctx.claim_tunnel(
            &bare_candidate(7),
            &file(),
            PartBitmap::downloader_empty(0),
            true
        ),
        "a plain 0x42 candidate has no hash to be claimed under"
    );
    assert!(registry.is_empty(), "nothing was filed");
}

/// Every road is filed under its callback's key while a claim is keyed by its
/// *target's* hash, so a download that claimed two targets releases exactly
/// the one whose callback ended.
#[test]
fn ending_one_callback_leaves_another_targets_claim_standing() {
    let registry = AwaitedInbound::default();
    let mut ctx = context(&registry);
    let first = candidate_with_hash(7, hash(0xAB));
    let second = candidate_with_hash(8, hash(0xCD));
    for candidate in [&first, &second] {
        ctx.claim_tunnel(candidate, &file(), PartBitmap::downloader_empty(0), true);
    }

    ctx.end_callback(first.key());

    let nobody = ctx.routing_key(bare_candidate(9).key());
    assert!(
        !awaited(
            &registry,
            InboundArrival::DialedToward(hash(0xAB)),
            hash(0xAB),
            nobody
        ),
        "the ended callback's claim is gone"
    );
    assert!(
        awaited(
            &registry,
            InboundArrival::DialedToward(hash(0xCD)),
            hash(0xCD),
            nobody
        ),
        "the other target's claim still stands"
    );
}
