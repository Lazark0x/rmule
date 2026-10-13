//! The sans-I/O brain asserted as plain `Vec<Decision>` values: racing peers
//! on one part, mid-part resume, retire-all, candidate backfill, the callback
//! leg, AICH trust and recovery, and what a stop does to the fleet.

mod aich;
mod ask_cadence;
mod buddy_callback;
mod buddy_hash_fallback;
mod callback_walk;
mod callbacks;
mod capability;
mod direct_ipv6;
mod dual_stack;
mod intake;
mod ownership;
mod reask;
mod scheduling;
mod seeds;
mod sources;

use std::net::Ipv4Addr;

use rmule_primitives::{AichHashSet, EMBLOCKSIZE, Ipv4Endpoint, SourceSighting};

use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;

use crate::adapters::PeerWorkerEvent;
use crate::download::source_book::{CLIENT_LIST_CLEANUP, FILE_REASK_TIME};
use crate::download::state::candidates::TRAVERSAL_SLOT_BOUND;
use crate::hello_facts::HelloFacts;
use crate::service::{PeerRetirementReason, VerificationAuthority};

use super::*;
use crate::download::source_book::Gate;

/// What a worker reports when its peer's hello names `user_hash` and little
/// else ([`HelloFacts::of`]).
fn identified(user_hash: UserHash) -> PeerWorkerEvent {
    PeerWorkerEvent::Identity(HelloFacts::of(user_hash).identity())
}

/// [`identified`] with the hello's crypt stance spelled out.
fn identified_with(user_hash: UserHash, crypt: rmule_primitives::CryptStance) -> PeerWorkerEvent {
    PeerWorkerEvent::Identity(
        HelloFacts {
            crypt,
            ..HelloFacts::of(user_hash)
        }
        .identity(),
    )
}

/// One decoded type-3/5 Kad row: a firewalled publisher behind its buddy,
/// observed at `198.51.100.77:4672`, with its User Hash, buddy and
/// connect-options byte left to the caller.
fn kad_buddy_sighting(
    user_hash: Option<UserHash>,
    buddy_id: rmule_kad::KadId,
    buddy_udp: Option<Ipv4Endpoint>,
    connect_options: u8,
) -> SourceSighting {
    SourceSighting::by_road(
        rmule_primitives::SourceRoad::Buddy {
            buddy: rmule_primitives::SightedBuddy {
                buddy_id: *buddy_id.as_bytes(),
                buddy_udp,
            },
            kad_udp: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 77), 4672),
            tcp_port: 4662,
        },
        user_hash,
        Some(rmule_primitives::SourceCryptOptions::from_byte(
            connect_options,
        )),
    )
}

/// The instant every test's run starts at; a test hands later ones in as
/// offsets from it.
fn t0() -> Instant {
    static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *T0.get_or_init(Instant::now)
}

/// Run the brain's clock wake by wake, as the runner does, until `key`'s road
/// ends: the decisions of every tick, in order.
fn until_road_ends(state: &mut DownloadState, key: CallbackKey) -> Vec<Decision> {
    let mut out = Vec::new();
    for _ in 0..16 {
        let at = state.next_wake().expect("a pending road has a deadline");
        let ticked = state.on_tick(at);
        let ended = ticked
            .iter()
            .any(|d| matches!(d, Decision::EndCallback { key: held } if *held == key));
        out.extend(ticked);
        if ended {
            return out;
        }
    }
    panic!("{key:?}'s road never ended: {out:?}");
}

/// The worker on `peer` completed its handshake and its peer answered the
/// probe with every part (ADR-0112): the decisions of both, in order.
fn connect(state: &mut DownloadState, now: Instant, peer: PeerEndpoint) -> Vec<Decision> {
    let mut out = state.on_worker_event(now, peer, PeerWorkerEvent::Connected);
    out.extend(state.on_worker_event(now, peer, PeerWorkerEvent::every_part(state.file_size)));
    out
}

fn peer(n: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, n), 4662))
}

/// The endpoints `decisions` spawns a worker at, in order.
fn spawned(decisions: &[Decision]) -> Vec<PeerEndpoint> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Spawn { peer, .. } => Some(*peer),
            _ => None,
        })
        .collect()
}

fn slot(n: usize) -> WorkerSlot {
    WorkerSlot::from_usize(n)
}

/// A file small enough to be exactly one part.
const ONE_PART: u64 = 1_000;

/// The injected per-callback slot-hold span (`CoreConfig::callback_timeout`):
/// a road opened at an instant lapses this long after it.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(30);

/// File-hash-only content of `file_size` bytes: no link hash set, no AICH
/// root, nothing verified yet.
fn file_hash_only_content(file_size: u64) -> ContentFacts {
    ContentFacts {
        file_hash: FileHash::from_bytes([0; 16]),
        file_size,
        link_part_hash_set: None,
        resolved: ResolvedHashSet {
            authority: VerificationAuthority::FileHashOnly,
            hashes: Vec::new(),
        },
        trusted_aich_root: None,
        verified_parts: Vec::new(),
    }
}

/// The sightings of `pool`'s endpoints, none obfuscated.
fn plain_sightings(pool: &[PeerEndpoint]) -> Vec<SourceSighting> {
    pool.iter()
        .map(|&endpoint| match endpoint {
            PeerEndpoint::V4(v4) => SourceSighting::plain(rmule_primitives::PeerSource::HighId(v4)),
            PeerEndpoint::V6(v6) => SourceSighting::plain(rmule_primitives::PeerSource::Ipv6(v6)),
        })
        .collect()
}

/// Take `sightings` of `channel` behind an open gate at the state's own Dial
/// Position.
fn take(
    state: &mut DownloadState,
    channel: Channel,
    sightings: impl IntoIterator<Item = SourceSighting>,
) -> Taken {
    let filter = crate::ip_filter::IpFilter::default();
    let gate = Gate {
        filter: &filter,
        dial: state.dial,
    };
    state.on_sightings(t0(), channel, sightings, &gate)
}

fn via_kad(state: &mut DownloadState, rows: Vec<SourceSighting>) -> Vec<Decision> {
    take(state, Channel::Kad, rows).decisions
}

fn via_global(
    state: &mut DownloadState,
    server: Ipv4Endpoint,
    rows: Vec<rmule_primitives::PeerSource>,
) -> Vec<Decision> {
    let rows = rows.into_iter().map(SourceSighting::plain);
    take(state, Channel::Global(server), rows).decisions
}

fn via_exchange(
    state: &mut DownloadState,
    from: PeerEndpoint,
    rows: Vec<SourceSighting>,
) -> Vec<Decision> {
    take(state, Channel::Exchanged(from), rows).decisions
}

/// A state whose run has sighted `batches` before its first fill, then the
/// `lows` a decoder names no facts for — a buddy, the NAT-T bit — pooled
/// through the book's candidate entry. Sightings after it fill as a started
/// run's do.
fn state_from(
    content: ContentFacts,
    posture: SourcingPosture,
    peer_concurrency: usize,
    facts: StartingFacts,
    batches: Vec<(Channel, Vec<SourceSighting>)>,
    lows: Vec<SourceSighting>,
) -> DownloadState {
    let mut state = DownloadState::new(
        DownloadId::from_u64(1),
        content,
        facts,
        posture,
        CALLBACK_TIMEOUT,
        peer_concurrency,
    );
    for (channel, sightings) in batches {
        take(&mut state, channel, sightings);
    }
    // A Low-ID record arrives as a server names it; a Kad callback row as Kad
    // does.
    let (kad, server): (Vec<_>, Vec<_>) = lows
        .into_iter()
        .partition(|sighting| !matches!(sighting.road(), rmule_primitives::SourceRoad::Record(_)));
    take(&mut state, Channel::Server, server);
    take(&mut state, Channel::Kad, kad);
    state.started = true;
    state
}

fn no_facts() -> StartingFacts {
    StartingFacts {
        distrusted: HashSet::new(),
        seeds_written: 0,
    }
}

/// `pool` dialable, none obfuscated, sighted as a server answer.
fn pooled_state(
    content: ContentFacts,
    pool: &[PeerEndpoint],
    posture: SourcingPosture,
    peer_concurrency: usize,
) -> DownloadState {
    state_from(
        content,
        posture,
        peer_concurrency,
        no_facts(),
        vec![(Channel::Server, plain_sightings(pool))],
        Vec::new(),
    )
}

/// A posture with nothing armed: not callback-capable, Low-ID, no discovery.
const QUIET_POSTURE: SourcingPosture = SourcingPosture {
    callback_capability: CallbackCapability::UNCALLABLE,
    dial: DialPosition { known_ipv6: None },
    discovery_active: false,
    client_udp: false,
};

/// A Low-ID source id (`< ClientId::LOW_ID_THRESHOLD`), routable for callback
/// when `> 0` (ADR-0039).
fn low(n: u32) -> ClientId {
    ClientId::from_u32(n)
}

/// A connected-server Low-ID candidate as a plain `0x42` answer names it: an id
/// and a port, and nothing rung 1 could use beyond the server namespace.
/// A connected-server Low-ID source, as a server answer names it.
fn low_candidate(n: u32) -> SourceSighting {
    SourceSighting::plain(rmule_primitives::PeerSource::new(low(n), 4662))
}

/// The connected-server (`server: None`) callback key for `low_id` — the form
/// `fill` mints for a connected-server Low-ID candidate (ADR-0039).
fn connected_key(low_id: ClientId) -> CallbackKey {
    CallbackKey {
        server: None,
        low_id,
    }
}

/// A one-part download with explicit High-ID + Low-ID candidate pools and a
/// callback-capability flag (ADR-0039).
fn callback_state(
    high: Vec<PeerEndpoint>,
    low_ids: Vec<SourceSighting>,
    callback_capability: bool,
    peer_concurrency: usize,
) -> DownloadState {
    state_from(
        file_hash_only_content(ONE_PART),
        SourcingPosture {
            callback_capability: if callback_capability {
                CallbackCapability::server_high_id()
            } else {
                CallbackCapability::UNCALLABLE
            },
            ..QUIET_POSTURE
        },
        peer_concurrency,
        no_facts(),
        vec![(Channel::Server, plain_sightings(&high))],
        low_ids,
    )
}

fn file_hash_only_state(pool: Vec<PeerEndpoint>, peer_concurrency: usize) -> DownloadState {
    pooled_state(
        file_hash_only_content(ONE_PART),
        &pool,
        QUIET_POSTURE,
        peer_concurrency,
    )
}

#[test]
fn our_part_status_reports_the_verified_parts_as_the_reask_ping_bitfield() {
    // The `0x90` reask ping (ADR-0057) and the connect-time name ask
    // carry our availability — a bit per ED2K part we have verified. A
    // download of exactly five parts with parts 0, 2 and 4 verified encodes
    // aMule's `WritePartStatus` count, six (`size / PARTSIZE + 1`), with the
    // phantom sixth read held: bits 0, 2, 4, 5 (`0x35`). Any other count and
    // aMule's uploader drops the status. Completion is by absence in the
    // scheduler, so the three pre-verified parts read back present and parts
    // 1, 3 read absent.
    let state = pooled_state(
        ContentFacts {
            verified_parts: vec![0, 2, 4],
            ..file_hash_only_content(5 * rmule_primitives::ED2K_PART_SIZE)
        },
        &[],
        QUIET_POSTURE,
        1,
    );
    assert_eq!(
        state.our_part_status(),
        PartBitmap::decode(6, &[0b0011_0101]).unwrap(),
    );
}

/// A one-part download with server-UDP global discovery armed (ADR-0051): an
/// exhausted pool waits for a future UDP sweep instead of failing.
fn discovery_armed_state(pool: Vec<PeerEndpoint>, peer_concurrency: usize) -> DownloadState {
    pooled_state(
        file_hash_only_content(ONE_PART),
        &pool,
        SourcingPosture {
            discovery_active: true,
            ..QUIET_POSTURE
        },
        peer_concurrency,
    )
}

/// A download carrying a trusted AICH root (from the link `h=`), so an MD4
/// failure triggers block-level recovery (ADR-0038) instead of retire-all.
fn aich_state(
    file_size: u64,
    root: AichRootHash,
    pool: Vec<PeerEndpoint>,
    peer_concurrency: usize,
) -> DownloadState {
    pooled_state(
        ContentFacts {
            trusted_aich_root: Some(root),
            ..file_hash_only_content(file_size)
        },
        &pool,
        QUIET_POSTURE,
        peer_concurrency,
    )
}

/// A two-peer download whose workers have spawned and are ready to connect:
/// the initial fill registered `peer(1)` in slot 0 and `peer(2)` in slot 1.
fn two_peer_state() -> DownloadState {
    let mut state = file_hash_only_state(vec![peer(1), peer(2)], 2);
    let _ = state.start(t0());
    state
}

/// A discovered global source's source-server (the server that answered
/// `OP_GLOBFOUNDSOURCES`), used as the per-server callback key (ADR-0051, ADR-0039).
fn source_server(octet: u8) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(1, 1, 1, octet), 4661)
}
