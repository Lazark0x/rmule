//! The sans-I/O brain asserted as plain `Vec<Decision>` values: racing peers
//! on one part, mid-part resume, retire-all, candidate backfill, the callback
//! leg, AICH trust and recovery, and what a stop does to the fleet.

mod aich;
mod buddy_callback;
mod buddy_hash_fallback;
mod callback_walk;
mod callbacks;
mod capability;
mod direct_ipv6;
mod dual_stack;
mod ownership;
mod scheduling;
mod seeds;
mod sources;

use std::net::Ipv4Addr;

use rmule_primitives::{AichHashSet, EMBLOCKSIZE, Ipv4Endpoint};

use crate::adapters::PeerWorkerEvent;
use crate::service::{PeerRetirementReason, VerificationAuthority};

use super::*;

/// The identification a hello naming no user yields: the brain only carries
/// it to the worker's row.
fn hello_software() -> rmule_peer::ClientSoftware {
    rmule_peer::ClientSoftware::from_hello_body(&rmule_peer::PeerHelloBody {
        user_hash: UserHash::from_bytes([0; UserHash::BYTE_LEN]),
        client_id: rmule_primitives::ClientId::from_u32(0),
        tcp_port: 0,
        tags: Vec::new(),
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    })
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

/// The injected per-callback slot-hold span (`CoreConfig::callback_timeout`);
/// surfaces as [`Decision::ArmCallbackTimeout`]'s `after`.
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

/// `high` dialable candidates, none obfuscated, and no Low-ID ones.
fn high_id_candidates(high: Vec<PeerEndpoint>) -> StartingCandidates {
    StartingCandidates {
        high_id: high,
        peer_crypts: HashMap::new(),
        low_id: Vec::new(),
        distrusted: HashSet::new(),
        remembered: RememberedSeeds::default(),
    }
}

/// A posture with nothing armed: not callback-capable, Low-ID, no discovery.
const QUIET_POSTURE: SourcingPosture = SourcingPosture {
    callback_capability: CallbackCapability::UNCALLABLE,
    dial: DialPosition { known_ipv6: None },
    discovery_active: false,
};

/// A Low-ID source id (`< ClientId::LOW_ID_THRESHOLD`), routable for callback
/// when `> 0` (ADR-0039).
fn low(n: u32) -> ClientId {
    ClientId::from_u32(n)
}

/// A connected-server Low-ID candidate as a plain `0x42` answer names it: an id
/// and a port, and nothing rung 1 could use beyond the server namespace.
fn low_candidate(n: u32) -> ConnectedServerCandidate {
    LowIdCandidate::from_connected_server(rmule_primitives::ExchangedSource::plain(
        rmule_primitives::PeerSource::new(low(n), 4662),
    ))
    .expect("a Low-ID source is a candidate")
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
    low_ids: Vec<ConnectedServerCandidate>,
    callback_capability: bool,
    peer_concurrency: usize,
) -> DownloadState {
    DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        StartingCandidates {
            high_id: high,
            peer_crypts: HashMap::new(),
            low_id: low_ids,
            distrusted: HashSet::new(),
            remembered: RememberedSeeds::default(),
        },
        SourcingPosture {
            callback_capability: if callback_capability {
                CallbackCapability::server_high_id()
            } else {
                CallbackCapability::UNCALLABLE
            },
            ..QUIET_POSTURE
        },
        CALLBACK_TIMEOUT,
        peer_concurrency,
    )
}

fn file_hash_only_state(pool: Vec<PeerEndpoint>, peer_concurrency: usize) -> DownloadState {
    DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        high_id_candidates(pool),
        QUIET_POSTURE,
        CALLBACK_TIMEOUT,
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
    let state = DownloadState::new(
        DownloadId::from_u64(1),
        ContentFacts {
            verified_parts: vec![0, 2, 4],
            ..file_hash_only_content(5 * rmule_primitives::ED2K_PART_SIZE)
        },
        high_id_candidates(Vec::new()),
        QUIET_POSTURE,
        CALLBACK_TIMEOUT,
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
    DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        high_id_candidates(pool),
        SourcingPosture {
            discovery_active: true,
            ..QUIET_POSTURE
        },
        CALLBACK_TIMEOUT,
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
    DownloadState::new(
        DownloadId::from_u64(1),
        ContentFacts {
            trusted_aich_root: Some(root),
            ..file_hash_only_content(file_size)
        },
        high_id_candidates(pool),
        QUIET_POSTURE,
        CALLBACK_TIMEOUT,
        peer_concurrency,
    )
}

/// A two-peer download whose workers have spawned and are ready to connect:
/// the initial fill registered `peer(1)` in slot 0 and `peer(2)` in slot 1.
fn two_peer_state() -> DownloadState {
    let mut state = file_hash_only_state(vec![peer(1), peer(2)], 2);
    let _ = state.start();
    state
}

/// A discovered global source's source-server (the server that answered
/// `OP_GLOBFOUNDSOURCES`), used as the per-server callback key (ADR-0051, ADR-0039).
fn source_server(octet: u8) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(1, 1, 1, octet), 4661)
}
