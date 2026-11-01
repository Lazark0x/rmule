//! The measuring rig for the download path's brain: what one arrival costs on
//! a 300-record book, through the turn the fleet loop gives it. By hand, in
//! release: `cargo test --release -p rmule-core drain_bench -- --ignored
//! --nocapture`. Every speed change on this path lands with this rig's number
//! before and after it.

use rmule_peer::PartIndex;

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_primitives::{
    Ed2kText, FileHash, Informant, Ipv4Endpoint, PeerEndpoint, PeerSource, SourceSighting, UserHash,
};

use super::enact_drain;
use crate::VerificationAuthority;
use crate::adapters::PeerWorkerEvent;
use crate::dialable::DialPosition;
use crate::download::runner::republish::WakeReading;
use crate::download::runner::test_context::{NeverLooksUp, NeverTransfers, loop_ctx};
use crate::download::source_book::Gate;
use crate::download::state::{
    CallbackCapability, Channel, ContentFacts, Decision, DownloadState, SourcingPosture,
    StartingFacts,
};
use crate::hashing::ResolvedHashSet;
use crate::hello_facts::HelloFacts;
use crate::ip_filter::IpFilter;
use crate::service::DownloadId;

/// A file of 440 parts, what a 4 GiB file carries.
const FILE_SIZE: u64 = 440 * rmule_primitives::ED2K_PART_SIZE;
/// Sources in the RemoteQueued stage.
const QUEUED: usize = 200;
/// Sources a worker still dials.
const DIALING: usize = 90;
/// Workers delivering, the rest of the 300 records.
const LIVE: usize = 10;
/// The bytes one rig turn walks: 300 MiB, none of it finishing a part.
const WALKED: u64 = 300 * 1024 * 1024;

fn source(index: usize) -> PeerEndpoint {
    let [_, _, high, low] = u32::try_from(index).unwrap().to_be_bytes();
    PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::new(45, 55, high, low.wrapping_add(1)),
        4662,
    ))
}

fn book_state() -> DownloadState {
    let mut state = DownloadState::new(
        DownloadId::from_u64(1),
        ContentFacts {
            file_hash: FileHash::from_bytes([0; 16]),
            file_size: FILE_SIZE,
            link_part_hash_set: None,
            resolved: ResolvedHashSet {
                authority: VerificationAuthority::FileHashOnly,
                hashes: Vec::new(),
            },
            aich_root: crate::download::state::AichRootAuthority::Rootless,
            verified_parts: Vec::new(),
            order: crate::scheduler::PartOrder::Rarest,
        },
        StartingFacts {
            distrusted: std::collections::HashSet::new(),
            seeds_written: 0,
        },
        SourcingPosture {
            callback_capability: CallbackCapability::server_high_id(),
            dial: DialPosition::default(),
            discovery_active: false,
            client_udp: false,
        },
        Duration::from_secs(30),
        crate::download::connection_budget::BudgetSeat::ceiling(1_000),
    );
    let _ = state.start(Instant::now());
    state
}

fn sighted(state: &mut DownloadState, index: usize) {
    let filter = IpFilter::default();
    let gate = Gate {
        filter: &filter,
        dial: DialPosition::default(),
        own: Default::default(),
    };
    let PeerEndpoint::V4(endpoint) = source(index) else {
        unreachable!("the rig's sources are IPv4")
    };
    let rows = vec![SourceSighting::plain(
        PeerSource::HighId(endpoint),
        Informant::Own,
    )];
    let _ = state.on_sightings(Instant::now(), Channel::Link, rows, &gate);
}

/// The source at `index` connects, names itself and advertises every part.
fn connected(state: &mut DownloadState, index: usize) {
    let (peer, now) = (source(index), Instant::now());
    let _ = state.on_worker_event(now, peer, PeerWorkerEvent::Connected);
    let hash = UserHash::from_bytes([u8::try_from(index % 251).unwrap() + 1; 16]);
    let identity = HelloFacts::of(hash).identity();
    let _ = state.on_worker_event(now, peer, PeerWorkerEvent::Identity(identity));
    let _ = state.on_worker_event(now, peer, PeerWorkerEvent::every_part(FILE_SIZE));
}

/// 200 records queued and hung up, 10 live workers, 90 still dialing: the book
/// a popular download holds.
fn popular_book() -> DownloadState {
    let mut state = book_state();
    for index in 0..QUEUED {
        sighted(&mut state, index);
        connected(&mut state, index);
        let (peer, now) = (source(index), Instant::now());
        let rank = u16::try_from(index).unwrap() + 1;
        let _ = state.on_worker_event(now, peer, PeerWorkerEvent::Queued { rank });
        let _ = state.on_worker_event(now, peer, PeerWorkerEvent::Disconnected);
    }
    for index in QUEUED..QUEUED + LIVE {
        sighted(&mut state, index);
        connected(&mut state, index);
    }
    for index in QUEUED + LIVE..QUEUED + LIVE + DIALING {
        sighted(&mut state, index);
    }
    state
}

/// What one arrival of `chunk` bytes costs, in nanoseconds per MiB: `WALKED`
/// bytes, split over the live workers as the fleet loop would take them,
/// through the brain, the drain and the next wake.
async fn nanos_per_mib(chunk: u64, gated: bool) -> u64 {
    let diagnostics = crate::diagnostics::DiagnosticsState::default();
    let (runner, _held) = crate::download::runner::test_context::runner_context(
        NeverLooksUp,
        NeverTransfers,
        diagnostics,
    );
    let file = rmule_primitives::Ed2kFileLink::new(
        Ed2kText::from_utf8("drain-bench"),
        FILE_SIZE,
        FileHash::from_bytes([0; 16]),
    )
    .expect("a size eD2k addresses");
    runner.rt.diagnostics.ensure_download(
        DownloadId::from_u64(1),
        file.file_hash,
        crate::DownloadMetadata::from_link(&file),
    );
    let mut ctx = loop_ctx(&runner, &file, popular_book());
    let mut wake = WakeReading::default();
    enact_drain(&mut VecDeque::new(), &mut ctx)
        .await
        .expect("nothing to enact");

    let bytes = vec![0x5A; usize::try_from(chunk).unwrap()];
    // Short of the whole part, so no arrival persists one: the part boundary
    // is priced on its own.
    let per_part = rmule_primitives::ED2K_PART_SIZE / 2;
    let arrivals = WALKED / chunk;
    let started = Instant::now();
    for arrival in 0..arrivals {
        let walked = arrival * chunk;
        let (part, within) = (walked / per_part, walked % per_part);
        let peer = source(QUEUED + usize::try_from(arrival).unwrap() % LIVE);
        let event = PeerWorkerEvent::BlockReceived {
            part_index: PartIndex::new(u32::try_from(part).unwrap()),
            offset: part * rmule_primitives::ED2K_PART_SIZE + within,
            bytes: bytes.clone(),
        };
        let at = Instant::now();
        runner
            .rt
            .diagnostics
            .add_received_bytes(ctx.download_id, chunk);
        let mut queue: VecDeque<Decision> = ctx.state.on_worker_event(at, peer, event).into();
        if !gated {
            ctx.republished = None;
        }
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("no arrival fails the run");
        if gated {
            wake.block_turn();
            std::hint::black_box(wake.read(&ctx.state));
        } else {
            std::hint::black_box(ctx.state.next_wake());
        }
    }
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap();
    elapsed / (WALKED / (1024 * 1024))
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "by hand, in release: prints what the brain costs per MiB"]
async fn drain_bench() {
    for (label, chunk) in [("packet 10,240", 10_240), ("block 184,320", 184_320)] {
        for (gate, gated) in [("every drain republishes", false), ("gated", true)] {
            let nanos = nanos_per_mib(chunk, gated).await;
            let ceiling = 1_000_000_000 / nanos.max(1);
            println!("{label}, {gate}: {nanos} ns per MiB, tops at {ceiling} MiB/s");
        }
    }
}
