//! The adopt arm driven through the brain: a called-back peer's worker lands in
//! the slot the brain names for its callback, a surplus connection at an
//! endpoint a live worker holds leaves that worker its channel, and a worker
//! whose callback already ended is dropped.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Instant;

use rmule_primitives::{
    ClientId, Ed2kFileLink, Ed2kText, FileHash, Informant, Ipv4Endpoint, PeerEndpoint, PeerSource,
    SourceSighting,
};
use tokio::sync::mpsc;

use super::*;
use crate::diagnostics::{DiagnosticsState, WorkerSlot};
use crate::download::runner::test_context::{
    NeverLooksUp, NeverTransfers, loop_ctx, runner_context,
};
use crate::download::source_book::Gate;
use crate::download::state::{
    CallbackCapability, Channel, ContentFacts, DownloadState, SourcingPosture, StartingFacts,
};
use crate::hashing::ResolvedHashSet;
use crate::ip_filter::IpFilter;
use crate::service::DownloadId;
use crate::{PeerWorkerEvent, VerificationAuthority};

const LOW_ID: u32 = 0x0003_1A2B;

fn file() -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("adopted.bin"),
        size: 1_000,
        file_hash: FileHash::from_bytes([0x5E; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

fn high(last: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), 4662))
}

/// The key the accept-router reports: the connected server it saw the peer
/// logged into, which the brain resolves to its connected-server callback.
fn reported() -> CallbackKey {
    CallbackKey {
        server: Some(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 23), 4661)),
        low_id: ClientId::from_u32(LOW_ID),
        kad_port: None,
    }
}

/// A started one-part download, callable on a server High ID, whose first
/// sightings are `sightings`, `peer_concurrency` slots wide.
fn brain(sightings: Vec<SourceSighting>, peer_concurrency: usize, at: Instant) -> DownloadState {
    let mut state = DownloadState::new(
        DownloadId::from_u64(1),
        ContentFacts {
            file_hash: file().file_hash,
            file_size: 1_000,
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
            distrusted: HashSet::new(),
            seeds_written: 0,
        },
        SourcingPosture {
            callback_capability: CallbackCapability::server_high_id(),
            dial: crate::dialable::DialPosition::default(),
            discovery_active: false,
            client_udp: false,
        },
        std::time::Duration::from_secs(30),
        crate::download::connection_budget::BudgetSeat::ceiling(peer_concurrency),
    );
    let filter = IpFilter::default();
    let gate = Gate {
        filter: &filter,
        dial: crate::dialable::DialPosition::default(),
    };
    let _ = state.on_sightings(at, Channel::Server, sightings, &gate);
    let _ = state.start(at);
    state
}

fn low_id_source() -> SourceSighting {
    SourceSighting::plain(
        PeerSource::new(ClientId::from_u32(LOW_ID), 4662),
        Informant::Own,
    )
}

/// A worker the accept-router built from a connection at `peer`, and the
/// command half's far end, which reads `None` once the worker is dropped.
fn worker_at(
    peer: PeerEndpoint,
) -> (
    PeerWorker,
    mpsc::Receiver<crate::PeerWorkerCommand>,
    mpsc::Sender<PeerWorkerEvent>,
) {
    let (command_tx, command_rx) = mpsc::channel(4);
    let (event_tx, event_rx) = mpsc::channel(4);
    (
        PeerWorker::new(peer, command_tx, event_rx),
        command_rx,
        event_tx,
    )
}

/// The live channels, as (endpoint, slot).
fn live<S, P>(ctx: &LoopCtx<'_, S, P>) -> Vec<(PeerEndpoint, WorkerSlot)> {
    ctx.command_channels
        .iter()
        .map(|channel| (channel.peer, channel.slot))
        .collect()
}

#[tokio::test]
async fn an_adopted_worker_lands_in_the_slot_its_callback_held() {
    let (runner, _held) = runner_context(NeverLooksUp, NeverTransfers, DiagnosticsState::default());
    let file = file();
    let mut ctx = loop_ctx(
        &runner,
        &file,
        brain(vec![low_id_source()], 1, Instant::now()),
    );
    assert!(ctx.state.has_pending_callbacks());

    let (worker, _commands, _events) = worker_at(high(9));
    adopt(&mut ctx, reported(), worker).await.expect("adopts");

    assert_eq!(live(&ctx), vec![(high(9), WorkerSlot::from_usize(0))]);
    assert!(!ctx.state.has_pending_callbacks(), "the callback is over");
}

/// A called-back peer that dials in at an endpoint a live worker holds is
/// surplus: the brain names no slot, the live worker keeps its channel, and
/// the surplus worker is dropped.
#[tokio::test]
async fn a_surplus_connection_leaves_the_live_worker_its_channel() {
    let (runner, _held) = runner_context(NeverLooksUp, NeverTransfers, DiagnosticsState::default());
    let file = file();
    let at = Instant::now();
    let mut ctx = loop_ctx(
        &runner,
        &file,
        brain(
            vec![
                SourceSighting::plain(
                    PeerSource::HighId(match high(9) {
                        PeerEndpoint::V4(v4) => v4,
                        PeerEndpoint::V6(_) => unreachable!(),
                    }),
                    Informant::Own,
                ),
                low_id_source(),
            ],
            2,
            at,
        ),
    );
    let (live_tx, _live_rx) = mpsc::channel(4);
    let live_worker = ctx
        .command_channels
        .register(high(9), WorkerSlot::from_usize(0), live_tx);
    let _ = ctx
        .state
        .on_worker_event(at, high(9), PeerWorkerEvent::Connected);

    let (surplus, mut surplus_commands, _events) = worker_at(high(9));
    adopt(&mut ctx, reported(), surplus).await.expect("lands");

    assert!(ctx.command_channels.is_live(live_worker));
    assert_eq!(live(&ctx), vec![(high(9), WorkerSlot::from_usize(0))]);
    assert!(
        surplus_commands.recv().await.is_none(),
        "the surplus worker is dropped"
    );
}

/// A worker whose callback already lapsed matches nothing: it is dropped and
/// takes no slot.
#[tokio::test]
async fn a_worker_for_a_callback_already_ended_is_dropped() {
    let (runner, _held) = runner_context(NeverLooksUp, NeverTransfers, DiagnosticsState::default());
    let file = file();
    let mut ctx = loop_ctx(
        &runner,
        &file,
        brain(vec![low_id_source()], 1, Instant::now()),
    );
    while ctx.state.has_pending_callbacks() {
        let at = ctx.state.next_wake().expect("the road has a deadline");
        let _ = ctx.state.on_tick(at);
    }

    let (late, mut late_commands, _events) = worker_at(high(9));
    adopt(&mut ctx, reported(), late).await.expect("ignored");

    assert!(live(&ctx).is_empty());
    assert!(
        late_commands.recv().await.is_none(),
        "the late worker is dropped"
    );
}
