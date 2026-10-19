//! Kad liveness never flipped back when the live Kad node's pump
//! died mid-session, so `RoutePosition::kad_running` and the
//! `KadNotRunning` guard kept believing Kad was up. This leg kills a running
//! Kad activity's pump — by ending the channel behind it, the same effect a
//! receive-error budget exhaustion or any other driver death has on
//! the actor's discovery task — and proves the actor notices: `CoreEvent::KadStopped`
//! fires, and a buddy-only `ReachPeer` that took route 4 before the death
//! drops for want of a buddy afterward.

use rmule_testkit::HANG_GUARD;
use std::net::Ipv4Addr;

use rmule_core::{
    ClientUdpBind, Core, CoreCommand, CoreConfig, CoreError, CoreEvent, DownloadCommand,
    DownloadEvent, DownloadFailure, KadEnableConfig, KadReachLevel, KadRuntimeFactory,
    KadSourceChannel, KadStopReason, PeerBuddy, PeerReach, PeerReachDropReason, PeerReachRoute,
};
use rmule_primitives::{
    ClientId, FileHash, Ipv4Endpoint, PeerEndpoint, ServerEndpoint, SourceLookupTarget,
    SourceSighting,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::fixture::kad_enable_config;

/// The buddy row's relay key — arbitrary, since no walk or `0x52` ever
/// leaves on this leg (route selection alone is under test).
const BUDDY_ID: [u8; 16] = [0x7A; 16];

/// A Kad seam whose pump the test can kill on demand: `next_sources` blocks
/// until the test drops `kill_tx`, then reports the channel stopped — exactly
/// what the deep node's own death does to the actor's discovery task
/// (its `sources_tx` drops with it).
struct KillableChannel {
    killed: tokio::sync::Mutex<mpsc::Receiver<()>>,
}

impl KadSourceChannel for KillableChannel {
    async fn search_sources(&self, _target: SourceLookupTarget) {}
    async fn publish_source(&self, _target: SourceLookupTarget) {}
    async fn next_sources(&self) -> Option<(FileHash, Vec<SourceSighting>)> {
        let _ = self.killed.lock().await.recv().await;
        None
    }
}

struct KillableKad {
    channel: Option<KillableChannel>,
}

impl KadRuntimeFactory for KillableKad {
    type Channel = KillableChannel;

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _node: &rmule_core::KadNodeIdentity,
        _bind: ClientUdpBind,
        _cells: &rmule_core::KadCells,
    ) -> Result<KillableChannel, CoreError> {
        Ok(self.channel.take().expect("kad started once"))
    }
}

/// LowID, off our server, no direct-UDP callback, no IPv6 — the callback tree
/// has nothing left to try before route 4's buddy.
fn buddy_only_peer() -> PeerReach {
    PeerReach {
        id: ClientId::from_u32(42),
        tcp: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 4662)),
        supports_direct_udp_callback: false,
        kad_udp: None,
        on_our_server: false,
        buddy: Some(PeerBuddy {
            buddy_id: rmule_core::KadId::from_bytes(BUDDY_ID),
            buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)),
        }),
        ipv6: None,
        user_hash: None,
        supports_natt: false,
    }
}

async fn next_reach_route(core: &mut Core) -> PeerReachRoute {
    timeout(HANG_GUARD, async {
        loop {
            match core.next_event().await.expect("core still running") {
                CoreEvent::PeerReachRouted { route, .. } => return route,
                _ => continue,
            }
        }
    })
    .await
    .expect("the reach verdict arrives")
}

#[tokio::test]
async fn a_dead_pump_flips_kad_active_and_the_buddy_route_retires() {
    let (kill_tx, kill_rx) = mpsc::channel(1);
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .kad(KillableKad {
            channel: Some(KillableChannel {
                killed: tokio::sync::Mutex::new(kill_rx),
            }),
        })
        // Reachable on our own, so the buddy row (route 4) is what a
        // `ReachPeer` reaches for rather than the LowID→LowID drop rung
        // ahead of it (ADR-0061) — the fact under test is `kad_running`
        // alone.
        .kad_reach(KadReachLevel::fixed(true))
        .build();

    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("kad enabled");

    // Before death: Kad is up, so a buddy-only candidate takes route 4.
    core.send(CoreCommand::ReachPeer(buddy_only_peer()))
        .await
        .expect("reach the peer");
    assert_eq!(
        next_reach_route(&mut core).await,
        PeerReachRoute::Buddy {
            buddy_id: rmule_core::KadId::from_bytes(BUDDY_ID),
            emitted_to: None,
        },
        "kad up: the buddy row is reachable"
    );

    // Kill the pump: drop the sender the fake channel's `next_sources` is
    // blocked on, ending it exactly as a dead deep node would.
    drop(kill_tx);

    let stopped = timeout(HANG_GUARD, async {
        loop {
            if let CoreEvent::KadStopped { reason } =
                core.next_event().await.expect("core still running")
            {
                return reason;
            }
        }
    })
    .await
    .expect("KadStopped fires");
    assert_eq!(
        stopped,
        KadStopReason::Ended,
        "the channel closed on its own, not a task panic"
    );

    // After death: the same candidate has no route left — Kad's liveness is
    // read fresh from the ledger, not cached from the first reach.
    core.send(CoreCommand::ReachPeer(buddy_only_peer()))
        .await
        .expect("reach the peer again");
    assert_eq!(
        next_reach_route(&mut core).await,
        PeerReachRoute::Dropped {
            reason: PeerReachDropReason::NoBuddy
        },
        "kad down: the buddy row is unreachable, not held for a callback that will never come"
    );
}

/// ADR-0093's death leg for the Kad activity's liveness readers: a download
/// that started serverless and waits on Kad alone reads **Kad Liveness** from
/// the activity, not from a copy taken at its spawn — so the pump's death
/// turns its wait into the `NoUsableSources` it would have been with Kad off.
#[tokio::test]
async fn a_kad_death_ends_the_wait_of_a_download_that_had_only_kad() {
    let dir = tempfile::tempdir().unwrap();
    let (kill_tx, kill_rx) = mpsc::channel(1);
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .kad(KillableKad {
            channel: Some(KillableChannel {
                killed: tokio::sync::Mutex::new(kill_rx),
            }),
        })
        // Reachable on our own, so the buddy row (route 4) is what a
        // `ReachPeer` reaches for rather than the LowID→LowID drop rung
        // ahead of it (ADR-0061) — the fact under test is `kad_running`
        // alone.
        .kad_reach(KadReachLevel::fixed(true))
        .build();
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("kad enabled");

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: crate::fixture::stub_link("kad-only.bin", 1024, 0x5A),
        // Nothing listens: the lookup fails and the download waits on Kad.
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 1).unwrap()),
        name: rmule_testkit::file_name("kad-only.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .expect("download started");
    wait_for(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::WaitingForSources { .. })
        )
    })
    .await;

    drop(kill_tx);
    wait_for(&mut core, |event| {
        matches!(event, CoreEvent::KadStopped { .. })
    })
    .await;
    wait_for(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadFailed {
                reason: DownloadFailure::NoUsableSources,
                ..
            })
        )
    })
    .await;
}

async fn wait_for(core: &mut Core, wanted: impl Fn(&CoreEvent) -> bool) {
    timeout(HANG_GUARD, async {
        while !wanted(&core.next_event().await.expect("core still running")) {}
    })
    .await
    .expect("the awaited event arrives");
}
