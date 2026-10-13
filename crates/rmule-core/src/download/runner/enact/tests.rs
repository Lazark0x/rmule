//! `enact_drain` driven directly against hand-built runtime scaffolding: no
//! store, network or worker beyond what the exercised decisions touch.

use tokio::time::Duration;

use super::*;

/// A cancel that finds no live worker — every worker
/// already retired — must not enter the timeout at all: there is nothing
/// left to shut down, so the count starts at zero and the wait is skipped
/// outright rather than blocking on a channel that structurally never
/// closes (`WorkerPool`'s own `fact_tx` clone, ADR-0030).
#[tokio::test(start_paused = true)]
async fn a_cancel_with_no_live_workers_returns_without_the_shutdown_timeout() {
    let (_tx, mut rx) = mpsc::channel::<WorkerFact>(1);
    let start = tokio::time::Instant::now();

    await_worker_shutdown(&mut rx, HashSet::new()).await;

    assert_eq!(
        start.elapsed(),
        Duration::ZERO,
        "no live workers means nothing to wait for"
    );
}

/// A worker that never answers `Shutdown` with its own `Disconnected` — an
/// aborted task, or one wedged past recovery — must not hang the drain
/// forever: the wait is still capped at `WORKER_SHUTDOWN_TIMEOUT`.
#[tokio::test(start_paused = true)]
async fn a_worker_that_never_disconnects_still_hits_the_shutdown_cap() {
    let (_tx, mut rx) = mpsc::channel::<WorkerFact>(1);
    let start = tokio::time::Instant::now();

    await_worker_shutdown(&mut rx, HashSet::from([WorkerId(1)])).await;

    assert_eq!(
        start.elapsed(),
        WORKER_SHUTDOWN_TIMEOUT,
        "a stuck worker's drain is bounded by the shutdown timeout, not open-ended"
    );
}

/// `callback_fallback_spelling_sent_total`, counted where
/// `Decision::RequestFallbackBuddyCallback` is enacted (this file's
/// `RequestFallbackBuddyCallback` arm) — a primary buddy callback that drew
/// no dial-back in its whole wait earns exactly one more, under the other
/// `TAG_BUDDYHASH` spelling. Driven through the real sans-I/O brain
/// (`DownloadState::on_sightings`/`on_tick`) and the real
/// `enact_drain`, reading the counter off a live `DiagnosticsSnapshot` —
/// the decision-level rule itself is proven in
/// `download::state::tests::buddy_hash_fallback`.
mod buddy_hash_spelling {
    use std::net::Ipv4Addr;

    use rmule_kad::KadId;
    use rmule_primitives::{
        ClientId, Ed2kText, FileHash, Ipv4Endpoint, PeerEndpoint, SightedBuddy, SourceCryptOptions,
        SourceRoad, SourceSighting, UserHash,
    };

    use super::*;
    use crate::VerificationAuthority;
    use crate::download::runner::test_context::{NeverLooksUp, NeverTransfers, loop_ctx};
    use crate::download::source_book::Gate;
    use crate::download::state::{
        CallbackCapability, Channel, ContentFacts, Decision, DownloadState, SourcingPosture,
        StartingFacts,
    };
    use crate::hashing::ResolvedHashSet;
    use crate::ip_filter::IpFilter;

    /// Asymmetric per four-byte word (ADR-0061), so the primary
    /// spelling and its fallback name different IDs — a palindromic ID would
    /// pass whichever spelling the check used.
    const PRIMARY: KadId = KadId::from_bytes([
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ]);

    /// A Kad source row naming `PRIMARY` as the publisher's serving buddy —
    /// the one channel that names a buddy at all.
    fn buddy_source() -> SourceSighting {
        SourceSighting::by_road(
            SourceRoad::Buddy {
                buddy: SightedBuddy {
                    buddy_id: *PRIMARY.as_bytes(),
                    buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)),
                },
                kad_udp: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 77), 4672),
                tcp_port: 4662,
            },
            Some(UserHash::from_bytes([0xAB; UserHash::BYTE_LEN])),
            Some(SourceCryptOptions::from_byte(0x00)),
        )
    }

    fn file() -> Ed2kFileLink {
        Ed2kFileLink {
            name: Ed2kText::from_utf8("issue-433"),
            size: 1_000,
            file_hash: FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        }
    }

    /// A one-part, callback-capable download state — the brain half of the
    /// harness, matching `download::state::tests::callback_state`.
    fn download_state() -> DownloadState {
        let mut state = DownloadState::new(
            DownloadId::from_u64(1),
            ContentFacts {
                file_hash: FileHash::from_bytes([0; 16]),
                file_size: 1_000,
                link_part_hash_set: None,
                resolved: ResolvedHashSet {
                    authority: VerificationAuthority::FileHashOnly,
                    hashes: Vec::new(),
                },
                trusted_aich_root: None,
                verified_parts: Vec::new(),
                streaming_priority: false,
            },
            StartingFacts {
                distrusted: std::collections::HashSet::new(),
                seeds_written: 0,
            },
            SourcingPosture {
                callback_capability: CallbackCapability::server_high_id(),
                dial: crate::dialable::DialPosition::default(),
                discovery_active: false,
                client_udp: false,
            },
            Duration::from_secs(30),
            1,
            4,
        );
        let _ = state.start(std::time::Instant::now());
        state
    }

    /// Kad rows taken behind an open gate at `at`, as the fleet's Kad arm
    /// hands them.
    fn via_kad(
        state: &mut DownloadState,
        at: std::time::Instant,
        rows: Vec<SourceSighting>,
    ) -> Vec<Decision> {
        let filter = IpFilter::default();
        let gate = Gate {
            filter: &filter,
            dial: crate::dialable::DialPosition::default(),
        };
        state.on_sightings(at, Channel::Kad, rows, &gate).decisions
    }

    /// A `RunnerContext` wired just enough for
    /// `RequestBuddyCallback`/`RequestFallbackBuddyCallback`/
    /// the brain's ticks to enact: no real store, network or worker fleet.
    fn runner_context(
        diagnostics: crate::diagnostics::DiagnosticsState,
    ) -> (
        RunnerContext<NeverLooksUp, NeverTransfers>,
        mpsc::Receiver<DownloadReach>,
    ) {
        // The stop sender drops here, as it always did for these legs.
        let (runner, held) = crate::download::runner::test_context::runner_context(
            NeverLooksUp,
            NeverTransfers,
            diagnostics,
        );
        (runner, held.download_reach_rx)
    }

    /// The key of the buddy callback `opened` asks for — the key every later
    /// call in the leg addresses.
    fn asked_key(opened: &[Decision]) -> CallbackKey {
        opened
            .iter()
            .find_map(|d| match d {
                Decision::RequestBuddyCallback { candidate, .. } => Some(candidate.key()),
                _ => None,
            })
            .expect("the primary ask goes out")
    }

    /// A cancelled download ends every callback it still has
    /// pending. A buddy callback (its Dial-Back Claim) and a connected-server
    /// callback (its server-relayed road) are both filed for real, the brain's
    /// own stop is enacted, and once the run's context is gone the core-wide
    /// registry holds nothing of it — no dead `adopt_tx` is left for a later
    /// dial-back to be `Readopted` into and lost.
    #[tokio::test]
    async fn a_cancelled_download_leaves_no_callback_or_claim_behind() {
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let (runner, _download_reach_rx) = runner_context(diagnostics);
        let file = file();
        let mut ctx = loop_ctx(&runner, &file, download_state());

        let opened = via_kad(
            &mut ctx.state,
            std::time::Instant::now(),
            vec![buddy_source()],
        );
        assert!(
            opened
                .iter()
                .any(|d| matches!(d, Decision::RequestBuddyCallback { .. })),
            "the Kad row opens the buddy-callback road: {opened:?}"
        );
        let mut queue = VecDeque::from(opened);
        queue.push_back(Decision::RequestCallback {
            server: None,
            low_id: ClientId::from_u32(4242),
            want_sources: true,
        });
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("both asks enact cleanly");
        assert!(
            !runner.rt.awaited_inbound.is_empty(),
            "both callbacks are filed"
        );

        let mut queue = VecDeque::from(ctx.state.on_stop(DownloadFailure::Cancelled));
        assert_eq!(
            enact_drain(&mut queue, &mut ctx).await,
            Err(DownloadFailure::Cancelled)
        );
        drop(ctx);

        assert!(
            runner.rt.awaited_inbound.is_empty(),
            "both callbacks' roads ended with the run"
        );
    }

    /// A store that cannot keep a proven provisional
    /// hash set fails the run through the one whole-fleet terminal — the live
    /// worker is told `Shutdown` and its Download relation ends — rather than
    /// a bare `?` that returned past both and left the fleet running unowned.
    #[tokio::test(start_paused = true)]
    async fn a_store_error_on_the_provisional_set_shuts_the_fleet_down() {
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let (runner, _download_reach_rx) = runner_context(diagnostics);
        let file = file();
        let mut ctx = loop_ctx(&runner, &file, download_state());
        let peer = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 30), 4662);
        let (worker_tx, mut worker_rx) = mpsc::channel(4);
        ctx.command_channels.register(
            PeerEndpoint::V4(peer),
            crate::diagnostics::WorkerSlot::from_usize(0),
            worker_tx,
        );
        runner
            .rt
            .peer_roster
            .mark_known(PeerRelation::Download(ctx.download_id), peer);

        // No record for this download exists, so the store refuses the write.
        let mut queue = VecDeque::from([Decision::PersistProvisionalHashes(vec![
            rmule_primitives::PartHash::from_bytes([0x5A; 16]),
        ])]);
        assert_eq!(
            enact_drain(&mut queue, &mut ctx).await,
            Err(DownloadFailure::StoreFailed)
        );
        assert!(
            matches!(
                worker_rx.try_recv(),
                Ok(PeerWorkerCommand::Shutdown { cancel: false })
            ),
            "the live worker is told to shut down"
        );
        assert!(
            !runner.rt.peer_roster.knows(peer.ip),
            "its Download relation ended with the run"
        );
    }

    #[tokio::test]
    async fn a_silent_primary_buddy_callback_earns_one_fallback_spelling_send() {
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let (runner, _download_reach_rx) = runner_context(diagnostics.clone());
        let file = file();
        let mut ctx = loop_ctx(&runner, &file, download_state());

        // The primary `0x52`, enacted for real.
        let at = std::time::Instant::now();
        let opened = via_kad(&mut ctx.state, at, vec![buddy_source()]);
        let _ = asked_key(&opened);
        let mut queue = VecDeque::from(opened);
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("the primary ask enacts cleanly");

        // Thirty silent seconds: the brain earns the fallback, enacted for
        // real through the same `enact_drain` this counts inside.
        let lapsed = ctx.state.on_tick(at + Duration::from_secs(30));
        assert!(
            lapsed
                .iter()
                .any(|d| matches!(d, Decision::RequestFallbackBuddyCallback { .. })),
            "the lapsed primary must earn a fallback ask: {lapsed:?}"
        );
        let mut queue = VecDeque::from(lapsed);
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("the fallback ask enacts cleanly");

        assert_eq!(
            diagnostics
                .snapshot()
                .session
                .buddy_hash_spelling
                .callback_fallback_spelling_sent_total,
            1
        );
    }

    #[tokio::test]
    async fn a_primary_buddy_callback_that_drew_a_dial_back_sends_no_fallback_spelling() {
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let (runner, _download_reach_rx) = runner_context(diagnostics.clone());
        let file = file();
        let mut ctx = loop_ctx(&runner, &file, download_state());

        let at = std::time::Instant::now();
        let opened = via_kad(&mut ctx.state, at, vec![buddy_source()]);
        let key = asked_key(&opened);
        let mut queue = VecDeque::from(opened);
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("the primary ask enacts cleanly");

        // The primary drew its dial-back: the wait never lapses, so no
        // fallback decision is ever produced to enact.
        let _ = ctx.state.on_callback_connected(
            at,
            key,
            PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4662)),
        );
        let lapsed = ctx.state.on_tick(at + Duration::from_secs(30));
        assert!(
            lapsed.is_empty(),
            "a connected callback never lapses: {lapsed:?}"
        );
        let mut queue = VecDeque::from(lapsed);
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("the empty drain is a no-op");

        assert_eq!(
            diagnostics
                .snapshot()
                .session
                .buddy_hash_spelling
                .callback_fallback_spelling_sent_total,
            0
        );
    }
}

/// The Peer Roster's `Queued` leg (ADR-0059 "Roster relations") follows the
/// Source Book's RemoteQueued stage, however a record leaves it — here by a
/// merge, where the wire proves a queued source the same peer as a live
/// worker and its record gives way, which no reask event reports.
mod queued_roster {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rmule_primitives::{
        Ed2kText, FileHash, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, PeerSource, SourceSighting,
    };

    use super::*;
    use crate::VerificationAuthority;
    use crate::dialable::DialPosition;
    use crate::download::runner::test_context::{NeverLooksUp, NeverTransfers, loop_ctx};
    use crate::download::source_book::Gate;
    use crate::download::state::{
        CallbackCapability, Channel, ContentFacts, DownloadState, SourcingPosture, StartingFacts,
    };
    use crate::hashing::ResolvedHashSet;
    use crate::ip_filter::IpFilter;

    const QUEUED: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4662);

    fn live_half() -> Ipv6Endpoint {
        Ipv6Endpoint::new(Ipv6Addr::new(0x2a01, 0x4f8, 0, 0, 0, 0, 0, 1), 4662)
    }

    /// Where this node dials from: it holds a Known IPv6, so an IPv6 half is
    /// dialable.
    fn dual_stack() -> DialPosition {
        DialPosition {
            known_ipv6: Some("2001:db8::1".parse().unwrap()),
        }
    }

    fn file() -> Ed2kFileLink {
        Ed2kFileLink {
            name: Ed2kText::from_utf8("queued-roster"),
            size: 1_000,
            file_hash: FileHash::from_bytes([0xCE; FileHash::BYTE_LEN]),
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        }
    }

    /// A one-part, one-slot download dialing from [`dual_stack`].
    fn download_state() -> DownloadState {
        let mut state = DownloadState::new(
            DownloadId::from_u64(1),
            ContentFacts {
                file_hash: FileHash::from_bytes([0; 16]),
                file_size: 1_000,
                link_part_hash_set: None,
                resolved: ResolvedHashSet {
                    authority: VerificationAuthority::FileHashOnly,
                    hashes: Vec::new(),
                },
                trusted_aich_root: None,
                verified_parts: Vec::new(),
                streaming_priority: false,
            },
            StartingFacts {
                distrusted: std::collections::HashSet::new(),
                seeds_written: 0,
            },
            SourcingPosture {
                callback_capability: CallbackCapability::server_high_id(),
                dial: dual_stack(),
                discovery_active: false,
                client_udp: false,
            },
            Duration::from_secs(30),
            1,
            4,
        );
        let _ = state.start(std::time::Instant::now());
        state
    }

    /// `rows` taken from a link behind an open gate.
    fn sighted(state: &mut DownloadState, rows: Vec<SourceSighting>) {
        let filter = IpFilter::default();
        let gate = Gate {
            filter: &filter,
            dial: dual_stack(),
        };
        let _ = state.on_sightings(std::time::Instant::now(), Channel::Link, rows, &gate);
    }

    /// The worker at `peer` completes its handshake.
    fn connected(state: &mut DownloadState, peer: PeerEndpoint) {
        let _ = state.on_worker_event(std::time::Instant::now(), peer, PeerWorkerEvent::Connected);
    }

    #[tokio::test]
    async fn a_merged_standing_leaves_the_queued_relation() {
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let (runner, _held) = crate::download::runner::test_context::runner_context(
            NeverLooksUp,
            NeverTransfers,
            diagnostics,
        );
        let file = file();
        let mut ctx = loop_ctx(&runner, &file, download_state());
        let queued = PeerEndpoint::V4(QUEUED);
        let live = PeerEndpoint::V6(live_half());

        // The source at `QUEUED` queues us and hangs up: its record stands in
        // the RemoteQueued stage, and the relation is held.
        sighted(
            &mut ctx.state,
            vec![SourceSighting::plain(PeerSource::HighId(QUEUED))],
        );
        connected(&mut ctx.state, queued);
        let now = std::time::Instant::now();
        let _ = ctx
            .state
            .on_worker_event(now, queued, PeerWorkerEvent::Queued { rank: 3 });
        let _ = ctx
            .state
            .on_worker_event(now, queued, PeerWorkerEvent::Disconnected);
        enact_drain(&mut VecDeque::new(), &mut ctx)
            .await
            .expect("nothing to enact");
        assert!(
            runner.rt.peer_roster.knows(QUEUED.ip),
            "queued, then hung up"
        );

        // A worker dials the same peer's IPv6, and an exchange names both
        // halves: the queued record gives way to the live one.
        sighted(
            &mut ctx.state,
            vec![SourceSighting::plain(PeerSource::Ipv6(live_half()))],
        );
        connected(&mut ctx.state, live);
        sighted(
            &mut ctx.state,
            vec![
                SourceSighting::plain(PeerSource::HighId(QUEUED)).with_ipv6_half(Some(live_half())),
            ],
        );
        enact_drain(&mut VecDeque::new(), &mut ctx)
            .await
            .expect("nothing to enact");

        assert_eq!(ctx.state.remote_queued().collect::<Vec<_>>(), Vec::new());
        assert!(
            !runner.rt.peer_roster.knows(QUEUED.ip),
            "the merged standing's endpoint is no longer queued"
        );
    }
}
