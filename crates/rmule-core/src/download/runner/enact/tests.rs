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
/// (`DownloadState::on_kad_sources`/`on_callback_timeout`) and the real
/// `enact_drain`, reading the counter off a live `DiagnosticsSnapshot` —
/// the decision-level rule itself is proven in
/// `download::state::tests::buddy_hash_fallback`.
mod buddy_hash_spelling {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use rmule_kad::{KadBuddyContact, KadId};
    use rmule_peer::PeerHandshakeContext;
    use rmule_primitives::{
        ClientId, ClientIdentity, Ed2kText, FileHash, Ipv4Endpoint, PeerEndpoint,
        SourceCryptOptions, SourceLookupTarget, UserHash,
    };

    use super::*;
    use crate::download::runner::CallbackFacts;
    use crate::download::state::{
        CallbackCapability, ContentFacts, Decision, DownloadState, SourcingPosture,
        StartingCandidates,
    };
    use crate::hashing::ResolvedHashSet;
    use crate::{PeerWorker, SourceLookupOutcome, VerificationAuthority};

    /// Asymmetric per four-byte word (ADR-0061), so the primary
    /// spelling and its fallback name different IDs — a palindromic ID would
    /// pass whichever spelling the check used.
    const PRIMARY: KadId = KadId::from_bytes([
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ]);

    /// A Kad source row naming `PRIMARY` as the publisher's serving buddy —
    /// the one channel that names a buddy at all.
    fn buddy_source() -> crate::KadSource {
        crate::KadSource {
            direct: None,
            user_hash: Some(UserHash::from_bytes([0xAB; UserHash::BYTE_LEN])),
            kad_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 77), 4672)),
            connect_options: Some(SourceCryptOptions::from_byte(0x00)),
            buddy: Some(KadBuddyContact {
                buddy_id: PRIMARY,
                buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)),
                buddy_ipv6: None,
                buddy_udp_ipv6: None,
            }),
            direct_udp_callback: false,
            tcp_port: 4662,
            ipv6: None,
        }
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
        DownloadState::new(
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
            },
            StartingCandidates {
                high_id: Vec::new(),
                peer_crypts: HashMap::new(),
                low_id: Vec::new(),
                distrusted: std::collections::HashSet::new(),
                remembered: crate::download::state::RememberedSeeds::default(),
            },
            SourcingPosture {
                callback_capability: CallbackCapability::server_high_id(),
                dial: crate::dialable::DialPosition::default(),
                discovery_active: false,
            },
            Duration::from_secs(30),
            1,
        )
    }

    /// Never asked: the decisions this module drives touch no source lookup.
    #[derive(Clone)]
    struct NeverLooksUp;
    impl SourceLookupService for NeverLooksUp {
        async fn lookup_sources(
            &mut self,
            _target: SourceLookupTarget,
        ) -> Result<SourceLookupOutcome, DownloadFailure> {
            unreachable!("a buddy-callback decision never looks up sources")
        }
    }

    /// Never asked: the decisions this module drives spawn no worker.
    struct NeverTransfers;
    impl PeerTransferService for NeverTransfers {
        async fn start_peer_worker(
            &mut self,
            _peer: PeerEndpoint,
            _ctx: PeerHandshakeContext,
            _file: Ed2kFileLink,
        ) -> Result<PeerWorker, DownloadFailure> {
            unreachable!("a buddy-callback decision never spawns a peer worker")
        }
    }

    /// A `RunnerContext` wired just enough for
    /// `RequestBuddyCallback`/`RequestFallbackBuddyCallback`/
    /// `ArmCallbackTimeout` to enact: no real store, network or worker fleet.
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

    fn callback_context(runner: &RunnerContext<NeverLooksUp, NeverTransfers>) -> CallbackContext {
        let (adopt_tx, _adopt_rx) = mpsc::channel(4);
        let (retire_tx, _retire_rx) = mpsc::channel(4);
        CallbackContext::new(
            None,
            CallbackFacts {
                reach: crate::reachability::SharedSelfReach::new(
                    crate::KadReachLevel::fixed(false),
                    crate::own_identity::SharedOwnIdentity::default(),
                    crate::natt::front::SharedNattFront::default(),
                ),
                our_tcp_port: 4662,
            },
            adopt_tx,
            retire_tx,
            runner.pending_callbacks.clone(),
            runner.tunnel_claims.clone(),
        )
    }

    fn worker_pool<'a>(
        runner: &'a RunnerContext<NeverLooksUp, NeverTransfers>,
        file: &'a Ed2kFileLink,
        fact_tx: mpsc::Sender<WorkerFact>,
    ) -> WorkerPool<'a, NeverLooksUp, NeverTransfers> {
        WorkerPool {
            runner,
            file,
            ctx: PeerHandshakeContext {
                identity: ClientIdentity::new(
                    UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
                    Ed2kText::from_utf8("issue-433"),
                    4662,
                    0x3C,
                ),
                client_id: ClientId::from_u32(0),
                connected_server: None,
            },
            fact_tx,
        }
    }

    /// `opened`'s freshly armed slot-release deadline — the key every later
    /// call in the leg addresses.
    fn armed_key(opened: &[Decision]) -> CallbackKey {
        opened
            .iter()
            .find_map(|d| match d {
                Decision::ArmCallbackTimeout { key, .. } => Some(*key),
                _ => None,
            })
            .expect("the primary ask arms its slot-release deadline")
    }

    /// A cancelled download ends every callback it still has
    /// pending. A buddy callback (its Dial-Back Claim) and a connected-server
    /// callback (its routing entry) are both registered for real, the brain's
    /// own stop is enacted, and once the run's context is gone neither
    /// core-wide table holds anything of it — no dead `adopt_tx` is left for
    /// a later dial-back to be `Readopted` into and lost.
    #[tokio::test]
    async fn a_cancelled_download_leaves_no_callback_or_claim_behind() {
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let (runner, _download_reach_rx) = runner_context(diagnostics);
        let file = file();
        let (fact_tx, fact_rx) = mpsc::channel(8);
        let mut ctx = LoopCtx {
            state: download_state(),
            runner: &runner,
            download_id: DownloadId::from_u64(1),
            file: &file,
            evt_tx: &runner.evt_tx,
            worker_pool: worker_pool(&runner, &file, fact_tx),
            command_channels: WorkerChannels::default(),
            file_hash_only_parts: Vec::new(),
            fact_rx,
            callbacks: callback_context(&runner),
            source_ask_clock: crate::download::source_ask_clock::SourceAskClock::default(),
        };

        let opened = ctx.state.on_kad_sources(vec![buddy_source()]);
        assert!(
            opened
                .iter()
                .any(|d| matches!(d, Decision::RequestBuddyCallback { .. })),
            "the Kad row opens the buddy-callback road: {opened:?}"
        );
        let mut queue = VecDeque::from(opened);
        queue.push_back(Decision::RequestCallback {
            low_id: ClientId::from_u32(4242),
        });
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("both asks enact cleanly");
        let target = buddy_source()
            .user_hash
            .expect("the row names its publisher");
        assert_eq!(runner.pending_callbacks.lock().await.len(), 1);

        let mut queue = VecDeque::from(ctx.state.on_stop(DownloadFailure::Cancelled));
        assert_eq!(
            enact_drain(&mut queue, &mut ctx).await,
            Err(DownloadFailure::Cancelled)
        );
        drop(ctx);

        assert!(
            runner.pending_callbacks.lock().await.is_empty(),
            "the connected-server callback's routing entry ended with the run"
        );
        assert!(
            matches!(
                runner.tunnel_claims.rule(target, target).await,
                crate::adapters::TunnelClaimVerdict::Unclaimed
            ),
            "the buddy callback's claim ended with the run"
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
        let (fact_tx, fact_rx) = mpsc::channel(8);
        let mut ctx = LoopCtx {
            state: download_state(),
            runner: &runner,
            download_id: DownloadId::from_u64(1),
            file: &file,
            evt_tx: &runner.evt_tx,
            worker_pool: worker_pool(&runner, &file, fact_tx),
            command_channels: WorkerChannels::default(),
            file_hash_only_parts: Vec::new(),
            fact_rx,
            callbacks: callback_context(&runner),
            source_ask_clock: crate::download::source_ask_clock::SourceAskClock::default(),
        };
        let peer = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 30), 4662);
        let (worker_tx, mut worker_rx) = mpsc::channel(4);
        ctx.command_channels.register(
            PeerEndpoint::V4(peer),
            crate::diagnostics::WorkerSlot::from_usize(0),
            worker_tx,
        );
        runner
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
            !runner.peer_roster.knows(peer.ip),
            "its Download relation ended with the run"
        );
    }

    #[tokio::test]
    async fn a_silent_primary_buddy_callback_earns_one_fallback_spelling_send() {
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let (runner, _download_reach_rx) = runner_context(diagnostics.clone());
        let file = file();
        let (fact_tx, fact_rx) = mpsc::channel(8);
        let mut ctx = LoopCtx {
            state: download_state(),
            runner: &runner,
            download_id: DownloadId::from_u64(1),
            file: &file,
            evt_tx: &runner.evt_tx,
            worker_pool: worker_pool(&runner, &file, fact_tx),
            command_channels: WorkerChannels::default(),
            file_hash_only_parts: Vec::new(),
            fact_rx,
            callbacks: callback_context(&runner),
            source_ask_clock: crate::download::source_ask_clock::SourceAskClock::default(),
        };

        // The primary `0x52`, enacted for real.
        let opened = ctx.state.on_kad_sources(vec![buddy_source()]);
        let key = armed_key(&opened);
        let mut queue = VecDeque::from(opened);
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("the primary ask enacts cleanly");

        // Thirty silent seconds: the brain earns the fallback, enacted for
        // real through the same `enact_drain` this counts inside.
        let lapsed = ctx.state.on_callback_timeout(key);
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
        let (fact_tx, fact_rx) = mpsc::channel(8);
        let mut ctx = LoopCtx {
            state: download_state(),
            runner: &runner,
            download_id: DownloadId::from_u64(1),
            file: &file,
            evt_tx: &runner.evt_tx,
            worker_pool: worker_pool(&runner, &file, fact_tx),
            command_channels: WorkerChannels::default(),
            file_hash_only_parts: Vec::new(),
            fact_rx,
            callbacks: callback_context(&runner),
            source_ask_clock: crate::download::source_ask_clock::SourceAskClock::default(),
        };

        let opened = ctx.state.on_kad_sources(vec![buddy_source()]);
        let key = armed_key(&opened);
        let mut queue = VecDeque::from(opened);
        enact_drain(&mut queue, &mut ctx)
            .await
            .expect("the primary ask enacts cleanly");

        // The primary drew its dial-back: the wait never lapses, so no
        // fallback decision is ever produced to enact.
        let _ = ctx.state.on_callback_connected(
            key,
            PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4662)),
        );
        let lapsed = ctx.state.on_callback_timeout(key);
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

/// The source ask at the seam where the brain's counts meet the download's
/// clock (ADR-0108): the first connection to a peer of a very rare file asks,
/// a re-dial of that peer right after its answer does not, and a peer never
/// asked still does.
mod source_ask {
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;

    use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint};

    use super::super::{high_id_names, wants_sources};
    use crate::VerificationAuthority;
    use crate::download::source_ask_clock::SourceAskClock;
    use crate::download::state::{
        CallbackCapability, ContentFacts, DownloadState, SourcingPosture, StartingCandidates,
    };
    use crate::hashing::ResolvedHashSet;
    use crate::service::DownloadId;

    fn peer(last: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), 4662))
    }

    fn state_with(sources: &[PeerEndpoint]) -> DownloadState {
        DownloadState::new(
            DownloadId::from_u64(7),
            ContentFacts {
                file_hash: FileHash::from_bytes([
                    0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6,
                    0xD7, 0xE8, 0xF9,
                ]),
                file_size: 1_000,
                link_part_hash_set: None,
                resolved: ResolvedHashSet {
                    authority: VerificationAuthority::FileHashOnly,
                    hashes: Vec::new(),
                },
                trusted_aich_root: None,
                verified_parts: Vec::new(),
            },
            StartingCandidates {
                high_id: sources.to_vec(),
                peer_crypts: HashMap::new(),
                low_id: Vec::new(),
                distrusted: HashSet::new(),
                remembered: crate::download::state::RememberedSeeds::default(),
            },
            SourcingPosture {
                callback_capability: CallbackCapability::server_high_id(),
                dial: crate::dialable::DialPosition::default(),
                discovery_active: false,
            },
            std::time::Duration::from_secs(30),
            1,
        )
    }

    /// Deciding to want sources stamps nothing: a peer whose hello refused
    /// the ask, or whose connection never came, is still never asked. Only
    /// the worker's report that the ask went out stamps it, and an answer then
    /// holds the peer off for its next connection.
    #[test]
    fn only_an_ask_that_went_out_holds_the_peer_off() {
        let state = state_with(&[peer(1), peer(2), peer(3)]);
        let mut clock = SourceAskClock::default();
        let now = std::time::Instant::now();
        assert!(wants_sources(
            &clock,
            &state,
            &high_id_names(&state, peer(1))
        ));
        clock.answered(peer(1), now);
        assert!(
            wants_sources(&clock, &state, &high_id_names(&state, peer(1))),
            "never asked: an answer alone does not hold it off"
        );
        clock.asked(peer(1), now);
        clock.answered(peer(1), now);
        assert!(!wants_sources(
            &clock,
            &state,
            &high_id_names(&state, peer(1))
        ));
        assert!(wants_sources(
            &clock,
            &state,
            &high_id_names(&state, peer(2))
        ));
    }
}
