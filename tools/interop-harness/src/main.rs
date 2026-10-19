//! The harness binary: parse one subcommand and hand it to its flow.
//!
//! Every subcommand name printed here is part of the harness's contract with
//! Dockerfiles, docs and other tooling — renaming one breaks callers outside this
//! repo. The argument shapes and the handlers that resolve them live under
//! [`cli`], grouped by flow family; this file is the parse-and-dispatch seam and
//! holds no orchestration of its own.
#![warn(missing_docs)]

use std::path::Path;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod cli;

use rmule_interop_harness::docker::Docker;

use crate::cli::bootstrap::{
    Ed2kKadHandoffArgs, V2NodesDatHarvestArgs, ed2k_kad_handoff, http_bootstrap_cold_start,
    http_bootstrap_goldens, v2_nodes_dat_harvest,
};
use crate::cli::dial_back_grant::{
    PeerDialBackGrantArgs, PeerDialBackGrantScoreArgs, peer_dial_back_grant,
    peer_dial_back_grant_score,
};
use crate::cli::ed2k_server::{
    AmuleServesRmuleDownloadsArgs, BenchSmokeArgs, SearchSpacingArgs, SearchWireArgs,
    amule_low_id_callback, amule_serves_rmule_downloads, amule_serves_rmule_searches, bench_smoke,
    rmule_serves_amule_downloads, search_spacing, search_wire, server_cycle,
};
use crate::cli::holepunch_fail::{
    HolepunchFailArgs, HolepunchFailScoreArgs, holepunch_fail, holepunch_fail_score,
};
use crate::cli::kad_buddy::{
    KadCoreBuddyArgs, KadDirectCallbackArgs, KadFirewalledBuddyArgs, KadRequiredCheckArgs,
    kad_core_buddy, kad_direct_callback, kad_firewalled_buddy, kad_required_check,
};
use crate::cli::kad_capture::{
    KadFakePublicSourceArgs, KadSourceCaptureArgs, KadSourceLookupCaptureArgs,
    kad_distance_ordering_capture, kad_fake_public_source, kad_source_capture,
    kad_source_lookup_capture,
};
use crate::cli::kad_dialed_link::{KadDialedLinkArgs, kad_dialed_link};
use crate::cli::kad_network::{
    KadInvertedKeywordArgs, KadJoinArgs, KadSmokeArgs, kad_inverted_keyword, kad_join, kad_smoke,
};
use crate::cli::lowid_callback_reask::{
    PeerLowIdCallbackReaskArgs, PeerLowIdCallbackReaskScoreArgs, peer_lowid_callback_reask,
    peer_lowid_callback_reask_score,
};
use crate::cli::nat::{
    Ipv6DialectArgs, Ipv6NetAcceptArgs, NatgwSelfProofArgs, NattArgs, PortMapArgs,
    SentinelSourcesLegacyArgs, ipv6_dialect, ipv6_net_accept, natgw_selfproof, natt, portmap,
    sentinel_sources_legacy,
};
use crate::cli::one_link::{
    PeerOneLinkArgs, PeerOneLinkScoreArgs, peer_one_link, peer_one_link_score,
};
use crate::cli::packed_source_exchange::{PackedSourceExchangeArgs, packed_source_exchange};
use crate::cli::peer::{
    AmuleDirectSuiArgs, PeerUdpReaskArgs, PeerUdpReaskEmitArgs, PeerUdpReaskEmitScoreArgs,
    PeerUdpReaskScoreArgs, amule_direct_sui, peer_udp_reask, peer_udp_reask_emit,
    peer_udp_reask_emit_score, peer_udp_reask_score,
};
use crate::cli::queue_fanout::{
    PeerQueueFanoutArgs, PeerQueueFanoutScoreArgs, peer_queue_fanout, peer_queue_fanout_score,
};
use crate::cli::reciprocity::{
    PeerReciprocityArgs, PeerReciprocityScoreArgs, peer_reciprocity, peer_reciprocity_score,
};
use crate::cli::server_callback_serve::{
    ServerCallbackServeArgs, ServerCallbackServeScoreArgs, server_callback_serve,
    server_callback_serve_score,
};

#[derive(Debug, Parser)]
#[command(name = "rmule-interop-harness")]
#[command(about = "Opt-in local interoperability harness for rmule")]
struct Cli {
    #[command(subcommand)]
    command: HarnessCommand,
}

#[derive(Debug, Subcommand)]
enum HarnessCommand {
    /// Wire smoke: start the plain eserver and probe its advertised
    /// compression (SRV_TCPFLG) and UDP-obfuscation (SRV_UDPFLG) capabilities
    /// from an in-network rmule. Reports wire facts; captures no fixture.
    #[command(name = "bench-smoke")]
    BenchSmoke(BenchSmokeArgs),
    /// Full server cycle (flow A): rmule logs in to the eserver (records the
    /// IDCHANGE SRV_TCPFLG), answers a UDP status ping, global-searches for an
    /// aMule-shared file, get-sources it, and byte-completes the download.
    #[command(name = "server-cycle")]
    ServerCycle(AmuleServesRmuleDownloadsArgs),
    /// Search on the wire: against Lugdunum, then ed2k-server,
    /// each with five aMule sharers, rmule sends bursts of 3, 10 and 30
    /// back-to-back searches, tokenisation probes, Related-Files Searches and a
    /// `0x98` burst, as a High-ID and a Low-ID requester. Reports, no verdict.
    #[command(name = "search-wire")]
    SearchWire(SearchWireArgs),
    /// Announce switch: against Lugdunum, then ed2k-server, a probe offers
    /// files, offers an overlapping set, offers an empty list and hangs up,
    /// while a second client searches after each step. Reports what each
    /// server kept.
    #[command(name = "announce-switch")]
    AnnounceSwitch(crate::cli::announce_switch::AnnounceSwitchArgs),
    /// Late port test: stock Lugdunum's port test is held past its login
    /// answer by a network condition on its own attachment while rmule serves
    /// under `--peer-crypt required`; rmule must refuse the late test.
    #[command(name = "late-port-test")]
    LatePortTest(crate::cli::ed2k_server::LatePortTestArgs),
    /// Crypt-ping port: which port stock Lugdunum answers rmule's obfuscated
    /// status ping from, read off a tap in its namespace, and whether rmule
    /// reads the answer (no plain fallback inside the grace).
    #[command(name = "crypt-ping-port")]
    CryptPingPort(crate::cli::ed2k_server::CryptPingPortArgs),
    /// Server login crypt: rmule's server login under an obfuscation policy
    /// against stock Lugdunum — the link each dial chose, the port and first
    /// byte a tap in the server's namespace saw, and whether the login was
    /// answered over it.
    #[command(name = "server-login-crypt")]
    ServerLoginCrypt(crate::cli::ed2k_server::ServerLoginCryptArgs),
    /// Sweep follows the list: rmule searches on Lugdunum, lists ed2k-server
    /// mid-run and searches again; a tap on ed2k-server's UDP port (TCP+4)
    /// says whether the second search's Global Search Sweep reached it.
    #[command(name = "sweep-follows-list")]
    SweepFollowsList(crate::cli::sweep_follows_list::SweepFollowsListArgs),
    /// Ask budget: sixteen downloads in one rmule core on Lugdunum; a tap on
    /// the server says when each `OP_GETSOURCES` went and what answered it.
    #[command(name = "ask-budget")]
    AskBudget(crate::cli::ask_budget::AskBudgetArgs),
    /// Search spacing: against a fresh Lugdunum per round, rmule sends four
    /// searches a set gap apart, alone on a fresh login or after the
    /// search-wire leg's reconnect history, many times over, each sweep from
    /// its own address. Reports which sweeps kept the link, no verdict.
    #[command(name = "search-spacing")]
    SearchSpacing(SearchSpacingArgs),
    /// Run aMule/amuled as the source peer and download the file with rmule.
    #[command(name = "amule-serves-rmule-downloads")]
    AmuleServesRmuleDownloads(AmuleServesRmuleDownloadsArgs),
    /// Run aMule/amuled as the source peer and search for it with rmule.
    #[command(name = "amule-serves-rmule-searches")]
    AmuleServesRmuleSearches(AmuleServesRmuleDownloadsArgs),
    /// Run rmule as the source peer and download the file with aMule/amuled.
    #[command(name = "rmule-serves-amule-downloads")]
    RmuleServesAmuleDownloads(AmuleServesRmuleDownloadsArgs),
    /// Force aMule to Low-ID, then download from it via a server-relayed callback
    /// (ADR-0039): rmule serves to be reachable and adopts the called-back peer.
    #[command(name = "amule-low-id-callback")]
    AmuleLowIdCallback(AmuleServesRmuleDownloadsArgs),
    /// Capture private aMule-to-aMule Kad source-lookup evidence (no public Kad).
    #[command(name = "kad-source-lookup-capture")]
    KadSourceLookupCapture(KadSourceLookupCaptureArgs),
    /// Capture Kad distance-ordering evidence (ADR-0043): a seeded aMule
    /// responder returns the discrimination contacts ranked by XOR distance,
    /// naming the byte-order hypothesis. No public Kad.
    #[command(name = "kad-distance-ordering-capture")]
    KadDistanceOrderingCapture(KadSourceLookupCaptureArgs),
    /// Dial a real aMule peer directly (no eD2k server) and complete a Secure
    /// User Identification exchange (ADR-0041); full capture retained as the
    /// golden-vector source.
    #[command(name = "amule-direct-sui")]
    AmuleDirectSui(AmuleDirectSuiArgs),
    /// rmule joins a private patched-aMule mesh as a live Kad citizen
    /// (ADR-0043): aMule must route through rmule of its own volition.
    #[command(name = "kad-join")]
    KadJoin(KadJoinArgs),
    /// rmule publishes a source to a real aMule storer and captures aMule's
    /// genuine KADEMLIA2_SEARCH_RES (0x3B) answer (ADR-0043): the
    /// stimulus node breaks the 0x3B wall by being the publisher itself.
    #[command(name = "kad-source-capture")]
    KadSourceCapture(KadSourceCaptureArgs),
    /// Stock aMule Kad smoke on a fake-public subnet: two stock
    /// aMule nodes on an internal documentation-range /24 must reach "Kad:
    /// Connected" — the empirical check of the Config-A topology verdict.
    #[command(name = "kad-smoke")]
    KadSmoke(KadSmokeArgs),
    /// rmule joins a STOCK-aMule fake-public Kad swarm (Config A, flow F),
    /// publishes the synthetic file's source, and searches it back — aMule's
    /// 0x4B ack + genuine 0x3B answer close the round trip.
    #[command(name = "kad-fake-public-source")]
    KadFakePublicSource(KadFakePublicSourceArgs),
    /// The ROLE INVERSION of flow F (flow J): a STOCK aMule publishes a keyword
    /// and searches it toward rmule's keyword store, so rmule's serve side
    /// faces genuine aMule 0x43/0x33 request bytes (ADR-0062 recipes 2+4).
    /// rmule's KadID is pinned to the keyword target.
    #[command(name = "kad-inverted-keyword")]
    KadInvertedKeyword(KadInvertedKeywordArgs),
    /// The firewalled-counterparty leg (flow K, ADR-0061): a stock
    /// aMule Kad node with its Kad TCP (+ optionally UDP) port iptables-DROPped
    /// so it self-reports firewalled; rmule (pinned to ~aMuleKadID) taps whatever
    /// the firewalled node sends toward it and scans for the buddy/callback
    /// opcodes.
    #[command(name = "kad-firewalled-buddy")]
    KadFirewalledBuddy(KadFirewalledBuddyArgs),
    /// The CORE-PUMPED variant of flow K (flow M, ADR-0061): the
    /// same firewalled stock aMule, but rmule's side is `ed2k serve start --kad`
    /// — a Kad node inside the Core pump that owns the serve listener — so the
    /// counterparty's post-`0x5A` buddy TCP dial reaches a real listener and the
    /// held-link rows become capturable.
    #[command(name = "kad-core-buddy")]
    KadCoreBuddy(KadCoreBuddyArgs),
    /// The direct `0x95` callback leg (flow N, ADR-0061 route 2):
    /// the same Core-pumped stimulus and TCP-firewalled / UDP-open counterparty,
    /// but rmule speaks first — `OP_DIRECTCALLBACKREQ` at the counterparty's Kad
    /// UDP port — and the counterparty's dial back onto the serve listener is
    /// the evidence.
    #[command(name = "kad-direct-callback")]
    KadDirectCallback(KadDirectCallbackArgs),
    /// Kad under Required (flow R): a Core-pumped rmule under
    /// `--peer-crypt required` runs its live firewall self-checks against open
    /// stock aMule helpers; the verdict gates on its TCP check reading open
    /// (the UDP check cannot engage a helper in a swarm this small and is
    /// recorded, not gated), and each helper's tap says which dial-backs were
    /// obfuscated.
    #[command(name = "kad-required-check")]
    KadRequiredCheck(KadRequiredCheckArgs),
    /// A Kad TCP check concluding through a link rmule dialed (flow S): a Core
    /// downloading from one stock aMule helper asks that helper for the check,
    /// and the helper acks on the live link instead of connecting back; a
    /// second, plain helper connects back, and rmule's TCP verdict needs both.
    #[command(name = "kad-dialed-link")]
    KadDialedLink(KadDialedLinkArgs),
    /// Author the aMule-written server.met golden + assemble the HTTP-fixture
    /// payload for the cold-start bootstrap pipeline (flow H). Reports the v2 nodes.dat
    /// hole and the rmule HTTP-consumption gap.
    #[command(name = "http-bootstrap-goldens")]
    HttpBootstrapGoldens(AmuleServesRmuleDownloadsArgs),
    /// Report the ed2k→Kad handoff tooling gap (flow G): no rmule runnable
    /// binary spans both stacks to drive the ADR-0067 handoff. NOT-REACHED.
    #[command(name = "ed2k-kad-handoff")]
    Ed2kKadHandoff(Ed2kKadHandoffArgs),

    /// Harvest a genuine v2 nodes.dat golden from a seeded aMule Kad routing
    /// table (flow H leg 3).
    #[command(name = "v2-nodes-dat-harvest")]
    V2NodesDatHarvest(V2NodesDatHarvestArgs),

    /// The full HTTP-bootstrap cold start (flow H): a fresh rmule
    /// fetches server.met + nodes.dat over HTTP, connects, and Kad-joins.
    #[command(name = "http-bootstrap-cold-start")]
    HttpBootstrapColdStart(Ed2kKadHandoffArgs),

    /// Packed source-exchange capture (flow I): register ≥12
    /// fabricated High-ID identities for one hash on the eserver (ADR-0043),
    /// have a downloading aMule learn them via get-sources, then dial that aMule
    /// and ask it for sources — its packed OP_ANSWERSOURCES is the
    /// inbound-inflate and source-exchange capture.
    #[command(name = "packed-source-exchange")]
    PackedSourceExchange(PackedSourceExchangeArgs),

    /// The peer-UDP reask CONSUME flow (flow L, ADR-0057):
    /// rmule serves with a single upload slot, a throttled aMule holds it, and a
    /// second aMule is held queued — its own ~21.4-min FILEREASKTIME timer should
    /// emit OP_REASKFILEPING (0x90) toward rmule. A tcpdump on rmule's netns
    /// records the window. CLI/sweep-only (~25-min wall clock, not RMULE_BENCH).
    #[command(name = "peer-udp-reask")]
    PeerUdpReask(PeerUdpReaskArgs),

    /// Score a finished (or archived) `peer-udp-reask` run dir from its own
    /// tap and write its verdict file, without driving the ~25-min flow again.
    #[command(name = "peer-udp-reask-score")]
    PeerUdpReaskScore(PeerUdpReaskScoreArgs),

    /// Bench baseline (ADR-0092): stand every `NAT_TYPE` gateway up in turn and have
    /// the RFC 5780 reflector probe measure, from inside its LAN, the mapping
    /// and filtering behaviour it actually built. Writes the NAT Type Proof
    /// every later NAT verdict has to cite.
    #[command(name = "natgw-selfproof")]
    NatgwSelfProof(NatgwSelfProofArgs),

    /// Bench baseline (ADR-0092): start each IPv6-speaking counterparty body on a
    /// `3fff:<harness>:<net>::/64` address from RFC 9637's documentation block
    /// and record what its own log says about the address. The prefix's
    /// acceptance is MEASURED here, never inferred from a reject list.
    #[command(name = "ipv6-net-accept")]
    Ipv6NetAccept(Ipv6NetAcceptArgs),

    /// Bench baseline (ADR-0092's amendment): hand a Sentinel Source-bearing
    /// source list to a stock aMule 2.3.3 from an rmule-authored stimulus and
    /// judge aMule's own behaviour — which endpoints it dials, whether the
    /// records after the sentinel land at the right offset, whether the session
    /// survives. `--sentinel-reader-probe` gates rmule's own half; without
    /// `--drive-legacy` the flow is that gate alone and its verdict says so.
    #[command(name = "sentinel-sources-legacy")]
    SentinelSourcesLegacy(SentinelSourcesLegacyArgs),

    /// Port mapping (ADR-0092): drive rmule's **Port Mapper** (ADR-0086) against a
    /// real `miniupnpd` gateway and judge the GATEWAY's own lease table and log.
    /// `portmap-highid` asks for the exact port and watches it be renewed
    /// (`portmap-natpmp` the same over NAT-PMP), `portmap-mismatch` has a second LAN host claim the ports first so the
    /// grant comes back shifted, and `portmap-ipv6-pinhole` asks for a PCP MAP
    /// on the `3fff` address; `portmap-ipv6-pinhole-link-local` asks for it
    /// through the gateway's `fe80::` next hop and judges each request's
    /// source. Every run attaches its NAT Type Proof.
    #[command(name = "portmap")]
    PortMap(PortMapArgs),

    /// The six IPv6-dialect flows (ADR-0087/ADR-0092).
    /// `ipv6-hello-tags` takes the `0xAA` claim and the `CT_MOD_IP_V6` round
    /// trip off two independent oracles and adds the legacy-safety leg;
    /// `ipv6-udp-key` proves the 35-byte client-UDP key both ways;
    /// `ipv6-direct-dial-lowid` shows rung 0 outranking every callback;
    /// `ipv6-extsx`, `ipv6-kad-tags` and `ipv6-server-sentinel` record what the
    /// pins this repo carries can and cannot drive.
    #[command(name = "ipv6-dialect")]
    Ipv6Dialect(Ipv6DialectArgs),

    /// The NAT-traversal flows (ADR-0091/ADR-0092).
    /// `natt-caps-utp` puts the dialect's three opening frames — the `CAPS`
    /// probe, the `KEY` frame a dial arms, and a uTP `ST_SYN` — on kno's
    /// aMule's client-UDP socket and records what it did with each.
    #[command(name = "natt")]
    Natt(NattArgs),

    /// The peer-UDP reask EMIT flow (flow L emit-leg, ADR-0057
    /// s1): the roles-swapped mirror of `peer-udp-reask`. A stock aMule shares the
    /// file and sustains a single upload slot, a slot-holder aMule occupies it,
    /// and rmule downloads (High-ID via --serve) — held queued, it enters the
    /// Remote-Queued Pool and must emit its OWN OP_REASKFILEPING (0x90) toward the
    /// sharer on the ~21.4-min FILEREASKTIME cycle. A tcpdump on rmule's netns
    /// records the window. CLI/sweep-only (~25-min wall clock, not RMULE_BENCH).
    #[command(name = "peer-udp-reask-emit")]
    PeerUdpReaskEmit(PeerUdpReaskEmitArgs),
    /// The Low-ID callback re-ask flow: ed2ksrv, a Low-ID stock aMule sharer
    /// whose two upload slots two stock aMules hold, and rmule downloading
    /// through the sharer's callback. Queued, rmule must re-ask at
    /// FILEREASKTIME through the callback road — a second OP_CALLBACKREQUEST,
    /// no dial at the sharer. Taps in the server's and rmule's namespaces.
    /// CLI-only (~30-min wall clock).
    #[command(name = "peer-lowid-callback-reask")]
    PeerLowIdCallbackReask(PeerLowIdCallbackReaskArgs),
    /// Score a finished or archived `peer-lowid-callback-reask` run dir from
    /// its own taps and logs, without driving the flow again.
    #[command(name = "peer-lowid-callback-reask-score")]
    PeerLowIdCallbackReaskScore(PeerLowIdCallbackReaskScoreArgs),
    /// The one-link flow: the eserver, a High-ID stock aMule sharing two
    /// files and one rmule core downloading both over one link (ADR-0107).
    /// A tap in rmule's namespace.
    #[command(name = "peer-one-link")]
    PeerOneLink(PeerOneLinkArgs),
    /// Score a finished or archived `peer-one-link` run dir from its tap, its
    /// copies and rmule's log, without driving the flow again.
    #[command(name = "peer-one-link-score")]
    PeerOneLinkScore(PeerOneLinkScoreArgs),
    /// The dial-back grant flow: the eserver, a High-ID stock aMule sharer
    /// held to two slots by two stock aMule holders, and one rmule core
    /// queued behind them; one holder stops and the sharer dials rmule back
    /// with a grant (ADR-0057). A tap in rmule's namespace.
    #[command(name = "peer-dial-back-grant")]
    PeerDialBackGrant(PeerDialBackGrantArgs),
    /// Score a finished or archived `peer-dial-back-grant` run dir from its
    /// tap, its copy and rmule's log, without driving the flow again.
    #[command(name = "peer-dial-back-grant-score")]
    PeerDialBackGrantScore(PeerDialBackGrantScoreArgs),
    /// The queue fan-out flow: the eserver, many High-ID stock aMule sharers
    /// of one file, some held to their two slots by stock aMule holders, and
    /// one rmule core asking them all; some holders stop and their sharers
    /// grant rmule late (ADR-0116). A tap in rmule's namespace.
    #[command(name = "peer-queue-fanout")]
    PeerQueueFanout(PeerQueueFanoutArgs),
    /// Score a finished or archived `peer-queue-fanout` run dir from its tap,
    /// its copy and rmule's log, without driving the flow again.
    #[command(name = "peer-queue-fanout-score")]
    PeerQueueFanoutScore(PeerQueueFanoutScoreArgs),
    /// The reciprocity flow: a stock aMule sharer that queues rmule and
    /// honours credits — rmule's upload preference and the credit it earns
    /// (`--leg credit`), or a Low-ID rmule's 15-minute reask (`--leg
    /// low-id`) (ADR-0116). Taps in rmule's and the sharer's namespaces.
    #[command(name = "peer-reciprocity")]
    PeerReciprocity(PeerReciprocityArgs),
    /// Score a finished or archived `peer-reciprocity` run dir from its taps,
    /// its copy and rmule's log, without driving the flow again.
    #[command(name = "peer-reciprocity-score")]
    PeerReciprocityScore(PeerReciprocityScoreArgs),
    /// The server-callback-serve flow: ed2ksrv, a Low-ID rmule sharer (its
    /// listener's inbound TCP dropped) and a High-ID stock aMule downloading
    /// the file through the server's callback relay: OP_CALLBACKREQUEST,
    /// OP_CALLBACKREQUESTED, rmule's dial-back, a byte-equal upload. Taps in
    /// the server's and rmule's namespaces.
    #[command(name = "server-callback-serve")]
    ServerCallbackServe(ServerCallbackServeArgs),
    /// Score a finished or archived `server-callback-serve` run dir from its
    /// own taps and the downloader's copy, without driving the flow again.
    #[command(name = "server-callback-serve-score")]
    ServerCallbackServeScore(ServerCallbackServeScoreArgs),
    /// The holepunch-fail leg: ed2ksrv and one in-network server probe asking
    /// a punch toward a Low ID nobody holds; ed2ksrv's OP_LOWID_HOLEPUNCH_FAIL
    /// (0x62) is cut from the server tap for fixture promotion.
    #[command(name = "ed2ksrv-holepunch-fail")]
    Ed2ksrvHolepunchFail(HolepunchFailArgs),
    /// Score a finished or archived `ed2ksrv-holepunch-fail` run dir from its
    /// own tap, without driving the leg again.
    #[command(name = "ed2ksrv-holepunch-fail-score")]
    Ed2ksrvHolepunchFailScore(HolepunchFailScoreArgs),
    /// Score a finished (or archived) `peer-udp-reask-emit` run dir from its
    /// own tap and write its verdict file, without driving the flow again.
    #[command(name = "peer-udp-reask-emit-score")]
    PeerUdpReaskEmitScore(PeerUdpReaskEmitScoreArgs),
    /// The streaming-window flow (ADR-0112): one Streaming Priority file held
    /// in part by stock aMule seeds, downloaded by rmule with a chosen window;
    /// scores the part filter, the rank, both status forms and NoNeededParts,
    /// and measures the verified prefix over time.
    #[command(name = "peer-streaming-window")]
    PeerStreamingWindow(crate::cli::streaming_window::PeerStreamingWindowArgs),
    /// Score a finished, kept (`--collect`) or archived `peer-streaming-window`
    /// run dir from its own tap and logs.
    #[command(name = "peer-streaming-window-score")]
    PeerStreamingWindowScore(crate::cli::streaming_window::PeerStreamingWindowScoreArgs),
    /// The partial-share flow (ADR-0113): stock aMule fetches a download
    /// rmule is still fetching — probes before and after its first part, the
    /// hash set, verified bytes only, a straddling request, the announce
    /// markers, the reask, a pause, a restart's Offer Check, and the upload
    /// carried across the completion move (ADR-0115).
    #[command(name = "peer-partial-share")]
    PeerPartialShare(Box<crate::cli::partial_share::PeerPartialShareArgs>),
    /// Score a finished or archived `peer-partial-share` run dir from its own
    /// tap and logs.
    #[command(name = "peer-partial-share-score")]
    PeerPartialShareScore(crate::cli::partial_share::PeerPartialShareScoreArgs),
    /// Two hellos, one client: from one address, two peer-TCP connections say
    /// the same user hash and listen port to a High-ID aMule (and, as the
    /// control, two different ports); records whether aMule closed the first
    /// socket.
    #[command(name = "two-hellos")]
    TwoHellos(crate::cli::peer::TwoHellosArgs),
    /// SX1 gate (fake-backed): two scripted sources state source-exchange
    /// version 1 and 3; records whether rmule asked each for sources.
    #[command(name = "sx1-gate")]
    Sx1Gate(crate::cli::peer::Sx1GateArgs),
    /// Read a retained pcap's TCP links as eD2k frames: each direction
    /// reassembled by sequence number, one line per frame. No Docker.
    #[command(name = "ed2k-frames")]
    Ed2kFrames {
        /// The pcap to read.
        pcap: std::path::PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let reads_only = cli.command.reads_only();
    let scored = cli.command.scored_run_dir().map(Path::to_owned);
    let result = dispatch(cli.command);
    if !reads_only {
        rmule_interop_harness::run_record::finish(result.is_err());
        sweep_dangling_bench_stage_images();
    } else if let (Some(run_dir), Ok(())) = (scored, &result) {
        rmule_interop_harness::run_record::rescored(&run_dir);
    }
    result
}

impl HarnessCommand {
    /// The retained run dir a score subcommand reads, so the re-score can note
    /// itself in that run's record.
    fn scored_run_dir(&self) -> Option<&Path> {
        match self {
            Self::PeerUdpReaskScore(args) => Some(&args.run_dir),
            Self::PeerLowIdCallbackReaskScore(args) => Some(&args.run_dir),
            Self::ServerCallbackServeScore(args) => Some(&args.run_dir),
            Self::PeerOneLinkScore(args) => Some(&args.run_dir),
            Self::PeerDialBackGrantScore(args) => Some(&args.run_dir),
            Self::PeerQueueFanoutScore(args) => Some(&args.run_dir),
            Self::PeerReciprocityScore(args) => Some(&args.run_dir),
            Self::Ed2ksrvHolepunchFailScore(args) => Some(&args.run_dir),
            Self::PeerUdpReaskEmitScore(args) => Some(&args.run_dir),
            Self::PeerStreamingWindowScore(args) => Some(&args.run_dir),
            Self::PeerPartialShareScore(args) => Some(&args.run_dir),
            _ => None,
        }
    }

    /// Whether the subcommand only reads a retained run: it builds nothing,
    /// so it leaves the image store alone. Its sweep would race a build
    /// running beside it: the legacy builder's step images stay untagged
    /// until the build's tag lands, and a prune removes them under it.
    fn reads_only(&self) -> bool {
        matches!(
            self,
            Self::Ed2kFrames { .. }
                | Self::PeerUdpReaskScore(_)
                | Self::PeerLowIdCallbackReaskScore(_)
                | Self::ServerCallbackServeScore(_)
                | Self::PeerOneLinkScore(_)
                | Self::PeerDialBackGrantScore(_)
                | Self::PeerQueueFanoutScore(_)
                | Self::PeerReciprocityScore(_)
                | Self::Ed2ksrvHolepunchFailScore(_)
                | Self::PeerUdpReaskEmitScore(_)
                | Self::PeerStreamingWindowScore(_)
                | Self::PeerPartialShareScore(_)
        )
    }
}

/// Best-effort: run after every subcommand, success or failure. A harness
/// build that used [`rmule_interop_harness::docker::Docker::build_image_with_dockerfile`]
/// on a multi-stage Dockerfile left its non-final stage dangling
/// — this sweeps exactly the images labeled for that, on the default
/// `docker` runtime. A missing runtime, a podman-only run, or an
/// already-clean image store all fail this the same harmless way: a warning,
/// never a red flow.
fn sweep_dangling_bench_stage_images() {
    let docker = Docker::new("docker");
    if let Err(err) = docker.prune_bench_stage_images().to_command().output() {
        eprintln!("warning: bench-stage image prune skipped: {err}");
    }
}

fn dispatch(command: HarnessCommand) -> Result<()> {
    match command {
        HarnessCommand::Ed2kFrames { pcap } => {
            print!(
                "{}",
                rmule_interop_harness::flow::ed2k_frame_listing(&pcap)?
            );
        }
        HarnessCommand::BenchSmoke(args) => {
            bench_smoke(args)?;
        }
        HarnessCommand::ServerCycle(args) => {
            server_cycle(args)?;
        }
        HarnessCommand::SearchWire(args) => {
            search_wire(args)?;
        }
        HarnessCommand::CryptPingPort(args) => {
            crate::cli::ed2k_server::crypt_ping_port(args)?;
        }
        HarnessCommand::ServerLoginCrypt(args) => {
            crate::cli::ed2k_server::server_login_crypt(args)?;
        }
        HarnessCommand::SweepFollowsList(args) => {
            crate::cli::sweep_follows_list::sweep_follows_list(args)?;
        }
        HarnessCommand::AskBudget(args) => {
            crate::cli::ask_budget::ask_budget(args)?;
        }
        HarnessCommand::LatePortTest(args) => {
            crate::cli::ed2k_server::late_port_test(args)?;
        }
        HarnessCommand::AnnounceSwitch(args) => {
            crate::cli::announce_switch::announce_switch(args)?;
        }
        HarnessCommand::SearchSpacing(args) => {
            search_spacing(args)?;
        }
        HarnessCommand::AmuleServesRmuleDownloads(args) => {
            amule_serves_rmule_downloads(args)?;
        }
        HarnessCommand::AmuleServesRmuleSearches(args) => {
            amule_serves_rmule_searches(args)?;
        }
        HarnessCommand::RmuleServesAmuleDownloads(args) => {
            rmule_serves_amule_downloads(args)?;
        }
        HarnessCommand::AmuleLowIdCallback(args) => {
            amule_low_id_callback(args)?;
        }
        HarnessCommand::KadSourceLookupCapture(args) => {
            kad_source_lookup_capture(args)?;
        }
        HarnessCommand::KadDistanceOrderingCapture(args) => {
            kad_distance_ordering_capture(args)?;
        }
        HarnessCommand::AmuleDirectSui(args) => {
            amule_direct_sui(args)?;
        }
        HarnessCommand::KadJoin(args) => {
            kad_join(args)?;
        }
        HarnessCommand::KadSourceCapture(args) => {
            kad_source_capture(args)?;
        }
        HarnessCommand::KadSmoke(args) => {
            kad_smoke(args)?;
        }
        HarnessCommand::KadFakePublicSource(args) => {
            kad_fake_public_source(args)?;
        }
        HarnessCommand::KadInvertedKeyword(args) => {
            kad_inverted_keyword(args)?;
        }
        HarnessCommand::KadFirewalledBuddy(args) => {
            kad_firewalled_buddy(args)?;
        }
        HarnessCommand::KadCoreBuddy(args) => {
            kad_core_buddy(args)?;
        }
        HarnessCommand::KadDirectCallback(args) => {
            kad_direct_callback(args)?;
        }
        HarnessCommand::KadRequiredCheck(args) => {
            kad_required_check(args)?;
        }
        HarnessCommand::KadDialedLink(args) => {
            kad_dialed_link(args)?;
        }
        HarnessCommand::HttpBootstrapGoldens(args) => {
            http_bootstrap_goldens(args)?;
        }
        HarnessCommand::Ed2kKadHandoff(args) => {
            ed2k_kad_handoff(args)?;
        }
        HarnessCommand::V2NodesDatHarvest(args) => {
            v2_nodes_dat_harvest(args)?;
        }
        HarnessCommand::HttpBootstrapColdStart(args) => {
            http_bootstrap_cold_start(args)?;
        }
        HarnessCommand::PackedSourceExchange(args) => {
            packed_source_exchange(args)?;
        }
        HarnessCommand::PeerUdpReask(args) => {
            peer_udp_reask(args)?;
        }
        HarnessCommand::PeerUdpReaskScore(args) => {
            peer_udp_reask_score(args)?;
        }
        HarnessCommand::PeerUdpReaskEmit(args) => {
            peer_udp_reask_emit(args)?;
        }
        HarnessCommand::PeerLowIdCallbackReask(args) => {
            peer_lowid_callback_reask(args)?;
        }
        HarnessCommand::PeerLowIdCallbackReaskScore(args) => {
            peer_lowid_callback_reask_score(args)?;
        }
        HarnessCommand::PeerOneLink(args) => {
            peer_one_link(args)?;
        }
        HarnessCommand::PeerOneLinkScore(args) => {
            peer_one_link_score(args)?;
        }
        HarnessCommand::PeerDialBackGrant(args) => {
            peer_dial_back_grant(args)?;
        }
        HarnessCommand::PeerDialBackGrantScore(args) => {
            peer_dial_back_grant_score(args)?;
        }
        HarnessCommand::PeerQueueFanout(args) => {
            peer_queue_fanout(args)?;
        }
        HarnessCommand::PeerQueueFanoutScore(args) => {
            peer_queue_fanout_score(args)?;
        }
        HarnessCommand::PeerReciprocity(args) => {
            peer_reciprocity(args)?;
        }
        HarnessCommand::PeerReciprocityScore(args) => {
            peer_reciprocity_score(args)?;
        }
        HarnessCommand::ServerCallbackServe(args) => {
            server_callback_serve(args)?;
        }
        HarnessCommand::ServerCallbackServeScore(args) => {
            server_callback_serve_score(args)?;
        }
        HarnessCommand::Ed2ksrvHolepunchFail(args) => {
            holepunch_fail(args)?;
        }
        HarnessCommand::Ed2ksrvHolepunchFailScore(args) => {
            holepunch_fail_score(args)?;
        }
        HarnessCommand::PeerUdpReaskEmitScore(args) => {
            peer_udp_reask_emit_score(args)?;
        }
        HarnessCommand::PeerStreamingWindow(args) => {
            crate::cli::streaming_window::peer_streaming_window(args)?;
        }
        HarnessCommand::PeerStreamingWindowScore(args) => {
            crate::cli::streaming_window::peer_streaming_window_score(args)?;
        }
        HarnessCommand::PeerPartialShare(args) => {
            crate::cli::partial_share::peer_partial_share(*args)?;
        }
        HarnessCommand::PeerPartialShareScore(args) => {
            crate::cli::partial_share::peer_partial_share_score(args)?;
        }
        HarnessCommand::Sx1Gate(args) => {
            crate::cli::peer::sx1_gate(args)?;
        }
        HarnessCommand::TwoHellos(args) => {
            crate::cli::peer::two_hellos(args)?;
        }
        HarnessCommand::NatgwSelfProof(args) => {
            natgw_selfproof(args)?;
        }
        HarnessCommand::Ipv6NetAccept(args) => {
            ipv6_net_accept(args)?;
        }
        HarnessCommand::SentinelSourcesLegacy(args) => {
            sentinel_sources_legacy(args)?;
        }
        HarnessCommand::PortMap(args) => {
            portmap(args)?;
        }
        HarnessCommand::Ipv6Dialect(args) => {
            ipv6_dialect(args)?;
        }
        HarnessCommand::Natt(args) => {
            natt(args)?;
        }
    }
    Ok(())
}
