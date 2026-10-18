//! The interop flows: every live Docker flow the harness can drive.
//!
//! A *flow* stands up real counterparties — a Lugdunum eserver, one or more
//! stock or patched aMules, rmule itself — on a private Docker network, drives
//! one exchange between them, and writes what it observed into the run dir. The
//! families below group the flows by which surface they exercise; the fabric
//! they share (the bench, readiness gates, log collection, evidence readback,
//! the private Kad mesh) lives beside them and is crate-internal.
//!
//! Two rules hold across every flow. Counterparty bytes are the only evidence
//! (ADR-0045) — rmule's own datagrams are stimulus, and an absent observation is
//! recorded as an absence, never fabricated. And the public surface here is
//! flat: each flow is one `*Options` value and one `run_*` entry point,
//! re-exported from this module whatever submodule implements it.

pub(crate) mod bench;
pub(crate) mod bootstrap;
pub(crate) mod driver_image;
pub(crate) mod ed2k_server;
pub(crate) mod ed2ksrv;
pub(crate) mod evidence;
pub(crate) mod gate;
pub(crate) mod identity;
pub(crate) mod kad_buddy;
pub(crate) mod kad_capture;
pub(crate) mod kad_member;
pub(crate) mod kad_network;
pub(crate) mod logs;
pub(crate) mod mesh;
pub(crate) mod nat;
pub(crate) mod packed_source_exchange;
pub(crate) mod pcap;
pub(crate) mod peer;
pub(crate) mod pinned_image;
pub(crate) mod taps;
pub(crate) mod wire_filter;

pub use self::bootstrap::{
    Ed2kKadHandoffOptions, HttpBootstrapColdStartOptions, HttpBootstrapGoldensOptions,
    V2NodesDatHarvestOptions, run_ed2k_kad_handoff, run_http_bootstrap_cold_start,
    run_http_bootstrap_goldens, run_v2_nodes_dat_harvest,
};
pub use self::ed2k_server::{
    AnnounceSwitchOptions, AskBudgetOptions, BenchSmokeOptions, CryptPingPortOptions,
    DEFAULT_HELLO_DELAY_MS, LatePortTestOptions, RmuleClientAction, SearchSpacingOptions,
    SearchWireOptions, SearchWireServer, ServerCycleOptions, ServerLoginCryptOptions,
    ServerSkeletonOptions, SweepFollowsListOptions, rescore_ask_budget, run_announce_switch,
    run_ask_budget, run_bench_smoke, run_crypt_ping_port, run_late_port_test, run_search_spacing,
    run_search_wire, run_server_cycle, run_server_login_crypt, run_server_skeleton,
    run_sweep_follows_list,
};
pub use self::ed2k_server::{HolepunchFailOptions, run_holepunch_fail, score_holepunch_fail};
pub use self::evidence::flush_golden_files;
pub use self::gate::start_rmule_serve_with_login_retry;
pub use self::kad_buddy::{
    DialedLinkVerdict, KadCoreBuddyOptions, KadDialedLinkOptions, KadDirectCallbackOptions,
    KadFirewalledBuddyOptions, KadRequiredCheckOptions, RequiredCheckVerdict, run_kad_core_buddy,
    run_kad_dialed_link, run_kad_direct_callback, run_kad_firewalled_buddy, run_kad_required_check,
};
pub use self::kad_capture::{
    KadFakePublicSourceOptions, KadSourceCaptureOptions, run_kad_distance_ordering_capture,
    run_kad_fake_public_source, run_kad_source_capture, run_kad_source_lookup_capture,
};
pub use self::kad_network::{
    KadInvertedKeywordOptions, KadJoinOptions, KadSmokeOptions, run_kad_inverted_keyword,
    run_kad_join, run_kad_smoke,
};
pub use self::mesh::{KAD_PUBLISHER_USER_HASH_HEX, KadCaptureOptions};
pub use self::nat::{
    Ipv6Body, Ipv6DialectOptions, Ipv6Flow, Ipv6NetAcceptOptions, LegacyDrive,
    NatGatewaySelfProofOptions, NattFlow, NattOptions, PortMapFlow, PortMapOptions,
    SentinelSourcesLegacyOptions, run_ipv6_dialect, run_ipv6_net_accept, run_natgw_selfproof,
    run_natt, run_portmap, run_sentinel_sources_legacy,
};
pub use self::packed_source_exchange::{PackedSourceExchangeOptions, run_packed_source_exchange};
pub use self::pcap::ed2k_frame_listing;
pub use self::peer::{
    DEFAULT_REASK_WINDOW_SECS, DirectSuiOptions, PeerLowIdCallbackReaskOptions,
    PeerUdpReaskEmitOptions, PeerUdpReaskOptions, SeedHolding, StreamingWindowOptions,
    Sx1GateOptions, TwoHellosOptions, collect_streaming_window_run, default_seeds,
    run_amule_direct_sui, run_peer_lowid_callback_reask, run_peer_udp_reask,
    run_peer_udp_reask_emit, run_rmule_serves_amule_downloads, run_streaming_window, run_sx1_gate,
    run_two_hellos, score_emit_run_dir as score_peer_udp_reask_emit, score_lowid_callback_reask,
    score_run_dir as score_peer_udp_reask, score_streaming_window, seed_holding_arg,
    stage_reask_emit_files,
};
pub use self::peer::{PartialShareOptions, run_partial_share, score_partial_share};
pub use self::peer::{
    PeerDialBackGrantOptions, run_peer_dial_back_grant, score_peer_dial_back_grant,
    stage_dial_back_files,
};
pub use self::peer::{PeerOneLinkOptions, run_peer_one_link, score_peer_one_link};
pub use self::peer::{
    ServerCallbackServeOptions, run_server_callback_serve, score_server_callback_serve,
};
