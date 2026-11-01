//! Dev-only Correctness-Tier scaffolding (ADR-0040): the deterministic
//! protocol counterparties and scenario wiring shared by Protocol-Counterparty
//! Tests across the workspace. Consumed exclusively as a `[dev-dependencies]`
//! entry; never published, never part of a production dependency graph, and
//! never wired into the Local Interop Harness (the Compatibility Tier stays a
//! separate tool, per ADR-0040).
//!
//! The bar for every fake in this crate (ADR-0040): faithful to *behaviour*,
//! not to wire bytes, and a new seam is added only when a test demands it —
//! never speculatively.
//!
//! Both-fakes policy (ADR-0040): happy paths run against a real serving core
//! ([`ServingCore`]); adversarial paths use the scriptable [`FakePeer`].
//! Neither replaces the other.
//!
//! Counterparties and scenario wiring are re-exported flat; the per-protocol
//! fixture vocabularies stay namespaced ([`kad_mesh`], [`kad_node`],
//! [`kad_keyword`], [`kad_source`], [`peer_session`], [`wire`]) because their
//! names — `node`, `key`, `publish`, `ctx`, `A` — would collide at the crate
//! root. A consumer picks: name the few it wants, or glob one vocabulary in
//! when that vocabulary is the whole subject of the leg.

#![warn(missing_docs)]

mod client_software;
#[cfg(feature = "runtime")]
mod download;
#[cfg(feature = "runtime")]
mod fake_dialer;
#[cfg(feature = "runtime")]
mod fake_ed2k_server;
#[cfg(feature = "runtime")]
mod fake_peer;
#[cfg(feature = "runtime")]
mod framing;
mod hang_guard;
#[cfg(feature = "runtime")]
mod interfaces;
pub mod kad_keyword;
pub mod kad_mesh;
pub mod kad_node;
pub mod kad_source;
#[cfg(feature = "runtime")]
mod operator;
pub mod peer_session;
#[cfg(feature = "runtime")]
mod portmap;
#[cfg(feature = "runtime")]
mod serve;
#[cfg(feature = "runtime")]
mod server_udp;
#[cfg(feature = "runtime")]
mod store;
#[cfg(feature = "runtime")]
mod test_tracing;
pub mod wire;

pub use client_software::{amule_233, client_software, emule_qt};
#[cfg(feature = "runtime")]
pub use download::{
    PendingPeerTransfer, PlanAssertingPeerTransfer, StaticPeerTransfer, StaticSourceLookup,
    emit_blocks, every_part, file_link, file_link_without_part_hash_set, file_name,
    in_download_dir, loopback_peer, next_event, plain_sources, run_download, run_download_with,
    source_with_high_id, two_high_id_sources,
};
#[cfg(feature = "runtime")]
pub use fake_dialer::{FakeBuddy, FakeDialer};
#[cfg(feature = "runtime")]
pub use fake_ed2k_server::{FakeEd2kServer, spawn_check_answering_listener};
#[cfg(feature = "runtime")]
pub use fake_peer::{
    FakePeer, HashSetPolicy, MultiPacketPolicy, PeerScript, PeerStats, SeenMultiPacketRequest,
    ServePolicy, SlotPolicy, SourcesPolicy,
};
pub use hang_guard::HANG_GUARD;
#[cfg(feature = "runtime")]
pub use interfaces::FakeInterfaces;
pub use peer_session::test_identity;
pub use kad_mesh::{FakeKadPeer, KadMeshSim, LinkPolicy, TraceEntry, drain_split};
#[cfg(feature = "runtime")]
pub use operator::{absolute_path, connect_to, share_directory};
#[cfg(feature = "runtime")]
pub use portmap::{FakeGateways, GrantPolicy, ScriptedBackend};
#[cfg(feature = "runtime")]
pub use serve::{
    LoopbackServeRuntime, PendingSourceLookup, RefusingPeerTransfer, ServingCore,
    test_handshake_ctx,
};
#[cfg(feature = "runtime")]
pub use server_udp::FakeServerUdp;
#[cfg(feature = "runtime")]
pub use store::{memory_store, scratch_ports};
#[cfg(feature = "runtime")]
pub use test_tracing::{CapturedLog, TracingGuard, capture_tracing, init_tracing};
