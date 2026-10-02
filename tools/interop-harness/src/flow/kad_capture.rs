//! The Kad capture family: flows that provoke a real aMule into emitting Kad
//! bytes and record what it emitted.
//!
//! rmule participates as a **Kad Stimulus Node** (ADR-0043) — publisher,
//! requester, or both — so its own datagrams are context and only the aMule's
//! answers are evidence. Spans the source-lookup and distance-ordering captures
//! against a patched-aMule mesh, and the source captures against the LAN-mode
//! and fake-public storer topologies.

pub(crate) mod distance_ordering;
pub(crate) mod fake_public_source;
pub(crate) mod source;
pub(crate) mod source_lookup;
pub(crate) mod verdict;

pub use self::distance_ordering::run_kad_distance_ordering_capture;
pub use self::fake_public_source::{KadFakePublicSourceOptions, run_kad_fake_public_source};
pub use self::source::{KadSourceCaptureOptions, run_kad_source_capture};
pub use self::source_lookup::run_kad_source_lookup_capture;
