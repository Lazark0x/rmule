//! The harness driving itself against a **Fake Docker**: every orchestration
//! shape the flows depend on — build order, readiness gating, seeded identities,
//! teardown — asserted from the argv the stub runtime recorded, with no
//! container runtime present. It proves orchestration only; a counterparty's
//! bytes are never faked here, so nothing in this suite is evidence.

mod cleanup;
mod client;
mod ed2k_server;
mod kad_capture;
mod kad_network;
mod nat;
pub(crate) mod script;
mod serve;
