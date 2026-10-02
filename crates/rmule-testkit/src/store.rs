//! The Durable Store a test runs on: the same `rmule-store` database
//! production opens, on the engine's in-memory backend instead of a file
//! (ADR-0083). There is no in-memory twin of any seam, so this is what a test
//! hands [`Core::builder`](rmule_core::Core::builder) or a seam constructor.

use std::sync::Arc;

use rmule_core::{DurableStore, open_durable_store_in_memory};

/// One open Durable Store on the engine's in-memory backend, isolated to the
/// caller and dying with it.
///
/// Hand **one** of these to everything that shares state in the test — the
/// core builder, and any seam the test also holds — so the seams see each
/// other's writes exactly as a front-end's do. Two calls are two unrelated
/// databases.
///
/// # Panics
/// When the store refuses to open, which for a fresh in-memory backend against
/// core's own schema means core's schema is broken — not something a test can
/// handle.
#[must_use]
pub fn memory_store() -> Arc<DurableStore> {
    open_durable_store_in_memory().expect("the in-memory Durable Store opens")
}
