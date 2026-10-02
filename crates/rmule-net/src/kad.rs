//! Thin tokio UDP runtime for the sans-I/O `rmule_kad::KadNode`.
//!
//! One task per node: a single `select!` loop over transport receives, driver
//! commands, and the node's own `next_wake()` deadline. The loop maps real time
//! onto the node's explicit `KadInstant` scale (driver start = epoch), flushes
//! outbound datagrams, forwards `KadEvent`s to the handle, and optionally taps
//! every datagram into a capture directory (ADR-0022: capture is a first-class
//! library feature).
//!
//! **One loop, two transports** (ADR-0057): [`spawn`] binds a
//! **Family Pair** the node owns — the standalone shape the `rmule-tools`
//! drivers, the Kad Stimulus Node and the mesh sim run — while [`spawn_over`]
//! rides a socket the caller already owns, which is how a Kad node inside a
//! core shares the one client-UDP bind an eMule-family client listens on. The
//! capture tap, the `nodes.dat` persistence, the summary counters and the
//! firewall self-check arming are the driver's either way.
//!
//! Deliberately *not* a [`crate::driver::DrivenSession`]: that contract is
//! connection-shaped (byte stream, startup deadline, close reason) while a Kad
//! node is connectionless with a rich timer set (ADR-0043, considered options).

mod capture;
mod driver;
mod error;
mod persist;
mod transport;

pub use driver::{KadNetConfig, KadNetHandle, KadNetSummary, spawn, spawn_over};
pub use error::KadNetError;
pub use transport::{KAD_INLET_CAPACITY, KadDatagram, KadInlet, KadTraffic, KadTrafficTotals};
