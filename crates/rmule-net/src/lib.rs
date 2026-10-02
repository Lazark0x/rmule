//! Live network runtimes for rmule: one crate, one module per wire surface.
//!
//! [`driver`] is the shared generic tokio harness — the `select!` loop, output
//! drain, synthesize-`Disconnected` invariant, capture engine, and crypt
//! stream. [`ed2k`] and [`peer`] are the connection-shaped TCP runtimes that
//! drive their sans-I/O sessions through it; [`kad`] is the connectionless UDP
//! runtime, deliberately not a [`driver::DrivenSession`] (see its module docs).
//! The sans-I/O protocol crates (`rmule-ed2k`, `rmule-peer`, `rmule-kad`) stay
//! runtime-agnostic; this crate owns every socket. [`family`] owns the
//! **Family Pair** every role binds behind (ADR-0085): two sockets, one per
//! Address Family, merged by one pump that speaks `PeerEndpoint`,
//! [`interfaces`] owns the **Interface Source** seam (ADR-0084) — the one
//! place rmule asks the OS which addresses this host holds — and [`portmap`]
//! owns the **Mapping Backend** and **Gateway Source** seams (ADR-0086), the
//! I/O half of port mapping whose sans-I/O brain lives in `rmule-core`.
//! [`natt`] owns ADR-0091's NAT-T transport: the `0xB2` demux on the client-UDP
//! Family Pair, the uTP and QUIC engines that never bind a socket of their own,
//! and the `Tunnel` an unmodified peer session runs inside.

#![warn(missing_docs)]

pub mod driver;
pub mod ed2k;
pub mod family;
pub mod interfaces;
pub mod kad;
pub mod natt;
pub mod peer;
pub mod portmap;
