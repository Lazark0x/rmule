//! Live runtime layer for the eD2k peer protocol: the dial-out
//! [`Connection`], the inbound [`PeerListener`], the driver adapter, capture,
//! and timeouts, driving the sans-I/O `rmule_peer::PeerSession`.
//!
//! One bidirectional session serves both roles — a dialed connection sends
//! the hello first, an accepted one waits for the peer's — so the hello
//! timeout inverts with the role (our `OP_HELLO` unanswered vs. the peer's
//! hello never arriving) yet closes with the same `HelloTimeout`; the TCP
//! connect timeout applies to dials only. The consumer observes exactly one
//! `Disconnected` as the final event: the session emits its own paired
//! `Disconnected` on every close path, and the harness synthesizes one only
//! for the closes the session cannot see (clean EOF → `PeerClosed`, socket
//! I/O error → `Io`). The listener owns sockets, not policy: accepted
//! connections go up to core, which decides what to serve — and it is a
//! **Family Pair** behind one accept pump, reached through the
//! [`InboundSource`] seam (ADR-0085).

mod capture;
mod connection;
mod driver;
mod error;
mod inbound;
mod listener;
mod obfuscation;
mod options;

pub use capture::ELISION_MARKER;
pub use connection::{Connection, DialedStream, OpenedDial, PeerStreamRole};
pub use error::PeerNetError;
pub use inbound::{InboundSource, PushBack};
pub use listener::{Admitted, PeerListener};
pub use obfuscation::{
    AwaitedTesters, ObfuscationConfig, ObfuscationPolicy, PeerObfuscationTransport,
};
pub use options::{CaptureMode, ConnectOptions, Ipv6Follow, PEER_CRYPT_TIMEOUT};
