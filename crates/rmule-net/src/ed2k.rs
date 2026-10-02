//! Live runtime layer for the eD2k server protocol: TCP sockets, the driver
//! adapter, the public [`Connection`] handle, connect / login timeouts, the
//! server-UDP and client-UDP sockets, and the capture format that turns a
//! real session into checked-in fixtures.
//!
//! Every protocol fact comes from `rmule_ed2k`'s sans-I/O session — including
//! the login timeout, which the session owns (`login_deadline_elapsed`); the
//! driver only arms the clock. The consumer observes exactly one
//! `Disconnected` as the final event: the session emits its own paired
//! `Disconnected` on every close path, and the harness synthesizes one only
//! for the driver-originated closes the session cannot see (clean EOF →
//! `ServerClosed`, socket I/O error → `Io`). `connect` returns once TCP is
//! up, before login completes; the login outcome arrives as an event.

mod capture;
mod client_udp;
mod connection;
mod driver;
mod error;
mod obfuscation;
mod options;
mod resolve;
mod server_udp;

pub use client_udp::{ClientUdpSocket, PREDICTION_SOCKET_BUDGET, PredictionFanId, PredictionHit};
pub use connection::Connection;
pub use driver::{drive, drive_with_login_timeout};
pub use error::Ed2kNetError;
pub use obfuscation::ServerObfuscationTransport;
pub use options::ConnectOptions;
pub use server_udp::ServerUdpSocket;
