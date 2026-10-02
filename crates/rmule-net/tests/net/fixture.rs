//! What more than one leg needs and no second crate does: the eD2k session
//! every driver leg drives, the captured frames it replays, the bound-address
//! to `PeerEndpoint` conversion every dialing leg makes, and the loopback dial
//! options they share.
//!
//! Anything a second crate reaches for belongs in `rmule-testkit` instead —
//! which is where the handshake contexts these legs dial with live.

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use rmule_ed2k::Ed2kSession;
use rmule_net::peer::ConnectOptions;
use rmule_primitives::{
    ClientIdentity, Ed2kText, Ipv4Endpoint, PeerEndpoint, ServerEndpoint, UserHash,
};
use tokio::net::TcpListener;

/// The responder's User Hash in the obfuscation legs: an RC4 dial is keyed on
/// it, so the dialer and the accepting side must name the same bytes.
pub const RESPONDER_HASH: [u8; 16] = [0x11; 16];

/// A frame or artifact captured from a real server, read out of the eD2k
/// crate's fixture tree — the wire these driver legs replay.
pub fn ed2k_fixture(path: &str) -> Vec<u8> {
    let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rmule-ed2k/tests/fixtures")
        .join(path);
    fs::read(&full).unwrap_or_else(|e| panic!("read {}: {e}", full.display()))
}

/// One stream of the stock aMule 2.3.3 helper's dial-back captured on bench
/// flow R under `Required`, out of this crate's own fixture tree.
pub fn flow_r_dialback(name: &str) -> Vec<u8> {
    let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/kad_fwcheck/captured/amule-233-required-dialback-20260929")
        .join(name);
    fs::read(&full).unwrap_or_else(|e| panic!("read {}: {e}", full.display()))
}

/// A fresh session toward a server that is never dialed (`example.invalid`):
/// the legs here drive it over a duplex pipe or a fake, never over DNS.
pub fn test_session() -> Ed2kSession {
    let endpoint = ServerEndpoint::new("example.invalid", 4661).unwrap();
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-test"),
        4662,
        60,
    );
    Ed2kSession::new(endpoint, identity)
}

/// A bound listen address — a `FakePeer`'s, a `PeerListener`'s, or a raw
/// socket's — as the peer endpoint to dial. The one home for this conversion:
/// every leg that dials a counterparty it just bound comes through here.
pub fn peer_endpoint(addr: SocketAddrV4) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(*addr.ip(), addr.port()))
}

/// The loopback address a hand-rolled test socket bound. The legs all bind
/// `127.0.0.1:0`, so the address is known and only the port needs reading —
/// no family question to answer, and nothing to panic about.
pub fn bound_v4(listener: &TcpListener) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        listener.local_addr().expect("local_addr").port(),
    )
}

/// Dial options with room for a loopback handshake and no capture: seconds,
/// not the production minutes, so a hung leg fails the run instead of it.
pub fn options() -> ConnectOptions {
    ConnectOptions {
        connect_timeout: Duration::from_secs(2),
        hello_timeout: Duration::from_secs(5),
        capture_dir: None,
        ..Default::default()
    }
}
