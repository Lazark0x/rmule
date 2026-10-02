//! The TUI's own units for the data a sentence carries: an address as
//! `host:port`, a hash or a Kad id as its short hex form, a wait in whole
//! seconds. Fragments, never sentences of their own.

use std::net::IpAddr;
use std::time::Duration;

use rmule_primitives::{FileHash, PeerEndpoint, ServerEndpoint};

/// How many hex digits a short hash keeps.
const SHORT_HEX_DIGITS: usize = 10;

/// A peer as `host:port`; an IPv6 host in brackets, so the port reads apart.
#[must_use]
pub fn address(peer: PeerEndpoint) -> String {
    match peer.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", peer.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", peer.port()),
    }
}

/// A server as `host:port` — the one spelling the status feed, the log and
/// the Servers tab's modals share, so a flash and a confirm never name the
/// same server differently.
#[must_use]
pub fn server_label(server: &ServerEndpoint) -> String {
    format!("{}:{}", server.host(), server.port())
}

/// The short hex form of a file hash, a user hash or a Kad id (spec §3.5):
/// its first ten upper-case hex digits and `…`, so every
/// surface that abbreviates an identity reads alike.
#[must_use]
pub fn short_hex(bytes: &[u8]) -> String {
    let mut short: String = bytes
        .iter()
        .flat_map(|byte| {
            let hex = format!("{byte:02X}");
            hex.chars().collect::<Vec<_>>()
        })
        .take(SHORT_HEX_DIGITS)
        .collect();
    short.push('…');
    short
}

/// A file hash in its short hex form.
#[must_use]
pub fn short_hash(hash: FileHash) -> String {
    short_hex(hash.as_bytes())
}

/// [`short_hash`], or `—` while the hash itself is not yet known.
#[must_use]
pub fn short_hash_or_dash(hash: Option<FileHash>) -> String {
    hash.map_or_else(|| "—".to_string(), short_hash)
}

/// A wait in whole seconds, rounded up: a request due in 300 ms is "1 s",
/// never "0 s".
#[must_use]
pub fn seconds(wait: Duration) -> u64 {
    wait.as_millis()
        .div_ceil(1000)
        .try_into()
        .unwrap_or(u64::MAX)
}

/// "1 part" / "N parts", with the noun given.
#[must_use]
pub fn count(n: u64, one: &str, many: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    }
}
