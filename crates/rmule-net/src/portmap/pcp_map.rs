//! PCP `MAP` over IPv6 from a **pinned source address** (ADR-0086): the
//! one slice of RFC 6887 rmule speaks itself instead of through `crab_nat`.
//!
//! RFC 6887 §8.2 makes the server compare the packet's source address with the
//! PCP Client IP Address field and answer `ADDRESS_MISMATCH` when they differ,
//! and on IPv6 the mapping *is* for that address — a pinhole, not a
//! translation. A v6 default route is via a link-local next hop (RFC 4861 §4.2:
//! a Router Advertisement always comes from one), so a socket bound to `::`
//! sources from `fe80::…`: the request is refused (`ADDRESS_MISMATCH` on
//! miniupnpd, `NOT_AUTHORIZED` measured on a FRITZ!Box), and even an honest
//! header would pinhole a link-local address no peer can reach. `crab_nat`
//! 0.8.1 always binds the unspecified address and exposes no knob, so this
//! module binds the socket to the address the request names — §8.4's "GUAs
//! SHOULD be used as the source address" made a guarantee rather than a hope.
//!
//! Scope is exactly what the IPv6 half of the race uses: `MAP` to create or
//! renew a pinhole, and `MAP` with lifetime 0 to delete one (the state-free
//! probe and the release). No options — rmule sends neither `THIRD_PARTY` nor
//! `PREFER_FAILURE` nor `FILTER` — and no `PEER`, which the NAT-T pin speaks
//! over IPv4 only. IPv4 and NAT-PMP stay on `crab_nat`: an IPv4 next hop is
//! not link-local, so the kernel's source is the interface address the header
//! already names.
//!
//! The codec is sans-I/O and pinned by vectors captured from two real gateways
//! (miniupnpd 2.3.10 on the bench, a FRITZ!Box via emule-qt's wire tests); the
//! transport is one socket per request, as the rest of the backend.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use crab_nat::TimeoutConfig;
use tokio::net::UdpSocket;

use super::{MappingError, MappingProtocol, MappingTransportFault};

/// The port a PCP server listens on (RFC 6887 §19.1).
pub(super) const PCP_SERVER_PORT: u16 = 5351;

const VERSION: u8 = 2;
const OPCODE_MAP: u8 = 1;
const RESPONSE_BIT: u8 = 0x80;
/// Common header (24) plus the `MAP` opcode body (36), with no options.
const MAP_LEN: usize = 60;
const HEADER_LEN: usize = 24;
/// RFC 6887 §7: nothing a server sends is longer.
const MAX_DATAGRAM: usize = 1100;

/// One `MAP` request, as the IPv6 pinhole path sends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MapRequest {
    /// The PCP Client IP Address — and, because this module binds to it, the
    /// packet's source address too.
    pub client: Ipv6Addr,
    /// The Mapping Nonce (RFC 6887 §11.1), big-endian word by word.
    pub nonce: [u32; 3],
    /// The IANA protocol number: 6 for TCP, 17 for UDP.
    pub protocol: u8,
    /// The port the pinhole opens.
    pub internal_port: u16,
    /// The external port to suggest; `0` lets the gateway choose.
    pub suggested_external_port: u16,
    /// The lifetime asked for; `0` deletes the mapping (§11.1).
    pub lifetime: u32,
}

impl MapRequest {
    /// The request's wire form. The suggested external address is `::`
    /// (no preference), which a pinhole ignores anyway.
    pub(super) fn encode(&self) -> [u8; MAP_LEN] {
        let mut wire = [0_u8; MAP_LEN];
        wire[0] = VERSION;
        wire[1] = OPCODE_MAP;
        wire[4..8].copy_from_slice(&self.lifetime.to_be_bytes());
        wire[8..24].copy_from_slice(&self.client.octets());
        for (slot, word) in wire[24..36].chunks_exact_mut(4).zip(self.nonce) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        wire[36] = self.protocol;
        wire[40..42].copy_from_slice(&self.internal_port.to_be_bytes());
        wire[42..44].copy_from_slice(&self.suggested_external_port.to_be_bytes());
        wire
    }

    /// Read one datagram as the answer to this request.
    ///
    /// A success must echo this request's nonce, protocol and internal port
    /// (§11.3) or it answers someone else. An error response is accepted from
    /// its header alone when it is too short to carry the body — §7.2 lets a
    /// server that cannot parse the request answer with only the header.
    pub(super) fn decode(&self, datagram: &[u8]) -> MapReply {
        if datagram.len() < 2 {
            return MapReply::Foreign;
        }
        if datagram[0] != VERSION {
            // A NAT-PMP-only box answers with its own version in byte 0; a
            // PCP server that speaks another version names the one it speaks.
            return MapReply::UnsupportedVersion(datagram[0]);
        }
        if datagram.len() < HEADER_LEN || datagram[1] != RESPONSE_BIT | OPCODE_MAP {
            return MapReply::Foreign;
        }
        let code = datagram[3];
        let lifetime = be_u32(&datagram[4..8]);
        let epoch = be_u32(&datagram[8..12]);
        if datagram.len() < MAP_LEN {
            return if code == 0 {
                MapReply::Foreign
            } else {
                MapReply::Refused { code, lifetime }
            };
        }
        let echoes = datagram[24..36] == self.encode()[24..36]
            && datagram[36] == self.protocol
            && datagram[40..42] == self.internal_port.to_be_bytes();
        if !echoes {
            return MapReply::Foreign;
        }
        if code != 0 {
            return MapReply::Refused { code, lifetime };
        }
        let mut external = [0_u8; 16];
        external.copy_from_slice(&datagram[44..60]);
        MapReply::Granted(MapGrant {
            lifetime,
            epoch,
            external_port: u16::from_be_bytes([datagram[42], datagram[43]]),
            external_address: Ipv6Addr::from(external),
        })
    }
}

/// What one datagram said about one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MapReply {
    /// The mapping holds (or, for lifetime 0, is gone).
    Granted(MapGrant),
    /// A PCP error: the result code, and the lifetime — §7.4's hold-off.
    Refused { code: u8, lifetime: u32 },
    /// The server speaks another version (a NAT-PMP box answers `0`).
    UnsupportedVersion(u8),
    /// Not an answer to this request; keep waiting.
    Foreign,
}

/// A successful `MAP` response's facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MapGrant {
    /// The lifetime granted, in seconds.
    pub lifetime: u32,
    /// The server's epoch (§8.5).
    pub epoch: u32,
    /// The assigned external port; a pinhole's is the internal port.
    pub external_port: u16,
    /// The assigned external address; a pinhole's is our own.
    pub external_address: Ipv6Addr,
}

/// The codes whose lifetime the backend carries as a hold-off — the same set
/// the `crab_nat` path carries, so both families pace a refusal alike.
pub(super) const fn carries_hold_off(code: u8) -> bool {
    matches!(code, 2 | 7 | 8 | 10 | 11)
}

/// Send `request` from its own client address to `server`, on `ladder` — the
/// backend's own retransmit ladder, read the way `crab_nat` reads it for every
/// other request: one send, then `max_retries` more, the wait doubling from
/// `initial_timeout` and capped at `max_retry_timeout`.
///
/// The bind *is* the pin: a Known IPv6 that is not an address of this host
/// fails here, with the reason, rather than leaving from another source.
pub(super) async fn exchange(
    server: SocketAddrV6,
    request: &MapRequest,
    ladder: TimeoutConfig,
) -> Result<MapReply, MappingError> {
    let transport = |error: std::io::Error| {
        tracing::debug!(%error, client = %request.client, "PCP exchange socket error");
        MappingError::Transport {
            protocol: MappingProtocol::Pcp,
            fault: MappingTransportFault::io(&error),
        }
    };
    let source = SocketAddr::new(IpAddr::V6(request.client), 0);
    // Not `family::bind_udp`: this socket is connected, and on every platform
    // a connected socket's ICMP port-unreachable is the gateway's answer that
    // it speaks no PCP, ending the exchange before the ladder runs out. The
    // Windows ICMP-reset switch would hide that answer on Windows alone.
    let socket = UdpSocket::bind(source).await.map_err(transport)?;
    socket
        .connect(SocketAddr::V6(server))
        .await
        .map_err(transport)?;
    let wire = request.encode();
    let mut buffer = [0_u8; MAX_DATAGRAM];
    for wait in ladder_waits(ladder) {
        socket.send(&wire).await.map_err(transport)?;
        let deadline = tokio::time::Instant::now() + wait;
        while let Ok(received) = tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await {
            let length = received.map_err(transport)?;
            match request.decode(&buffer[..length]) {
                MapReply::Foreign => {}
                reply => return Ok(reply),
            }
        }
    }
    Err(MappingError::Timeout(MappingProtocol::Pcp))
}

/// How long each send of `ladder` waits for its answer: one send, then
/// `max_retries` more, the wait doubling from `initial_timeout` and capped at
/// `max_retry_timeout` — `crab_nat`'s reading of the same config, unfuzzed.
fn ladder_waits(ladder: TimeoutConfig) -> impl Iterator<Item = std::time::Duration> {
    std::iter::successors(Some(ladder.initial_timeout), move |wait| {
        let next = wait.saturating_mul(2);
        Some(ladder.max_retry_timeout.map_or(next, |cap| next.min(cap)))
    })
    .take(ladder.max_retries.saturating_add(1))
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests;
