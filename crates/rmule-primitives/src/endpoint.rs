//! The bare address+port wire values, one per **Address Family**, and the
//! family itself. A type here is exactly as wide as its wire meaning: an
//! `Ipv4Endpoint` is the six bytes every IPv4-packing surface carries, an
//! `Ipv6Endpoint` is the sixteen-byte address the inline sentinel appends plus
//! the port its record already carried. Neither holds a `std::net::SocketAddr`:
//! flow-info and scope-id are not wire values (ADR-0085).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::PrimitiveError;

/// IPv4 or IPv6, as a property of an endpoint or a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressFamily {
    /// The 32-bit family every classic eD2k/Kad surface packs.
    V4,
    /// The 128-bit family the sentinel and the IPv6 dialect carry.
    V6,
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// An address:port pair exactly as the wire carries it — six bytes, no
/// hostnames.
///
/// Distinct from [`ServerEndpoint`](crate::ServerEndpoint) on purpose: this
/// is a *decoded wire field*, so it is always a literal address and always
/// round-trips.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Endpoint {
    /// The address.
    pub ip: Ipv4Addr,
    /// The port.
    pub port: u16,
}

impl Ipv4Endpoint {
    /// How many bytes the encoded form occupies.
    pub const WIRE_LEN: usize = 6;

    /// An endpoint from its two parts.
    #[must_use]
    pub const fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip, port }
    }

    /// Encode as `[octet0, octet1, octet2, octet3, port_lo, port_hi]`.
    /// `Ipv4Addr::octets` is network-order (big-endian wire format),
    /// which happens to coincide with the LE `u32` rendering used by
    /// `Uint32toStringIP` in `docs/reference/notes/ed2k-welcome-packets.md`
    /// (OP_SERVERLIST section). Documented to spare a future reader the
    /// "wait, where's the LE conversion on the IP" puzzle.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::WIRE_LEN] {
        let o = self.ip.octets();
        let p = self.port.to_le_bytes();
        [o[0], o[1], o[2], o[3], p[0], p[1]]
    }

    /// Read the six-byte wire form back.
    #[must_use]
    pub fn decode(bytes: &[u8; Self::WIRE_LEN]) -> Self {
        Self {
            ip: Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            port: u16::from_le_bytes([bytes[4], bytes[5]]),
        }
    }
}

impl fmt::Display for Ipv4Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

impl FromStr for Ipv4Endpoint {
    type Err = PrimitiveError;

    /// Strict `a.b.c.d:port` — a literal address, a colon, a decimal port.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (ip, port) = input
            .rsplit_once(':')
            .ok_or(PrimitiveError::InvalidPeerEndpoint {
                reason: "endpoint missing ':port'",
            })?;
        let ip = ip
            .parse::<Ipv4Addr>()
            .map_err(|_| PrimitiveError::InvalidPeerEndpoint {
                reason: "not an IPv4 literal",
            })?;
        Ok(Self::new(ip, parse_port(port)?))
    }
}

/// An IPv6 address plus a port — the address as the sixteen network-order
/// bytes the inline sentinel appends to a source record (ADR-0085), the port
/// as the record's own `u16`. Printed and parsed in the bracketed
/// `[addr]:port` form; a scope id is refused because it is not a wire value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Endpoint {
    /// The address.
    pub ip: Ipv6Addr,
    /// The port.
    pub port: u16,
}

impl Ipv6Endpoint {
    /// How many bytes the address alone occupies on the wire — the sentinel
    /// block and every `TAGTYPE_HASH` IPv6 tag.
    pub const ADDR_WIRE_LEN: usize = 16;

    /// An endpoint from its two parts.
    #[must_use]
    pub const fn new(ip: Ipv6Addr, port: u16) -> Self {
        Self { ip, port }
    }

    /// An endpoint from the sixteen network-order address bytes a sentinel
    /// block carries and the port its record carried.
    #[must_use]
    pub const fn from_addr_bytes(bytes: [u8; Self::ADDR_WIRE_LEN], port: u16) -> Self {
        Self {
            ip: Ipv6Addr::from_bits(u128::from_be_bytes(bytes)),
            port,
        }
    }

    /// The address as the sixteen network-order bytes the wire carries.
    #[must_use]
    pub const fn addr_bytes(&self) -> [u8; Self::ADDR_WIRE_LEN] {
        self.ip.octets()
    }
}

impl fmt::Display for Ipv6Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]:{}", self.ip, self.port)
    }
}

impl FromStr for Ipv6Endpoint {
    type Err = PrimitiveError;

    /// Strict `[addr]:port` — brackets required, no scope id.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let inner = input
            .strip_prefix('[')
            .ok_or(PrimitiveError::InvalidPeerEndpoint {
                reason: "IPv6 endpoint must be bracketed as [addr]:port",
            })?;
        let (ip, port) = inner
            .split_once("]:")
            .ok_or(PrimitiveError::InvalidPeerEndpoint {
                reason: "IPv6 endpoint missing ']:port'",
            })?;
        let ip = ip
            .parse::<Ipv6Addr>()
            .map_err(|_| PrimitiveError::InvalidPeerEndpoint {
                reason: "not an IPv6 literal",
            })?;
        Ok(Self::new(ip, parse_port(port)?))
    }
}

fn parse_port(text: &str) -> Result<u16, PrimitiveError> {
    text.parse()
        .map_err(|_| PrimitiveError::InvalidPeerEndpoint {
            reason: "endpoint port is not a valid u16",
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_endpoint_round_trips_the_sentinel_block_bytes() {
        let bytes: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01,
        ];
        let ep = Ipv6Endpoint::from_addr_bytes(bytes, 4662);
        assert_eq!(ep.ip, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ep.addr_bytes(), bytes);
    }

    #[test]
    fn text_forms_are_strict_and_round_trip() {
        let v4: Ipv4Endpoint = "198.51.100.7:4662".parse().unwrap();
        assert_eq!(v4.to_string(), "198.51.100.7:4662");
        let v6: Ipv6Endpoint = "[2001:db8::1]:4662".parse().unwrap();
        assert_eq!(v6.to_string(), "[2001:db8::1]:4662");

        for bad in ["198.51.100.7", "[2001:db8::1]", "2001:db8::1:4662"] {
            assert!(bad.parse::<Ipv4Endpoint>().is_err(), "{bad}");
            assert!(bad.parse::<Ipv6Endpoint>().is_err(), "{bad}");
        }
        // A scope id is a host concept, never a wire value.
        assert!("[fe80::1%3]:4662".parse::<Ipv6Endpoint>().is_err());
        assert!("[2001:db8::1]:70000".parse::<Ipv6Endpoint>().is_err());
    }
}
