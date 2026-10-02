//! The endpoint a peer is dialed at — the closed enum over the **Address
//! Families** a peer can be reached in (ADR-0085). Every family-sensitive
//! site matches it exhaustively, so the compiler lists them; the sites that
//! only need an address and a port use the family-generic accessors.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::{AddressFamily, ClientId, Ipv4Endpoint, Ipv6Endpoint, PrimitiveError};

/// The endpoint a peer is reached at.
///
/// `Ord` = family, then endpoint order (ip, then port): ordered containers
/// need a stable key (e.g. the TUI's upload-peers projection).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerEndpoint {
    /// A peer reached over IPv4.
    V4(Ipv4Endpoint),
    /// A peer reached over IPv6.
    V6(Ipv6Endpoint),
}

impl PeerEndpoint {
    /// Which family this endpoint is in.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self {
            Self::V4(_) => AddressFamily::V4,
            Self::V6(_) => AddressFamily::V6,
        }
    }

    /// The address, family-generic.
    #[must_use]
    pub const fn ip(self) -> IpAddr {
        match self {
            Self::V4(ep) => IpAddr::V4(ep.ip),
            Self::V6(ep) => IpAddr::V6(ep.ip),
        }
    }

    /// The port.
    #[must_use]
    pub const fn port(self) -> u16 {
        match self {
            Self::V4(ep) => ep.port,
            Self::V6(ep) => ep.port,
        }
    }

    /// The same address at another port — a peer's UDP endpoint derived from
    /// its TCP one, in the peer's own family.
    #[must_use]
    pub const fn with_port(self, port: u16) -> Self {
        match self {
            Self::V4(ep) => Self::V4(Ipv4Endpoint::new(ep.ip, port)),
            Self::V6(ep) => Self::V6(Ipv6Endpoint::new(ep.ip, port)),
        }
    }

    /// The IPv4 endpoint, for the surfaces whose wire packs 32 bits; `None`
    /// for an IPv6 peer, which those surfaces cannot name.
    #[must_use]
    pub const fn as_v4(self) -> Option<Ipv4Endpoint> {
        match self {
            Self::V4(ep) => Some(ep),
            Self::V6(_) => None,
        }
    }

    /// The IPv6 endpoint, or `None` for an IPv4 peer.
    #[must_use]
    pub const fn as_v6(self) -> Option<Ipv6Endpoint> {
        match self {
            Self::V4(_) => None,
            Self::V6(ep) => Some(ep),
        }
    }

    /// The form this peer takes in a 32-bit wire field — a `.part.met` seed, a
    /// classic source-exchange entry, a server source list — or `None` when it
    /// has none (ADR-0087's `HasEd2kWireForm`).
    ///
    /// A native-IPv6 peer is **omitted** from such a field, never written as
    /// `0`: a zero reads as a Low ID with no server behind it, which sends the
    /// reader down a callback that can never be brokered. `0.0.0.0` is refused
    /// for the same reason — it is the absence of an address wearing one.
    /// So is every address whose packed id would read back as something else:
    /// `255.255.255.255` packs to the `0xFFFFFFFF` **Sentinel Source** id, and
    /// an `x.y.z.0` packs below the Low-ID ceiling and reads back as a Low ID.
    /// ADR-0085's Family Pairs bind `IPV6_V6ONLY`, so `::ffff:0.0.0.0` never
    /// reaches this call.
    #[must_use]
    pub const fn ed2k_wire_form(self) -> Option<Ipv4Endpoint> {
        match self {
            Self::V4(ep)
                if !ep.ip.is_unspecified()
                    && !ep.ip.is_broadcast()
                    && u32::from_le_bytes(ep.ip.octets()) >= ClientId::LOW_ID_THRESHOLD =>
            {
                Some(ep)
            }
            Self::V4(_) | Self::V6(_) => None,
        }
    }
}

impl From<Ipv4Endpoint> for PeerEndpoint {
    fn from(endpoint: Ipv4Endpoint) -> Self {
        Self::V4(endpoint)
    }
}

impl From<Ipv6Endpoint> for PeerEndpoint {
    fn from(endpoint: Ipv6Endpoint) -> Self {
        Self::V6(endpoint)
    }
}

impl fmt::Display for PeerEndpoint {
    /// `a.b.c.d:port` or `[addr]:port` — each family's own spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(ep) => ep.fmt(f),
            Self::V6(ep) => ep.fmt(f),
        }
    }
}

impl FromStr for PeerEndpoint {
    type Err = PrimitiveError;

    /// A bracketed literal is IPv6, anything else must be a dotted-quad — the
    /// two `Display` spellings and nothing in between.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.starts_with('[') {
            input.parse().map(Self::V6)
        } else {
            input.parse().map(Self::V4)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_selects_the_family_by_spelling() {
        let v4: PeerEndpoint = "198.51.100.7:4662".parse().unwrap();
        let v6: PeerEndpoint = "[2001:db8::1]:4662".parse().unwrap();
        assert_eq!(v4.family(), AddressFamily::V4);
        assert_eq!(v6.family(), AddressFamily::V6);
        assert_eq!(v4.to_string().parse::<PeerEndpoint>().unwrap(), v4);
        assert_eq!(v6.to_string().parse::<PeerEndpoint>().unwrap(), v6);
        assert_eq!(v6.with_port(4672).ip(), v6.ip());
        assert_eq!(v6.with_port(4672).port(), 4672);
        assert!(v6.as_v4().is_none());
        assert!(v4.as_v6().is_none());
        assert!("2001:db8::1:4662".parse::<PeerEndpoint>().is_err());
    }

    /// `HasEd2kWireForm` (ADR-0087): a native-IPv6 peer has no 32-bit form, and
    /// neither does the unspecified IPv4 address — the two cases that would
    /// otherwise be written as a bare `0` into a wire field that means "Low ID".
    #[test]
    fn only_a_real_ipv4_peer_has_an_ed2k_wire_form() {
        let real: PeerEndpoint = "198.51.100.7:4662".parse().unwrap();
        let zero = PeerEndpoint::V4(Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 4662));
        let native_v6: PeerEndpoint = "[2001:db8::1]:4662".parse().unwrap();

        assert_eq!(real.ed2k_wire_form(), real.as_v4());
        assert_eq!(zero.ed2k_wire_form(), None);
        assert_eq!(native_v6.ed2k_wire_form(), None);
    }

    /// An address whose packed id reads back as something else has no wire
    /// form either: the broadcast address is the sentinel id, and `x.y.z.0`
    /// packs below `0x01000000` and reads back as a Low ID.
    #[test]
    fn an_address_that_packs_to_another_meaning_has_no_ed2k_wire_form() {
        let broadcast: PeerEndpoint = "255.255.255.255:4662".parse().unwrap();
        let dot_zero: PeerEndpoint = "10.0.0.0:4662".parse().unwrap();
        let dot_one: PeerEndpoint = "10.0.0.1:4662".parse().unwrap();
        assert_eq!(broadcast.ed2k_wire_form(), None);
        assert_eq!(dot_zero.ed2k_wire_form(), None);
        assert_eq!(dot_one.ed2k_wire_form(), dot_one.as_v4());
    }
}
