//! The NAT and IPv6 flows (ADR-0092) and the topology they share.
//!
//! The baseline flows make the *bench* provable before any port-mapping,
//! IPv6-dialect or NAT-traversal flow leans on it: `natgw-selfproof` shows each
//! **NAT Gateway** builds the RFC 4787 behaviour its `NAT_TYPE` claims,
//! `ipv6-net-accept` shows each counterparty body actually admits a
//! **Fake-Public v6 Plan** address instead of the harness inferring it from a
//! reject list, and `sentinel-sources-legacy` shows the legacy body reads a
//! **Sentinel Source**-bearing list without desyncing. All three are `fast` tier
//! and none needs a counterparty transfer.
//!
//! The addresses are fixed here rather than at each call site so a gateway, its
//! reflector and its client cannot drift apart: the WAN is the first
//! fake-public `/24`, the LAN is RFC1918 on purpose (a leaked LAN address fails
//! every client's `IsGoodIP`, which is a free tripwire), and the gateway holds
//! `.2` on both.

pub(crate) mod claims;
pub(crate) mod dialect;
pub(crate) mod ipv6_accept;
pub(crate) mod natt;
pub(crate) mod portmap;
pub(crate) mod selfproof;
pub(crate) mod sentinel;
pub(crate) mod synthetic;

pub use self::dialect::{Ipv6DialectOptions, Ipv6Flow, run_ipv6_dialect};
pub use self::ipv6_accept::{Ipv6Body, Ipv6NetAcceptOptions, run_ipv6_net_accept};
pub use self::natt::{NattFlow, NattOptions, run_natt};
pub use self::portmap::{PortMapFlow, PortMapOptions, run_portmap};
pub use self::selfproof::{NatGatewaySelfProofOptions, run_natgw_selfproof};
pub use self::sentinel::{LegacyDrive, SentinelSourcesLegacyOptions, run_sentinel_sources_legacy};

/// The **NAT Gateway**'s LAN bridge. RFC1918 deliberately: the gateway must
/// translate it away, and a client that ever leaks this address into a Kad
/// contact or a peer advertisement is rejected by every counterparty's
/// `IsGoodIP` — a tripwire the bench gets for free.
pub(crate) const NAT_LAN_SUBNET: &str = "10.77.0.0/24";

/// The gateway's LAN address. `.1` is Docker's own bridge gateway, so the NAT
/// gateway takes `.2` and the client `.3`.
pub(crate) const NAT_LAN_GATEWAY: &str = "10.77.0.2";

/// The client's LAN address — the one the gateway's pinned SNAT and DNAT name.
pub(crate) const NAT_LAN_CLIENT: &str = "10.77.0.3";

/// The **Pinned-Pair Reach** leg's second LAN, one `/24` along, with the same
/// `.2`/`.3` split. A second bridge rather than a second address on the first:
/// the leg's whole subject is two *gateways* translating toward each other, and
/// two clients sharing one gateway would have nothing to measure.
pub(crate) const NAT_PEER_LAN_SUBNET: &str = "10.78.0.0/24";
pub(crate) const NAT_PEER_LAN_GATEWAY: &str = "10.78.0.2";
pub(crate) const NAT_PEER_LAN_CLIENT: &str = "10.78.0.3";

/// The reflector's UDP ports. Two of them, because RFC 5780's filtering tests
/// ask for an answer from a port the client never sent to.
pub(crate) const NATPROBE_PRIMARY_PORT: u16 = 3478;
pub(crate) const NATPROBE_SECONDARY_PORT: u16 = 3479;

/// The client's UDP port, and therefore the port `full-cone-pinned` pins. It is
/// aMule's and rmule's default Kad/peer UDP port, so the gateway a NAT-traversal flow
/// later puts a real client behind is the same gateway this one proves.
pub(crate) const NAT_CLIENT_UDP_PORT: u16 = 4672;
