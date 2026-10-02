//! The **Port Mapping** flows (ADR-0092): `portmap-highid`,
//! `portmap-mismatch` and `portmap-ipv6-pinhole`.
//!
//! All three stand up the same bench — a `miniupnpd` **Port-Mapping Gateway**
//! holding a fake-public WAN and a masquerade-free LAN, a **Reflector Probe**
//! on the WAN for the **NAT Type Proof**, per-attachment taps on both of the
//! gateway's sides, and rmule driven by `rmule-tools nat portmap` from inside
//! the LAN — and differ only in the knobs the driver is given and the sentence
//! each one is trying to settle:
//!
//! - **`portmap-highid`** — the mapping lands on the **exact** port, the
//!   gateway renews it, and every row rmule publishes is `Mapped`.
//! - **`portmap-mismatch`** — a second container pre-claims the ports, so the
//!   grant comes back shifted: the TCP row must read `Degraded` and must not be
//!   advertised, while the UDP rows carry the shifted port.
//! - **`portmap-ipv6-pinhole`** — a PCP MAP on the `3fff` address.
//! - **`portmap-ipv6-pinhole-link-local`** — the same MAP with the gateway
//!   reached through its `fe80::` address, the shape every SLAAC default route
//!   takes: the request must still leave from the Known IPv6 its header names.
//!
//! **What is evidence here.** The gateway is the counterparty: its own lease
//! table (`upnp.leases` / `upnp6.leases`), its own `nft list ruleset`, and its
//! own log are the bytes a verdict rests on. Everything rmule reports about
//! itself is Stimulus (ADR-0045) and is recorded beside them so the two can be
//! read against each other — never in place of them.

pub(crate) mod bench;
pub(crate) mod gateway;
pub(crate) mod helper;
pub(crate) mod link_local;
pub(crate) mod row;
pub(crate) mod verdict;

use anyhow::Result;

pub use self::bench::PortMapOptions;

use crate::nat::NatType;

/// Which of the three port-mapping flows is running.
///
/// One enum rather than three entry points because the bench is identical and
/// the differences are a handful of knobs: splitting them would triplicate the
/// topology and let the three copies drift apart, which is exactly what a
/// gateway flow cannot afford — a verdict cites the NAT type the same bench
/// proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortMapFlow {
    /// The mapping lands on the exact port and is renewed.
    HighId,
    /// The ports are pre-claimed, so the grant shifts.
    Mismatch,
    /// A PCP MAP on the **Fake-Public v6 Plan** address.
    Ipv6Pinhole,
    /// [`Ipv6Pinhole`](Self::Ipv6Pinhole) through a link-local next hop.
    Ipv6PinholeLinkLocal,
}

impl PortMapFlow {
    /// Every flow, in the order the README lists them.
    pub const ALL: [Self; 4] = [
        Self::HighId,
        Self::Mismatch,
        Self::Ipv6Pinhole,
        Self::Ipv6PinholeLinkLocal,
    ];

    /// The flow's name in every artifact it writes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HighId => "portmap-highid",
            Self::Mismatch => "portmap-mismatch",
            Self::Ipv6Pinhole => "portmap-ipv6-pinhole",
            Self::Ipv6PinholeLinkLocal => "portmap-ipv6-pinhole-link-local",
        }
    }

    /// Whether this is one of the two IPv6 pinhole flows.
    pub(crate) const fn pinhole(self) -> bool {
        matches!(self, Self::Ipv6Pinhole | Self::Ipv6PinholeLinkLocal)
    }

    /// Parse a flow name.
    ///
    /// # Errors
    /// If `name` is not one of the three.
    pub fn from_name(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|flow| flow.name() == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown port-mapping flow `{name}`; the harness carries {}",
                    Self::ALL.map(Self::name).join(", ")
                )
            })
    }

    /// Which protocol the driver is forced onto.
    ///
    /// One per flow, never the full race: a race's winner is whichever protocol
    /// answered first, so a row taken from one could not say *which* surface it
    /// measured. The two UPnP flows also avoid the PCP lifetime floor the
    /// gateway applies (`images/miniupnpd/entrypoint.sh`), which is what makes a
    /// renewal observable inside a bounded window at all.
    pub(crate) const fn protocol(self) -> &'static str {
        match self {
            Self::HighId | Self::Mismatch => "upnp",
            Self::Ipv6Pinhole | Self::Ipv6PinholeLinkLocal => "pcp",
        }
    }

    /// Which families the driver's sockets bind.
    ///
    /// The two UPnP flows bind IPv4 alone, and that is not a shortcut: the
    /// **Desired Mapping Set** is derived from what bound, so on a dual-stack
    /// container an IPv4-only protocol is asked for the v6 rows too, answers
    /// `Unsupported`, and the whole trial grades `Partial` — a perfect router
    /// could then never produce an `Exact` install.
    pub(crate) const fn families(self) -> &'static str {
        match self {
            Self::HighId | Self::Mismatch => "v4",
            Self::Ipv6Pinhole | Self::Ipv6PinholeLinkLocal => "both",
        }
    }

    /// The lifetime the driver asks the gateway for.
    pub(crate) const fn lease_secs(self) -> u64 {
        match self {
            // Short enough that the renewal ladder's first rung (L/2) fires
            // several times inside the window.
            Self::HighId => 12,
            // Longer: this flow is about the shifted grant, and a fast renewal
            // cadence would only add rows to read.
            Self::Mismatch => 20,
            Self::Ipv6Pinhole | Self::Ipv6PinholeLinkLocal => 12,
        }
    }

    /// Whether the driver also runs a Kad node.
    ///
    /// On for the two IPv4 flows: Kad rides the one UDP socket (ADR-0057), so
    /// it adds no row of its own — what it adds is the `kad.firewall` verdict
    /// ADR-0092's fourth assertion reads, and a reason for that socket's port
    /// to be *known* (so a pre-claim can target it). Off for the pinhole flow,
    /// whose Kad half is IPv4-only and says nothing about the v6 question.
    pub(crate) const fn kad(self) -> bool {
        matches!(self, Self::HighId | Self::Mismatch)
    }

    /// How many stock-aMule **Kad helpers** stand on the WAN.
    ///
    /// Two for `portmap-highid`, and the number is the ADR-0058 verdict rule
    /// rather than a choice: the TCP verdict reads open on two connect-back
    /// acks, each helper answers one of rmule's checks, so one helper could
    /// prove at most half the rule.
    ///
    /// None for the other two. `portmap-mismatch` asserts that a shifted grant
    /// earns *no* recheck, so helpers there could only add noise to a claim
    /// about silence; the pinhole flow runs no Kad node at all.
    pub(crate) const fn kad_helpers(self) -> usize {
        match self {
            Self::HighId => 2,
            Self::Mismatch | Self::Ipv6Pinhole | Self::Ipv6PinholeLinkLocal => 0,
        }
    }

    /// The `(protocol, external port)` pairs a second container claims on the
    /// gateway before rmule asks for them.
    pub(crate) const fn preclaims(self) -> &'static [(&'static str, u16)] {
        match self {
            Self::Mismatch => &[("TCP", PEER_TCP_PORT), ("UDP", UDP_PORT)],
            Self::HighId | Self::Ipv6Pinhole | Self::Ipv6PinholeLinkLocal => &[],
        }
    }

    /// How long the driver watches before writing its row.
    pub(crate) const fn window_secs(self) -> u64 {
        match self {
            // Longer than its siblings: this window has to hold the whole
            // firewall-check round trip the Exact grant triggers — rmule's
            // hello probes, the helpers' `0x58`s, their connect-backs through
            // the fresh redirect, and the acks that land on it.
            Self::HighId => 75,
            Self::Mismatch => 40,
            Self::Ipv6Pinhole | Self::Ipv6PinholeLinkLocal => 45,
        }
    }
}

/// The NAT type the gateway claims. Its entrypoint renders the same
/// port-preserving SNAT the `natgw` image's `port-restricted` branch does, so
/// the claim the **Reflector Probe** checks is the same one `natgw-selfproof` proved.
pub(crate) const GATEWAY_NAT_TYPE: NatType = NatType::PortRestricted;

/// rmule's eD2k peer listener port inside the driver container — the mapping
/// that earns a High-ID, and the port `portmap-mismatch` pre-claims.
pub(crate) const PEER_TCP_PORT: u16 = 4662;

/// rmule's one UDP port inside the driver container — peer reask, the NAT-T
/// frames and Kad share it (ADR-0057), so it is one mapping in the **Desired
/// Mapping Set**, not two. Pinned rather than ephemeral precisely so a
/// pre-claim can name it.
pub(crate) const UDP_PORT: u16 = 4672;

/// The driver's LAN address. `.2` is the gateway and `.3` is the probe client
/// (`NAT_LAN_CLIENT`), so the driver takes `.4` and the pre-claimer `.5`.
pub(crate) const DRIVER_LAN_ADDRESS: &str = "10.77.0.4";

/// The pre-claiming container's LAN address — a *different* host, which is what
/// makes the conflict a real one rather than rmule colliding with itself.
pub(crate) const PRECLAIM_LAN_ADDRESS: &str = "10.77.0.5";

/// Run one port-mapping flow.
///
/// # Errors
/// If the bench cannot be stood up, the driver never produces a row, or the
/// verdict cannot be written. A gateway that refused, shifted or dropped a
/// mapping is **not** an error — that is the row the flow exists to take.
pub fn run_portmap(options: PortMapOptions<'_>) -> Result<()> {
    bench::run(options)
}
