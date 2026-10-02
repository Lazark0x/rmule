//! The **Fake-Public v6 Plan**: IPv6 addressing for the harness's `--internal`
//! WAN bridges, from RFC 9637's documentation block `3fff::/20`.
//!
//! The v4 plan ([`crate::fake_public`]) exists because stock aMule rejects
//! RFC1918 at its Kad routing gate. The v6 plan exists for the harder version of
//! the same problem: every IPv6-speaking counterparty whose source was read
//! rejects ULA
//! (`fc00::/7`), and emule-qt additionally rejects `2001:db8::/32`, so Docker's
//! own auto-allocated ULA `/64`s are useless for a peer-visible address and the
//! obvious documentation prefix is useless for half the bodies. `3fff::/20` is
//! global-unicast-shaped (its first byte `0x3f` satisfies kno's
//! `IsGlobalUnicast`, `(byte0 & 0xE0) == 0x20`, i.e. `2000::/3`), unroutable by
//! registry policy, and absent from every reject list read — but *absent from a
//! reject list* is a reading, not a measurement, which is why the
//! `ipv6-net-accept` flow starts each body on the prefix and asserts its own log
//! before any v6 flow trusts the plan.
//!
//! One `/64` per WAN: `3fff:<harness>:<net>::/64`. The module is pure — it owns
//! the plan, and [`crate::docker`] turns it into `network create --ipv6
//! --subnet` / `run --ip6` argv.

use anyhow::{Result, bail};

/// RFC 9637's IPv6 documentation block, as the plan's leading hextet. The whole
/// block is `3fff::/20`; every subnet below sits inside it.
pub const FAKE_PUBLIC_V6_BLOCK: &str = "3fff";

/// The `<harness>` hextet. RFC 9637 reserves `3fff::/20`, so only the low
/// twelve bits of the second hextet are ours — `0ed2` ("ed2") is inside the
/// block and still recognisable in a pcap as this harness's squat rather than
/// some other lab's. Spelled without the leading zero because that is the
/// canonical rendering docker's `--subnet` round-trips.
pub const FAKE_PUBLIC_V6_HARNESS: &str = "ed2";

/// WAN `/64`s the plan carries (`<net>` ∈ `1..=16`). `0` is deliberately unused:
/// `3fff:ed2:0::/64` renders as `3fff:ed2::/64`, which a `--subnet` round trip
/// through docker's own normalisation would not return verbatim.
pub const MAX_FAKE_PUBLIC_V6_NETS: u16 = 16;

/// The first usable host suffix on a `/64`: `::1` is the Docker bridge gateway,
/// so static addresses start at `::2` — the same discipline as the v4 plan.
const FIRST_HOST_SUFFIX: u16 = 2;

/// One WAN's `/64` and the addresses on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakePublicV6Plan {
    net: u16,
}

impl FakePublicV6Plan {
    /// The plan for WAN `net` (`1..=`[`MAX_FAKE_PUBLIC_V6_NETS`]).
    ///
    /// # Errors
    /// If `net` is `0` or beyond the nets the plan carries.
    pub fn for_network(net: u16) -> Result<Self> {
        if net == 0 || net > MAX_FAKE_PUBLIC_V6_NETS {
            bail!(
                "fake-public v6 net {net} outside 1..={MAX_FAKE_PUBLIC_V6_NETS}; \
                 net 0 renders as an elided `::` and would not round-trip"
            );
        }
        Ok(Self { net })
    }

    /// This WAN's CIDR — the value passed to `network create --subnet`.
    pub fn subnet(&self) -> String {
        format!(
            "{FAKE_PUBLIC_V6_BLOCK}:{FAKE_PUBLIC_V6_HARNESS}:{:x}::/64",
            self.net
        )
    }

    /// The `index`-th static address on this WAN (index `0` is `::2`) — the
    /// value passed to `run --ip6`.
    ///
    /// # Errors
    /// If `index` would run past the `/64`'s low hextet.
    pub fn address(&self, index: u16) -> Result<String> {
        let suffix = FIRST_HOST_SUFFIX
            .checked_add(index)
            .filter(|suffix| *suffix != u16::MAX)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "fake-public v6 host index {index} runs past the /64's low hextet \
                     (max {})",
                    u16::MAX - FIRST_HOST_SUFFIX - 1
                )
            })?;
        Ok(format!(
            "{FAKE_PUBLIC_V6_BLOCK}:{FAKE_PUBLIC_V6_HARNESS}:{:x}::{suffix:x}",
            self.net
        ))
    }

    /// The WAN index this plan addresses.
    pub fn net(&self) -> u16 {
        self.net
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn a_wan_gets_a_documentation_block_slash_64_with_hosts_from_two() {
        let plan = FakePublicV6Plan::for_network(1).unwrap();
        assert_eq!(plan.subnet(), "3fff:ed2:1::/64");
        assert_eq!(plan.address(0).unwrap(), "3fff:ed2:1::2");
        assert_eq!(plan.address(1).unwrap(), "3fff:ed2:1::3");
    }

    #[test]
    fn distinct_wans_get_distinct_slash_64s() {
        let first = FakePublicV6Plan::for_network(1).unwrap();
        let second = FakePublicV6Plan::for_network(2).unwrap();
        assert_ne!(first.subnet(), second.subnet());
        assert_eq!(second.subnet(), "3fff:ed2:2::/64");
        assert_eq!(second.address(0).unwrap(), "3fff:ed2:2::2");
    }

    #[test]
    fn net_zero_and_overflowing_nets_are_refused() {
        assert!(FakePublicV6Plan::for_network(0).is_err());
        assert!(FakePublicV6Plan::for_network(MAX_FAKE_PUBLIC_V6_NETS).is_ok());
        assert!(FakePublicV6Plan::for_network(MAX_FAKE_PUBLIC_V6_NETS + 1).is_err());
    }

    #[test]
    fn every_planned_address_passes_the_counterparty_global_unicast_test() {
        // kno/amule's `IsGlobalUnicast` is `(value[0] & 0xE0) == 0x20` (2000::/3)
        // and both read reject lists name `fc00::/7`, `fe80::/10`, `2001::/32`,
        // `2001:db8::/32`, `2002::/16`, `5f00::/16` — none of which can contain a
        // `3fff:` address. The measurement is `ipv6-net-accept`; this is the
        // guard that the *plan* cannot drift out of the space that measurement
        // covers.
        for net in 1..=MAX_FAKE_PUBLIC_V6_NETS {
            let plan = FakePublicV6Plan::for_network(net).unwrap();
            for index in [0_u16, 1, 253] {
                let text = plan.address(index).unwrap();
                let parsed: Ipv6Addr = text.parse().unwrap_or_else(|error| {
                    panic!("planned address {text} does not parse: {error}")
                });
                let octets = parsed.octets();
                assert_eq!(
                    octets[0] & 0xE0,
                    0x20,
                    "{text} fails the global-unicast test the counterparties apply"
                );
                assert!(
                    parsed >= "3fff::".parse::<Ipv6Addr>().unwrap()
                        && parsed < "3fff:1000::".parse::<Ipv6Addr>().unwrap(),
                    "{text} is outside RFC 9637's 3fff::/20"
                );
            }
        }
    }

    #[test]
    fn a_host_index_past_the_low_hextet_is_a_clean_error() {
        let plan = FakePublicV6Plan::for_network(1).unwrap();
        assert!(plan.address(u16::MAX - FIRST_HOST_SUFFIX - 1).is_ok());
        assert!(plan.address(u16::MAX - FIRST_HOST_SUFFIX).is_err());
        assert!(plan.address(u16::MAX).is_err());
    }
}
