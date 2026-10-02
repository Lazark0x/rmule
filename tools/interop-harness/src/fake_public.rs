//! Fake-public address allocation for the internal aMule Kad swarm.
//!
//! Stock aMule 2.3.3 hard-blocks an all-RFC1918 Kad routing table: every
//! contact-admission path funnels through `IsGoodIPPort`, whose `filterLAN`
//! argument is hardcoded `true`, so `10/8`, `172.16/12`, and `192.168/16` are
//! rejected at the routing-add gate independent of any preference. The answer
//! is **Config A**: address the swarm from the RFC 5737 *documentation* ranges,
//! which `IsGoodIP`/`IsLanIP` do **not** classify as LAN or reserved, so the
//! node accepts them on its normal (non-LAN-mode) code paths and every captured
//! wire is genuine real-client behaviour.
//!
//! This module owns the address plan — subnet choice + static per-node IP —
//! rather than hardcoding it at each call site, so a >8-node swarm spreads
//! across further `/24`s deterministically. It is pure (no I/O); the docker
//! layer ([`crate::docker::Docker::create_internal_network_with_subnet`]) turns
//! the plan into `network create`/`run --ip` commands.

use anyhow::{Result, bail};

/// Fake-public `/24` prefixes, in allocation order. All must pass aMule
/// 2.3.3's `IsGoodIP`: its `reserved_ranges` REJECTS the third RFC 5737 block
/// (`192.0.2.0/24`) and the RFC 2544 benchmarking block (`198.18.0.0/15`)
/// (capture-corrected against aMule), so only two documentation `/24`s survive
/// and the third slot uses the same non-reserved public space the v2-harvest
/// seed proved live (`45.55.x`, clear of the seed's own `45.55.N` range).
pub const FAKE_PUBLIC_PREFIXES: [&str; 3] = ["203.0.113", "198.51.100", "45.55.200"];

/// Routable Kad nodes per `/24`. aMule caps **non-LAN** contacts at 10 per `/24`
/// globally (`RoutingBin.cpp` `MAX_CONTACTS_SUBNET`), and those
/// caps are enforced (not bypassed) for the fake-public range — so a single
/// `/24` cannot hold more than 10 mutually-known nodes. We stay two under the
/// cap to leave headroom for helpers and to keep the per-bucket math simple.
pub const MAX_NODES_PER_SUBNET: usize = 8;

/// The first usable host octet in each `/24`: `.1` is the Docker bridge gateway,
/// so static node addresses start at `.2`.
const FIRST_HOST_OCTET: u8 = 2;

/// One node's allocated address on the fake-public plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakePublicAddress {
    /// The CIDR of the `/24` this node lives on, e.g. `203.0.113.0/24` — the
    /// value passed to `--subnet` when the network is created.
    pub subnet: String,
    /// The static IPv4 address, e.g. `203.0.113.2` — the value passed to `--ip`.
    pub ip: String,
    /// Index into [`FAKE_PUBLIC_PREFIXES`] of this node's `/24`. Nodes sharing a
    /// subnet index share a network; distinct indices need distinct networks.
    pub subnet_index: usize,
}

/// The `/24` CIDR for subnet `index` (e.g. `index = 0` → `203.0.113.0/24`).
///
/// # Errors
/// If `index` exceeds the documentation-range prefixes we carry.
pub fn subnet_cidr(index: usize) -> Result<String> {
    match FAKE_PUBLIC_PREFIXES.get(index) {
        Some(prefix) => Ok(format!("{prefix}.0/24")),
        None => bail!(
            "fake-public subnet index {index} exceeds the {} documentation ranges available",
            FAKE_PUBLIC_PREFIXES.len()
        ),
    }
}

/// Allocate the `index`-th node's fake-public address. Nodes fill a `/24` from
/// `.2` up to [`MAX_NODES_PER_SUBNET`] hosts, then spill onto the next `/24`, so
/// the plan is reproducible from the node index alone (which is what makes a
/// seeded `nodes.dat`'s peer IPs knowable before any container starts).
///
/// # Errors
/// If the node count would exhaust the documentation ranges we carry.
pub fn fake_public_address(index: usize) -> Result<FakePublicAddress> {
    let subnet_index = index / MAX_NODES_PER_SUBNET;
    let host = FIRST_HOST_OCTET as usize + (index % MAX_NODES_PER_SUBNET);
    let prefix = match FAKE_PUBLIC_PREFIXES.get(subnet_index) {
        Some(prefix) => prefix,
        None => bail!(
            "fake-public node {index} needs subnet index {subnet_index}, beyond the {} \
             documentation ranges available (max {} nodes)",
            FAKE_PUBLIC_PREFIXES.len(),
            FAKE_PUBLIC_PREFIXES.len() * MAX_NODES_PER_SUBNET
        ),
    };
    Ok(FakePublicAddress {
        subnet: format!("{prefix}.0/24"),
        ip: format!("{prefix}.{host}"),
        subnet_index,
    })
}

/// The distinct `/24` CIDRs a swarm of `node_count` nodes spans, in order — one
/// `network create --internal --subnet <cidr>` per entry. A single-subnet swarm
/// (the common bench case) returns exactly one CIDR.
///
/// # Errors
/// If `node_count` would exhaust the documentation ranges we carry.
pub fn subnets_for(node_count: usize) -> Result<Vec<String>> {
    if node_count == 0 {
        return Ok(Vec::new());
    }
    let last_index = (node_count - 1) / MAX_NODES_PER_SUBNET;
    (0..=last_index).map(subnet_cidr).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_node_takes_the_gateway_plus_one_on_the_first_documentation_range() {
        let addr = fake_public_address(0).unwrap();
        assert_eq!(addr.subnet, "203.0.113.0/24");
        assert_eq!(addr.ip, "203.0.113.2", ".1 is the bridge gateway");
        assert_eq!(addr.subnet_index, 0);
    }

    #[test]
    fn a_full_subnet_spills_onto_the_next_documentation_range() {
        // The last host on subnet 0 is index 7 (.2..=.9 = 8 nodes), and index 8
        // is the first host on subnet 1 — allocation logic, not a hardcoded map.
        let last_on_first = fake_public_address(MAX_NODES_PER_SUBNET - 1).unwrap();
        assert_eq!(last_on_first.ip, "203.0.113.9");
        assert_eq!(last_on_first.subnet_index, 0);

        let first_on_second = fake_public_address(MAX_NODES_PER_SUBNET).unwrap();
        assert_eq!(first_on_second.subnet, "198.51.100.0/24");
        assert_eq!(first_on_second.ip, "198.51.100.2");
        assert_eq!(first_on_second.subnet_index, 1);

        let first_on_third = fake_public_address(2 * MAX_NODES_PER_SUBNET).unwrap();
        assert_eq!(first_on_third.subnet, "45.55.200.0/24");
        assert_eq!(first_on_third.ip, "45.55.200.2");
    }

    #[test]
    fn every_node_gets_a_distinct_address_until_the_ranges_are_exhausted() {
        let capacity = FAKE_PUBLIC_PREFIXES.len() * MAX_NODES_PER_SUBNET;
        let mut seen = std::collections::HashSet::new();
        for index in 0..capacity {
            let addr = fake_public_address(index).unwrap();
            assert!(seen.insert(addr.ip.clone()), "address {} reused", addr.ip);
        }
        // One past capacity is a clean error, never a silent collision.
        assert!(fake_public_address(capacity).is_err());
    }

    #[test]
    fn subnets_for_returns_one_cidr_per_used_range() {
        assert_eq!(subnets_for(0).unwrap(), Vec::<String>::new());
        assert_eq!(subnets_for(1).unwrap(), vec!["203.0.113.0/24"]);
        assert_eq!(
            subnets_for(MAX_NODES_PER_SUBNET).unwrap(),
            vec!["203.0.113.0/24"],
            "a subnet exactly full still needs only its own /24"
        );
        assert_eq!(
            subnets_for(MAX_NODES_PER_SUBNET + 1).unwrap(),
            vec!["203.0.113.0/24", "198.51.100.0/24"]
        );
    }

    #[test]
    fn subnet_cidr_rejects_indexes_past_the_documentation_ranges() {
        assert_eq!(subnet_cidr(0).unwrap(), "203.0.113.0/24");
        assert_eq!(subnet_cidr(2).unwrap(), "45.55.200.0/24");
        assert!(subnet_cidr(FAKE_PUBLIC_PREFIXES.len()).is_err());
    }
}
