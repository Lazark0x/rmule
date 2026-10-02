//! Flow M's swarm plan: who the firewalled aMule is seeded with, and how the
//! UDP firewall helpers reach it without being seeded.
//!
//! aMule's `CUDPFirewallTester::QueryNextClient` (`UDPFirewallTester.cpp:291-292`,
//! kno `ab483654`; stock `:249-252`) refuses any helper candidate its routing
//! zone already holds — `GetContact(ip, 0, false)` matches on the IP alone
//! (`RoutingBin.cpp:148-153`) — and `DoRequestFirewallCheckUDP` refuses a known
//! client (`ClientList.cpp:1209`). Candidates are harvested only from the
//! `0x29` answers to its own random-target helper lookup
//! (`KademliaUDPListener.cpp:842-879`). So a helper is usable only if some
//! answering node names it and the zone does not already hold it.
//!
//! The plan meets both at once:
//!
//!   * the aMule's zone is filled by seeds that are never helpers — rmule, then
//!     the placed members. The whole swarm shares one `/24` and a routing bin
//!     admits two contacts per `/24` (`RoutingBin.cpp:91`), and seeds load
//!     before anything is learned, so rmule and member 0 take both slots and no
//!     helper can later enter the zone. That is why helpers need
//!     `mesh_members >= 1`: with rmule alone, the first helper learned from any
//!     `0x29` would take the second slot and be disqualified;
//!   * each helper is seeded with rmule's contact, so it greets rmule at its own
//!     Kad start (aMule's small timer fires at once for the root zone,
//!     `RoutingZone.cpp:111`) and rmule's answers to the aMule's helper lookup
//!     name it — the root-seeded enrollment `natt-udp-selfcheck-cone` proved in the other
//!     direction.
//!     The helpers start before the aMule, so rmule holds them by then.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::flow::bench::KadMeshNames;
use crate::flow::identity::{hex_lower, parse_ipv4_octets};
use crate::flow::kad_buddy::core::KAD_CORE_BUDDY_RMULE_KAD_ID;
use crate::flow::mesh::{KAD_CONTACT_VERSION, KAD_RMULE_UDP_PORT, KAD_TCP_PORT, KadNodeSpec};
use crate::kad_seed::KadContact;
use crate::rmule::RMULE_SERVE_TCP_PORT;

/// The placed members' Kad ID prefixes. Far from the FindBuddy target
/// (`~0x33.. = 0xCC..`) on purpose, so adding them never moves the walk off
/// rmule — which is what keeps "the recruit landed on rmule" a measurement.
const MESH_MEMBER_KAD_ID_PREFIX: u8 = 0x41;

/// What [`plan_core_swarm`] reads.
pub(crate) struct CoreSwarmInputs<'a> {
    pub(crate) rmule_ip: [u8; 4],
    pub(crate) kad_udp_port_base: u16,
    pub(crate) helper_count: usize,
    pub(crate) mesh_members: usize,
    /// The last member's Kad ID when `--publish-source` pins it to the file key.
    pub(crate) near_file_kad_id: Option<[u8; 16]>,
    pub(crate) names: &'a KadMeshNames,
    pub(crate) helper_incoming: &'a Path,
}

/// Flow M's swarm, before any container starts.
pub(crate) struct CoreSwarm {
    /// The firewalled aMule's routing-zone seed: rmule, then the members.
    /// Never a helper.
    pub(crate) storer_seed: Vec<KadContact>,
    /// `(ipv4, udp_port, kad_id_hex)` per placed `join-node` member.
    pub(crate) members: Vec<(String, u16, String)>,
    /// Open stock aMule helpers, each routing-zone seeded with rmule alone.
    pub(crate) helpers: Vec<KadNodeSpec>,
}

pub(crate) fn plan_core_swarm(inputs: &CoreSwarmInputs<'_>) -> Result<CoreSwarm> {
    if inputs.helper_count > 0 && inputs.mesh_members == 0 {
        bail!(
            "--helpers needs --mesh-members >= 1: the one-/24 swarm leaves the firewalled \
             aMule's routing bin two slots (RoutingBin.cpp:91), and unless rmule and a member \
             fill them the first helper it learns takes one, which disqualifies it as a UDP \
             firewall helper (UDPFirewallTester.cpp QueryNextClient)"
        );
    }
    // rmule: the advertised TCP port is the SERVE LISTENER's, which is what
    // the buddy dial must land on.
    let rmule = KadContact {
        kad_id: KAD_CORE_BUDDY_RMULE_KAD_ID,
        ipv4: inputs.rmule_ip,
        udp_port: KAD_RMULE_UDP_PORT,
        tcp_port: RMULE_SERVE_TCP_PORT,
        version: KAD_CONTACT_VERSION,
    };
    let mut storer_seed = vec![rmule];

    // Placed members take the fake-public slots after the helpers', so the two
    // knobs can be used together without colliding.
    let mut members = Vec::with_capacity(inputs.mesh_members);
    for index in 0..inputs.mesh_members {
        let addr = crate::fake_public::fake_public_address(2 + inputs.helper_count + index)?;
        let ip = parse_ipv4_octets(&addr.ip)?;
        let udp_port = inputs.kad_udp_port_base + 16 + u16::try_from(index).unwrap_or(0);
        let mut kad_id = [0x40u8; 16];
        kad_id[0] = MESH_MEMBER_KAD_ID_PREFIX + u8::try_from(index).unwrap_or(0);
        // The last member is the publish's destination, not padding.
        if index + 1 == inputs.mesh_members
            && let Some(placed) = inputs.near_file_kad_id
        {
            kad_id = placed;
        }
        storer_seed.push(KadContact {
            kad_id,
            ipv4: ip,
            udp_port,
            tcp_port: KAD_TCP_PORT,
            version: KAD_CONTACT_VERSION,
        });
        members.push((addr.ip, udp_port, hex_lower(&kad_id)));
    }

    let mut helpers = Vec::with_capacity(inputs.helper_count);
    for helper_index in 0..inputs.helper_count {
        let addr = crate::fake_public::fake_public_address(2 + helper_index)?;
        let ip = parse_ipv4_octets(&addr.ip)?;
        let udp_port = inputs.kad_udp_port_base + 3 + u16::try_from(helper_index).unwrap_or(0);
        // Kad IDs far from the FindBuddy target (`~aMuleKadID`), so the recruit
        // walk still converges on rmule at distance 0.
        let mut kad_id = [0x70u8; 16];
        kad_id[0] = 0x71 + u8::try_from(helper_index).unwrap_or(0);
        helpers.push(KadNodeSpec {
            role: format!("helper-{helper_index}"),
            container: inputs
                .names
                .routing(u32::try_from(helper_index).unwrap_or(0)),
            udp_port,
            ip,
            kad_id,
            user_hash_hex: None,
            shared_host_dir: PathBuf::from(inputs.helper_incoming),
            bootstrap_peers: Vec::new(),
            routing_zone_seed: true,
            seed_contacts: vec![rmule],
        });
    }
    Ok(CoreSwarm {
        storer_seed,
        members,
        helpers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> KadMeshNames {
        KadMeshNames {
            network_name: "net".to_owned(),
            publisher: "publisher".to_owned(),
            requester: "requester".to_owned(),
            storer: "storer".to_owned(),
            capture: "capture".to_owned(),
            rmule: "rmule".to_owned(),
            suffix: "t".to_owned(),
        }
    }

    fn plan(helper_count: usize, mesh_members: usize) -> Result<CoreSwarm> {
        let names = names();
        plan_core_swarm(&CoreSwarmInputs {
            rmule_ip: [203, 0, 113, 3],
            kad_udp_port_base: 4670,
            helper_count,
            mesh_members,
            near_file_kad_id: None,
            names: &names,
            helper_incoming: Path::new("/tmp/helper-incoming"),
        })
    }

    /// A helper in the aMule's seed is in its routing zone, which
    /// `QueryNextClient` refuses. The seed holds rmule and the members only;
    /// each helper is seeded with rmule, so rmule's answers name it.
    #[test]
    fn helpers_stay_out_of_the_firewalled_seed_and_are_seeded_with_rmule() {
        let swarm = plan(2, 1).unwrap();
        let seeded: Vec<[u8; 4]> = swarm.storer_seed.iter().map(|c| c.ipv4).collect();
        assert_eq!(seeded, [[203, 0, 113, 3], [203, 0, 113, 6]]);
        assert_eq!(swarm.helpers.len(), 2);
        for helper in &swarm.helpers {
            assert!(!seeded.contains(&helper.ip), "{} seeded", helper.role);
            assert!(helper.routing_zone_seed);
            assert_eq!(helper.seed_contacts.len(), 1);
            assert_eq!(helper.seed_contacts[0].ipv4, [203, 0, 113, 3]);
            assert_eq!(helper.seed_contacts[0].kad_id, KAD_CORE_BUDDY_RMULE_KAD_ID);
        }
    }

    /// With rmule alone in the seed, the first helper the aMule learns takes
    /// the bin's second `/24` slot and is disqualified.
    #[test]
    fn helpers_without_a_member_are_refused() {
        let err = plan(2, 0).err().unwrap().to_string();
        assert!(err.contains("--mesh-members >= 1"), "{err}");
        assert!(plan(0, 0).is_ok());
    }
}
