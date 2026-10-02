//! The **Desired Mapping Set** (ADR-0086): what rmule wants on the router right
//! now, derived from the **Family Pairs** that actually bound.
//!
//! Three rules, each of them a decision rather than an omission:
//!
//! - **Derived, never configured.** The configured family selection says what
//!   was *attempted*; the bind table says what came up. A mapping for a socket
//!   that refused to bind would forward a port to nothing, and on the eD2k
//!   hello it would advertise a port no peer can reach.
//! - **The server-UDP socket is never mapped.** Every datagram it receives
//!   answers one we sent, so our own outbound packet already opens the binding.
//!   It is not a [`SocketRole`] at all, so this falls out of the vocabulary
//!   rather than needing a guard.
//! - **An IPv6 pinhole needs a Known IPv6 first.** On IPv6 a PCP MAP is a
//!   firewall pinhole to *our own* address, not a translation — so asking for
//!   one while the store holds no confident v6 would punch a hole at whichever
//!   address the request happened to leave from. The row carries that Known
//!   IPv6, and the PCP request is sent from it.

use std::net::IpAddr;

use rmule_primitives::AddressFamily;

use crate::address_learning::{SharedAddressLearning, SocketRole};

use super::DesiredMapping;

/// The set of mappings rmule wants, in a stable order (role, then family) so a
/// trial's commands, a diagnostics table and a test all read the same way.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DesiredMappingSet(Vec<DesiredMapping>);

impl DesiredMappingSet {
    /// Derive the set from what the **Address Learning** store says bound.
    pub(crate) fn derive(addresses: &SharedAddressLearning) -> Self {
        let mut mappings = Vec::new();
        for role in SocketRole::ALL {
            let Some((families, port)) = addresses.bind(role) else {
                continue;
            };
            // A zero port is an unresolved ephemeral bind, not a port: asking a
            // gateway to forward port 0 is asking it for every port.
            if port == 0 {
                continue;
            }
            for family in [AddressFamily::V4, AddressFamily::V6] {
                if !families.contains(&family) {
                    continue;
                }
                let pinhole = match (family, addresses.known_address(family)) {
                    (AddressFamily::V4, _) => None,
                    (AddressFamily::V6, Some(IpAddr::V6(known))) => Some(known),
                    (AddressFamily::V6, _) => continue,
                };
                mappings.push(DesiredMapping {
                    role,
                    family,
                    internal_port: port,
                    pinhole,
                });
            }
        }
        Self(mappings)
    }

    /// The mappings, in order.
    pub(crate) fn mappings(&self) -> &[DesiredMapping] {
        &self.0
    }

    /// Whether the set is empty — nothing bound, so nothing to map.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The family whose grade leads a trial's standing: IPv4 whenever the set
    /// wants it, because the eD2k hello, the server's High-ID and Kad all ride
    /// on IPv4; IPv6 only on a set that has no IPv4 row at all.
    pub(crate) fn lead_family(&self) -> AddressFamily {
        if self.wants(AddressFamily::V4) {
            AddressFamily::V4
        } else {
            AddressFamily::V6
        }
    }

    /// The rows `protocol` can express — what one trial of it asks for and is
    /// graded on. Asking an IPv4-only backend for an IPv6 pinhole would only
    /// count a refusal against it that no router could have avoided.
    pub(crate) fn expressible(
        &self,
        protocol: rmule_net::portmap::MappingProtocol,
    ) -> impl Iterator<Item = DesiredMapping> + '_ {
        self.0
            .iter()
            .filter(move |mapping| protocol.supports(mapping.family))
            .copied()
    }

    /// Whether `family` appears in the set — the gate that keeps an IPv4-only
    /// protocol out of a race it could only lose.
    pub(crate) fn wants(&self, family: AddressFamily) -> bool {
        self.0.iter().any(|mapping| mapping.family == family)
    }
}
