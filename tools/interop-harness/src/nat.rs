//! The **NAT Gateway**'s type vocabulary: the four `NAT_TYPE` knob values, what
//! each one *is* in RFC 4787 terms, and the `nat-type.toml` row a flow writes to
//! turn a configuration into a **NAT Type Proof**.
//!
//! RFC 4787 §4 deprecates the STUN cone/symmetric names outright ("proved
//! inadequate for describing real NAT behavior"), so the claim and the
//! observation are both recorded as a *mapping behaviour* × *filtering
//! behaviour* pair; the knob keeps the legacy name only because that is what an
//! operator types. The knob strings and the behaviour strings are a read
//! contract shared with `rmule-tools nat probe`, which writes the observed half
//! of the same row from inside the bench — the two sides agree by spelling, not
//! by a shared type, because the probe must not depend on the harness.
//!
//! Nothing here builds a ruleset: the nftables recipes live in the `natgw`
//! **Image Recipe** (`images/natgw/entrypoint.sh`), which is what `nft list
//! ruleset` later dumps as the proof's provenance.

use std::fmt;

use anyhow::{Result, bail};
use serde::Serialize;

/// RFC 4787 §4.1 mapping behaviour — how the NAT picks the external port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MappingBehaviour {
    /// The same internal `(addr, port)` keeps one external port for every
    /// destination (netfilter's default; RFC 4787 REQ-1).
    EndpointIndependent,
    /// The external port varies by destination address but not by port.
    /// Not expressible in netfilter — the probe can observe it, the bench
    /// cannot build it.
    AddressDependent,
    /// A fresh external port per destination `(addr, port)` — `snat …
    /// fully-random`, the legacy "symmetric" NAT.
    AddressAndPortDependent,
}

/// RFC 4787 §5 filtering behaviour — which unsolicited inbound datagrams the
/// NAT admits to an existing mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilteringBehaviour {
    /// Any external endpoint may reach the mapping (legacy "full cone").
    EndpointIndependent,
    /// Only endpoints at an address the client has sent to (legacy "restricted
    /// cone") — an nftables dynamic set of peer addresses.
    AddressDependent,
    /// Only the exact `(addr, port)` the client sent to — plain conntrack, and
    /// the default for a Docker bridge.
    AddressAndPortDependent,
}

impl MappingBehaviour {
    /// The `nat-type.toml` spelling, shared with `rmule-tools nat probe`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EndpointIndependent => "endpoint-independent",
            Self::AddressDependent => "address-dependent",
            Self::AddressAndPortDependent => "address-and-port-dependent",
        }
    }
}

impl FilteringBehaviour {
    /// The `nat-type.toml` spelling, shared with `rmule-tools nat probe`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EndpointIndependent => "endpoint-independent",
            Self::AddressDependent => "address-dependent",
            Self::AddressAndPortDependent => "address-and-port-dependent",
        }
    }
}

impl fmt::Display for MappingBehaviour {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for FilteringBehaviour {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The four gateway types the `natgw` image can build, by their `NAT_TYPE` knob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NatType {
    /// EIM + APDF — plain SNAT, what netfilter and Docker do with no extra work.
    PortRestricted,
    /// EIM + ADF — port-pinned SNAT plus a DNAT gated on an nft dynamic set of
    /// the peer addresses the client has sent to.
    Restricted,
    /// EIM + EIF **for the pinned UDP port only** — port-pinned SNAT plus an
    /// unconditional DNAT of that one port. Named for what it is: stateful NAT
    /// cannot express a general endpoint-independent filter, and a flow that
    /// claimed one would be claiming a behaviour the kernel does not have.
    FullConePinned,
    /// APDM + APDF — `snat … fully-random`, the legacy "symmetric" NAT.
    Symmetric,
}

impl NatType {
    /// Every type, in the order `natgw-selfproof` proves them.
    pub const ALL: [Self; 4] = [
        Self::PortRestricted,
        Self::Restricted,
        Self::FullConePinned,
        Self::Symmetric,
    ];

    /// The `NAT_TYPE` environment value the `natgw` entrypoint reads.
    pub fn knob(&self) -> &'static str {
        match self {
            Self::PortRestricted => "port-restricted",
            Self::Restricted => "restricted",
            Self::FullConePinned => "full-cone-pinned",
            Self::Symmetric => "symmetric",
        }
    }

    /// Parse a `NAT_TYPE` knob value.
    ///
    /// # Errors
    /// If `knob` is not one of the four the image builds.
    pub fn from_knob(knob: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|nat_type| nat_type.knob() == knob)
            .map_or_else(
                || {
                    bail!(
                        "unknown NAT_TYPE `{knob}`; the natgw image builds {}",
                        Self::ALL.map(|nat_type| nat_type.knob()).join(", ")
                    )
                },
                Ok,
            )
    }

    /// What this type claims in RFC 4787 terms — the claim the probe checks.
    pub fn claim(&self) -> (MappingBehaviour, FilteringBehaviour) {
        match self {
            Self::PortRestricted => (
                MappingBehaviour::EndpointIndependent,
                FilteringBehaviour::AddressAndPortDependent,
            ),
            Self::Restricted => (
                MappingBehaviour::EndpointIndependent,
                FilteringBehaviour::AddressDependent,
            ),
            Self::FullConePinned => (
                MappingBehaviour::EndpointIndependent,
                FilteringBehaviour::EndpointIndependent,
            ),
            Self::Symmetric => (
                MappingBehaviour::AddressAndPortDependent,
                FilteringBehaviour::AddressAndPortDependent,
            ),
        }
    }
}

impl fmt::Display for NatType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.knob())
    }
}

/// The **NAT Type Proof**'s `nat-type.toml` row: the gateway's claim, the
/// reflector probe's observation from the same run, and whether they agree.
///
/// `agrees = false` is a real, publishable outcome — it says the bench built
/// something other than what it claimed, which is exactly the fabrication
/// ADR-0045 exists to catch. The ruleset and conntrack dumps beside this file
/// are the provenance; this row is the readable verdict over them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NatTypeProof {
    /// The gateway's `NAT_TYPE` knob.
    pub nat_type: NatType,
    /// The mapping behaviour the knob claims.
    pub claimed_mapping: MappingBehaviour,
    /// The filtering behaviour the knob claims.
    pub claimed_filtering: FilteringBehaviour,
    /// The mapping behaviour the reflector probe observed.
    pub observed_mapping: String,
    /// The filtering behaviour the reflector probe observed.
    pub observed_filtering: String,
    /// The gateway's pinned client port, `0` when no **Pinned-Port Sink** was
    /// placed on the WAN for this leg.
    pub pinned_port: u16,
    /// Whether one datagram the LAN addressed to that port on a WAN host
    /// arrived. This is **not** an RFC 4787 axis and is deliberately separate
    /// from `agrees`: it asks whether the gateway forwards at all on the port
    /// every punch is aimed at, which the RFC 5780 tests cannot see because
    /// they only ever address the reflector's own two ports.
    pub pinned_port_reachable: bool,
    /// Whether the observation matched the claim on both axes.
    pub agrees: bool,
    /// The `nft list ruleset` dump's file name in the same directory.
    pub ruleset_file: String,
    /// The `conntrack -L` dump's file name in the same directory.
    pub conntrack_file: String,
    /// The reflector probe's own row file in the same directory.
    pub probe_file: String,
}

/// What the probe's **Pinned-Port Sink** leg observed, as the two fields its
/// row carries. A pair rather than two arguments, so a call site cannot swap
/// the port for the flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedPortReach {
    /// The pinned client port the sink held, or `0` for a leg with no sink.
    pub port: u16,
    /// Whether the single datagram aimed at it arrived.
    pub reachable: bool,
}

impl PinnedPortReach {
    /// A leg that placed no sink on the WAN — the **Port-Mapping
    /// Gateway**, whose plain SNAT carries no pinned-port rule to be wrong
    /// about. It reads `false`, never "assume fine": a proof one can skip by
    /// forgetting an operand is not a proof.
    #[must_use]
    pub const fn not_probed() -> Self {
        Self {
            port: 0,
            reachable: false,
        }
    }
}

impl NatTypeProof {
    /// Pair a gateway's claim with the probe's observed behaviour strings.
    pub fn new(
        nat_type: NatType,
        observed_mapping: impl Into<String>,
        observed_filtering: impl Into<String>,
        pinned: PinnedPortReach,
    ) -> Self {
        let (claimed_mapping, claimed_filtering) = nat_type.claim();
        let observed_mapping = observed_mapping.into();
        let observed_filtering = observed_filtering.into();
        let agrees = observed_mapping == claimed_mapping.as_str()
            && observed_filtering == claimed_filtering.as_str();
        Self {
            nat_type,
            claimed_mapping,
            claimed_filtering,
            observed_mapping,
            observed_filtering,
            pinned_port: pinned.port,
            pinned_port_reachable: pinned.reachable,
            agrees,
            ruleset_file: "nft-ruleset.txt".to_owned(),
            conntrack_file: "conntrack.txt".to_owned(),
            probe_file: "nat-probe.toml".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_knob_round_trips_and_a_stranger_is_refused() {
        for nat_type in NatType::ALL {
            assert_eq!(NatType::from_knob(nat_type.knob()).unwrap(), nat_type);
        }
        assert!(NatType::from_knob("hard").is_err());
    }

    #[test]
    fn the_four_types_are_four_distinct_rfc_4787_pairs() {
        let mut claims: Vec<_> = NatType::ALL.into_iter().map(|t| t.claim()).collect();
        claims.sort_by_key(|(mapping, filtering)| (mapping.as_str(), filtering.as_str()));
        claims.dedup();
        assert_eq!(claims.len(), 4, "two knobs would build the same NAT");
    }

    const REACHED: PinnedPortReach = PinnedPortReach {
        port: 4672,
        reachable: true,
    };

    #[test]
    fn a_proof_agrees_only_when_both_axes_match_the_claim() {
        let matching = NatTypeProof::new(
            NatType::Symmetric,
            "address-and-port-dependent",
            "address-and-port-dependent",
            REACHED,
        );
        assert!(matching.agrees);

        // A symmetric gateway whose mapping probed endpoint-independent is a
        // bench that did not build what it claimed — recorded, not silently
        // upgraded to a pass.
        let mismatched = NatTypeProof::new(
            NatType::Symmetric,
            "endpoint-independent",
            "address-and-port-dependent",
            REACHED,
        );
        assert!(!mismatched.agrees);

        // Filtering alone is enough to disagree: full-cone-pinned that probed
        // address-and-port-dependent means the DNAT never installed.
        let filtering_only = NatTypeProof::new(
            NatType::FullConePinned,
            "endpoint-independent",
            "address-and-port-dependent",
            REACHED,
        );
        assert!(!filtering_only.agrees);
    }

    /// The pinned-port leg is a **separate** axis, and the two must not be
    /// collapsed: a gateway that translates exactly as it claims while eating
    /// everything aimed at the pinned port is precisely run `1790028867`, and
    /// it agreed on both RFC 4787 axes.
    #[test]
    fn the_pinned_port_leg_is_not_an_rfc_4787_axis() {
        let hairpinned = NatTypeProof::new(
            NatType::FullConePinned,
            "endpoint-independent",
            "endpoint-independent",
            PinnedPortReach {
                port: 4672,
                reachable: false,
            },
        );
        assert!(hairpinned.agrees, "both RFC 4787 axes still matched");
        assert!(!hairpinned.pinned_port_reachable);
    }
}
