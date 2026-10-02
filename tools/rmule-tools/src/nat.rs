//! Bench-provenance and port-mapping workflows for the NAT topologies
//! (ADR-0092).
//!
//! Two drivers, both **Stimulus** and never evidence (ADR-0045):
//!
//! - [`probe`] is the **Reflector Probe**'s client half — RFC 5780 mapping- and
//!   filtering-behaviour discovery run from inside a gateway's LAN, which turns
//!   a gateway's *configuration* into the observation half of a **NAT Type
//!   Proof**. It observes the bench, never a counterparty.
//! - [`peer_reach`] is the leg the probe cannot be: the far end is another
//!   *translated* client rather than a host on the WAN, which is the only
//!   arrangement in which two gateways pinning the same port can collide over
//!   it.
//! - [`portmap`] drives a real [`rmule_core::Core`] with the three live
//!   **Mapping Backends** (ADR-0086) pointed at a pinned gateway, and writes
//!   what rmule's own diagnostics said about the mappings, the learned
//!   addresses and the Kad verdict. rmule's own state is stimulus; the gateway's
//!   table and log beside it are what a port-mapping flow judges on.

pub(crate) mod peer_reach;
pub(crate) mod portmap;
pub(crate) mod probe;

pub(crate) use peer_reach::{NatPeerReachArgs, run_nat_peer_reach};
pub(crate) use portmap::{NatPortMapArgs, run_nat_portmap};
pub(crate) use probe::{NatProbeArgs, run_nat_probe};
