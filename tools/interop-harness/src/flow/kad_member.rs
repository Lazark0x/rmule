//! What a **placed Kad member** is, in one place.
//!
//! Several flows need contacts that sit at *chosen* keyspace positions rather
//! than wherever a generated identity lands: a FINDBUDDY walk has to converge
//! somewhere on purpose, and a firewalled counterparty's own probes have to
//! have more than one contact to spread across. Each such member is the same
//! thing — a standalone `rmule-tools kad join-node` (the **Kad Stimulus Node**
//! of ADR-0043) on its own fake-public address, holding a Kad ID the flow
//! picked.
//!
//! This module owns the member's *shape*: its Kad ID in hex, the
//! `<kad-id-hex>@<ipv4>:<udp-port>` seed operand a driver parses, and the
//! container that runs it. It deliberately owns nothing about *lifecycle* —
//! the buddy-rendezvous flow tracks its containers through `Bench`, the flow-M
//! family through `KadResources`, and those are honest differences rather than
//! something to unify.
//!
//! **One member per fake-public address** (aMule's `MAX_CONTACTS_IP` is 1).
//!
//! # What a placed member can and cannot do to a counterparty
//!
//! A `join-node` binds **no peer-TCP listener**. That is what makes it safe as
//! a padding contact for a firewalled stock aMule: aMule's UDP firewall check
//! asks a contact over peer-TCP (`OP_FWCHECKUDPREQ`) to answer with a `0x62`
//! from another port, so a member can never complete that check and can never
//! flip the counterparty's UDP verdict to open. It *does* answer
//! `KADEMLIA2_PING` with a `PONG` carrying the observed port, which is what
//! aMule's extern-port probe counts (`CPrefs::SetExternKadPort` records
//! distinct reporting IPs and stops at two agreeing on a port).

use std::path::Path;

use crate::docker::RunContainer;

/// Sixteen bytes as lower-case hex — the form every Kad-ID operand takes.
pub(crate) fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The `<kad-id-hex>@<ipv4>:<udp-port>` operand form the driver parses.
pub(crate) fn seed_operand(kad_id: &str, address_v4: &str, udp_port: u16) -> String {
    format!("{kad_id}@{address_v4}:{udp_port}")
}

/// Everything one placed member needs to run.
pub(crate) struct PlacedMember<'a> {
    /// The `rmule-tools` image the member runs in.
    pub(crate) image: &'a str,
    /// The container's name — the caller's to choose and to track.
    pub(crate) container: &'a str,
    /// The docker network it joins.
    pub(crate) network: &'a str,
    /// Its fake-public address.
    pub(crate) address_v4: &'a str,
    /// The UDP port it binds Kad on.
    pub(crate) udp_port: u16,
    /// The TCP port it *advertises* (it binds none — see the module docs).
    pub(crate) tcp_port: u16,
    /// Its Kad ID, lower-case hex.
    pub(crate) kad_id: &'a str,
    /// A peer to bootstrap from, `ip:port`; `None` leaves it to be dialed.
    pub(crate) bootstrap: Option<&'a str>,
    /// Where its capture and event log land on the host.
    pub(crate) host_dir: &'a Path,
    /// How long it runs before finalizing its capture. It must outlive the
    /// whole flow, every convergence wait included.
    pub(crate) run_secs: u64,
}

impl PlacedMember<'_> {
    /// The container that runs this member.
    pub(crate) fn container_spec(&self) -> RunContainer {
        let mut container = RunContainer::new(self.image)
            .detach()
            .name(self.container)
            .network(self.network)
            .ip(self.address_v4)
            .cap_add("NET_ADMIN")
            .volume(self.host_dir, "/out")
            .arg("kad")
            .arg("join-node")
            .arg("--bind")
            .arg(format!("0.0.0.0:{}", self.udp_port))
            .arg("--id-hex")
            .arg(self.kad_id)
            .arg("--tcp-port")
            .arg(self.tcp_port.to_string());
        if let Some(bootstrap) = self.bootstrap {
            container = container.arg("--bootstrap").arg(bootstrap);
        }
        container
            .arg("--capture-dir")
            .arg("/out/capture")
            .arg("--events-file")
            .arg("/out/events.log")
            .arg("--run-secs")
            .arg(self.run_secs.to_string())
    }
}
