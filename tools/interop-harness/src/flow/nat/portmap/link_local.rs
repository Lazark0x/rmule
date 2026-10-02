//! `portmap-ipv6-pinhole-link-local`: the gateway reached through its
//! `fe80::` address, and the claims only this variant can make — about the
//! *source* of every PCP request, read off the gateway's LAN tap.
//!
//! RFC 6887 §8.2 has the server refuse a request whose source differs from the
//! client address its header names, and a v6 default route is always via a
//! link-local next hop (RFC 4861 §4.2). A client that let the kernel choose
//! would source from `fe80::…` here. So the variant stands the driver's default
//! route on the gateway's link-local address and asks four questions of the
//! wire and the gateway: did every request leave from the address its header
//! names, was that the Known IPv6 rather than a link-local or ULA, did the
//! gateway's own pinhole row name it, and did the pinhole land.

use std::ffi::OsString;
use std::net::Ipv6Addr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::flow::bench::{Bench, run_checked};
use crate::flow::nat::portmap::gateway::GatewayRecord;
use crate::flow::nat::portmap::verdict::Claim;
use crate::flow::pcap::udp6_datagrams;

/// The LAN-tap filter selecting rmule's PCP requests.
pub(crate) const PCP_REQUEST_FILTER: &str = "ip6 and udp dst port 5351";

/// Where the lifted requests land in the leg dir.
pub(crate) const PCP_REQUEST_PCAP: &str = "pcp-requests.pcap";

/// The interface the driver's one LAN attachment comes up as.
pub(crate) const DRIVER_LAN_INTERFACE: &str = "eth0";

/// The gateway's own link-local address on its LAN side — what a Router
/// Advertisement would have named as the default router.
///
/// # Errors
/// If the address cannot be read, or the interface holds none.
pub(crate) fn gateway_link_local(bench: &Bench, gateway: &str, lan_if: &str) -> Result<Ipv6Addr> {
    let listing = run_checked(
        bench.docker.exec(
            gateway.to_owned(),
            [
                "ip", "-6", "-o", "addr", "show", "dev", lan_if, "scope", "link",
            ]
            .map(OsString::from),
        ),
        "read the gateway's LAN link-local address",
    )?;
    listing
        .split_whitespace()
        .skip_while(|token| *token != "inet6")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next())
        .and_then(|address| address.parse().ok())
        .with_context(|| format!("the gateway's {lan_if} holds no link-local address: {listing}"))
}

/// What the LAN tap says about the PCP requests' sources.
#[derive(Debug, Serialize)]
pub(crate) struct PcpSources {
    /// The Known IPv6 the driver was told (its Override tier).
    pub(crate) known: String,
    /// The link-local next hop the requests were sent to.
    pub(crate) next_hop: String,
    /// Every request, `source -> destination header_client`.
    pub(crate) request: Vec<String>,
    /// Requests whose source equals the client address in their header.
    pub(crate) source_equals_header: usize,
    /// Requests that left from the Known IPv6.
    pub(crate) from_known: usize,
    /// Requests that left from a link-local or unique-local source.
    pub(crate) from_non_global: usize,
    /// Requests addressed to the link-local next hop.
    pub(crate) to_next_hop: usize,
}

impl PcpSources {
    /// Read the lifted requests.
    ///
    /// # Errors
    /// If the lifted pcap cannot be read.
    pub(crate) fn read(pcap: &Path, known: Ipv6Addr, next_hop: Ipv6Addr) -> Result<Self> {
        let datagrams = udp6_datagrams(pcap)?;
        let header = |payload: &[u8]| {
            payload.get(8..24).map(|octets| {
                let mut address = [0_u8; 16];
                address.copy_from_slice(octets);
                Ipv6Addr::from(address)
            })
        };
        let non_global = |address: Ipv6Addr| {
            let leading = address.segments()[0];
            (leading & 0xffc0) == 0xfe80 || (leading & 0xfe00) == 0xfc00
        };
        Ok(Self {
            known: known.to_string(),
            next_hop: next_hop.to_string(),
            request: datagrams
                .iter()
                .map(|datagram| {
                    format!(
                        "[{}]:{} -> [{}]:{} client={}",
                        datagram.source,
                        datagram.source_port,
                        datagram.destination,
                        datagram.destination_port,
                        header(&datagram.payload)
                            .map_or_else(|| "(short)".to_owned(), |client| client.to_string())
                    )
                })
                .collect(),
            source_equals_header: datagrams
                .iter()
                .filter(|datagram| header(&datagram.payload) == Some(datagram.source))
                .count(),
            from_known: datagrams
                .iter()
                .filter(|datagram| datagram.source == known)
                .count(),
            from_non_global: datagrams
                .iter()
                .filter(|datagram| non_global(datagram.source))
                .count(),
            to_next_hop: datagrams
                .iter()
                .filter(|datagram| datagram.destination == next_hop)
                .count(),
        })
    }

    /// The variant's own claims, beside the pinhole flow's.
    pub(crate) fn claims(&self, gateway: &GatewayRecord) -> Vec<Claim> {
        let total = self.request.len();
        let rows_on_known: Vec<&str> = gateway
            .leases
            .iter()
            .filter(|lease| lease.family == "v6" && lease.internal_address == self.known)
            .map(|lease| lease.line.as_str())
            .collect();
        let sample = self
            .request
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join(" | ");
        vec![
            Claim::about(
                "every-pcp-request-went-to-the-link-local-next-hop",
                total > 0 && self.to_next_hop == total,
                format!(
                    "{} of {total} PCP requests on the LAN tap were addressed to {}: {sample}",
                    self.to_next_hop, self.next_hop
                ),
            ),
            Claim::about(
                "every-pcp-request-left-from-its-header-client-address",
                total > 0 && self.source_equals_header == total,
                format!(
                    "{} of {total} requests carried their own source in the PCP Client IP \
                     field (RFC 6887 section 8.2)",
                    self.source_equals_header
                ),
            ),
            Claim::about(
                "every-pcp-request-left-from-the-known-ipv6",
                total > 0 && self.from_known == total && self.from_non_global == 0,
                format!(
                    "{} of {total} requests left from the Known IPv6 {}; {} from a link-local \
                     or unique-local source",
                    self.from_known, self.known, self.from_non_global
                ),
            ),
            Claim::about(
                "the-gateway-pinhole-row-names-the-known-ipv6",
                !rows_on_known.is_empty(),
                format!(
                    "lease_file6 rows naming {}: {}",
                    self.known,
                    if rows_on_known.is_empty() {
                        "(none)".to_owned()
                    } else {
                        rows_on_known.join(" | ")
                    }
                ),
            ),
        ]
    }
}
