//! Command-line operands parsed into protocol values: the endpoints and the
//! 16-byte identities (User Hash, Kad ID, File Hash) an operator types as hex.

use anyhow::{Context, Result};
use rmule_primitives::{PeerEndpoint, UserHash};

/// `a.b.c.d:port` or `[addr]:port` — whichever family the operator typed
/// (ADR-0085). A subcommand whose wire packs 32 bits declines an IPv6 peer
/// itself, with its own reason.
pub(crate) fn parse_peer_endpoint(input: &str) -> Result<PeerEndpoint> {
    input
        .parse()
        .with_context(|| format!("parse peer endpoint {input}"))
}

pub(crate) fn parse_user_hash(input: &str) -> Result<[u8; UserHash::BYTE_LEN]> {
    parse_hex16("user-hash", input)
}

/// Parse a 16-byte identity from hex. `label` names the field so a Kad ID and a
/// User Hash — same length, different meanings — do not report each other's
/// errors.
pub(crate) fn parse_hex16(label: &str, input: &str) -> Result<[u8; 16]> {
    if input.len() != 32 {
        anyhow::bail!("{label} must be 32 hex characters, got {}", input.len());
    }
    let mut out = [0u8; 16];
    for (i, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let hex = std::str::from_utf8(chunk)
            .with_context(|| format!("{label} byte {i} is not valid UTF-8"))?;
        out[i] =
            u8::from_str_radix(hex, 16).with_context(|| format!("{label} byte {i} not hex"))?;
    }
    Ok(out)
}

/// The Kad protocol version every body in the mesh advertises — aMule 2.3.3's
/// `KADEMLIA_VERSION`, the one the harness's seeded contacts carry.
const SEEDED_KAD_CONTACT_VERSION: u8 = 8;

/// Parse `--kad-contact <kad-id-hex>@<ipv4>:<udp-port>` operands into
/// **Seeded Bootstrap** contacts — already placed in the routing table
/// (`MergeContacts`, the ADR-0065 v1/v2-merge), never greeted first.
pub(crate) fn parse_seeded_kad_contacts(operands: &[String]) -> Result<Vec<rmule_kad::KadContact>> {
    operands
        .iter()
        .map(|operand| {
            let (id, endpoint) = operand.split_once('@').with_context(|| {
                format!("--kad-contact must read <kad-id-hex>@<ipv4>:<udp-port>, got {operand}")
            })?;
            let addr: std::net::SocketAddrV4 = endpoint
                .parse()
                .with_context(|| format!("parse the contact endpoint {endpoint}"))?;
            Ok(rmule_kad::KadContact::new(
                rmule_kad::KadId::from_bytes(parse_hex16("--kad-contact id", id)?),
                rmule_kad::KadNodeEndpoint::new(*addr.ip(), addr.port()),
                0,
                SEEDED_KAD_CONTACT_VERSION,
            ))
        })
        .collect()
}
