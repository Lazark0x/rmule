//! The per-server **Capability Store** (ADR-0052): the typed record a valid
//! `OP_GLOBSERVSTATRES` populates, shared by every consumer that gates on a
//! server's advertised abilities — the `0x94` get-sources upgrade
//! (`ExtGetSources2`), global-search variant selection (`ExtGetFiles` /
//! `LargeFiles`, ADR-0051), and datagram crypt (`ServerUDPKey`, ADR-0046).
//! Keyed by the server's **TCP** endpoint — the same key the answering UDP
//! source maps back to via the port offset, and the one every consumer
//! already holds. Only the [`ServerUdpEngine`](crate::server_udp) writes it,
//! after the challenge gate; a server with no record simply has no proven
//! capabilities yet (emit paths then use their legacy/baseline forms).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use rmule_ed2k::{GlobServStatRes, ServerDescTags, ServerUdpFlags};
use rmule_primitives::{Ipv4Endpoint, ServerEndpoint};

use crate::server_list::ServerUdpCrypt;

/// What one `0x97` reply proved about a server. The progressive body means
/// older servers stop early — absent fields stay `None`, never defaulted, so
/// consumers can tell "advertised nothing" from "advertised zero". The
/// `display` strings are the ADR-0068 desc pair's rows — same record, no
/// second map — surviving each fresh `0x97` (a status re-ping refreshes the
/// counts, not the description).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerCapabilities {
    pub(crate) users: u32,
    pub(crate) files: u32,
    pub(crate) max_users: Option<u32>,
    pub(crate) soft_files: Option<u32>,
    pub(crate) hard_files: Option<u32>,
    pub(crate) udp_flags: Option<ServerUdpFlags>,
    pub(crate) low_id_users: Option<u32>,
    /// How to key UDP to it, learned under the public IPv4 we held when
    /// the reply arrived; `None` for a body too short to carry it.
    pub(crate) udp_crypt: Option<ServerUdpCrypt>,
    /// Display/metadata strings from the `0xA3` description reply
    /// (ADR-0068): name, description, version, dyn-IP, aux ports.
    pub(crate) display: ServerDescTags,
}

impl ServerCapabilities {
    /// Project a challenge-validated status reply into the store's record
    /// (the challenge itself is transport state, not a capability),
    /// carrying `display` forward from the record it replaces; its crypt
    /// facts are recorded as learned while our public IPv4 was `key_ip`.
    pub(crate) fn from_status(
        status: &GlobServStatRes,
        display: ServerDescTags,
        key_ip: Option<Ipv4Addr>,
    ) -> Self {
        Self {
            users: status.users(),
            files: status.files(),
            max_users: status.max_users(),
            soft_files: status.soft_files(),
            hard_files: status.hard_files(),
            udp_flags: status.udp_flags(),
            low_id_users: status.low_id_users(),
            udp_crypt: ServerUdpCrypt::from_status(status, key_ip),
            display,
        }
    }

    /// Merge a tagged `0xA3`'s strings per field — a tag the server omitted
    /// leaves the prior value, exactly as aMule's per-tag setters do.
    pub(crate) fn apply_desc_tags(&mut self, tags: ServerDescTags) {
        let ServerDescTags {
            name,
            description,
            version,
            dyn_ip,
            aux_ports_list,
        } = tags;
        let display = &mut self.display;
        display.name = name.or(display.name.take());
        display.description = description.or(display.description.take());
        display.version = version.or(display.version.take());
        display.dyn_ip = dyn_ip.or(display.dyn_ip.take());
        display.aux_ports_list = aux_ports_list.or(display.aux_ports_list.take());
    }

    /// Apply a legacy `0xA3`'s two strings (aMule 2.3.3's assignment order:
    /// first the description, then the name).
    pub(crate) fn apply_legacy_desc(&mut self, description: String, name: String) {
        self.display.description = Some(description);
        self.display.name = Some(name);
    }
}

/// The shared store: server TCP endpoint → its last proven capabilities.
/// Cloned to the engine (writer) and to each gating consumer (readers).
pub(crate) type SharedServerCapabilities = Arc<Mutex<HashMap<Ipv4Endpoint, ServerCapabilities>>>;

/// A test record carrying just `udp_flags` — what every gating consumer
/// reads. Built through the real `0x97` projection so the store shape stays
/// single-sourced.
#[cfg(test)]
pub(crate) fn test_record_with_flags(bits: u32) -> ServerCapabilities {
    let mut datagram = vec![0xE3, rmule_ed2k::Opcode::GlobServStatRes.as_u8()];
    datagram.extend_from_slice(&0u32.to_le_bytes()); // challenge
    datagram.extend_from_slice(&1u32.to_le_bytes()); // users
    datagram.extend_from_slice(&2u32.to_le_bytes()); // files
    datagram.extend_from_slice(&3u32.to_le_bytes()); // max users
    datagram.extend_from_slice(&4u32.to_le_bytes()); // soft
    datagram.extend_from_slice(&5u32.to_le_bytes()); // hard
    datagram.extend_from_slice(&bits.to_le_bytes()); // udp flags
    ServerCapabilities::from_status(
        &GlobServStatRes::decode_udp(&datagram).expect("valid status body"),
        ServerDescTags::default(),
        None,
    )
}

/// An IPv4-literal server's store key — its TCP endpoint. A DNS-named server
/// has none (and its UDP sends are skipped by the transport anyway), so it
/// reads as capability-less and the status sweep walks past it.
pub(crate) fn server_tcp_key(server: &ServerEndpoint) -> Option<Ipv4Endpoint> {
    let ip = server.host().parse::<std::net::Ipv4Addr>().ok()?;
    Some(Ipv4Endpoint::new(ip, server.port()))
}

/// A server's proven UDP flags, keyed by its TCP endpoint — the lookup every
/// gating consumer performs (search variant selection, the `0x94` upgrade).
/// A DNS-named server has no `Ipv4Endpoint` key; it reads as capability-less,
/// like a server whose `0x97` has not arrived.
pub(crate) fn capability_flags(
    capabilities: &SharedServerCapabilities,
    server: &ServerEndpoint,
) -> Option<ServerUdpFlags> {
    capabilities
        .lock()
        .unwrap()
        .get(&server_tcp_key(server)?)
        .and_then(|caps| caps.udp_flags)
}
