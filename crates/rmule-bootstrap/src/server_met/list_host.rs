//! Whose word a fetched server.met is: the host its URL names (ADR-0085). A
//! row is a server only when its address lies in no Reserved Range that host
//! cannot vouch for, as aMule runs `IsGoodIP` on every server it adds
//! (`ServerList.cpp:206`) — LAN rows included, which aMule's `FilterLanIPs`
//! drops and rmule keeps.

use std::net::{IpAddr, Ipv4Addr};

use rmule_ed2k::ServerMetEntry;
use rmule_primitives::{Informant, is_reserved_address};

/// The party a server.met fetched from one URL is the word of.
///
/// An address literal is that party, and `localhost` is this host, the name
/// RFC 6761 §6.3 fixes to the loopback address. Any other name is a remote
/// party: the fetch resolves it but never surfaces the address it reached, and
/// that address would be a proxy's when one is configured.
#[derive(Clone, Copy, Debug)]
pub(super) struct ListHost(Option<Informant>);

impl ListHost {
    /// The host `url` names.
    pub(super) fn of(url: &str) -> Self {
        let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let host = match host.strip_prefix('[') {
            Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
            None => host.split(':').next().unwrap_or_default(),
        };
        let informant = match host.parse::<IpAddr>() {
            Ok(ip) => Some(Informant::Party(ip)),
            Err(_) if is_localhost(host) => Some(Informant::Party(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            Err(_) => None,
        };
        Self(informant)
    }

    /// Whether `entry` can be a server as this host's word. A row that names
    /// no address at all is left to the projection that drops it.
    pub(super) fn admits(self, entry: &ServerMetEntry) -> bool {
        let Some(ip) = entry.dialable_address() else {
            return true;
        };
        let admitted = match self.0 {
            Some(informant) => informant.admits(ip),
            None => !is_reserved_address(ip),
        };
        if !admitted {
            tracing::warn!(
                %ip,
                port = entry.endpoint().port,
                "dropping a server.met row whose address no server can be at"
            );
        }
        admitted
    }
}

/// Whether `host` is `localhost` or a name under it (RFC 6761 §6.3), with or
/// without the root's trailing dot.
fn is_localhost(host: &str) -> bool {
    const LOCALHOST: &str = "localhost";
    let host = host.strip_suffix('.').unwrap_or(host).as_bytes();
    let Some(split) = host.len().checked_sub(LOCALHOST.len()) else {
        return false;
    };
    let (prefix, tail) = host.split_at(split);
    tail.eq_ignore_ascii_case(LOCALHOST.as_bytes()) && (prefix.is_empty() || prefix.ends_with(b"."))
}
