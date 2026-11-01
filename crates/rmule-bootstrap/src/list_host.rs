//! Whose word a fetched list is: the host its URL names (ADR-0085). A row is
//! usable only when its address lies in no Reserved Range that host cannot
//! vouch for, as aMule runs `IsGoodIP` on every server it adds
//! (`ServerList.cpp:206`) — LAN rows included, which aMule's `FilterLanIPs`
//! drops and rmule keeps.

use std::net::{IpAddr, Ipv4Addr};

use rmule_primitives::{Informant, is_reserved_address};

/// The party a list fetched from one URL is the word of.
///
/// An address literal is that party, and `localhost` is this host, the name
/// RFC 6761 §6.3 fixes to the loopback address. Any other name is a remote
/// party: the fetch resolves it but never surfaces the address it reached, and
/// that address would be a proxy's when one is configured.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ListHost(Option<Informant>);

impl ListHost {
    /// The host `url` names.
    pub(crate) fn of(url: &str) -> Self {
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

    /// Whether a row at `ip` can be usable as this host's word.
    pub(crate) fn admits(self, ip: IpAddr) -> bool {
        let admitted = match self.0 {
            Some(informant) => informant.admits(ip),
            None => !is_reserved_address(ip),
        };
        if !admitted {
            tracing::warn!(%ip, "dropping a fetched row whose address no party can be at");
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
