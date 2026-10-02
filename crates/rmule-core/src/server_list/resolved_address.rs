//! A named row's **Resolved Address** (ADR-0052's amendment): what the
//! host name the operator listed answered the last time the Status Ping Sweep
//! asked. A run-time fact beside the row — never its key, never stored.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_primitives::{Ipv4Endpoint, ServerEndpoint};
use tokio::time::Instant;

/// How long a successful answer is reused before the name is asked again:
/// aMule's `DNS_SOLVE_TIME` (`AsyncDNS.h:46`).
pub(crate) const RESOLVED_ADDRESS_REUSE: Duration = Duration::from_secs(30 * 60);

/// What a row's host name answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedAddress {
    /// The name resolved to this IPv4 address; the row is pinged, and swept,
    /// there.
    Resolved(Ipv4Addr),
    /// The name gave no IPv4 address within the bound. Each pass that finds
    /// none counts as one unanswered try.
    DoesNotResolve,
}

/// Every named row's answer, and when it came.
#[derive(Debug, Default)]
pub(crate) struct ResolvedAddresses {
    answers: HashMap<ServerEndpoint, (ResolvedAddress, Instant)>,
}

impl ResolvedAddresses {
    /// `row`'s name answered `address` just now.
    pub(crate) fn record(&mut self, row: &ServerEndpoint, address: ResolvedAddress) {
        self.answers.insert(row.clone(), (address, Instant::now()));
    }

    /// `row`'s last answer, if its name was ever asked.
    pub(crate) fn of(&self, row: &ServerEndpoint) -> Option<ResolvedAddress> {
        self.answers.get(row).map(|(address, _)| *address)
    }

    /// `row`'s address when it may be reused without asking again: a
    /// success younger than [`RESOLVED_ADDRESS_REUSE`].
    pub(crate) fn fresh(&self, row: &ServerEndpoint) -> Option<Ipv4Addr> {
        match self.answers.get(row) {
            Some((ResolvedAddress::Resolved(ip), at)) if at.elapsed() < RESOLVED_ADDRESS_REUSE => {
                Some(*ip)
            }
            _ => None,
        }
    }

    /// The endpoint `row` is reached at: itself for a listed address, the
    /// resolved one for a name, `None` for a name without one.
    pub(crate) fn endpoint_of(&self, row: &ServerEndpoint) -> Option<Ipv4Endpoint> {
        if let Ok(ip) = row.host().parse::<Ipv4Addr>() {
            return Some(Ipv4Endpoint::new(ip, row.port()));
        }
        match self.of(row)? {
            ResolvedAddress::Resolved(ip) => Some(Ipv4Endpoint::new(ip, row.port())),
            ResolvedAddress::DoesNotResolve => None,
        }
    }

    /// The named row that resolved to `endpoint`, if any.
    pub(crate) fn row_at(&self, endpoint: Ipv4Endpoint) -> Option<ServerEndpoint> {
        self.answers.iter().find_map(|(row, (address, _))| {
            (*address == ResolvedAddress::Resolved(endpoint.ip) && row.port() == endpoint.port)
                .then(|| row.clone())
        })
    }

    /// Forget every row not in `listed`: a removed row's answer goes with it.
    pub(crate) fn keep_only(&mut self, listed: &[super::ManagedServer]) {
        self.answers
            .retain(|row, _| listed.iter().any(|server| &server.endpoint == row));
    }
}
