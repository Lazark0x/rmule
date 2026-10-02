//! The **Name Resolver**: how core turns a host name into an IPv4 address —
//! a link's named source (ADR-0089's amendment) and a server the operator
//! listed by name (ADR-0052's amendment). One seam, so the one bound and
//! the one family rule hold for both, and a test can answer for DNS.
//!
//! A lookup runs on the Tokio runtime, never on the actor, and ends by its
//! bound: a name that has not answered by then does not resolve. Only an A
//! answer counts — every eD2k surface a name feeds is IPv4 (ADR-0087's
//! server-UDP ruling resolves A-first), and a link's IPv6 hints ride `s6=`.
//! Resolving a name is not a connection: nothing is sent to the address.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// How long one name may take to resolve before it counts as not resolving.
pub(crate) const RESOLVE_BOUND: Duration = Duration::from_secs(5);

/// A name's answer: its first IPv4 address, or `None` when it has none within
/// the bound.
pub(crate) type Resolution = Pin<Box<dyn Future<Output = Option<Ipv4Addr>> + Send>>;

/// The resolver seam.
pub(crate) trait NameResolver: Send + Sync + 'static {
    /// Resolve `host` to one IPv4 address, bounded.
    fn resolve_ipv4(&self, host: String) -> Resolution;
}

/// The resolver every holder shares.
pub(crate) type SharedNameResolver = Arc<dyn NameResolver>;

/// The system resolver (`getaddrinfo` through `tokio::net::lookup_host`),
/// bounded by [`RESOLVE_BOUND`].
pub(crate) struct SystemNameResolver;

impl NameResolver for SystemNameResolver {
    fn resolve_ipv4(&self, host: String) -> Resolution {
        Box::pin(async move {
            let lookup = tokio::net::lookup_host((host.as_str(), 0));
            let addresses = tokio::time::timeout(RESOLVE_BOUND, lookup)
                .await
                .ok()?
                .ok()?;
            addresses
                .into_iter()
                .find_map(|address| match address.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
        })
    }
}

/// The production resolver, shared.
pub(crate) fn system_resolver() -> SharedNameResolver {
    Arc::new(SystemNameResolver)
}

/// A resolver that answers from a table and counts what it was asked.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct FakeNameResolver {
    answers: std::sync::Mutex<std::collections::HashMap<String, Ipv4Addr>>,
    asked: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl FakeNameResolver {
    /// A resolver that knows `answers` and nothing else.
    pub(crate) fn knowing(answers: &[(&str, Ipv4Addr)]) -> Arc<Self> {
        let resolver = Self::default();
        resolver
            .answers
            .lock()
            .unwrap()
            .extend(answers.iter().map(|(name, ip)| ((*name).to_owned(), *ip)));
        Arc::new(resolver)
    }

    /// From now on `name` answers `ip`, or nothing for `None`.
    pub(crate) fn answer(&self, name: &str, ip: Option<Ipv4Addr>) {
        let mut answers = self.answers.lock().unwrap();
        match ip {
            Some(ip) => answers.insert(name.to_owned(), ip),
            None => answers.remove(name),
        };
    }

    /// Every name asked so far, in order.
    pub(crate) fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl NameResolver for FakeNameResolver {
    fn resolve_ipv4(&self, host: String) -> Resolution {
        let answer = self.answers.lock().unwrap().get(&host).copied();
        self.asked.lock().unwrap().push(host);
        Box::pin(async move { answer })
    }
}
