//! A scripted **Interface Source** (ADR-0084): the set of addresses a test
//! says this host holds.
//!
//! The real enumeration answers whatever the machine running the test happens
//! to have, which makes the two rules that read it — the interface *tier* and
//! the local-interface *corroboration filter* — untestable on CI. This fake
//! makes the set an input instead, so a dual-homed host, a host with only a
//! link-local IPv6, and a host with nothing routable are all one call away.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use rmule_net::interfaces::InterfaceSource;

/// An **Interface Source** whose answer a test writes. Cheap to clone; every
/// clone reads the one set, so the subject and the test see the same host.
#[derive(Clone, Debug, Default)]
pub struct FakeInterfaces(Arc<Mutex<Vec<IpAddr>>>);

impl FakeInterfaces {
    /// A source holding exactly `addresses`.
    #[must_use]
    pub fn holding(addresses: &[IpAddr]) -> Self {
        Self(Arc::new(Mutex::new(addresses.to_vec())))
    }
}

impl InterfaceSource for FakeInterfaces {
    fn addresses(&self) -> Vec<IpAddr> {
        self.0.lock().expect("fake interface mutex").clone()
    }
}
