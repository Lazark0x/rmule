//! The UPnP-IGD **Mapping Backend** (ADR-0086), over `igd-next` (MIT).
//!
//! `igd-next`'s default transport is blocking (`attohttpc`), which is what this
//! backend uses: the async `aio_tokio` feature hard-requires hyper 1 plus
//! hyper-util, http, http-body-util and futures for one SOAP call a session.
//! The blocking client runs on `spawn_blocking`, which is also emule-qt's own
//! shape — blocking SOAP isolated on a worker thread.
//!
//! **The discovery is the slow part, so it is cached.** SSDP waits out a fixed
//! multicast window and then fetches a description document *per* responder,
//! which measures about seven seconds on an ordinary LAN — the measurement that
//! made the race's grace extend to fifteen. Re-running it per mapping would
//! spend that per request; the device is remembered per gateway instead.
//!
//! ## One deliberate divergence from ADR-0086
//!
//! The ADR states the mapping path as `AddAnyPortMapping` first, falling back to
//! `AddPortMapping`. That is miniupnpc's order, where `AddAnyPortMapping`
//! carries the *suggested* external port. `igd-next`'s `add_any_port` carries no
//! suggestion — it picks a random external port — so following the stated order
//! here would grant a random port every time, which on the eD2k listener is a
//! silent LowID: precisely the outcome exact-port grading exists to prevent.
//!
//! So the order is inverted: `AddPortMapping` on the port rmule actually wants,
//! which is exact-or-error, and `add_any_port` only as the fallback that turns a
//! conflict into a *graded* `Mismatched` grant rather than nothing. The one
//! thing the ADR's order buys — not silently stealing another LAN host's
//! mapping on the same external port — is the cost, and it is the smaller one: a
//! conflicting entry is far more often our own stale mapping than a neighbour's.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use igd_next::{AddPortError, PortMappingProtocol, SearchOptions};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint};

use super::epoch::EpochVerdict;
use super::{
    Gateway, MappedTransport, MappingBackend, MappingError, MappingFuture, MappingGrant,
    MappingProtocol, MappingRefusal, MappingRequest, MappingTransportFault, ProbeReport,
};

/// The SSDP search budget. Shorter than `igd-next`'s 10 s default so a UPnP
/// probe still lands inside the race's extended 15-second grace, and long
/// enough for the per-responder description fetch that makes the search take
/// about seven seconds on an ordinary LAN.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(8);

/// The per-response read budget inside that search.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// What the mapping is labelled as in the router's table. Operators read this
/// list; "rmule" plus the port is what makes an entry identifiable as ours and
/// safe to delete.
const DESCRIPTION: &str = "rmule";

/// The UPnP-IGD backend.
#[derive(Debug, Default)]
pub struct UpnpMappingBackend {
    /// The discovered device, and the next hop it was discovered from. Cached
    /// because SSDP plus a description fetch per responder is the expensive
    /// part; re-discovered when the next hop changes, because that is a
    /// different router.
    device: Mutex<Option<(Gateway, igd_next::Gateway)>>,
}

impl UpnpMappingBackend {
    /// A backend with nothing discovered yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached device for `gateway`, if it is still the one we found.
    fn cached(&self, gateway: Gateway) -> Option<igd_next::Gateway> {
        self.device
            .lock()
            .expect("upnp device cache")
            .as_ref()
            .filter(|(found_at, _)| *found_at == gateway)
            .map(|(_, device)| device.clone())
    }

    fn remember(&self, gateway: Gateway, device: &igd_next::Gateway) {
        *self.device.lock().expect("upnp device cache") = Some((gateway, device.clone()));
    }

    /// Find the IGD, or answer from the cache.
    ///
    /// IPv4 only in this wave: an IPv6 pinhole needs IGD2
    /// `WANIPv6FirewallControl:1` `AddPinhole`, which `igd-next` cannot issue at
    /// all — it has no such action, and the service name appears in its tree
    /// only inside a test fixture.
    async fn device(&self, gateway: Gateway) -> Result<igd_next::Gateway, MappingError> {
        if gateway.family() != AddressFamily::V4 {
            return Err(MappingError::Unsupported(MappingProtocol::Upnp));
        }
        if let Some(device) = self.cached(gateway) {
            return Ok(device);
        }
        let bind_addr = SocketAddr::new(gateway.local_address, 0);
        let found = tokio::task::spawn_blocking(move || {
            igd_next::search_gateway(SearchOptions {
                // Bound to the address the default route leaves from, so the
                // M-SEARCH goes out the right interface on a multi-homed host
                // rather than whichever one the kernel picks.
                bind_addr,
                timeout: Some(SEARCH_TIMEOUT),
                single_search_timeout: Some(RESPONSE_TIMEOUT),
                ..SearchOptions::default()
            })
        })
        .await
        .map_err(|error| transport(&error))?
        .map_err(|_| MappingError::Unsupported(MappingProtocol::Upnp))?;
        self.remember(gateway, &found);
        Ok(found)
    }
}

impl MappingBackend for UpnpMappingBackend {
    fn protocol(&self) -> MappingProtocol {
        MappingProtocol::Upnp
    }

    fn probe(
        self: Arc<Self>,
        gateway: Gateway,
    ) -> MappingFuture<'static, Result<ProbeReport, MappingError>> {
        Box::pin(async move {
            let device = self.device(gateway).await?;
            // SSDP proves a device answered; `GetExternalIPAddress` proves it
            // is a WAN connection service that will talk to us, which is the
            // question the race is actually asking.
            let external = tokio::task::spawn_blocking(move || device.get_external_ip())
                .await
                .map_err(|error| transport(&error))?
                .map_err(|error| refused(&error))?;
            Ok(ProbeReport {
                external_address: Some(external),
                families: vec![AddressFamily::V4],
                // UPnP-IGD has no uptime counter, so a reboot shows up only as
                // a lease that stopped being honoured.
                epoch: EpochVerdict::Absent,
            })
        })
    }

    fn map(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
    ) -> MappingFuture<'static, Result<MappingGrant, MappingError>> {
        Box::pin(async move {
            let device = self.device(gateway).await?;
            let local = SocketAddr::new(gateway.local_address, request.internal_port);
            let protocol = protocol_of(request.transport);
            let wanted = request.suggested_external_port;
            let lease = lease_seconds(request.lease);
            let external_ip = {
                let device = device.clone();
                tokio::task::spawn_blocking(move || device.get_external_ip())
                    .await
                    .map_err(|error| transport(&error))?
                    .map_err(|error| refused(&error))?
            };
            let granted = tokio::task::spawn_blocking(move || {
                add_mapping(&device, protocol, wanted, local, lease)
            })
            .await
            .map_err(|error| transport(&error))??;
            Ok(MappingGrant {
                external: join(external_ip, granted.port),
                lease: granted.lease,
                epoch: EpochVerdict::Absent,
            })
        })
    }

    fn release(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
        external_port: u16,
    ) -> MappingFuture<'static, ()> {
        Box::pin(async move {
            let Ok(device) = self.device(gateway).await else {
                return;
            };
            let protocol = protocol_of(request.transport);
            let _ =
                tokio::task::spawn_blocking(move || device.remove_port(protocol, external_port))
                    .await;
        })
    }
}

/// What one `AddPortMapping` round produced.
struct Granted {
    port: u16,
    /// `None` when the gateway granted a **permanent** mapping — IGD1's lease
    /// of 0. It has no expiry to renew against, so the mapper polls it instead.
    lease: Option<Duration>,
}

/// Ask for the exact port; fall back to a permanent lease, then to whatever the
/// gateway will give.
fn add_mapping(
    device: &igd_next::Gateway,
    protocol: PortMappingProtocol,
    wanted: u16,
    local: SocketAddr,
    lease: u32,
) -> Result<Granted, MappingError> {
    match device.add_port(protocol, wanted, local, lease, DESCRIPTION) {
        Ok(()) => Ok(Granted {
            port: wanted,
            lease: Some(Duration::from_secs(u64::from(lease))),
        }),
        // UPnP error 725. IGD1's lease of 0 *means* permanent, while IGD2
        // forbids infinite leases outright — so the same request earns a
        // permanent mapping on one class of router and a one-week one on
        // another. Asking again with 0 is the only way to be mapped at all on
        // the first class.
        Err(AddPortError::OnlyPermanentLeasesSupported) => device
            .add_port(protocol, wanted, local, 0, DESCRIPTION)
            .map(|()| Granted {
                port: wanted,
                lease: None,
            })
            .map_err(|error| refused(&error)),
        // The port is taken, or the gateway insists on choosing. A grant on
        // another port is still worth having on the UDP surfaces — it is the
        // same fact Kad's extern-port rule learns — and the grade is what
        // stops it being advertised on the TCP one.
        Err(_) => device
            .add_any_port(protocol, local, lease, DESCRIPTION)
            .map(|port| Granted {
                port,
                lease: Some(Duration::from_secs(u64::from(lease))),
            })
            .map_err(|error| refused(&error)),
    }
}

const fn protocol_of(transport: MappedTransport) -> PortMappingProtocol {
    match transport {
        MappedTransport::Tcp => PortMappingProtocol::TCP,
        MappedTransport::Udp => PortMappingProtocol::UDP,
    }
}

/// IGD2 caps a lease at one week and IGD1 reads 0 as permanent, so a request is
/// stated in seconds and saturated rather than wrapped.
fn lease_seconds(lease: Duration) -> u32 {
    u32::try_from(lease.as_secs()).unwrap_or(u32::MAX)
}

/// The device refused; what it said goes to the Run Log.
fn refused(error: &dyn std::fmt::Display) -> MappingError {
    tracing::debug!(%error, "UPnP device refused");
    MappingError::Refused {
        protocol: MappingProtocol::Upnp,
        refusal: MappingRefusal::DeviceRefused,
        // UPnP carries no retry estimate, so the mapper's own backoff floor
        // paces a refusal.
        hold_off: None,
    }
}

/// The device could not be spoken to; why goes to the Run Log.
fn transport(error: &dyn std::fmt::Display) -> MappingError {
    tracing::debug!(%error, "UPnP device could not be spoken to");
    MappingError::Transport {
        protocol: MappingProtocol::Upnp,
        fault: MappingTransportFault::Device,
    }
}

/// An external address and a granted port as one endpoint. UPnP-IGD1 is IPv4
/// only, so a v6 external address means the device answered something this
/// backend did not ask for; it is carried through rather than invented away,
/// and the store refuses what it cannot use.
const fn join(address: IpAddr, port: u16) -> PeerEndpoint {
    match address {
        IpAddr::V4(ip) => PeerEndpoint::V4(Ipv4Endpoint::new(ip, port)),
        IpAddr::V6(ip) => PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(ip, port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn an_ipv6_gateway_is_refused_before_any_search_runs() {
        // IGD2 `AddPinhole` is the only UPnP route to an IPv6 pinhole and
        // `igd-next` cannot issue it, so claiming otherwise would put a
        // permanently failing candidate in every dual-stack race.
        let backend = Arc::new(UpnpMappingBackend::new());
        let gateway = Gateway {
            address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            scope_id: Some(4),
            local_address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
        };
        assert!(matches!(
            backend.probe(gateway).await,
            Err(MappingError::Unsupported(MappingProtocol::Upnp))
        ));
    }

    #[test]
    fn the_device_cache_is_keyed_on_the_next_hop_it_was_found_from() {
        // A different next hop is a different router: answering from the cache
        // would map ports on a box that is no longer in the path.
        let backend = UpnpMappingBackend::new();
        let first = Gateway::v4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 5));
        let second = Gateway::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5));
        let device = igd_next::Gateway {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5000),
            root_url: String::new(),
            control_url: String::new(),
            control_schema_url: String::new(),
            control_schema: std::collections::HashMap::new(),
        };
        backend.remember(first, &device);
        assert!(backend.cached(first).is_some());
        assert!(backend.cached(second).is_none());
    }
}
