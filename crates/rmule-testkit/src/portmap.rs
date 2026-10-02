//! Scripted **Port Mapping** counterparties (ADR-0086): a [`GatewaySource`]
//! that names whatever gateway a test says, and a [`MappingBackend`] that
//! answers whatever a test scripts.
//!
//! A real gateway is the one thing the port-mapping subsystem cannot be tested
//! against: the router on the machine running the test may not speak any of the
//! three protocols, may speak one badly, and certainly must not have rmule's
//! ports forwarded on it as a side effect of `cargo test`. These two fakes make
//! the gateway an *input*, so the race, the grading, the renewal ladder and the
//! epoch re-add are all driven deterministically — and the one behaviour that
//! decides High-ID, *which external port the gateway grants*, becomes a knob.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule_net::portmap::{
    EpochVerdict, Gateway, GatewaySource, MappingBackend, MappingError, MappingFuture,
    MappingGrant, MappingProtocol, MappingRequest, ProbeReport,
};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint};

/// A **Gateway Source** whose answer a test writes.
#[derive(Clone, Debug)]
pub struct FakeGateways(Arc<Mutex<Vec<Gateway>>>);

impl FakeGateways {
    /// A source naming exactly `gateways`.
    #[must_use]
    pub fn naming(gateways: &[Gateway]) -> Self {
        Self(Arc::new(Mutex::new(gateways.to_vec())))
    }

    /// The ordinary home-LAN answer: one IPv4 next hop at `192.168.1.1`,
    /// spoken to from `192.168.1.50`.
    #[must_use]
    pub fn home_lan() -> Self {
        Self::naming(&[Gateway::v4(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 50),
        )])
    }

    /// A host with no default route at all — the container case, where port
    /// mapping is simply not available.
    #[must_use]
    pub fn none() -> Self {
        Self::naming(&[])
    }
}

impl GatewaySource for FakeGateways {
    fn gateways(&self) -> Vec<Gateway> {
        self.0.lock().expect("fake gateway mutex").clone()
    }
}

/// What a scripted backend does with a mapping request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantPolicy {
    /// Grant the exact port asked for — the High-ID answer.
    Exact,
    /// Grant every mapping, but on the internal port plus this offset: the
    /// router had the port taken, or simply reassigns. On the TCP listener this
    /// is a silent LowID, which is the whole reason the grade exists.
    Shifted(u16),
    /// Grant nothing.
    Refuse,
}

/// A scripted **Mapping Backend**: one protocol, one probe answer, one grant
/// policy, and an optional epoch reset to report.
#[derive(Clone, Debug)]
pub struct ScriptedBackend {
    protocol: MappingProtocol,
    script: Arc<Mutex<Script>>,
}

#[derive(Clone, Debug)]
struct Script {
    /// The families the protocol reports it can map, or `None` for "not here".
    families: Option<Vec<AddressFamily>>,
    grants: GrantPolicy,
    lease: Option<Duration>,
    epoch: EpochVerdict,
    external_address: IpAddr,
    /// Every request the backend was asked for, in order — what a test asserts
    /// the runtime actually enacted.
    asked: Vec<MappingRequest>,
    released: Vec<(MappingRequest, u16)>,
    /// The local address each map and release was spoken from, with the
    /// request — the PCP source a v6 pinhole is keyed by.
    spoken_from: Vec<(MappingRequest, IpAddr)>,
}

impl ScriptedBackend {
    /// A backend that is present, maps IPv4, and grants the exact ports for an
    /// hour.
    #[must_use]
    pub fn available(protocol: MappingProtocol) -> Self {
        Self {
            protocol,
            script: Arc::new(Mutex::new(Script {
                families: Some(vec![AddressFamily::V4]),
                grants: GrantPolicy::Exact,
                lease: Some(Duration::from_secs(3600)),
                epoch: EpochVerdict::Consistent,
                external_address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                asked: Vec::new(),
                released: Vec::new(),
                spoken_from: Vec::new(),
            })),
        }
    }

    /// A backend that is not on this gateway at all.
    #[must_use]
    pub fn absent(protocol: MappingProtocol) -> Self {
        let backend = Self::available(protocol);
        backend.script.lock().expect("script mutex").families = None;
        backend
    }

    /// Report that it maps `families` — both, for a dual-stack PCP gateway.
    #[must_use]
    pub fn mapping(self, families: &[AddressFamily]) -> Self {
        self.script.lock().expect("script mutex").families = Some(families.to_vec());
        self
    }

    /// Change what it grants.
    #[must_use]
    pub fn granting(self, policy: GrantPolicy) -> Self {
        self.script.lock().expect("script mutex").grants = policy;
        self
    }

    /// Report the gateway's external address as `address` — a private or
    /// `100.64/10` one drives the double-NAT and carrier-grade paths.
    #[must_use]
    pub fn at_external_address(self, address: IpAddr) -> Self {
        self.script.lock().expect("script mutex").external_address = address;
        self
    }

    /// Report a gateway epoch reset on every answer from now on.
    pub fn report_epoch_reset(&self, reset: bool) {
        self.script.lock().expect("script mutex").epoch = if reset {
            EpochVerdict::Reset
        } else {
            EpochVerdict::Consistent
        };
    }

    /// Every mapping request this backend was asked for, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<MappingRequest> {
        self.script.lock().expect("script mutex").asked.clone()
    }

    /// Every release this backend was asked for, with the external port.
    #[must_use]
    pub fn released(&self) -> Vec<(MappingRequest, u16)> {
        self.script.lock().expect("script mutex").released.clone()
    }

    /// Every map and release, with the local address its gateway was spoken
    /// to from, in order.
    #[must_use]
    pub fn spoken_from(&self) -> Vec<(MappingRequest, IpAddr)> {
        self.script
            .lock()
            .expect("script mutex")
            .spoken_from
            .clone()
    }

    fn answer(&self, request: MappingRequest) -> Result<MappingGrant, MappingError> {
        let mut script = self.script.lock().expect("script mutex");
        script.asked.push(request);
        let external_port = match script.grants {
            GrantPolicy::Exact => request.internal_port,
            GrantPolicy::Shifted(offset) => request.internal_port.wrapping_add(offset),
            GrantPolicy::Refuse => {
                return Err(MappingError::Refused {
                    protocol: self.protocol,
                    refusal: rmule_net::portmap::MappingRefusal::NoResources,
                    hold_off: None,
                });
            }
        };
        let external = match script.external_address {
            IpAddr::V4(address) => PeerEndpoint::V4(Ipv4Endpoint::new(address, external_port)),
            IpAddr::V6(address) => {
                PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(address, external_port))
            }
        };
        Ok(MappingGrant {
            external,
            lease: script.lease,
            epoch: script.epoch,
        })
    }
}

impl MappingBackend for ScriptedBackend {
    fn protocol(&self) -> MappingProtocol {
        self.protocol
    }

    fn probe(
        self: Arc<Self>,
        _gateway: Gateway,
    ) -> MappingFuture<'static, Result<ProbeReport, MappingError>> {
        let script = self.script.lock().expect("script mutex").clone();
        let protocol = self.protocol;
        Box::pin(async move {
            script
                .families
                .map_or(Err(MappingError::Unsupported(protocol)), |families| {
                    Ok(ProbeReport {
                        external_address: Some(script.external_address),
                        families,
                        epoch: script.epoch,
                    })
                })
        })
    }

    fn map(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
    ) -> MappingFuture<'static, Result<MappingGrant, MappingError>> {
        self.script
            .lock()
            .expect("script mutex")
            .spoken_from
            .push((request, gateway.local_address));
        let answer = self.answer(request);
        Box::pin(async move { answer })
    }

    fn release(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
        external_port: u16,
    ) -> MappingFuture<'static, ()> {
        let mut script = self.script.lock().expect("script mutex");
        script.released.push((request, external_port));
        script.spoken_from.push((request, gateway.local_address));
        drop(script);
        Box::pin(async {})
    }
}
