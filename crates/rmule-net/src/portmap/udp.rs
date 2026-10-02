//! The two UDP **Mapping Backends** (ADR-0086): PCP (RFC 6887) and NAT-PMP
//! (RFC 6886), over `crab_nat` (MIT).
//!
//! The crate owns the codecs and the socket; rmule owns everything the audit
//! found it leaves to the caller:
//!
//! - **A bounded retransmit ladder.** `crab_nat`'s default is three retries,
//!   and the RFCs' own schedules are worse for a client waiting to come online:
//!   RFC 6886 takes about 128 s to give up, and RFC 6887 with `MRC = 0` retries
//!   *forever*. The race has a 3-second grace and a 15-second cap, so a backend
//!   that outlived them would simply never be graded. Ours is tighter than the
//!   RFC and stated as such.
//! - **Epoch validation** ([`EpochTracker`]): the crate parses the gateway's
//!   uptime into every response and compares nothing. One tracker per protocol
//!   per **Address Family**, because a reboot invalidates every mapping and
//!   nothing else reports one — and a dual-stack router is reached at two next
//!   hops, one per family, whose alternation must not read as a new gateway.
//! - **A derived nonce.** RFC 6887 §11.3 makes the PCP Mapping Nonce a
//!   capability: re-requesting the same internal port with a *different* nonce
//!   earns `NOT_AUTHORIZED` against our own mapping until it expires. A random
//!   nonce therefore cannot survive a restart, and measured firmware answers a
//!   renew-or-delete with the wrong nonce by *silence* rather than the refusal
//!   §11.3 requires. So the nonce is derived from stable facts, and optionally
//!   from a caller-held secret.
//!
//! - **IPv6 source-address pinning** ([`pcp_map`]). `crab_nat`
//!   always binds the unspecified address and exposes no way to pin a source,
//!   so over a link-local next hop the kernel picks a link-local source and the
//!   gateway refuses (`ADDRESS_MISMATCH`, RFC 6887 §8.2). PCP over IPv6 is
//!   therefore rmule's own `MAP` exchange from a socket bound to the address the
//!   request names — the reserve ADR-0086 held, drawn for this one case;
//!   IPv4 PCP, `PEER` and NAT-PMP stay on the crate.
//!
//! One socket per attempt — the quirk that makes a FRITZ!Box answer exactly one
//! PCP request per source port over IPv6 — is the crate's own behaviour: every
//! logical request binds a fresh socket.

use std::net::{IpAddr, SocketAddrV6};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crab_nat::{
    GatewayAddress, InternetProtocol, PortMappingOptions, PortMappingType, TimeoutConfig, natpmp,
    pcp,
};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint};

use super::epoch::{EpochTracker, EpochVerdict};
use super::pcp_map::{self, MapReply, MapRequest};
use super::{
    Gateway, MappedTransport, MappingBackend, MappingError, MappingFuture, MappingGrant,
    MappingProtocol, MappingRefusal, MappingRequest, MappingTransportFault, PeerPinRequest,
    ProbeReport,
};

/// The retransmit ladder both UDP backends run — through `crab_nat`, and
/// through rmule's own pinned IPv6 PCP exchange ([`pcp_map::exchange`]), so a
/// retune reaches every PCP and NAT-PMP request alike.
///
/// Deliberately tighter than either RFC: RFC 6886's nine attempts take about
/// 128 s to conclude "unsupported" and RFC 6887's default retries without limit,
/// while the race that drives these backends closes at 3 s and gives up at 15.
/// A ladder that outlived the round would produce answers nothing reads.
pub(super) const LADDER: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_millis(250),
    max_retries: 3,
    max_retry_timeout: Some(Duration::from_secs(4)),
};

/// The mixing constant the derived nonce is salted with — an rmule-specific
/// value so two clients on one LAN mapping the same port derive different
/// nonces.
const NONCE_SALT: u32 = 0x726D_756C;

/// The two protocols `crab_nat` speaks, as one backend each.
#[derive(Debug)]
pub struct UdpMappingBackend {
    protocol: MappingProtocol,
    /// A caller-held per-install secret mixed into the PCP nonce. `0` — the
    /// default — still derives a *stable* nonce, which is the property renew
    /// and delete need; a front end that persists a secret additionally gets
    /// §11.3's capability property, where a LAN neighbour cannot guess the
    /// nonce that deletes our mapping.
    secret: u32,
    /// Counterparty state per **Address Family**, indexed by [`family_slot`]:
    /// the epoch tracker and, for NAT-PMP, the external address its MAP
    /// response does not carry. One backend serves both families' next hops,
    /// and one shared slot would re-anchor on every v4/v6 alternation — so a
    /// dual-stack gateway's reboot would never read as one (RFC 6887 §8.5).
    state: Mutex<[GatewayState; 2]>,
}

#[derive(Clone, Copy, Debug)]
struct GatewayState {
    epoch: EpochTracker,
    /// The last external address learned from this gateway. NAT-PMP's MAP
    /// response carries only a port, so the address comes from the opcode-0
    /// request the probe already makes — kept rather than re-asked per mapping,
    /// which would double every map's round trips.
    external: Option<IpAddr>,
    /// Which next hop (address and zone) the two above describe, so pointing
    /// the backend at a different router re-anchors instead of comparing two
    /// boxes' uptimes. The local address is not part of it: a pinhole names
    /// its own Known IPv6 as the source, and that is still the same router.
    next_hop: Option<(IpAddr, Option<u32>)>,
}

/// Which [`UdpMappingBackend::state`] slot a family's next hop keeps.
const fn family_slot(family: AddressFamily) -> usize {
    match family {
        AddressFamily::V4 => 0,
        AddressFamily::V6 => 1,
    }
}

impl UdpMappingBackend {
    /// A PCP backend (RFC 6887).
    #[must_use]
    pub fn pcp() -> Self {
        Self::new(MappingProtocol::Pcp, EpochTracker::pcp())
    }

    /// A NAT-PMP backend (RFC 6886).
    #[must_use]
    pub fn nat_pmp() -> Self {
        Self::new(MappingProtocol::NatPmp, EpochTracker::nat_pmp())
    }

    /// Mix a per-install secret into the derived PCP nonce, so the nonce is a
    /// capability a LAN neighbour cannot guess (RFC 6887 §11.3) as well as one
    /// that survives a restart.
    #[must_use]
    pub const fn with_secret(mut self, secret: u32) -> Self {
        self.secret = secret;
        self
    }

    fn new(protocol: MappingProtocol, epoch: EpochTracker) -> Self {
        let fresh = GatewayState {
            epoch,
            external: None,
            next_hop: None,
        };
        Self {
            protocol,
            secret: 0,
            state: Mutex::new([fresh; 2]),
        }
    }

    /// Run `f` on `gateway`'s family slot, re-anchoring it first when that
    /// family's next hop itself changed.
    fn with_state<T>(&self, gateway: Gateway, f: impl FnOnce(&mut GatewayState) -> T) -> T {
        let mut states = self.state.lock().expect("portmap gateway state");
        let state = &mut states[family_slot(gateway.family())];
        let next_hop = (gateway.address, gateway.scope_id);
        if state.next_hop != Some(next_hop) {
            state.epoch.forget();
            state.next_hop = Some(next_hop);
            state.external = None;
        }
        f(state)
    }

    /// Read one response's epoch against its own family's history.
    fn observe_epoch(&self, gateway: Gateway, epoch_seconds: u32) -> EpochVerdict {
        self.with_state(gateway, |state| {
            state.epoch.observe(epoch_seconds, Instant::now())
        })
    }

    fn remember_external(&self, gateway: Gateway, address: IpAddr) {
        self.with_state(gateway, |state| state.external = Some(address));
    }

    fn external(&self, gateway: Gateway) -> Option<IpAddr> {
        self.with_state(gateway, |state| state.external)
    }

    /// The PCP Mapping Nonce for one request, derived rather than drawn.
    ///
    /// Stable across restarts by construction: the same (secret, family,
    /// transport, internal port) always yields the same nonce, which is what
    /// lets a renew or a delete be authorized against a mapping this process
    /// did not create.
    fn nonce(&self, request: MappingRequest) -> pcp::Nonce {
        let family = match request.family {
            AddressFamily::V4 => 4_u32,
            AddressFamily::V6 => 6,
        };
        let transport = match request.transport {
            MappedTransport::Tcp => 6_u32,
            MappedTransport::Udp => 17,
        };
        let seed = u64::from(self.secret) << 32
            | u64::from(request.internal_port) << 16
            | u64::from(family) << 8
            | u64::from(transport);
        [
            mix(seed ^ u64::from(NONCE_SALT)),
            mix(seed.rotate_left(17)),
            mix(seed.rotate_left(41) ^ 0xA5A5_A5A5_A5A5_A5A5),
        ]
    }
}

impl MappingBackend for UdpMappingBackend {
    fn protocol(&self) -> MappingProtocol {
        self.protocol
    }

    fn probe(
        self: Arc<Self>,
        gateway: Gateway,
    ) -> MappingFuture<'static, Result<ProbeReport, MappingError>> {
        Box::pin(async move { self.run_probe(gateway).await })
    }

    fn map(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
    ) -> MappingFuture<'static, Result<MappingGrant, MappingError>> {
        Box::pin(async move { self.run_map(gateway, request).await })
    }

    fn pin_peer(
        self: Arc<Self>,
        gateway: Gateway,
        request: PeerPinRequest,
    ) -> MappingFuture<'static, Result<MappingGrant, MappingError>> {
        Box::pin(async move { self.run_pin_peer(gateway, request).await })
    }

    fn release(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
        _external_port: u16,
    ) -> MappingFuture<'static, ()> {
        Box::pin(async move {
            // Fire and forget: at least one firmware never acknowledges a PCP
            // delete, and the finite lease is the real cleanup.
            let _ = self.run_release(gateway, request).await;
        })
    }
}

impl UdpMappingBackend {
    async fn run_probe(&self, gateway: Gateway) -> Result<ProbeReport, MappingError> {
        let address = gateway_address(gateway);
        match self.protocol {
            // NAT-PMP's opcode-0 external-address request is the state-free
            // probe the protocol provides, and it answers the address too.
            MappingProtocol::NatPmp => {
                let external = natpmp::external_address(address, Some(LADDER))
                    .await
                    .map_err(|error| self.nat_pmp_error(&error))?;
                self.remember_external(gateway, IpAddr::V4(external));
                Ok(ProbeReport {
                    external_address: Some(IpAddr::V4(external)),
                    families: vec![AddressFamily::V4],
                    epoch: EpochVerdict::Absent,
                })
            }
            // PCP has no `ANNOUNCE` in this crate, so the state-free question
            // is a *delete* of a mapping we never made: a gateway that answers
            // it at all — success or refusal — speaks PCP, and one that does
            // not answers `UNSUPP_VERSION` or nothing. Nothing is created
            // either way, which is what lets every enabled backend probe at
            // once without leaving state on a router that loses the race.
            MappingProtocol::Pcp if gateway.address.is_ipv6() => {
                let probe = pcp_probe_request(gateway);
                match self.pinned_exchange(gateway, probe).await {
                    Ok(_) | Err(MappingError::Refused { .. }) => Ok(pcp_present(gateway)),
                    Err(_) => Err(MappingError::Unsupported(MappingProtocol::Pcp)),
                }
            }
            MappingProtocol::Pcp => {
                match self.pcp_drop(gateway, pcp_probe_request(gateway)).await {
                    Ok(()) => Ok(pcp_present(gateway)),
                    // A refusal is still an answer in PCP, so the protocol is
                    // there; only a version mismatch or silence says it is not.
                    Err(
                        pcp::Failure::Timeout
                        | pcp::Failure::Socket(_)
                        | pcp::Failure::UnsupportedVersion(_),
                    ) => Err(MappingError::Unsupported(MappingProtocol::Pcp)),
                    Err(_) => Ok(pcp_present(gateway)),
                }
            }
            MappingProtocol::Upnp => Err(MappingError::Unsupported(MappingProtocol::Upnp)),
        }
    }

    async fn run_map(
        &self,
        gateway: Gateway,
        request: MappingRequest,
    ) -> Result<MappingGrant, MappingError> {
        let address = gateway_address(gateway);
        let internal = NonZeroU16::new(request.internal_port)
            .ok_or_else(|| self.transport_error(MappingTransportFault::PortZero))?;
        if self.protocol == MappingProtocol::Pcp && gateway.address.is_ipv6() {
            return self.pinned_exchange(gateway, request).await;
        }
        let options = PortMappingOptions {
            external_port: NonZeroU16::new(request.suggested_external_port),
            lifetime_seconds: Some(lease_seconds(request.lease)),
            timeout_config: Some(LADDER),
        };
        let mapping = match self.protocol {
            MappingProtocol::Pcp => pcp::port_mapping(
                pcp::BaseMapRequest::new(
                    address,
                    gateway.local_address,
                    protocol_of(request.transport),
                    internal,
                ),
                Some(self.nonce(request)),
                None,
                options,
            )
            .await
            .map_err(|error| self.pcp_error(&error))?,
            MappingProtocol::NatPmp => {
                natpmp::port_mapping(address, protocol_of(request.transport), internal, options)
                    .await
                    .map_err(|error| self.nat_pmp_error(&error))?
            }
            MappingProtocol::Upnp => {
                return Err(MappingError::Unsupported(MappingProtocol::Upnp));
            }
        };
        let epoch = self.observe_epoch(gateway, mapping.gateway_epoch());
        // PCP's MAP response carries the assigned external address; NAT-PMP's
        // does not, so its address is the one the probe's opcode-0 request
        // learned.
        let external_address = match mapping.mapping_type() {
            PortMappingType::Pcp { external_ip, .. } => {
                self.remember_external(gateway, external_ip);
                external_ip
            }
            PortMappingType::NatPmp => self
                .external(gateway)
                .ok_or_else(|| self.transport_error(MappingTransportFault::NoExternalAddress))?,
        };
        Ok(MappingGrant {
            external: join(external_address, mapping.external_port().get()),
            lease: Some(Duration::from_secs(u64::from(mapping.lifetime()))),
            epoch,
        })
    }

    async fn run_pin_peer(
        &self,
        gateway: Gateway,
        request: PeerPinRequest,
    ) -> Result<MappingGrant, MappingError> {
        if self.protocol != MappingProtocol::Pcp {
            return Err(MappingError::Unsupported(self.protocol));
        }
        let internal = NonZeroU16::new(request.internal_port)
            .ok_or_else(|| self.transport_error(MappingTransportFault::PortZero))?;
        // The nonce is the one a MAP of this same port uses. RFC 6887 §12.2
        // requires it when an explicit mapping already covers the port — the
        // common case, since ADR-0086 maps the client-UDP bind — and a router
        // with no such mapping simply adopts it for the new one.
        let nonce = self.nonce(MappingRequest {
            family: AddressFamily::V4,
            transport: MappedTransport::Udp,
            internal_port: request.internal_port,
            suggested_external_port: request.internal_port,
            lease: request.lease,
        });
        let mapping = pcp::peer_mapping(
            pcp::BaseMapRequest::new(
                gateway_address(gateway),
                gateway.local_address,
                protocol_of(MappedTransport::Udp),
                internal,
            ),
            Some(nonce),
            None,
            std::net::SocketAddr::V4(request.remote),
            PortMappingOptions {
                external_port: request.suggested_external_port.and_then(NonZeroU16::new),
                lifetime_seconds: Some(lease_seconds(request.lease)),
                timeout_config: Some(LADDER),
            },
        )
        .await
        .map_err(|error| self.pcp_error(&error))?;
        let epoch = self.observe_epoch(gateway, mapping.gateway_epoch_seconds());
        Ok(MappingGrant {
            external: join(mapping.external_ip(), mapping.external_port().get()),
            lease: Some(Duration::from_secs(u64::from(mapping.lifetime_seconds()))),
            epoch,
        })
    }

    async fn run_release(&self, gateway: Gateway, request: MappingRequest) -> Result<(), ()> {
        let address = gateway_address(gateway);
        let Some(internal) = NonZeroU16::new(request.internal_port) else {
            return Err(());
        };
        match self.protocol {
            MappingProtocol::Pcp if gateway.address.is_ipv6() => {
                let delete = MappingRequest {
                    lease: Duration::ZERO,
                    ..request
                };
                self.pinned_exchange(gateway, delete)
                    .await
                    .map(drop)
                    .map_err(drop)
            }
            MappingProtocol::Pcp => self.pcp_drop(gateway, request).await.map_err(|_| ()),
            MappingProtocol::NatPmp => natpmp::try_drop_mapping(
                address,
                protocol_of(request.transport),
                Some(internal),
                Some(LADDER),
            )
            .await
            .map_err(|_| ()),
            MappingProtocol::Upnp => Err(()),
        }
    }

    /// The `MAP` this backend sends over IPv6 for `request`: from the
    /// gateway's local address, under the derived nonce — the same nonce the
    /// `crab_nat` path uses, so a mapping made before a restart is still ours.
    fn pinned_request(&self, gateway: Gateway, request: MappingRequest) -> Option<MapRequest> {
        let IpAddr::V6(client) = gateway.local_address else {
            return None;
        };
        Some(MapRequest {
            client,
            nonce: self.nonce(request),
            protocol: match request.transport {
                MappedTransport::Tcp => 6,
                MappedTransport::Udp => 17,
            },
            internal_port: request.internal_port,
            // A delete names no external port (the `crab_nat` path's wire,
            // captured): the mapping is identified by nonce, protocol and
            // internal port.
            suggested_external_port: if request.lease.is_zero() {
                0
            } else {
                request.suggested_external_port
            },
            lifetime: lease_seconds(request.lease),
        })
    }

    /// One IPv6 PCP `MAP` (or delete, at lease zero) from the pinned source.
    async fn pinned_exchange(
        &self,
        gateway: Gateway,
        request: MappingRequest,
    ) -> Result<MappingGrant, MappingError> {
        let (IpAddr::V6(next_hop), Some(map)) =
            (gateway.address, self.pinned_request(gateway, request))
        else {
            return Err(self.transport_error(MappingTransportFault::NoIpv6Local));
        };
        let server = SocketAddrV6::new(
            next_hop,
            pcp_map::PCP_SERVER_PORT,
            0,
            gateway.scope_id.unwrap_or(0),
        );
        match pcp_map::exchange(server, &map, LADDER).await? {
            MapReply::Granted(grant) => Ok(MappingGrant {
                external: join(IpAddr::V6(grant.external_address), grant.external_port),
                lease: Some(Duration::from_secs(u64::from(grant.lifetime))),
                epoch: self.observe_epoch(gateway, grant.epoch),
            }),
            MapReply::Refused { code, lifetime } => Err(MappingError::Refused {
                protocol: MappingProtocol::Pcp,
                refusal: MappingRefusal::from_pcp_code(code),
                hold_off: pcp_map::carries_hold_off(code)
                    .then(|| Duration::from_secs(u64::from(lifetime))),
            }),
            MapReply::UnsupportedVersion(_) | MapReply::Foreign => {
                Err(MappingError::Unsupported(MappingProtocol::Pcp))
            }
        }
    }

    async fn pcp_drop(
        &self,
        gateway: Gateway,
        request: MappingRequest,
    ) -> Result<(), pcp::Failure> {
        let Some(internal) = NonZeroU16::new(request.internal_port) else {
            return Err(pcp::Failure::MalformedRequest);
        };
        pcp::try_drop_mapping(
            gateway_address(gateway),
            gateway.local_address,
            self.nonce(request),
            pcp::DropMappingRange::Single {
                protocol: protocol_of(request.transport),
                internal_port: internal,
            },
            Some(LADDER),
        )
        .await
    }

    /// Translate a PCP failure, carrying the RFC 6887 §7.4 hold-off estimate
    /// **raw** — clamping it is the caller's, because an unclamped
    /// `0xFFFFFFFF` is a denial of service and the policy that bounds it lives
    /// with the mapper.
    fn pcp_error(&self, failure: &pcp::Failure) -> MappingError {
        let hold_off = match failure {
            pcp::Failure::NotAuthorized(seconds)
            | pcp::Failure::NetworkFailure(seconds)
            | pcp::Failure::NoResources(seconds)
            | pcp::Failure::UserExceededQuota(seconds)
            | pcp::Failure::CannotProvideExternal(seconds) => {
                Some(Duration::from_secs(u64::from(*seconds)))
            }
            _ => None,
        };
        match failure {
            pcp::Failure::Timeout => MappingError::Timeout(MappingProtocol::Pcp),
            pcp::Failure::UnsupportedVersion(_) => MappingError::Unsupported(MappingProtocol::Pcp),
            pcp::Failure::Socket(error) => {
                tracing::debug!(%error, "PCP socket error");
                MappingError::Transport {
                    protocol: MappingProtocol::Pcp,
                    fault: MappingTransportFault::io(error),
                }
            }
            other => MappingError::Refused {
                protocol: MappingProtocol::Pcp,
                refusal: MappingRefusal::of_pcp(other).unwrap_or(MappingRefusal::BadAnswer),
                hold_off,
            },
        }
    }

    fn nat_pmp_error(&self, failure: &natpmp::Failure) -> MappingError {
        match failure {
            natpmp::Failure::Timeout => MappingError::Timeout(MappingProtocol::NatPmp),
            natpmp::Failure::UnsupportedVersion(_) => {
                MappingError::Unsupported(MappingProtocol::NatPmp)
            }
            natpmp::Failure::Socket(error) => {
                tracing::debug!(%error, "NAT-PMP socket error");
                MappingError::Transport {
                    protocol: MappingProtocol::NatPmp,
                    fault: MappingTransportFault::io(error),
                }
            }
            // RFC 6886 carries no hold-off estimate, so the mapper's own
            // backoff floor paces a refusal.
            other => MappingError::Refused {
                protocol: MappingProtocol::NatPmp,
                refusal: MappingRefusal::of_nat_pmp(other).unwrap_or(MappingRefusal::BadAnswer),
                hold_off: None,
            },
        }
    }

    fn transport_error(&self, fault: MappingTransportFault) -> MappingError {
        MappingError::Transport {
            protocol: self.protocol,
            fault,
        }
    }
}

/// The internal port a PCP probe names. Nothing is created — the probe is a
/// delete — so this only has to be a port rmule would never really map, so a
/// gateway that *does* hold a mapping for it loses nothing of ours.
const PCP_PROBE_PORT: u16 = 1;

/// The state-free probe: a delete of [`PCP_PROBE_PORT`], which creates
/// nothing whether or not the gateway speaks PCP.
const fn pcp_probe_request(gateway: Gateway) -> MappingRequest {
    MappingRequest {
        family: gateway.family(),
        transport: MappedTransport::Udp,
        internal_port: PCP_PROBE_PORT,
        suggested_external_port: PCP_PROBE_PORT,
        lease: Duration::ZERO,
    }
}

/// What a PCP gateway that answered can map: both families, since a PCP MAP on
/// IPv6 is a pinhole rather than a translation and the protocol covers both.
/// Only the family this gateway is reached in is claimed — a v4 next hop says
/// nothing about v6.
fn pcp_present(gateway: Gateway) -> ProbeReport {
    ProbeReport {
        external_address: None,
        families: vec![gateway.family()],
        epoch: EpochVerdict::Absent,
    }
}

/// `crab_nat`'s gateway shape, carrying the scope id a link-local v6 next hop
/// needs.
const fn gateway_address(gateway: Gateway) -> GatewayAddress {
    match gateway.address {
        IpAddr::V4(address) => GatewayAddress::IpV4(address),
        IpAddr::V6(address) => GatewayAddress::IpV6(address, gateway.scope_id),
    }
}

const fn protocol_of(transport: MappedTransport) -> InternetProtocol {
    match transport {
        MappedTransport::Tcp => InternetProtocol::Tcp,
        MappedTransport::Udp => InternetProtocol::Udp,
    }
}

/// The lifetime to ask for, in the seconds both wire formats carry. Saturating
/// rather than wrapping: a caller asking for more than a `u32` of seconds gets
/// the longest the protocol can state, not a tiny one.
fn lease_seconds(lease: Duration) -> u32 {
    u32::try_from(lease.as_secs()).unwrap_or(u32::MAX)
}

/// An address and a granted port as the endpoint they name together.
const fn join(address: IpAddr, port: u16) -> PeerEndpoint {
    match address {
        IpAddr::V4(ip) => PeerEndpoint::V4(Ipv4Endpoint::new(ip, port)),
        IpAddr::V6(ip) => PeerEndpoint::V6(Ipv6Endpoint::new(ip, port)),
    }
}

/// One `splitmix64` finalizer, narrowed — the nonce derivation's mixer. The
/// quality bar is diffusion, not secrecy: what makes the nonce a capability is
/// the caller's secret, not this function.
fn mix(value: u64) -> u32 {
    let mut z = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    // The shift leaves 32 significant bits, so the narrowing is exact.
    ((z ^ (z >> 31)) >> 32) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn request(port: u16, transport: MappedTransport) -> MappingRequest {
        MappingRequest {
            family: AddressFamily::V4,
            transport,
            internal_port: port,
            suggested_external_port: port,
            lease: Duration::from_secs(3600),
        }
    }

    /// A peer pin is PCP's alone: NAT-PMP has no opcode that names a remote
    /// peer, and it must say so *without touching the network* — a caller
    /// treats `Unsupported` as "the keepalive carries this path", and a
    /// timeout in its place would stall every punched path for the full
    /// retry ladder on a NAT-PMP router.
    #[tokio::test]
    async fn only_pcp_can_pin_a_punched_path_and_nat_pmp_says_so_at_once() {
        let gateway = Gateway {
            // TEST-NET-1: nothing answers, so a backend that did send would
            // sit out the whole ladder and fail the bound below.
            address: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            local_address: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
            scope_id: None,
        };
        let request = PeerPinRequest {
            internal_port: 4672,
            suggested_external_port: None,
            remote: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(45, 55, 200, 9), 31999),
            lease: Duration::from_secs(600),
        };
        let answer = tokio::time::timeout(
            Duration::from_millis(200),
            Arc::new(UdpMappingBackend::nat_pmp()).pin_peer(gateway, request),
        )
        .await
        .expect("no network round trip");
        assert_eq!(
            answer,
            Err(MappingError::Unsupported(MappingProtocol::NatPmp))
        );
    }

    #[test]
    fn the_pcp_nonce_is_stable_across_backends_and_distinct_per_mapping() {
        // RFC 6887 §11.3 makes the nonce a capability: a *different* nonce for
        // the same internal port earns NOT_AUTHORIZED against our own mapping
        // until it expires, and measured firmware answers with silence rather
        // than the refusal the RFC requires. So a restart must derive the same
        // nonce — that is the whole reason it is derived and not drawn.
        let first = UdpMappingBackend::pcp();
        let second = UdpMappingBackend::pcp();
        let tcp = request(4662, MappedTransport::Tcp);
        assert_eq!(first.nonce(tcp), second.nonce(tcp));

        // And two mappings must not share one, or deleting either would delete
        // both.
        assert_ne!(
            first.nonce(tcp),
            first.nonce(request(4672, MappedTransport::Udp))
        );
        assert_ne!(
            first.nonce(tcp),
            first.nonce(request(4662, MappedTransport::Udp)),
            "the transport is part of the mapping's identity"
        );
        // A per-install secret changes every nonce, which is what makes it a
        // capability a LAN neighbour cannot guess.
        assert_ne!(
            first.nonce(tcp),
            UdpMappingBackend::pcp().with_secret(7).nonce(tcp)
        );
    }

    /// The IPv6 path sends, byte for byte, what the `crab_nat` path sent to
    /// the bench's miniupnpd in the `portmap-ipv6-pinhole` PASS (run
    /// `1790023348`, `tap-lan.pcap`): same derived nonces, same delete shape.
    /// That identity is what lets a pinhole granted before this change be
    /// renewed and released after it without `NOT_AUTHORIZED` (§11.3).
    #[test]
    fn the_pinned_v6_path_reproduces_the_captured_pinhole_requests() {
        let host: std::net::Ipv6Addr = "3fff:ed2:2::4".parse().expect("literal");
        let gateway = Gateway {
            address: IpAddr::V6("3fff:ed2:2::2".parse().expect("literal")),
            local_address: IpAddr::V6(host),
            scope_id: None,
        };
        let backend = UdpMappingBackend::pcp();
        let wire = |request: MappingRequest| {
            let map = backend
                .pinned_request(gateway, request)
                .expect("v6 local address");
            map.encode()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let tcp = MappingRequest {
            family: AddressFamily::V6,
            lease: Duration::from_secs(12),
            ..request(4662, MappedTransport::Tcp)
        };
        // 22:42:41.352611 — the state-free probe.
        assert_eq!(
            wire(pcp_probe_request(gateway)),
            "02010000000000003fff0ed200020000000000000000000418c83c008fc4927eb4e997be110000000001000000000000000000000000000000000000"
        );
        // 22:42:41.353200 — the TCP 4662 pinhole.
        assert_eq!(
            wire(tcp),
            "020100000000000c3fff0ed20002000000000000000000042d8d6ac49374337eeacf2d72060000001236123600000000000000000000000000000000"
        );
        // 22:43:26.375392 — its release.
        assert_eq!(
            wire(MappingRequest {
                lease: Duration::ZERO,
                ..tcp
            }),
            "02010000000000003fff0ed20002000000000000000000042d8d6ac49374337eeacf2d72060000001236000000000000000000000000000000000000"
        );
    }

    #[test]
    fn a_refusal_carries_its_hold_off_raw_and_a_version_mismatch_is_unsupported() {
        // The hold-off is attacker-controlled input (RFC 6887 §7.4); clamping
        // it is the mapper's job, so this layer must not quietly shrink it and
        // hide what the gateway actually said.
        let backend = UdpMappingBackend::pcp();
        let refused = backend.pcp_error(&pcp::Failure::NoResources(u32::MAX));
        assert_eq!(
            refused.hold_off(),
            Some(Duration::from_secs(u64::from(u32::MAX)))
        );
        assert!(matches!(refused, MappingError::Refused { .. }));

        assert!(matches!(
            backend.pcp_error(&pcp::Failure::UnsupportedVersion(
                crab_nat::VersionCode::NatPmp
            )),
            MappingError::Unsupported(MappingProtocol::Pcp)
        ));
        assert!(matches!(
            backend.pcp_error(&pcp::Failure::Timeout),
            MappingError::Timeout(MappingProtocol::Pcp)
        ));
    }

    #[test]
    fn pointing_a_backend_at_a_second_gateway_re_anchors_its_epoch() {
        // Two routers' uptimes are not comparable: without the re-anchor, a
        // renumber onto a longer-running box would read as a reboot and re-add
        // every mapping for nothing.
        let backend = UdpMappingBackend::pcp();
        let first = Gateway::v4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 5));
        let second = Gateway::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(backend.observe_epoch(first, 90_000), EpochVerdict::Anchored);
        assert_eq!(
            backend.observe_epoch(first, 90_001),
            EpochVerdict::Consistent
        );
        assert_eq!(
            backend.observe_epoch(second, 12),
            EpochVerdict::Anchored,
            "a different gateway is a different counterparty"
        );
    }

    /// One dual-stack router, reached at its IPv4 next hop and its link-local
    /// IPv6 one. The PCP backend serves both, so a map or renew alternates
    /// between them; each family keeps its own epoch history, and a pinhole
    /// spoken from another Known IPv6 is still the same router.
    #[test]
    fn alternating_v4_and_v6_next_hops_keep_each_familys_epoch() {
        let backend = UdpMappingBackend::pcp();
        let v4 = Gateway::v4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 5));
        let v6 = |local: &str| Gateway {
            address: IpAddr::V6("fe80::1".parse().expect("literal")),
            scope_id: Some(2),
            local_address: IpAddr::V6(local.parse().expect("literal")),
        };
        assert_eq!(backend.observe_epoch(v4, 90_000), EpochVerdict::Anchored);
        assert_eq!(
            backend.observe_epoch(v6("2001:db8::5"), 90_000),
            EpochVerdict::Anchored
        );
        assert_eq!(
            backend.observe_epoch(v4, 90_001),
            EpochVerdict::Consistent,
            "the IPv6 exchange in between did not erase the IPv4 history"
        );
        assert_eq!(
            backend.observe_epoch(v6("2001:db8::7"), 90_001),
            EpochVerdict::Consistent,
            "a pinhole from another Known IPv6 is the same next hop"
        );
        // The router reboots: whichever family answers first reads it.
        assert_eq!(backend.observe_epoch(v4, 12), EpochVerdict::Reset);
    }

    /// NAT-PMP's MAP carries no address, so a map reads the one its probe
    /// learned; the first epoch reading after that probe must not wipe it.
    #[test]
    fn a_nat_pmp_probe_address_survives_the_first_map_epoch() {
        let backend = UdpMappingBackend::nat_pmp();
        let gateway = Gateway::v4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 5));
        let external = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        backend.remember_external(gateway, external);
        assert_eq!(backend.observe_epoch(gateway, 500), EpochVerdict::Anchored);
        assert_eq!(backend.external(gateway), Some(external));
    }

    #[test]
    fn an_absurd_requested_lease_saturates_rather_than_wrapping() {
        // A caller asking for more than the wire can state gets the longest it
        // can, not a tiny one — the clamp that matters is the *granted*
        // lifetime, and this must not undercut it.
        assert_eq!(lease_seconds(Duration::from_secs(3600)), 3600);
        assert_eq!(lease_seconds(Duration::from_secs(u64::MAX)), u32::MAX);
    }
}
