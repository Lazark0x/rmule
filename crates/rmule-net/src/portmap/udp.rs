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
//! - **IPv6 source-address pinning** ([`pcp_map`](super::pcp_map)). `crab_nat`
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

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crab_nat::{
    GatewayAddress, InternetProtocol, PortMappingOptions, PortMappingType, TimeoutConfig, natpmp,
    pcp,
};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint};

use super::epoch::{EpochTracker, EpochVerdict};
use super::{
    Gateway, MappedTransport, MappingBackend, MappingError, MappingFuture, MappingGrant,
    MappingProtocol, MappingRefusal, MappingRequest, MappingTransportFault, PeerPinRequest,
    ProbeReport,
};

mod pinned;

/// The retransmit ladder both UDP backends run — through `crab_nat`, and
/// through rmule's own pinned IPv6 PCP exchange
/// ([`pcp_map::exchange`](super::pcp_map::exchange)), so a retune reaches
/// every PCP and NAT-PMP request alike.
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

/// The mixing constant the derived nonce is salted with: a fixed domain
/// separator that keeps rmule's derivation apart from any other client's over
/// the same inputs. It is the same in every install, so it is not what tells
/// two rmule clients on one LAN apart — the per-install `secret` both apps
/// persist is.
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
        if mapping.lifetime() == 0 && !request.lease.is_zero() {
            return Err(empty_grant(self.protocol));
        }
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
        if mapping.lifetime_seconds() == 0 {
            return Err(empty_grant(MappingProtocol::Pcp));
        }
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
/// A success to a create that granted nothing (RFC 6887 §15, RFC 6886
/// §3.4: lifetime 0 is a delete, and port 0 is no port). The answer
/// does not parse as a grant, whatever its result code says.
const fn empty_grant(protocol: MappingProtocol) -> MappingError {
    MappingError::Refused {
        protocol,
        refusal: MappingRefusal::BadAnswer,
        hold_off: None,
    }
}

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
mod tests;
