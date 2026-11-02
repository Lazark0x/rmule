//! The pinned IPv6 PCP path of the UDP backend (ADR-0086): the `MAP` built
//! from the gateway's local address under the derived nonce, and one exchange
//! of it through [`pcp_map`] read back into the backend's own vocabulary.

use std::net::{IpAddr, SocketAddrV6};
use std::time::Duration;

use super::super::pcp_map::{self, MapReply, MapRequest};
use super::super::{
    Gateway, MappedTransport, MappingError, MappingGrant, MappingProtocol, MappingRefusal,
    MappingRequest, MappingTransportFault,
};
use super::{LADDER, UdpMappingBackend, empty_grant, join, lease_seconds};

impl UdpMappingBackend {
    /// The `MAP` this backend sends over IPv6 for `request`: from the
    /// gateway's local address, under the derived nonce — the same nonce the
    /// `crab_nat` path uses, so a mapping made before a restart is still ours.
    pub(super) fn pinned_request(
        &self,
        gateway: Gateway,
        request: MappingRequest,
    ) -> Option<MapRequest> {
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
    pub(super) async fn pinned_exchange(
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
            MapReply::Empty => Err(empty_grant(MappingProtocol::Pcp)),
            MapReply::UnsupportedVersion(_) | MapReply::Foreign => {
                Err(MappingError::Unsupported(MappingProtocol::Pcp))
            }
        }
    }
}
