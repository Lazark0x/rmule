//! Port mapping's words (ADR-0086): which protocol, why a gateway did not
//! map a port, and why a release left one standing — from the codes core
//! carries, never a library's sentence.

use rmule_core::SocketRole;
use rmule_core::port_mapping::{
    DesiredMapping, MappingError, MappingProtocol, MappingRefusal, MappingTransportFault,
    ReleaseKept,
};

use super::Sentence;
use super::os::refusal_words;
use super::units::address;

/// A mapping protocol by its name.
#[must_use]
pub const fn protocol_words(protocol: MappingProtocol) -> &'static str {
    match protocol {
        MappingProtocol::Pcp => "PCP",
        MappingProtocol::NatPmp => "NAT-PMP",
        MappingProtocol::Upnp => "UPnP",
    }
}

/// Why a mapping failed: "UPnP: the router refused".
#[must_use]
pub fn mapping_error_words(error: &MappingError) -> String {
    let protocol = protocol_words(error.protocol());
    match error {
        MappingError::Unsupported(_) => format!("the router does not speak {protocol}"),
        MappingError::Timeout(_) => format!("{protocol}: the router did not answer"),
        MappingError::Refused { refusal, .. } => {
            format!(
                "{protocol}: the router refused — {}",
                refusal_words_of(*refusal)
            )
        }
        MappingError::Transport { fault, .. } => {
            format!("{protocol}: {}", transport_words(*fault))
        }
    }
}

/// A release that sent no delete, as a Networks log line (ADR-0086, "A
/// release takes down only rmule's own mapping"): the router's port was
/// another host's, gone, or not vouched for, so rmule left it alone.
#[must_use]
pub fn release_kept(
    mapping: &DesiredMapping,
    protocol: MappingProtocol,
    external_port: u16,
    kept: &ReleaseKept,
) -> Sentence {
    let protocol = protocol_words(protocol);
    let transport = match mapping.role {
        SocketRole::Tcp => "TCP",
        SocketRole::Udp => "UDP",
    };
    let outside = format!("{protocol}: outside {transport} port {external_port}");
    Sentence::owned(match kept {
        ReleaseKept::Absent => format!("{outside} was already gone from the router"),
        ReleaseKept::ForwardsElsewhere(holder) => format!(
            "{outside} left alone — the router forwards it to {}, not to {transport} {} here",
            address(*holder),
            mapping.internal_port
        ),
        ReleaseKept::Unchecked(error) => format!(
            "{outside} left to expire — the router did not say where it forwards ({})",
            unanswered_words(error)
        ),
    })
}

/// Why a router's answer settled nothing, as a clause about the router.
fn unanswered_words(error: &MappingError) -> String {
    match error {
        MappingError::Unsupported(protocol) => {
            format!("it does not speak {}", protocol_words(*protocol))
        }
        MappingError::Timeout(_) => "it did not answer".to_string(),
        MappingError::Refused { refusal, .. } => {
            format!("it refused — {}", refusal_words_of(*refusal))
        }
        MappingError::Transport { fault, .. } => transport_words(*fault),
    }
}

/// Why a router refused, as a clause.
fn refusal_words_of(refusal: MappingRefusal) -> String {
    let text = match refusal {
        MappingRefusal::NotAuthorized => "it does not let this machine map ports",
        MappingRefusal::Malformed => "it could not read the request",
        MappingRefusal::Unsupported => "it does not do what was asked",
        MappingRefusal::NetworkFailure => "its uplink is down",
        MappingRefusal::NoResources => "it has no mappings left",
        MappingRefusal::QuotaExceeded => "this machine holds all the mappings it allows",
        MappingRefusal::CannotProvideExternal => "the outside port is taken",
        MappingRefusal::AddressMismatch => "it sees this machine at another address",
        MappingRefusal::ExcessiveRemotePeers => "it limits remote peers",
        MappingRefusal::BadAnswer => "its answer could not be read",
        MappingRefusal::DeviceRefused => "it declined (see the run log)",
        MappingRefusal::UnknownCode(code) => return format!("result code {code}"),
    };
    text.to_string()
}

/// What failed below the protocol, as a clause.
fn transport_words(fault: MappingTransportFault) -> String {
    match fault {
        MappingTransportFault::Io { kind, os_code } => refusal_words(kind, os_code),
        MappingTransportFault::PortZero => "no port to map".to_string(),
        MappingTransportFault::NoExternalAddress => {
            "this machine's outside address is not known yet".to_string()
        }
        MappingTransportFault::NoIpv6Local => {
            "the router speaks IPv6 and this machine has no IPv6 address".to_string()
        }
        MappingTransportFault::Device => {
            "the router could not be reached (see the run log)".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint};

    #[test]
    fn a_kept_release_says_whose_the_port_is_or_why_nobody_said() {
        let listener = DesiredMapping {
            role: SocketRole::Tcp,
            family: AddressFamily::V4,
            internal_port: 4662,
            pinhole: None,
        };
        let neighbour = PeerEndpoint::V4(Ipv4Endpoint::new("10.77.0.5".parse().unwrap(), 4662));
        let kept = |port, why| release_kept(&listener, MappingProtocol::Upnp, port, &why);
        assert_eq!(
            *kept(4662, ReleaseKept::ForwardsElsewhere(neighbour)),
            *"UPnP: outside TCP port 4662 left alone — the router forwards it to 10.77.0.5:4662, not to TCP 4662 here"
        );
        assert_eq!(
            *kept(4662, ReleaseKept::Absent),
            *"UPnP: outside TCP port 4662 was already gone from the router"
        );
        assert_eq!(
            *kept(
                53906,
                ReleaseKept::Unchecked(MappingError::Timeout(MappingProtocol::Upnp))
            ),
            *"UPnP: outside TCP port 53906 left to expire — the router did not say where it forwards (it did not answer)"
        );
    }
}
