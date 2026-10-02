//! Port mapping's words (ADR-0086): which protocol, and why a gateway did
//! not map a port — from the codes core carries, never a library's sentence.

use rmule_core::port_mapping::{
    MappingError, MappingProtocol, MappingRefusal, MappingTransportFault,
};

use super::os::refusal_words;

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
