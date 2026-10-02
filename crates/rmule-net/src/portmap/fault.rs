//! Why a mapping failed, as codes: a gateway's refusal and a fault
//! below the protocol, each with its data and never a rendered sentence, so a
//! front end words them. What a library or the OS said beyond the code is
//! traced where it happened.

use std::fmt;
use std::io;

use crab_nat::{natpmp, pcp};

/// Why a gateway refused a mapping: PCP's (RFC 6887 §7.4) and NAT-PMP's
/// (RFC 6886 §3.5) result codes by what they mean, and UPnP's refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MappingRefusal {
    /// The gateway does not let this host map ports (`NOT_AUTHORIZED`).
    NotAuthorized,
    /// The gateway could not parse the request (`MALFORMED_REQUEST`,
    /// `MALFORMED_OPTION`).
    Malformed,
    /// The gateway does not do what was asked (`UNSUPP_OPCODE`,
    /// `UNSUPP_OPTION`, `UNSUPP_PROTOCOL`).
    Unsupported,
    /// The gateway has no working uplink right now (`NETWORK_FAILURE`).
    NetworkFailure,
    /// The gateway is out of mappings (`NO_RESOURCES`).
    NoResources,
    /// This host holds all the mappings the gateway allows it
    /// (`USER_EX_QUOTA`).
    QuotaExceeded,
    /// The external port asked for is taken (`CANNOT_PROVIDE_EXTERNAL`).
    CannotProvideExternal,
    /// The gateway sees this host at another address than the request names
    /// (`ADDRESS_MISMATCH`).
    AddressMismatch,
    /// The gateway limits remote peers (`EXCESSIVE_REMOTE_PEERS`).
    ExcessiveRemotePeers,
    /// A result code the protocol does not define, raw.
    UnknownCode(u16),
    /// The answer did not parse, or answered another request (a wrong nonce).
    BadAnswer,
    /// The UPnP device refused the action.
    DeviceRefused,
}

impl fmt::Display for MappingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAuthorized => f.write_str("not authorized"),
            Self::Malformed => f.write_str("malformed request"),
            Self::Unsupported => f.write_str("unsupported request"),
            Self::NetworkFailure => f.write_str("the gateway has no working uplink"),
            Self::NoResources => f.write_str("the gateway is out of mappings"),
            Self::QuotaExceeded => f.write_str("mapping quota exceeded"),
            Self::CannotProvideExternal => f.write_str("the external port is taken"),
            Self::AddressMismatch => f.write_str("the gateway sees another address"),
            Self::ExcessiveRemotePeers => f.write_str("too many remote peers"),
            Self::UnknownCode(code) => write!(f, "unknown result code {code}"),
            Self::BadAnswer => f.write_str("the answer did not parse or was for another request"),
            Self::DeviceRefused => f.write_str("the device refused the action"),
        }
    }
}

impl MappingRefusal {
    /// A PCP result code (RFC 6887 §7.4) other than success.
    #[must_use]
    pub const fn from_pcp_code(code: u8) -> Self {
        match code {
            2 => Self::NotAuthorized,
            3 | 6 => Self::Malformed,
            1 | 4 | 5 | 9 => Self::Unsupported,
            7 => Self::NetworkFailure,
            8 => Self::NoResources,
            10 => Self::QuotaExceeded,
            11 => Self::CannotProvideExternal,
            12 => Self::AddressMismatch,
            13 => Self::ExcessiveRemotePeers,
            other => Self::UnknownCode(other as u16),
        }
    }

    /// A refusal `crab_nat`'s PCP client reported; `None` for the failures
    /// that are not refusals (a timeout, a socket, an unsupported version).
    pub(super) const fn of_pcp(failure: &pcp::Failure) -> Option<Self> {
        Some(match failure {
            pcp::Failure::NotAuthorized(_) => Self::NotAuthorized,
            pcp::Failure::MalformedRequest | pcp::Failure::MalformedOption => Self::Malformed,
            pcp::Failure::UnsupportedOpcode
            | pcp::Failure::UnsupportedOption
            | pcp::Failure::UnsupportedProtocol => Self::Unsupported,
            pcp::Failure::NetworkFailure(_) => Self::NetworkFailure,
            pcp::Failure::NoResources(_) => Self::NoResources,
            pcp::Failure::UserExceededQuota(_) => Self::QuotaExceeded,
            pcp::Failure::CannotProvideExternal(_) => Self::CannotProvideExternal,
            pcp::Failure::AddressMismatch => Self::AddressMismatch,
            pcp::Failure::ExcessiveRemotePeers => Self::ExcessiveRemotePeers,
            pcp::Failure::Nonce | pcp::Failure::InvalidResponse(_) => Self::BadAnswer,
            pcp::Failure::Socket(_)
            | pcp::Failure::Timeout
            | pcp::Failure::UnsupportedVersion(_) => {
                return None;
            }
        })
    }

    /// A refusal `crab_nat`'s NAT-PMP client reported; `None` for the
    /// failures that are not refusals.
    pub(super) const fn of_nat_pmp(failure: &natpmp::Failure) -> Option<Self> {
        Some(match failure {
            natpmp::Failure::NotAuthorized => Self::NotAuthorized,
            natpmp::Failure::NetworkFailure => Self::NetworkFailure,
            natpmp::Failure::OutOfResources => Self::NoResources,
            natpmp::Failure::UnsupportedOpcode => Self::Unsupported,
            natpmp::Failure::InvalidResponse(_) => Self::BadAnswer,
            natpmp::Failure::Socket(_)
            | natpmp::Failure::Timeout
            | natpmp::Failure::UnsupportedVersion(_) => return None,
        })
    }
}

/// A fault below the protocol: the OS refused a socket operation, or the
/// request could not be put on the wire at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MappingTransportFault {
    /// The OS refused: its error kind, and its error number when it gave one.
    /// An ICMP port-unreachable on a connected socket surfaces here.
    Io {
        /// The kind of the OS error.
        kind: io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// The mapping names port 0, which asks for every port or names no socket.
    PortZero,
    /// A peer mapping needs this host's external address, and none is learned
    /// yet.
    NoExternalAddress,
    /// An IPv6 gateway was asked from a host with no IPv6 address to ask from.
    NoIpv6Local,
    /// The UPnP device could not be spoken to.
    Device,
}

impl fmt::Display for MappingTransportFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                kind,
                os_code: Some(code),
            } => write!(f, "{kind} (os error {code})"),
            Self::Io {
                kind,
                os_code: None,
            } => write!(f, "{kind}"),
            Self::PortZero => f.write_str("the mapping names port 0"),
            Self::NoExternalAddress => f.write_str("no external address is learned yet"),
            Self::NoIpv6Local => f.write_str("no IPv6 address to ask from"),
            Self::Device => f.write_str("the device could not be spoken to"),
        }
    }
}

impl MappingTransportFault {
    /// The code for an OS error.
    #[must_use]
    pub fn io(error: &io::Error) -> Self {
        Self::Io {
            kind: error.kind(),
            os_code: error.raw_os_error(),
        }
    }
}
