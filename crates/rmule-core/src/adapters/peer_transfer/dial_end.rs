//! Why a download dial ended before the peer's hello, read off what ended it:
//! the outbound crypt rule's refusal, the connect's error, or the session's
//! close before the peer identified.

use rmule_net::driver::DriverError;
use rmule_net::peer::PeerNetError;
use rmule_peer::PeerCloseReason;
use rmule_primitives::{CryptStance, PeerCrypt};

use crate::service::DialEnd;

/// Which side of aMule's outbound rule (`PeerCrypt::outbound`, ADR-0049)
/// refused a dial before any socket, given the peer's crypt side and `ours`.
pub(super) fn crypt_refusal(peer: PeerCrypt, ours: CryptStance) -> DialEnd {
    let theirs = peer.stance();
    if theirs.requires() && !ours.supports() {
        DialEnd::CryptRequiredByPeer
    } else if ours.requires() && peer.stated_stance().is_none() {
        DialEnd::CryptStanceUnknown
    } else if ours.requires() && !theirs.supports() {
        DialEnd::CryptUnsupported
    } else {
        DialEnd::CryptKeyUnknown
    }
}

/// Why `connect` failed, for every error but the crypt refusal.
pub(super) fn connect_failure(error: &PeerNetError) -> DialEnd {
    match error {
        PeerNetError::Connect { source } => io_kind(source.kind()),
        PeerNetError::Driver(DriverError::ConnectTimeout) => DialEnd::TimedOut,
        PeerNetError::Driver(DriverError::Io(source)) => io_kind(source.kind()),
        PeerNetError::HandshakeIncomplete(reason) => closed_before_hello(*reason),
        PeerNetError::CryptIncompatible => DialEnd::CryptKeyUnknown,
        // `PeerNetError` is non-exhaustive, and the rest end a dial only as
        // a link gone before the hello.
        _ => DialEnd::ClosedBeforeHello,
    }
}

/// Why the session closed before the peer's hello.
pub(in crate::adapters) fn closed_before_hello(reason: PeerCloseReason) -> DialEnd {
    match reason {
        PeerCloseReason::Local => DialEnd::ClosedLocally,
        PeerCloseReason::ProtocolViolation => DialEnd::ProtocolViolation,
        PeerCloseReason::Io(kind) => io_kind(kind),
        PeerCloseReason::ConnectTimeout => DialEnd::TimedOut,
        PeerCloseReason::HelloTimeout => DialEnd::NoHelloInTime,
        // `PeerCloseReason` is non-exhaustive; a close it gains is still a
        // close by the peer's side of the link until it is named.
        _ => DialEnd::ClosedBeforeHello,
    }
}

fn io_kind(kind: std::io::ErrorKind) -> DialEnd {
    match kind {
        std::io::ErrorKind::ConnectionRefused => DialEnd::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
            DialEnd::Reset
        }
        std::io::ErrorKind::TimedOut => DialEnd::TimedOut,
        std::io::ErrorKind::UnexpectedEof => DialEnd::ClosedBeforeHello,
        kind => DialEnd::Os { kind },
    }
}

#[cfg(test)]
mod tests {
    use rmule_primitives::{OutboundCrypt, UserHash};

    use super::*;

    /// Every refusal the outbound rule makes is named for the side that
    /// made it, and the rule refuses exactly the pairs named.
    #[test]
    fn a_crypt_refusal_names_the_side_that_cannot_meet() {
        let required = CryptStance::new(true, true, true);
        let off = CryptStance::disabled();
        let hash = Some(UserHash::from_bytes([
            0x3C, 0x91, 0x07, 0xE2, 0x5A, 0x14, 0xB8, 0x66, 0x0D, 0xF3, 0x2A, 0x79, 0xC4, 0x18,
            0x5E, 0xA7,
        ]));
        let cases = [
            (PeerCrypt::unknown(), required, DialEnd::CryptStanceUnknown),
            (
                PeerCrypt::new(off, hash),
                required,
                DialEnd::CryptUnsupported,
            ),
            (
                PeerCrypt::new(required, hash),
                off,
                DialEnd::CryptRequiredByPeer,
            ),
            (
                PeerCrypt::new(required, None),
                required,
                DialEnd::CryptKeyUnknown,
            ),
        ];
        for (peer, ours, cause) in cases {
            assert_eq!(peer.outbound(ours), OutboundCrypt::Incompatible);
            assert_eq!(crypt_refusal(peer, ours), cause);
        }
    }
}
