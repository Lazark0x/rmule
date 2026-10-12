//! Reachability's words: how a peer is reached (ADR-0061's routes, ADR-0091's
//! NAT traversal), a secured identity that did not match, and the sockets
//! that did not come up whole (ADR-0057, ADR-0085).

use rmule_core::{
    Consequence, HalfBound, NatTraversalUnavailableReason, ObfuscationPolicy, PairRole,
    PeerReachDropReason, PeerReachRoute, PeerStreamRole, TunnelTransport,
};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint, UserHash};

use super::Sentence;
use super::os::kind_words;
use super::units::{address, short_hex};

/// An address family by its name.
#[must_use]
pub const fn family_words(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::V4 => "IPv4",
        AddressFamily::V6 => "IPv6",
    }
}

/// A Kad endpoint as `host:port`.
fn kad_address(endpoint: Ipv4Endpoint) -> String {
    address(PeerEndpoint::from(endpoint))
}

/// How the route chosen for a peer reaches it, in words rather than the raw
/// `PeerReachRoute`.
#[must_use]
pub fn route(peer: PeerEndpoint, route: &PeerReachRoute) -> Sentence {
    let peer = address(peer);
    let how = match route {
        PeerReachRoute::Direct { endpoint } => match endpoint {
            PeerEndpoint::V4(_) => format!("dialing it directly at {}", address(*endpoint)),
            PeerEndpoint::V6(_) => {
                format!("dialing it directly over IPv6 at {}", address(*endpoint))
            }
        },
        PeerReachRoute::DirectUdp { target_kad_udp } => format!(
            "asked it over UDP at {} to call back",
            kad_address(*target_kad_udp)
        ),
        PeerReachRoute::DirectUdpUnavailable { .. } => {
            "it could be asked over UDP to call back, but no UDP socket is up".to_string()
        }
        PeerReachRoute::Server { .. } => "asking our server to have it call back".to_string(),
        PeerReachRoute::Buddy {
            buddy_id,
            emitted_to: Some(buddy),
        } => format!(
            "asked its Kad buddy {} at {} to have it call back",
            short_hex(buddy_id.as_bytes()),
            kad_address(*buddy)
        ),
        PeerReachRoute::Buddy {
            buddy_id,
            emitted_to: None,
        } => format!(
            "reached through its Kad buddy {}, but nothing could be sent to it yet",
            short_hex(buddy_id.as_bytes())
        ),
        PeerReachRoute::CallbackWalk { buddy_id } => format!(
            "searching Kad for its buddy {} to have it call back",
            short_hex(buddy_id.as_bytes())
        ),
        PeerReachRoute::NatTraversal {
            buddy_id,
            buddy_udp,
        } => format!(
            "NAT traversal through its Kad buddy {} at {}",
            short_hex(buddy_id.as_bytes()),
            kad_address(*buddy_udp)
        ),
        PeerReachRoute::ServerPunch { .. } => {
            "asking our server to introduce us for NAT traversal".to_string()
        }
        PeerReachRoute::ServerPunchUnavailable { .. } => {
            "NAT traversal through our server was chosen, but NAT traversal is not running: it needs the client UDP port open"
                .to_string()
        }
        PeerReachRoute::NatTraversalUnavailable { reason, .. } => format!(
            "NAT traversal not attempted: {}",
            match reason {
                NatTraversalUnavailableReason::BuddyEndpointUnknown => {
                    "its buddy's address must be found on Kad first"
                }
                NatTraversalUnavailableReason::NotEnactable => {
                    "no UDP socket, no user hash yet, or no NAT traversal running"
                }
                NatTraversalUnavailableReason::TargetIdentityUnknown => {
                    "its user hash is not known"
                }
            }
        ),
        PeerReachRoute::Dropped { reason } => format!(
            "unreachable: {}",
            match reason {
                PeerReachDropReason::LowToLow => {
                    "both sides are LowID, with no shared server and no NAT traversal"
                }
                PeerReachDropReason::NoBuddy => "Kad is off, or it published no buddy",
                PeerReachDropReason::NoKadUdpEndpoint => {
                    "its UDP callback was chosen without a Kad address to send to"
                }
                PeerReachDropReason::NoCoordinator => {
                    "no live server session and no Kad buddy to introduce us for NAT traversal"
                }
            }
        ),
    };
    Sentence::owned(format!("peer {peer}: {how}"))
}

/// A NAT-T tunnel rose over a punched path (ADR-0091).
#[must_use]
pub fn tunnel_risen(
    peer: PeerEndpoint,
    transport: TunnelTransport,
    role: PeerStreamRole,
) -> Sentence {
    let transport = match transport {
        TunnelTransport::Utp => "uTP",
        TunnelTransport::Quic => "QUIC",
    };
    let role = match role {
        PeerStreamRole::Dialer => "we dialed",
        PeerStreamRole::Responder => "it dialed",
    };
    Sentence::owned(format!(
        "NAT traversal worked: a {transport} tunnel to {} is up ({role})",
        address(peer)
    ))
}

/// A peer proved a different key than the one stored for its user hash.
#[must_use]
pub fn identity_mismatch(user_hash: UserHash) -> Sentence {
    Sentence::owned(format!(
        "peer {} proved a different key than the one on record; its claim is denied",
        short_hex(user_hash.as_bytes())
    ))
}

/// The status bar's shorter note for [`identity_mismatch`].
pub const IDENTITY_MISMATCH_NOTE: Sentence =
    Sentence::fixed("a peer's secured identity did not match; its claim is denied");

/// Our obfuscation setting, by what it does.
const fn obfuscation_words(policy: Option<ObfuscationPolicy>) -> &'static str {
    match policy {
        None => "off",
        Some(ObfuscationPolicy::Supported) => "supported (accepted, never started)",
        Some(ObfuscationPolicy::Requested) => "requested (started where the other side takes it)",
        Some(ObfuscationPolicy::Required) => "required (plain links refused)",
    }
}

/// The obfuscation setting this run starts under (ADR-0046).
#[must_use]
pub fn obfuscation_at_start(policy: Option<ObfuscationPolicy>) -> Sentence {
    Sentence::owned(format!("obfuscation {}", obfuscation_words(policy)))
}

/// The obfuscation setting, changed while running (ADR-0046).
#[must_use]
pub fn obfuscation_changed(policy: Option<ObfuscationPolicy>) -> Sentence {
    Sentence::owned(format!(
        "obfuscation now {}; links already up keep theirs",
        obfuscation_words(policy)
    ))
}

/// The client UDP socket never bound at start (ADR-0057).
#[must_use]
pub fn client_udp_bind_failed(port: u16, kind: std::io::ErrorKind) -> Sentence {
    Sentence::owned(format!(
        "UDP port {port} could not be bound ({}) — Kad, reask and NAT traversal are off until restart",
        kind_words(kind)
    ))
}

/// A socket role by what it is.
const fn role_words(role: PairRole) -> &'static str {
    match role {
        PairRole::ClientUdp => "the client UDP socket",
        PairRole::Ed2kListener => "the eD2k listener",
        PairRole::ServerUdp => "the server UDP socket",
    }
}

/// What rides a family a socket came up without.
const fn consequence_words(consequence: Consequence) -> &'static str {
    match consequence {
        Consequence::Kad => "Kad",
        Consequence::NatTraversal => "NAT traversal",
        Consequence::Ipv4UdpAdvert => "the IPv4 UDP advert",
        Consequence::Ipv6Reask => "IPv6 reasks",
        Consequence::Ipv4Dials => "IPv4 dials",
        Consequence::HighId => "any HighID",
        Consequence::Ipv6Dials => "IPv6 dials",
        Consequence::Ipv6Advert => "the IPv6 advert",
        Consequence::ServerUdpSweep => "the UDP server sweep",
    }
}

/// A socket came up without one of its families, and what that
/// costs until restart.
#[must_use]
pub fn half_bound(half: &HalfBound) -> Sentence {
    let forfeits: Vec<&str> = half
        .forfeits()
        .iter()
        .map(|consequence| consequence_words(*consequence))
        .collect();
    let cost = match forfeits.split_last() {
        None => "nothing rides that family".to_string(),
        Some((last, [])) => format!("{last} is off until restart"),
        Some((last, rest)) => format!("{} and {last} are off until restart", rest.join(", ")),
    };
    Sentence::owned(format!(
        "{} came up without {} ({}): {cost}",
        role_words(half.role),
        family_words(half.missing),
        kind_words(half.kind)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::Ipv6Endpoint;

    #[test]
    fn a_direct_route_names_the_address_it_dials_in_either_family() {
        let v4 = PeerEndpoint::V4(Ipv4Endpoint::new("203.0.113.4".parse().unwrap(), 4662));
        let v6 = PeerEndpoint::V6(Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662));
        assert_eq!(
            *route(v4, &PeerReachRoute::Direct { endpoint: v4 }),
            *"peer 203.0.113.4:4662: dialing it directly at 203.0.113.4:4662"
        );
        assert_eq!(
            *route(v4, &PeerReachRoute::Direct { endpoint: v6 }),
            *"peer 203.0.113.4:4662: dialing it directly over IPv6 at [2a01:4f8::7]:4662"
        );
    }
}
