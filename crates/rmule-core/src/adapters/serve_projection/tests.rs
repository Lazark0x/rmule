//! Projection tests: the reask contact a serve command threads to the peer,
//! and the Server Capability split between a connection's two halves.

use std::net::Ipv4Addr;

use rmule_peer::{PeerCloseReason, PeerEvent, PeerIdentity};
use rmule_primitives::{ClientId, FileHash, Ipv4Endpoint, UserHash};

use crate::adapters::serve_runtime::ServeConnEvent;

use super::*;

/// The serve projection threads the peer's advertised **client-UDP reask
/// contact** (ADR-0057): a peer identified from a hello carrying
/// `CT_EMULE_UDPPORTS` (client half) + a `MiscOptions1` UDP version surfaces
/// that port and version on its `Identified` serve event, so a later queued
/// waiter's inbound `OP_REASKFILEPING` matches by IP + port (and its
/// `OP_REASKACK` carries our part status for a UDPv4 waiter). A hello with no
/// client-UDP port surfaces `(0, 0)` — the source is TCP-reask-only.
#[test]
fn the_serve_projection_threads_the_peers_reask_contact_and_extended_requests_claim() {
    use rmule_peer::{MiscOptions1, PeerHelloBody};
    use rmule_primitives::{Tag, TagName, TagValue};

    let identify = |tags: Vec<Tag>| {
        serve_event_from_peer(PeerEvent::PeerIdentified {
            identity: PeerIdentity::from_hello_body(&PeerHelloBody {
                user_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
                client_id: ClientId::from_u32(0),
                tcp_port: 4662,
                tags,
                connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
            }),
        })
    };

    // CT_EMULE_UDPPORTS client half 6000 (low 16), Kad half 4672 (high 16);
    // MiscOptions1 UDP version 4, extended-requests version 2 (bits [8..12)).
    let advertised = identify(vec![
        Tag::new(
            TagName::compact_id(0xF9),
            TagValue::U32((4672u32 << 16) | 6000),
        ),
        MiscOptions1::from_bits(2 << 8).with_udp_version(4).to_tag(),
    ]);
    match advertised {
        Some(ServeConnEvent::Identified {
            udp_port,
            udp_version,
            extended_requests_version,
            ..
        }) => assert_eq!(
            (udp_port, udp_version, extended_requests_version),
            (6000, 4, 2)
        ),
        other => panic!("expected an Identified serve event, got {other:?}"),
    }

    // No client-UDP advertisement ⇒ (0, 0): the waiter is TCP-reask-only.
    match identify(Vec::new()) {
        Some(ServeConnEvent::Identified {
            udp_port,
            udp_version,
            extended_requests_version,
            ..
        }) => assert_eq!(
            (udp_port, udp_version, extended_requests_version),
            (0, 0, 0)
        ),
        other => panic!("expected an Identified serve event, got {other:?}"),
    }
}

/// `Disconnected` is the one event **both** halves of a dialed connection must
/// see — the serve half frees its slot and its served ranges, the download half
/// retires its worker — so `route_dialed_connection` fans it to both and this
/// predicate must not claim it for the serve half. A Requester Capability event
/// is claimed by neither.
#[test]
fn a_disconnect_is_neutral_so_the_router_can_fan_it_to_both_halves() {
    assert!(!is_server_capability_event(&PeerEvent::Disconnected {
        reason: PeerCloseReason::PeerClosed
    }));
    assert!(!is_server_capability_event(&PeerEvent::SlotGranted {
        file_hash: FileHash::from_bytes([0x01; FileHash::BYTE_LEN])
    }));
}
