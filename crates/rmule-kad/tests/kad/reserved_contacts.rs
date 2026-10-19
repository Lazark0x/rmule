//! The Reserved Range check at the Kad contact intakes (ADR-0085). aMule runs
//! `IsGoodIPPort` before its IP filter at `CRoutingZone::Add`
//! (`RoutingZone.cpp:405-406`) and on every `KADEMLIA2_RES` row
//! (`KademliaUDPListener.cpp:732-733`): a contact naming a Reserved Range its
//! informant — the party whose datagram named it — cannot vouch for, port 0,
//! or port 53 on a contact older than Kad version 6 is never stored, probed or
//! walked. A LAN contact is a contact, where aMule's LAN filter drops it.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, KadCommand, KadContact, KadEvent, KadId, KadNode, KadNodeDiagnostic,
    KadNodeEndpoint, KadSourceLookupRequest,
};
use rmule_primitives::{FileHash, SourceLookupTarget};
use rmule_testkit::drain_split;
use rmule_testkit::kad_node::{T0, deliver, endpoint, id, info, node};

fn at(octets: [u8; 4], port: u16) -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::from(octets), port)
}

fn refused(events: &[KadEvent]) -> Vec<KadNodeEndpoint> {
    events
        .iter()
        .filter_map(|event| match event {
            KadEvent::Diagnostic(KadNodeDiagnostic::ContactRefused { endpoint }) => Some(*endpoint),
            _ => None,
        })
        .collect()
}

/// Rows a remote party names that no Kad node can be at: multicast, "this
/// network", loopback, broadcast, a zero port, and port 53 on a version-5
/// contact. Their IDs run from `0x10`.
fn unaddressable_rows() -> Vec<KadContact> {
    [
        (at([224, 0, 0, 1], 4672), 8),
        (at([0, 0, 0, 5], 4672), 8),
        (at([127, 0, 0, 1], 4672), 8),
        (at([255, 255, 255, 255], 4672), 8),
        (endpoint(30, 0), 8),
        (endpoint(31, 53), 5),
    ]
    .into_iter()
    .zip(0x10..)
    .map(|((endpoint, version), id_byte)| KadContact::new(id(id_byte), endpoint, 4662, version))
    .collect()
}

/// A node that asked `responder` to bootstrap it, so its answer is solicited.
fn bootstrapping(responder: KadNodeEndpoint) -> KadNode {
    let mut node = node();
    node.handle_command(
        T0,
        KadCommand::Bootstrap {
            endpoint: responder,
        },
    );
    let _ = drain_split(&mut node);
    node
}

/// A remote responder's hearsay rows are seated only where some Kad node can
/// be: the unaddressable rows are neither stored nor probed, while a LAN row
/// and a port-53 row of version 6 are both.
#[test]
fn a_bootstrap_answer_never_seats_a_contact_no_node_can_be_at() {
    let responder = endpoint(9, 4702);
    let mut node = bootstrapping(responder);
    let lan = KadContact::new(id(0x20), at([192, 168, 1, 5], 4672), 4662, 8);
    let dns_port_v6 = KadContact::new(id(0x21), endpoint(32, 53), 4662, 6);
    let unaddressable = unaddressable_rows();

    deliver(
        &mut node,
        T0,
        responder,
        &Kad2Message::BootstrapRes {
            sender: info(0x90, None),
            contacts: unaddressable
                .iter()
                .copied()
                .chain([lan, dns_port_v6])
                .collect(),
        },
    );
    let (datagrams, events) = drain_split(&mut node);

    for row in &unaddressable {
        assert!(node.routing_table().get(row.id()).is_none(), "{row:?}");
    }
    assert!(
        node.routing_table().get(id(0x20)).is_some(),
        "a LAN contact"
    );
    assert!(
        node.routing_table().get(id(0x21)).is_some(),
        "an encrypting DNS-port contact"
    );
    assert_eq!(
        refused(&events),
        unaddressable
            .iter()
            .map(|row| row.endpoint())
            .collect::<Vec<_>>()
    );
    let probed: Vec<_> = datagrams.iter().map(|(to, _)| *to).collect();
    for row in &unaddressable {
        assert!(
            !probed.contains(&row.endpoint()),
            "{row:?} probed: {probed:?}"
        );
    }
    assert!(
        probed.contains(&lan.endpoint()),
        "the LAN row is probed: {probed:?}"
    );
}

/// A loopback row names the host that reads it: it stands from a responder on
/// this host, as a single-host rig answers.
#[test]
fn loopback_hearsay_stands_from_a_responder_on_this_host() {
    let responder = at([127, 0, 0, 1], 4702);
    let mut node = bootstrapping(responder);
    let neighbour = KadContact::new(id(0x30), at([127, 0, 0, 2], 4672), 4662, 8);

    deliver(
        &mut node,
        T0,
        responder,
        &Kad2Message::BootstrapRes {
            sender: info(0x90, None),
            contacts: vec![neighbour],
        },
    );
    let (_, events) = drain_split(&mut node);

    assert!(node.routing_table().get(id(0x30)).is_some());
    assert_eq!(refused(&events), vec![]);
}

/// A `KADEMLIA2_RES` row no node can be at never takes a walk slot, even one
/// strictly closer than the addressable alternative.
#[test]
fn a_lookup_answer_row_no_node_can_be_at_is_never_walked() {
    let target = KadId::from_bytes([
        0xB5, 0x2D, 0x30, 0x8E, 0x5C, 0xA2, 0x06, 0xB8, 0x23, 0xFC, 0x85, 0x93, 0xD2, 0x62, 0x10,
        0xF2,
    ]);
    let file_hash = FileHash::from_bytes([
        0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62,
        0xD2,
    ]);
    // An ID at XOR distance `d` from the target (byte 12 is the least
    // significant byte of its least significant word).
    let id_near = |d: u8| {
        let mut bytes = *target.as_bytes();
        bytes[12] ^= d;
        KadId::from_bytes(bytes)
    };
    let mut node = node();
    let seed = endpoint(100, 4100);
    let mut seed_info = info(0, Some(seed.udp_port()));
    seed_info.id = id_near(100);
    deliver(&mut node, T0, seed, &Kad2Message::HelloReq(seed_info));
    let _ = drain_split(&mut node);
    node.handle_command(
        T0,
        KadCommand::SearchSources {
            request: KadSourceLookupRequest::new(SourceLookupTarget::new(file_hash, 65_536)),
        },
    );
    let _ = drain_split(&mut node);

    let unaddressable: Vec<KadContact> = unaddressable_rows()
        .into_iter()
        .zip(1..)
        .map(|(row, d)| KadContact::new(id_near(d), row.endpoint(), 4662, row.version()))
        .collect();
    let addressable = KadContact::new(id_near(40), endpoint(2, 4672), 4662, 8);
    deliver(
        &mut node,
        T0,
        seed,
        &Kad2Message::LookupRes {
            target,
            contacts: unaddressable.iter().copied().chain([addressable]).collect(),
        },
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(
        refused(&events),
        unaddressable
            .iter()
            .map(|row| row.endpoint())
            .collect::<Vec<_>>()
    );
    let queried: Vec<_> = datagrams.iter().map(|(to, _)| *to).collect();
    for row in &unaddressable {
        assert!(
            !queried.contains(&row.endpoint()),
            "{row:?} queried: {queried:?}"
        );
    }
    assert!(
        queried.contains(&addressable.endpoint()),
        "the addressable row takes a freed slot: {queried:?}"
    );
}
