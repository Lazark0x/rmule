//! Kad contact admission against the IP filter: aMule consults
//! `theApp->ipfilter` at every Kad contact intake — routing admission
//! (`CRoutingZone::Add`, `RoutingZone.cpp#L406`), the nodes.dat load
//! (`#L195`), the bootstrap-file dial selection (`#L252`), and
//! lookup-response rows before the search manager sees them
//! (`KademliaUDPListener.cpp#L733`). rmule funnels those intakes through the
//! armed [`KadContactAdmission`] predicate; these tests drive each intake with
//! a filtered and an admitted endpoint and assert the filtered one is never
//! stored, probed, walked, or dialed — and that the aMule-faithful *answering*
//! behavior (a hello from a filtered IP still gets its `HELLO_RES`) is
//! preserved, since aMule has no IP-filter gate at datagram entry.

use rmule_kad::KadInstant;
use rmule_kad::KadNodeStart;

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadBootstrapNode, KadCommand, KadContact, KadContactAdmission,
    KadEvent, KadId, KadNode, KadNodeConfig, KadNodeDiagnostic, KadNodeEndpoint,
    KadSourceLookupRequest,
};
use rmule_primitives::{FileHash, SourceLookupTarget};
use rmule_testkit::drain_split;
use rmule_testkit::kad_node::{T0, deliver, endpoint, host_ip, id};

/// The blocked host octet: the admission closure refuses exactly this IP.
const FILTERED_HOST: u8 = 66;

/// A node whose admission refuses `203.0.113.66` and admits everything else —
/// the smallest faithful stand-in for a loaded ipfilter.dat table.
fn filtering_node() -> KadNode {
    let config = KadNodeConfig {
        id: id(0xAA),
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
    };
    KadNode::new(
        KadNodeStart::new(config, KadInstant::EPOCH)
            .admission(KadContactAdmission::new(|ip| ip != host_ip(FILTERED_HOST))),
    )
}

fn node_info(id_byte: u8) -> Kad2NodeInfo {
    Kad2NodeInfo {
        id: id(id_byte),
        tcp_port: 4761,
        version: 8,
        udp_port_tag: None,
        misc_options: 0,
    }
}

fn filtered_diagnostics(events: &[KadEvent]) -> Vec<KadNodeEndpoint> {
    events
        .iter()
        .filter_map(|event| match event {
            KadEvent::Diagnostic(KadNodeDiagnostic::ContactIpFiltered { endpoint }) => {
                Some(*endpoint)
            }
            _ => None,
        })
        .collect()
}

/// The nodes.dat-load analog (aMule `RoutingZone.cpp#L195`): a merged
/// file-loaded contact with a filtered IP never enters the routing table,
/// while its admitted neighbor does.
#[test]
fn merge_contacts_drops_a_filtered_contact_at_admission() {
    let mut node = filtering_node();
    let filtered = KadContact::new(id(0x10), endpoint(FILTERED_HOST, 4672), 4662, 8);
    let admitted = KadContact::new(id(0x20), endpoint(2, 4672), 4662, 8);

    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![filtered, admitted],
        },
    );
    let (datagrams, events) = drain_split(&mut node);

    assert!(node.routing_table().get(id(0x10)).is_none());
    assert!(node.routing_table().get(id(0x20)).is_some());
    assert_eq!(
        filtered_diagnostics(&events),
        vec![endpoint(FILTERED_HOST, 4672)]
    );
    assert_eq!(datagrams, vec![], "a merge never dials either way");
}

/// The routing-admission gate behind a live intake (aMule
/// `CRoutingZone::Add`, `RoutingZone.cpp#L406`): a bootstrap response's
/// hearsay row with a filtered IP is neither stored nor probed — no datagram
/// ever leaves toward the filtered endpoint — while the admitted row is both.
#[test]
fn a_bootstrap_hearsay_row_with_a_filtered_ip_is_neither_stored_nor_probed() {
    let mut node = filtering_node();
    let responder = endpoint(9, 4702);
    node.handle_command(
        T0,
        KadCommand::Bootstrap {
            endpoint: responder,
        },
    );
    let _ = drain_split(&mut node);

    deliver(
        &mut node,
        T0,
        responder,
        &Kad2Message::BootstrapRes {
            sender: node_info(0x90),
            contacts: vec![
                KadContact::new(id(0x10), endpoint(FILTERED_HOST, 4672), 4662, 8),
                KadContact::new(id(0x20), endpoint(2, 4672), 4662, 8),
            ],
        },
    );
    let (datagrams, events) = drain_split(&mut node);

    assert!(node.routing_table().get(id(0x10)).is_none());
    assert!(node.routing_table().get(id(0x20)).is_some());
    assert_eq!(
        filtered_diagnostics(&events),
        vec![endpoint(FILTERED_HOST, 4672)]
    );
    assert!(
        datagrams
            .iter()
            .all(|(to, _)| to.ip() != host_ip(FILTERED_HOST)),
        "the filtered hearsay row is never probed: {datagrams:?}"
    );
    assert!(
        datagrams.iter().any(|(to, _)| *to == endpoint(2, 4672)),
        "the admitted hearsay row is probed"
    );
}

/// The bootstrap-file dial selection (aMule `RoutingZone.cpp#L252`): a seeded
/// dial candidate with a filtered IP never receives a
/// `KADEMLIA2_BOOTSTRAP_REQ`; with only filtered candidates the dial loop
/// never even arms.
#[test]
fn a_seeded_bootstrap_dial_candidate_with_a_filtered_ip_is_never_dialed() {
    let mut node = filtering_node();
    node.handle_command(
        T0,
        KadCommand::SeedBootstrapDialList {
            candidates: vec![
                KadBootstrapNode::new(endpoint(FILTERED_HOST, 4672), None),
                KadBootstrapNode::new(endpoint(2, 4672), None),
            ],
        },
    );
    let (_, events) = drain_split(&mut node);
    assert_eq!(
        filtered_diagnostics(&events),
        vec![endpoint(FILTERED_HOST, 4672)]
    );

    // Run the dial loop dry: across every armed wake, no datagram ever
    // targets the filtered candidate.
    let mut dialed = Vec::new();
    while let Some(wake) = node.next_wake() {
        node.tick(wake);
        let (datagrams, _) = drain_split(&mut node);
        dialed.extend(datagrams.into_iter().map(|(to, _)| to));
        if dialed.len() > 8 {
            break; // the list holds one admitted candidate; well past it
        }
    }
    assert!(
        dialed.contains(&endpoint(2, 4672)),
        "the admitted candidate is dialed: {dialed:?}"
    );
    assert!(
        !dialed.contains(&endpoint(FILTERED_HOST, 4672)),
        "the filtered candidate is never dialed: {dialed:?}"
    );

    // All-filtered seed: the list stays empty, so the dial loop never arms.
    let mut only_filtered = filtering_node();
    only_filtered.handle_command(
        T0,
        KadCommand::SeedBootstrapDialList {
            candidates: vec![KadBootstrapNode::new(endpoint(FILTERED_HOST, 4672), None)],
        },
    );
    let (datagrams, events) = drain_split(&mut only_filtered);
    assert_eq!(datagrams, vec![]);
    assert_eq!(
        filtered_diagnostics(&events),
        vec![endpoint(FILTERED_HOST, 4672)]
    );
    assert_eq!(
        only_filtered.next_wake(),
        None,
        "nothing admitted, nothing to dial"
    );
}

/// The lookup-response row drop (aMule `ProcessKademlia2Response`,
/// `KademliaUDPListener.cpp#L733` — rows are filtered before the search
/// manager or the routing zone sees them): a walk never dials a filtered
/// candidate, even one strictly closer than the admitted alternative.
#[test]
fn a_lookup_response_row_with_a_filtered_ip_is_never_walked() {
    // Word-swap fixture pair from the requester suite: the walk target.
    let target = KadId::from_bytes([
        0xB5, 0x2D, 0x30, 0x8E, 0x5C, 0xA2, 0x06, 0xB8, 0x23, 0xFC, 0x85, 0x93, 0xD2, 0x62, 0x10,
        0xF2,
    ]);
    let file_hash = FileHash::from_bytes([
        0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62,
        0xD2,
    ]);
    // An ID at XOR distance `d` from the target (byte 12 = LSB of the least
    // significant word under the capture-proven ordering).
    let id_near = |d: u8| {
        let mut bytes = *target.as_bytes();
        bytes[12] ^= d;
        KadId::from_bytes(bytes)
    };

    let mut node = filtering_node();
    // Seed one admitted contact the walk can start from.
    let seed = endpoint(100, 4100);
    deliver(
        &mut node,
        T0,
        seed,
        &Kad2Message::HelloReq(Kad2NodeInfo {
            id: id_near(100),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: Some(seed.udp_port()),
            misc_options: 0,
        }),
    );
    let _ = drain_split(&mut node);
    node.handle_command(
        T0,
        KadCommand::SearchSources {
            request: KadSourceLookupRequest::new(SourceLookupTarget::new(file_hash, 65_536)),
        },
    );
    let _ = drain_split(&mut node);

    // The seed answers with two strictly closer rows; the closer of the two
    // is filtered. Only the admitted row may be launched at.
    let filtered_row = KadContact::new(id_near(1), endpoint(FILTERED_HOST, 4672), 4662, 8);
    let admitted_row = KadContact::new(id_near(2), endpoint(2, 4672), 4662, 8);
    deliver(
        &mut node,
        T0,
        seed,
        &Kad2Message::LookupRes {
            target,
            contacts: vec![filtered_row, admitted_row],
        },
    );
    let (datagrams, events) = drain_split(&mut node);

    assert_eq!(
        filtered_diagnostics(&events),
        vec![endpoint(FILTERED_HOST, 4672)]
    );
    assert!(
        datagrams
            .iter()
            .all(|(to, _)| to.ip() != host_ip(FILTERED_HOST)),
        "the filtered row is never queried: {datagrams:?}"
    );
    assert!(
        datagrams.iter().any(|(to, _)| *to == endpoint(2, 4672)),
        "the admitted row takes the freed walk slot: {datagrams:?}"
    );
}

/// The aMule-faithful non-gate: aMule has no IP-filter check at Kad datagram
/// entry (`grep ipfilter src/kademlia/` — its four sites are all contact
/// intakes), so a `HELLO_REQ` from a filtered IP is still *answered*; the
/// sender just never becomes a contact. Locked deliberately — hardening
/// beyond aMule here would change observable bench behavior.
#[test]
fn a_hello_req_from_a_filtered_ip_is_answered_but_never_stored() {
    let mut node = filtering_node();
    let from = endpoint(FILTERED_HOST, 4672);

    deliver(&mut node, T0, from, &Kad2Message::HelloReq(node_info(0x10)));
    let (datagrams, events) = drain_split(&mut node);

    assert!(node.routing_table().get(id(0x10)).is_none());
    assert_eq!(filtered_diagnostics(&events), vec![from]);
    assert!(
        datagrams
            .iter()
            .any(|(to, bytes)| *to == from && bytes.get(1) == Some(&0x19)),
        "the HELLO_RES still goes out (aMule answers filtered hellos): {datagrams:?}"
    );
}
