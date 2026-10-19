//! The routing table's admission caps (ADR-0064, aMule `CRoutingBin`): one
//! contact per IPv4 address and ten per /24 across the table, two per /24 in
//! one bucket. The private ranges and loopback are exempt from the /24 caps,
//! loopback from the per-IP cap too. A lookup answer's rows reach a walk only
//! when the table would take them.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadAdmissionCap, KadCommand, KadContact, KadContactState, KadId,
    KadNode, KadNodeDiagnostic, KadNodeEndpoint, KadRoutingTable, KadRoutingUpdate,
    KadSourceLookupRequest,
};
use rmule_primitives::session::drain;
use rmule_primitives::{FileHash, SourceLookupTarget};
use rmule_testkit::kad_node::{T0, deliver, diagnostics, id, info, node, sent_messages};

/// An ID in bucket `bucket` (< 8) of the all-zero own ID: byte 3 is the most
/// significant distance byte, so its `bucket`-th bit from the top fixes the
/// leading-zero count; `salt` keeps the IDs apart.
fn id_in(bucket: u8, salt: u8) -> KadId {
    let mut bytes = [0u8; KadId::BYTE_LEN];
    bytes[3] = 0x80 >> bucket;
    bytes[0] = salt;
    KadId::from_bytes(bytes)
}

fn contact(id: KadId, ip: Ipv4Addr) -> KadContact {
    KadContact::new(id, KadNodeEndpoint::new(ip, 4672), 4662, 8)
}

fn public(host: u8) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, host)
}

fn table() -> KadRoutingTable {
    KadRoutingTable::new(id(0))
}

const fn refused(cap: KadAdmissionCap) -> KadRoutingUpdate {
    KadRoutingUpdate::RejectedAdmissionCap { cap }
}

#[test]
fn an_eleventh_contact_from_one_slash24_is_refused_across_the_table() {
    let mut table = table();
    // Ten contacts from one /24, two per bucket so no bucket cap binds.
    for n in 0..10u8 {
        let update = table.upsert(T0, contact(id_in(n / 2, n), public(n + 1)));
        assert_eq!(update, KadRoutingUpdate::Added, "contact {n}");
    }
    assert_eq!(
        table.upsert(T0, contact(id_in(5, 10), public(11))),
        refused(KadAdmissionCap::Subnet),
        "the /24 is counted table-wide, not per bucket"
    );
    assert_eq!(
        table.upsert(T0, contact(id_in(5, 11), Ipv4Addr::new(198, 51, 101, 1))),
        KadRoutingUpdate::Added,
        "the next /24 is untouched"
    );
}

#[test]
fn a_third_contact_from_one_slash24_in_one_bucket_is_refused() {
    let mut table = table();
    assert_eq!(
        table.upsert(T0, contact(id_in(0, 1), public(1))),
        KadRoutingUpdate::Added
    );
    assert_eq!(
        table.upsert(T0, contact(id_in(0, 2), public(2))),
        KadRoutingUpdate::Added
    );
    assert_eq!(
        table.upsert(T0, contact(id_in(0, 3), public(3))),
        refused(KadAdmissionCap::BucketSubnet)
    );
    assert_eq!(
        table.upsert(T0, contact(id_in(1, 3), public(3))),
        KadRoutingUpdate::Added,
        "another bucket still takes the /24"
    );
}

#[test]
fn the_private_ranges_and_loopback_are_exempt_from_the_slash24_caps() {
    for net in [[10, 0, 0], [172, 16, 5], [192, 168, 1], [127, 0, 0]] {
        let mut table = table();
        // Three per bucket and twelve in all: both /24 caps would bind.
        for n in 0..12u8 {
            let ip = Ipv4Addr::new(net[0], net[1], net[2], n + 1);
            let update = table.upsert(T0, contact(id_in(n / 3, n), ip));
            assert_eq!(update, KadRoutingUpdate::Added, "{ip}");
        }
    }
}

#[test]
fn one_address_holds_one_contact_except_on_loopback() {
    for ip in [public(1), Ipv4Addr::new(192, 168, 1, 1)] {
        let mut table = table();
        assert_eq!(
            table.upsert(T0, contact(id_in(0, 1), ip)),
            KadRoutingUpdate::Added
        );
        let same_ip = KadContact::new(id_in(1, 2), KadNodeEndpoint::new(ip, 4673), 4662, 8);
        assert_eq!(
            table.upsert(T0, same_ip),
            refused(KadAdmissionCap::Ip),
            "{ip}: a second ID at one address, whatever its port"
        );
    }
    let mut table = table();
    let loopback = Ipv4Addr::LOCALHOST;
    assert_eq!(
        table.upsert(T0, contact(id_in(0, 1), loopback)),
        KadRoutingUpdate::Added
    );
    let second = KadContact::new(id_in(1, 2), KadNodeEndpoint::new(loopback, 4673), 4662, 8);
    assert_eq!(
        table.upsert(T0, second),
        KadRoutingUpdate::Added,
        "nodes on this host share 127.0.0.1 by port"
    );
}

#[test]
fn a_move_onto_a_held_address_is_refused_and_leaves_the_entry_as_it_was() {
    let mut table = table();
    let held = contact(id_in(0, 1), public(1));
    let mover = contact(id_in(1, 2), public(2));
    table.upsert(T0, held);
    table.upsert(T0, mover);

    let onto_held = contact(mover.id(), public(1));
    assert_eq!(table.upsert(T0, onto_held), refused(KadAdmissionCap::Ip));
    assert_eq!(
        table.get(mover.id()).map(KadContact::endpoint),
        Some(mover.endpoint())
    );

    // A move to a free address passes, and frees the old one.
    assert_eq!(
        table.upsert(T0, contact(mover.id(), public(3))),
        KadRoutingUpdate::Updated
    );
    assert_eq!(
        table.upsert(T0, contact(id_in(2, 4), public(2))),
        KadRoutingUpdate::Added,
        "the address the mover left takes a new contact"
    );
}

#[test]
fn an_evicted_or_replaced_contact_no_longer_counts() {
    let mut table = table();
    let first = contact(id_in(0, 1), public(1));
    table.upsert(T0, first);
    table.upsert(T0, contact(id_in(0, 2), public(2)));
    assert!(table.evict(first.id()));
    assert_eq!(
        table.upsert(T0, contact(id_in(0, 3), public(1))),
        KadRoutingUpdate::Added,
        "eviction frees the address and the bucket's /24 slot"
    );

    // A full bucket holding two of the /24, one of them Failed: a newcomer from
    // the /24 takes the Failed one's place, which no longer counts against it.
    let mut full = self::table();
    let failed = contact(id_in(0, 1), public(1)).in_state(KadContactState::Failed);
    full.upsert(T0, failed);
    full.upsert(T0, contact(id_in(0, 2), public(2)));
    for n in 3..=KadRoutingTable::K as u8 {
        full.upsert(T0, contact(id_in(0, n), Ipv4Addr::new(198, 51, 100 + n, 1)));
    }
    assert_eq!(full.len(), KadRoutingTable::K);
    assert_eq!(
        full.upsert(T0, contact(id_in(0, 0x20), public(9))),
        KadRoutingUpdate::AddedEvictingFailed {
            evicted: failed.id()
        }
    );
}

#[test]
fn the_node_answers_a_capped_hello_but_never_stores_the_sender() {
    let mut node = node();
    // Every `id(b)` below 0x80 lands in one bucket of the node's `id(0xAA)`.
    for host in 1..=3u8 {
        let from = KadNodeEndpoint::new(public(host), 4672);
        deliver(
            &mut node,
            T0,
            from,
            &Kad2Message::HelloReq(info(host, None)),
        );
    }
    let outputs = drain(|| node.poll_output());
    assert!(node.routing_table().get(id(3)).is_none());
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::ContactOverAdmissionCap {
            endpoint: KadNodeEndpoint::new(public(3), 4672),
            cap: KadAdmissionCap::BucketSubnet,
        }]
    );
}

/// `id` with its `bit`-th distance bit flipped, counted from the top under
/// the capture-proven word order: bytes 0..4 are the most significant word,
/// read little-endian, and so on per word.
fn with_bit(id: KadId, bit: usize) -> KadId {
    let mut bytes = *id.as_bytes();
    bytes[bit / 32 * 4 + 3 - bit % 32 / 8] ^= 0x80 >> (bit % 8);
    KadId::from_bytes(bytes)
}

/// A node walking a source lookup toward its own ID from one seed, `id(0x55)`
/// at `45.55.100.1`, the farthest ID there is, with the walk's first query
/// sent. A row `with_bit(target, b)` then sits in bucket `b`, and the larger
/// `b`, the closer it lies to the target.
fn walking_node() -> (KadId, KadNode) {
    let request = KadSourceLookupRequest::new(SourceLookupTarget::new(
        FileHash::from_bytes([0xAA; 16]),
        65_536,
    ));
    let target = request.kad_target();
    let mut node = node();
    assert_eq!(target, id(0xAA), "the walk runs toward the node's own ID");
    deliver(
        &mut node,
        T0,
        seed(),
        &Kad2Message::HelloReq(Kad2NodeInfo {
            id: id(0x55),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: Some(seed().udp_port()),
            misc_options: 0,
        }),
    );
    node.handle_command(T0, KadCommand::SearchSources { request });
    let _ = drain(|| node.poll_output());
    (target, node)
}

fn seed() -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(45, 55, 100, 1), 4100)
}

/// Where the node sent a `KADEMLIA2_REQ` among `outputs`.
fn lookups_sent(outputs: &[rmule_kad::KadOutput]) -> Vec<KadNodeEndpoint> {
    sent_messages(outputs)
        .into_iter()
        .filter(|(_, message)| matches!(message, Kad2Message::LookupReq { .. }))
        .map(|(to, _)| to)
        .collect()
}

/// aMule stores each answer row its routing zone takes, unverified, and hands
/// its search the rows it stored or would accept (`ProcessKademlia2Response`,
/// `KademliaUDPListener.cpp:742-750`; `IsAcceptableContact`,
/// `RoutingZone.cpp:897-916`). Of eleven rows from one /24, one per bucket,
/// ten are stored unverified and unqueried, so none is served, and the walk
/// dials from them. The eleventh is neither stored nor dialed, though it lies
/// closest to the target.
#[test]
fn a_lookup_answer_stores_its_rows_unverified_up_to_the_slash24_cap() {
    let (target, mut node) = walking_node();
    let rows: Vec<KadContact> = (0..=10u8)
        .map(|bucket| contact(with_bit(target, usize::from(bucket)), public(bucket + 1)))
        .collect();
    deliver(
        &mut node,
        T0,
        seed(),
        &Kad2Message::LookupRes {
            target,
            contacts: rows.clone(),
        },
    );
    let outputs = drain(|| node.poll_output());

    let eleventh = KadNodeEndpoint::new(public(11), 4672);
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::ContactOverAdmissionCap {
            endpoint: eleventh,
            cap: KadAdmissionCap::Subnet,
        }]
    );
    assert_eq!(
        lookups_sent(&outputs),
        [10, 9, 8].map(|host| KadNodeEndpoint::new(public(host), 4672)),
        "the walk dials the three closest rows the table took"
    );
    let table = node.routing_table();
    for row in &rows[..10] {
        let stored = table.get(row.id()).expect("an accepted row is stored");
        assert!(!stored.verified(), "stored unverified: {stored:?}");
        assert_eq!(stored.state(), KadContactState::Unqueried);
    }
    assert!(table.get(rows[10].id()).is_none(), "a refused row is not");
    assert_eq!(
        table
            .select_closest_servable(target, 50)
            .iter()
            .map(|contact| contact.id())
            .collect::<Vec<_>>(),
        vec![id(0x55)],
        "nothing the answer named is served or seeds a walk"
    );
}

/// A row naming a contact the table holds verified, at another IP, leaves the
/// entry as it is and is never dialed: a lookup answer cannot re-home a proven
/// ID (`AddUnfiltered` with `update` false, then `IsAcceptableContact`,
/// `RoutingZone.cpp:905-913`). The honest row beside it is stored and dialed.
#[test]
fn a_lookup_answer_cannot_re_home_a_verified_contact() {
    let (target, mut node) = walking_node();
    let proven = contact(with_bit(target, 127), public(1)).into_verified();
    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![proven],
        },
    );
    let _ = drain(|| node.poll_output());
    let elsewhere = KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 9), 4672);
    let honest = KadContact::new(
        with_bit(target, 126),
        KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 10), 4672),
        4662,
        8,
    );
    deliver(
        &mut node,
        T0,
        seed(),
        &Kad2Message::LookupRes {
            target,
            contacts: vec![KadContact::new(proven.id(), elsewhere, 4662, 8), honest],
        },
    );
    let outputs = drain(|| node.poll_output());

    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::ContactContradictsStored {
            endpoint: elsewhere
        }]
    );
    assert_eq!(lookups_sent(&outputs), vec![honest.endpoint()]);
    let table = node.routing_table();
    let kept = table.get(proven.id()).expect("the proven entry stays");
    assert_eq!(kept.endpoint(), proven.endpoint());
    assert!(kept.verified());
    assert!(table.get(honest.id()).is_some_and(|row| !row.verified()));
}
