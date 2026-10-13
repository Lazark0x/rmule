//! The routing table's admission caps (ADR-0064, aMule `CRoutingBin`): one
//! contact per IPv4 address and ten per /24 across the table, two per /24 in
//! one bucket. The private ranges and loopback are exempt from the /24 caps,
//! loopback from the per-IP cap too.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, KadAdmissionCap, KadContact, KadContactState, KadId, KadNodeDiagnostic,
    KadNodeEndpoint, KadRoutingTable, KadRoutingUpdate,
};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{T0, deliver, diagnostics, id, info, node};

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
