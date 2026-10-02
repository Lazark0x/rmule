//! Serving `KADEMLIA2_REQ`: which contacts a lookup returns, when it answers
//! empty, and the check-ID guard that drops a request aimed at someone else.

use rmule_kad::{Kad2Message, KadId, KadNodeDiagnostic};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{T0, deliver, diagnostics, endpoint, id, info, node, sent_messages};

#[test]
fn lookup_req_with_our_check_id_returns_closest_responded_contacts() {
    let mut node = node();
    // Three live contacts via hello (Responded), one hearsay row (Pending).
    for (byte, port) in [(0x10, 4710u16), (0x12, 4712), (0x40, 4740)] {
        deliver(
            &mut node,
            T0,
            endpoint(byte, port),
            &Kad2Message::HelloReq(info(byte, None)),
        );
    }
    drain(|| node.poll_output());

    deliver(
        &mut node,
        T0,
        endpoint(7, 4707),
        &Kad2Message::LookupReq {
            count: 2,
            target: id(0x11),
            check: id(0xAA),
        },
    );

    let sent = sent_messages(&drain(|| node.poll_output()));
    let [(to, Kad2Message::LookupRes { target, contacts })] = sent.as_slice() else {
        panic!("expected exactly one lookup response, got {sent:?}");
    };
    assert_eq!(*to, endpoint(7, 4707));
    assert_eq!(*target, id(0x11));
    let ids: Vec<KadId> = contacts.iter().map(rmule_kad::KadContact::id).collect();
    assert_eq!(
        ids,
        vec![id(0x10), id(0x12)],
        "closest-first, capped at count"
    );
}

#[test]
fn lookup_req_with_a_foreign_check_id_is_dropped_with_a_diagnostic() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(7, 4707),
        &Kad2Message::LookupReq {
            count: 2,
            target: id(0x11),
            check: id(0xBB),
        },
    );

    let outputs = drain(|| node.poll_output());
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::LookupCheckMismatch {
            from: endpoint(7, 4707)
        }]
    );
    assert!(
        sent_messages(&outputs).is_empty(),
        "no reply to a misrouted lookup"
    );
}

#[test]
fn lookup_req_answers_empty_when_no_contact_is_responded_yet() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(7, 4707),
        &Kad2Message::LookupReq {
            count: 2,
            target: id(0x11),
            check: id(0xAA),
        },
    );

    // A zero-contact 0x29 is genuine aMule behavior (the June private pcaps
    // answered exactly this before the return-filter finding).
    assert_eq!(
        sent_messages(&drain(|| node.poll_output())),
        vec![(
            endpoint(7, 4707),
            Kad2Message::LookupRes {
                target: id(0x11),
                contacts: vec![],
            }
        )]
    );
}

#[test]
fn unsolicited_lookup_res_is_diagnosed_and_its_contacts_are_not_added() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(8, 4708),
        &Kad2Message::LookupRes {
            target: id(0x11),
            contacts: vec![rmule_kad::KadContact::new(
                id(0x30),
                endpoint(3, 4703),
                4761,
                8,
            )],
        },
    );

    assert_eq!(
        diagnostics(&drain(|| node.poll_output())),
        vec![KadNodeDiagnostic::UnsolicitedLookupRes {
            from: endpoint(8, 4708)
        }]
    );
    assert!(
        node.routing_table().is_empty(),
        "hearsay from nowhere is dropped"
    );
}
