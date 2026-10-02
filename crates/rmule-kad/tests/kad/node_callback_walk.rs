//! The **Callback Walk**: aMule's `FINDSOURCE` search toward a
//! firewalled source's buddy ID, for a Kad row that named the buddy by ID
//! alone. The walk never learns "the buddy's endpoint" as a fact; it sends the
//! `0x52 KADEMLIA_CALLBACK_REQ` to every responded contact close enough to the
//! buddy ID to *be* that buddy (`CSearch::StorePacket`, `Search.cpp:612-631`
//! tolerance gate, `:1081-1122` the `FINDSOURCE` arm), because the buddy was
//! recruited by a walk toward that same ID and so sits next to it.

use rmule_kad::{
    FileHash, Kad2Message, Kad2NodeInfo, KadCallbackWalkEnd, KadCommand, KadEvent, KadId,
    KadNodeEndpoint,
};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{T0, datagrams, deliver, endpoint, events, id, node};

const BUDDY_ID: KadId = KadId::from_bytes([0x55; KadId::BYTE_LEN]);
const FILE: FileHash = FileHash::from_bytes([0x11; 16]);

/// A contact whose Kad ID shares the buddy ID's top 32-bit word: XOR distance
/// below `SEARCHTOLERANCE`, so aMule's `StorePacket` would act on it.
fn near_id() -> KadId {
    let mut bytes = [0x55; KadId::BYTE_LEN];
    bytes[4..].fill(0x00);
    KadId::from_bytes(bytes)
}

fn seat(node: &mut rmule_kad::KadNode, contact: KadId, at: KadNodeEndpoint) {
    let info = Kad2NodeInfo {
        id: contact,
        tcp_port: 4761,
        version: 8,
        udp_port_tag: None,
        misc_options: 0,
    };
    deliver(node, T0, at, &Kad2Message::HelloReq(info));
}

fn walk() -> KadCommand {
    KadCommand::CallbackWalk {
        buddy_id: BUDDY_ID,
        file_hash: FILE,
        tcp_port: 4662,
    }
}

fn converge(
    node: &mut rmule_kad::KadNode,
    responders: &[KadNodeEndpoint],
) -> Vec<rmule_kad::KadOutput> {
    for at in responders {
        deliver(
            node,
            T0,
            *at,
            &Kad2Message::LookupRes {
                target: BUDDY_ID,
                contacts: Vec::new(),
            },
        );
    }
    drain(|| node.poll_output())
}

fn callback_reqs(outputs: &[rmule_kad::KadOutput]) -> Vec<(KadNodeEndpoint, Vec<u8>)> {
    datagrams(outputs)
        .into_iter()
        .filter(|(_, bytes)| bytes[1] == 0x52)
        .collect()
}

#[test]
fn a_callback_walk_asks_the_buddy_id_and_sends_the_0x52_to_the_responder_beside_it() {
    let mut node = node();
    let near = endpoint(0x50, 4750);
    let far = endpoint(0x90, 4790);
    seat(&mut node, near_id(), near);
    seat(&mut node, id(0x90), far);
    drain(|| node.poll_output());

    node.handle_command(T0, walk());
    // The walk is a lookup toward the buddy ID: FIND_VALUE `KADEMLIA2_REQ`s
    // (`GetRequestContactCount` → `KADEMLIA_FIND_VALUE` for `FINDSOURCE`,
    // `Search.cpp:1825`) naming that ID as their target, and no `0x52` yet.
    let queries = datagrams(&drain(|| node.poll_output()));
    assert!(!queries.is_empty(), "the walk queries");
    for (_, bytes) in &queries {
        assert_eq!(
            bytes[1], 0x21,
            "a KADEMLIA2_REQ, nothing else: {bytes:02x?}"
        );
        assert_eq!(bytes[2], 0x02, "FIND_VALUE's contact count");
        assert_eq!(
            &bytes[3..19],
            BUDDY_ID.as_bytes(),
            "targeted at the buddy ID"
        );
    }

    let outputs = converge(&mut node, &[near, far]);

    // `<buddyID 16><fileHash 16><tcpPort 2 LE>` — the body aMule's walk writes
    // (`Search.cpp:1092-1100`), to the one responder inside tolerance.
    let mut expected = vec![0xE4, 0x52];
    expected.extend_from_slice(&[0x55; 16]);
    expected.extend_from_slice(&[0x11; 16]);
    expected.extend_from_slice(&4662u16.to_le_bytes());
    assert_eq!(callback_reqs(&outputs), vec![(near, expected)]);
    assert!(
        events(&outputs).contains(&KadEvent::CallbackWalkEnded {
            buddy_id: BUDDY_ID,
            end: KadCallbackWalkEnd::Asked(1),
        }),
        "{:?}",
        events(&outputs)
    );
}

#[test]
fn a_callback_walk_that_meets_nobody_near_the_buddy_id_ends_saying_so() {
    let mut node = node();
    let far = endpoint(0x90, 4790);
    seat(&mut node, id(0x90), far);
    drain(|| node.poll_output());

    node.handle_command(T0, walk());
    drain(|| node.poll_output());
    let outputs = converge(&mut node, &[far]);

    assert!(
        callback_reqs(&outputs).is_empty(),
        "a contact outside tolerance cannot be the buddy"
    );
    assert_eq!(
        events(&outputs)
            .into_iter()
            .filter(|event| matches!(event, KadEvent::CallbackWalkEnded { .. }))
            .collect::<Vec<_>>(),
        vec![KadEvent::CallbackWalkEnded {
            buddy_id: BUDDY_ID,
            end: KadCallbackWalkEnd::NoneNear,
        }]
    );
}

#[test]
fn a_second_callback_walk_toward_a_buddy_id_already_walked_is_refused() {
    // `CSearchManager::StartSearch` refuses a search whose target is already
    // searched (`SearchManager.cpp:153-160`); `TryToConnect` then reports the
    // source declined (`BaseClient.cpp:2166-2171`).
    let mut node = node();
    let near = endpoint(0x50, 4750);
    seat(&mut node, near_id(), near);
    drain(|| node.poll_output());

    node.handle_command(T0, walk());
    drain(|| node.poll_output());
    node.handle_command(T0, walk());
    let outputs = drain(|| node.poll_output());

    assert!(
        datagrams(&outputs).is_empty(),
        "the refused walk sends nothing"
    );
    assert_eq!(
        events(&outputs),
        vec![KadEvent::CallbackWalkEnded {
            buddy_id: BUDDY_ID,
            end: KadCallbackWalkEnd::AlreadyWalking,
        }]
    );

    // The first walk is untouched and still ends in its own `0x52`.
    let outputs = converge(&mut node, &[near]);
    assert_eq!(callback_reqs(&outputs).len(), 1);
}

#[test]
fn an_empty_routing_table_ends_the_callback_walk_at_once() {
    let mut node = node();
    node.handle_command(T0, walk());
    let outputs = drain(|| node.poll_output());
    assert!(datagrams(&outputs).is_empty());
    assert_eq!(
        events(&outputs),
        vec![KadEvent::CallbackWalkEnded {
            buddy_id: BUDDY_ID,
            end: KadCallbackWalkEnd::NoneNear,
        }]
    );
}
