//! Verified-only serving: once anything in a bucket has verified, only
//! verified contacts are served — and the servable set never empties when
//! nothing can verify, which would strand the node.

use rmule_kad::{Kad2Message, KadContact, KadNodeEndpoint, KadRoutingTable, KadUdpKey};
use rmule_testkit::kad_node::{
    NODE_ID, OWN_IP, T0, crypt_node, crypt_to_node, drain_outputs, endpoint, hello, id, node,
    our_key_for, sent_messages,
};

#[test]
fn once_a_contact_verifies_only_verified_contacts_are_served() {
    // The Verified Contact glossary entry's second sentence, at the node: with
    // three Responded contacts of which one verifies through the three-way, a
    // KADEMLIA2_REQ answer holds that one alone (aMule's `GetClosestTo` gate,
    // `RoutingBin.cpp#L195`) — an unverified contact is never handed to another
    // node, however close to the target it sits.
    let mut node = crypt_node();
    let peers: Vec<KadNodeEndpoint> = (10u8..13)
        .map(|h| endpoint(h, 5000 + u16::from(h)))
        .collect();
    for (index, peer) in peers.iter().enumerate() {
        let contact_id = id(0x10 + index as u8);
        node.handle_datagram(
            T0,
            *peer,
            &Kad2Message::HelloReq(hello(contact_id, *peer, 8, 0))
                .encode()
                .encode(),
        );
    }
    let _ = drain_outputs(&mut node);
    assert_eq!(node.routing_table().contacts().count(), 3);

    // The middle one completes the three-way with a keyed 0x22.
    let verifier = peers[1];
    node.handle_datagram(
        T0,
        verifier,
        &crypt_to_node(
            &Kad2Message::HelloResAck { id: id(0x11) }.encode().encode(),
            our_key_for(verifier),
            0xFEED_1111,
        ),
    );
    let _ = drain_outputs(&mut node);
    assert!(
        node.routing_table()
            .get(id(0x11))
            .expect("stored")
            .verified()
    );

    // A lookup from a fourth node is answered from the verified set only.
    let asker = endpoint(40, 5040);
    node.handle_datagram(
        T0,
        asker,
        &Kad2Message::LookupReq {
            count: 10,
            target: id(0x12),
            check: NODE_ID,
        }
        .encode()
        .encode(),
    );
    let outputs = drain_outputs(&mut node);
    let sent = sent_messages(&outputs);
    let [(_, Kad2Message::LookupRes { contacts, .. })] = sent.as_slice() else {
        panic!("one lookup res");
    };
    assert_eq!(
        contacts.iter().map(KadContact::id).collect::<Vec<_>>(),
        vec![id(0x11)],
        "only the verified contact is servable — not the two closer unverified ones"
    );
}

#[test]
fn a_spoofed_ip_claimant_never_becomes_servable() {
    // The adversarial case the verified flag exists for. A contact verifies at
    // its real IP; an attacker then claims the same Kad ID from another address
    // (an unsolicited hello, the cheapest poisoning attempt there is). The
    // entry must not move, and the attacker's endpoint must never appear in a
    // routing answer — otherwise we would hand every asking node a pointer to
    // the attacker.
    let mut node = crypt_node();
    let honest = endpoint(7, 5000);
    let attacker = endpoint(66, 5000);
    let victim = id(0xC1);

    node.handle_datagram(
        T0,
        honest,
        &crypt_to_node(
            &Kad2Message::HelloReq(hello(victim, honest, 8, 0))
                .encode()
                .encode(),
            our_key_for(honest),
            0xFEED_1111,
        ),
    );
    let _ = drain_outputs(&mut node);
    assert!(node.routing_table().get(victim).expect("stored").verified());

    // The attacker hellos as the same Kad ID from its own IP. It cannot echo a
    // receiver key (it never received ours) and cannot present the victim's
    // sender key (it never saw the victim's trailer).
    node.handle_datagram(
        T0,
        attacker,
        &Kad2Message::HelloReq(hello(victim, attacker, 8, 0))
            .encode()
            .encode(),
    );
    let _ = drain_outputs(&mut node);

    let stored = node.routing_table().get(victim).expect("still stored");
    assert_eq!(
        stored.endpoint(),
        honest,
        "the verified contact is not relocated to the attacker's IP"
    );
    assert!(stored.verified(), "and stays verified");

    // Serving proves it end to end: the answer names the honest endpoint.
    let asker = endpoint(40, 5040);
    node.handle_datagram(
        T0,
        asker,
        &Kad2Message::LookupReq {
            count: 10,
            target: victim,
            check: NODE_ID,
        }
        .encode()
        .encode(),
    );
    let outputs = drain_outputs(&mut node);
    let sent = sent_messages(&outputs);
    let [(_, Kad2Message::LookupRes { contacts, .. })] = sent.as_slice() else {
        panic!("one lookup res");
    };
    assert!(
        contacts.iter().all(|c| c.endpoint() != attacker),
        "the spoofed endpoint is never served: {contacts:?}"
    );
    assert_eq!(
        contacts
            .iter()
            .map(KadContact::endpoint)
            .collect::<Vec<_>>(),
        vec![honest]
    );
}

#[test]
fn a_keyed_entry_is_never_updated_by_a_claimant_without_its_key() {
    // aMule's sender-key update gate (`RoutingZone.cpp#L442`): once an entry
    // carries a UDP key valid at our public IP, an update must present the same
    // key or be denied outright — the anti-hijack guard that protects even
    // *unverified* entries (which the endpoint-move rule alone would let an
    // attacker relocate at will).
    let mut node = crypt_node();
    let honest = endpoint(7, 5000);
    let attacker = endpoint(66, 5000);
    let victim = id(0xC1);

    // The honest node hellos with a sender key but no receiver echo: stored,
    // keyed, still unverified (it must complete the three-way to verify).
    node.handle_datagram(
        T0,
        honest,
        &crypt_to_node(
            &Kad2Message::HelloReq(hello(victim, honest, 8, 0))
                .encode()
                .encode(),
            0,
            0xABCD_0001,
        ),
    );
    let _ = drain_outputs(&mut node);
    let stored = node.routing_table().get(victim).expect("stored");
    assert!(!stored.verified(), "no receiver echo, so unverified");
    assert_eq!(stored.udp_key(), KadUdpKey::new(0xABCD_0001, OWN_IP));

    // The attacker claims the ID from elsewhere with a key of its own choosing.
    node.handle_datagram(
        T0,
        attacker,
        &crypt_to_node(
            &Kad2Message::HelloReq(hello(victim, attacker, 8, 0))
                .encode()
                .encode(),
            0,
            0xBADB_AD01,
        ),
    );
    let _ = drain_outputs(&mut node);

    let stored = node.routing_table().get(victim).expect("still stored");
    assert_eq!(
        stored.endpoint(),
        honest,
        "the key gate denies the update: the entry keeps its endpoint"
    );
    assert_eq!(
        stored.udp_key(),
        KadUdpKey::new(0xABCD_0001, OWN_IP),
        "and keeps the original key (the attacker cannot overwrite it)"
    );
}

#[test]
fn the_servable_set_never_empties_when_nothing_can_verify() {
    // The zero-servable-cliff invariant (ADR-0064 two-stage activation), stated
    // as the property rather than an example: for a node whose contacts are all
    // Responded, the servable answer is non-empty whether or not verification
    // is reachable. An all-plaintext topology (legacy peers, the deterministic
    // mesh) verifies nothing, and a strict gate there would silently unjoin the
    // node — aMule in that topology serves silence too, but it also loads its
    // nodes.dat all-verified, so it never actually lands in the empty state.
    for keyed in [false, true] {
        let mut node = if keyed { crypt_node() } else { node() };
        for host in [10u8, 20, 30] {
            let peer = endpoint(host, 5000 + u16::from(host));
            node.handle_datagram(
                T0,
                peer,
                &Kad2Message::HelloReq(hello(id(host), peer, 8, 0))
                    .encode()
                    .encode(),
            );
        }
        let _ = drain_outputs(&mut node);
        assert!(
            node.routing_table().contacts().all(|c| !c.verified()),
            "plaintext hellos verify nothing (keyed node: {keyed})"
        );

        let served = node
            .routing_table()
            .select_closest_servable(id(0x11), KadRoutingTable::K);
        assert!(
            !served.is_empty(),
            "the servable set must not empty out (keyed node: {keyed})"
        );
    }
}
