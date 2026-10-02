//! Moving the own public IP the verify-key state is bound to:
//! aMule re-reads `theApp->GetPublicIP()` on every send rather than pinning it
//! at Kad start (`CPrefs::GetUDPVerifyKey`, `Prefs.cpp:235-243`), so a key a
//! counterparty learned from us under a previous address silently retires
//! (`CKadUDPKey::GetKeyValue`, `KadUDPKey.h`) while the key *we* hand that
//! counterparty is untouched — it derives from the secret and the target's IP
//! alone, never our own.

use rmule_kad::{Kad2Message, KadUdpKey, udp_verify_key};
use rmule_primitives::{ClientDecryptKeys, decrypt_datagram_client};
use rmule_testkit::kad_node::{
    NODE_ID, OWN_IP, SECRET, T0, crypt_to_node, drain_outputs, endpoint, fixed_nonce, hello, id,
    keyed_node, our_key_for,
};

/// Decrypt one of the node's own NodeID-family sends toward `contact_id` —
/// the family a stored contact's own-initiated exchange (a plain `LookupReq`
/// with no fresh reply key to ride instead) uses.
fn opened_by_contact(
    bytes: &[u8],
    contact_id: rmule_kad::KadId,
) -> rmule_primitives::DecryptedDatagram {
    decrypt_datagram_client(
        bytes,
        &ClientDecryptKeys {
            kad_id: Some(contact_id.as_bytes()),
            ..Default::default()
        },
    )
    .expect("the node's own NodeID-keyed send opens under the contact's ID")
}

#[test]
fn moving_the_own_ip_retires_a_learned_key_but_leaves_the_own_key_derivation_alone() {
    let mut node = keyed_node();
    node.enable_datagram_obfuscation(fixed_nonce);
    let peer = endpoint(7, 5000);
    let contact = id(0xC1);
    let sender_key = 0xABCD_0001;

    // The peer hellos in keyed: the node learns and stores its sender key
    // bound to `OWN_IP` (`enable_verify_keys`'s binding).
    let hello_req = Kad2Message::HelloReq(hello(contact, peer, 8, 0))
        .encode()
        .encode();
    node.handle_datagram(T0, peer, &crypt_to_node(&hello_req, 0, sender_key));
    let _ = drain_outputs(&mut node);
    assert_eq!(
        node.routing_table().get(contact).expect("stored").udp_key(),
        KadUdpKey::new(sender_key, OWN_IP),
        "the sender key lands bound to the IP the node held when it learned it"
    );

    // A plain LookupReq carries no fresh key of its own, so the LookupRes
    // rides the NodeID family with the *stored* key — the path this test
    // means to observe (a HELLO_RES would ride the same family too, but only
    // because the contact is already stored; LookupRes is unambiguous).
    let plain_lookup = |target| {
        Kad2Message::LookupReq {
            count: 1,
            target,
            check: NODE_ID,
        }
        .encode()
        .encode()
    };
    let lookup_res_bytes = |node: &mut rmule_kad::KadNode, target| {
        node.handle_datagram(T0, peer, &plain_lookup(target));
        drain_outputs(node)
            .into_iter()
            .find_map(|output| match output {
                rmule_kad::KadOutput::Datagram { bytes, .. } => Some(bytes),
                rmule_kad::KadOutput::Event(_) => None,
            })
            .expect("the node answers a well-formed lookup")
    };

    // Before the move: the stored key, evaluated at the IP it was learned
    // under, still echoes — this is ordinary steady-state operation.
    let before_bytes = lookup_res_bytes(&mut node, id(0xE0));
    let before = opened_by_contact(&before_bytes, contact);
    assert_eq!(
        before.receiver_verify_key,
        Some(sender_key),
        "the stored key still echoes while our own IP is unchanged"
    );
    assert_eq!(
        before.sender_verify_key,
        Some(udp_verify_key(SECRET, peer.ip())),
        "our own key toward this peer, derived from secret + the peer's IP alone"
    );

    // Move the own IP (Address Learning's IPv4 verdict moving, ADR-0084).
    let moved_ip = std::net::Ipv4Addr::new(198, 51, 100, 9);
    assert_ne!(moved_ip, OWN_IP);
    node.set_own_public_ip(moved_ip);

    // The stored key's raw pair is untouched — only what it *evaluates to*
    // at the new IP changes (aMule's `GetKeyValue` reads live, it never
    // rewrites the stored pair).
    let stored = node.routing_table().get(contact).expect("still stored");
    assert_eq!(stored.udp_key(), KadUdpKey::new(sender_key, OWN_IP));
    assert_eq!(
        stored.udp_key().key_value(moved_ip),
        0,
        "a key learned under the old IP reads as absent at the new one"
    );

    // (1) The next send toward this contact goes out with the fresh
    // derivation: the stored key no longer echoes.
    let after_bytes = lookup_res_bytes(&mut node, id(0xE2));
    let after = opened_by_contact(&after_bytes, contact);
    assert_eq!(
        after.receiver_verify_key,
        Some(0),
        "the key learned under the retired IP is treated as absent, matching aMule's \
         CKadUDPKey::GetKeyValue collapsing to 0"
    );

    // (2) The own key handed to this target is unchanged: `GetUDPVerifyKey`
    // (`Prefs.cpp:235-243`) derives from the secret and the target's IP
    // alone, never our own.
    assert_eq!(
        after.sender_verify_key,
        Some(udp_verify_key(SECRET, peer.ip())),
        "our own key toward a target does not move with our own IP"
    );
    assert_eq!(
        after.sender_verify_key, before.sender_verify_key,
        "identical before and after the move"
    );

    // Sanity: `our_key_for` (the test vocabulary's own derivation) agrees.
    assert_eq!(after.sender_verify_key, Some(our_key_for(peer)));
}

#[test]
fn an_unarmed_node_ignores_a_public_ip_move() {
    // No verify-key state exists to move, and nothing in the routing table
    // reads `own_public_ip` while `enable_verify_keys` never ran — a no-op,
    // not a panic, matching the always-safe driver-facing command surface.
    let mut node = rmule_testkit::kad_node::node();
    node.set_own_public_ip(std::net::Ipv4Addr::new(203, 0, 113, 4));
}
