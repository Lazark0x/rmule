//! The crypt legs' reader of what a node sends: an obfuscated datagram that no
//! key of the recipient opens fails the leg — the recipient would drop it, so
//! reading it as if it were plain would let a mis-keyed send pass — while a
//! plaintext datagram stays readable.

use rmule_kad::Kad2Message;
use rmule_testkit::kad_node::{
    T0, crypt_node, crypt_to_node, drain_outputs, endpoint, hello, id, node, opened_messages,
    our_key_for,
};

#[test]
#[should_panic(expected = "opens the obfuscated datagram")]
fn an_obfuscated_send_no_key_of_its_recipient_opens_fails_the_reader() {
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
        .encode()
        .encode();
    let mut sender = crypt_node();
    sender.handle_datagram(
        T0,
        peer,
        &crypt_to_node(&hello_req, our_key_for(peer), 0xFEED_1111),
    );
    let outputs = drain_outputs(&mut sender);

    // The reply is keyed for the peer that sent the hello; another peer's Kad
    // ID, with no handed key, does not open it.
    opened_messages(&outputs, id(0xC2), None);
}

#[test]
fn a_plaintext_send_stays_readable() {
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
        .encode()
        .encode();
    let mut plain = node();
    plain.handle_datagram(T0, peer, &hello_req);
    let outputs = drain_outputs(&mut plain);

    let sent = opened_messages(&outputs, id(0xC2), None);
    assert!(matches!(sent.as_slice(), [(_, Kad2Message::HelloRes(_))]));
}
