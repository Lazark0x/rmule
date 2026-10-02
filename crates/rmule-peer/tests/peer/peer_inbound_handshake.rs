//! `new_inbound` makes `PeerSession` answer a dialing peer: it waits for
//! the peer's `OP_HELLO`, identifies them, and replies `OP_HELLOANSWER`
//! carrying *our* identity. The hello timeout fires before the peer
//! speaks (the inverse of the outbound deadline).

use crate::fixture::plain_hello_body;
use rmule_peer::{Hello, PeerCloseReason, PeerEvent, PeerOutput, PeerPacket, PeerSession};
use rmule_primitives::session::drain;
use rmule_primitives::{Packet, UserHash};
use rmule_testkit::peer_session::{peer_at, serverless_ctx};

#[test]
fn inbound_hello_identifies_peer_and_replies_hello_answer() {
    let remote = UserHash::from_bytes([0x99; UserHash::BYTE_LEN]);
    let hello = Hello::new(plain_hello_body(remote))
        .encode_packet()
        .encode();

    let mut session = PeerSession::new_inbound(peer_at(9), serverless_ctx());
    session.handle_bytes(&hello);
    let outputs = drain(|| session.poll_output());

    let identified = outputs
        .iter()
        .find_map(|o| match o {
            PeerOutput::Event(PeerEvent::PeerIdentified { identity }) => Some(identity),
            _ => None,
        })
        .expect("PeerIdentified emitted for the dialing peer");
    assert_eq!(identified.user_hash(), remote);

    let reply = outputs
        .iter()
        .find_map(|o| match o {
            PeerOutput::Write(b) => Some(Packet::decode(b).expect("frame decodes").0),
            _ => None,
        })
        .expect("an OP_HELLOANSWER reply was framed");
    match PeerPacket::decode(&reply).expect("reply decodes") {
        PeerPacket::HelloAnswer(answer) => {
            // We answer with OUR identity (0x11), not the remote's (0x99).
            assert_eq!(
                answer.body().user_hash,
                UserHash::from_bytes([0x11; UserHash::BYTE_LEN])
            );
        }
        other => panic!("expected HelloAnswer, got {other:?}"),
    }
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn inbound_hello_timeout_closes_before_peer_speaks() {
    let mut session = PeerSession::new_inbound(peer_at(9), serverless_ctx());
    session.hello_deadline_elapsed();
    let outputs = drain(|| session.poll_output());
    assert!(matches!(
        outputs.last(),
        Some(PeerOutput::Close(PeerCloseReason::HelloTimeout))
    ));
}
