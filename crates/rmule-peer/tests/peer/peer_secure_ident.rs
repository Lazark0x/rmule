//! Secure User Identification session state machine (ADR-0041).
//!
//! Drives a real outbound `PeerSession` with SUI enabled against a *scripted*
//! peer built from a distinct keypair and explicit challenges. The asymmetry is
//! deliberate: a symmetric rmule↔rmule loopback would still pass even if the
//! signing direction were flipped, so these tests assert the exact signing
//! inputs (we sign the verifier's key + challenge; we verify our key + our
//! challenge) rather than only that the exchange completes.

use std::sync::Arc;

use crate::fixture::{CT_EMULE_MISCOPTIONS1, hello_body};
use rmule_peer::{
    Hello, HelloAnswer, PeerEvent, PeerHandshakeContext, PeerHelloBody, PeerOutput, PeerSession,
    PublicKeyPacket, SecIdentState, SecIdentStatePacket, SecureIdentConfig, SecureIdentFailure,
    SignaturePacket,
};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, Packet, SecureIdentKey, SecureIdentPublicKey, Tag, TagName,
    TagValue, UserHash,
};
use rmule_testkit::peer_session::peer;

const OUR_CHALLENGE: u32 = 0x1111_2222;
const PEER_CHALLENGE: u32 = 0x3333_4444;
fn plain_ctx() -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("rmule"),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0x10000001),
        connected_server: None,
    }
}

/// A peer hello answer that advertises Secure User Identification (MiscOptions1
/// SecIdent nibble = 1).
fn sui_answer_body(user_hash: UserHash) -> PeerHelloBody {
    sui_answer_body_v(user_hash, 1)
}

/// A peer hello answer advertising SUI `version` in the SecIdent nibble.
fn sui_answer_body_v(user_hash: UserHash, version: u32) -> PeerHelloBody {
    hello_body(
        user_hash,
        0x20000002,
        vec![Tag::new(
            TagName::compact_id(CT_EMULE_MISCOPTIONS1),
            TagValue::U32(version << 16),
        )],
    )
}

fn feed(session: &mut PeerSession, packet: Packet) {
    session.handle_bytes(&packet.encode());
}

/// Drain outputs and return the decoded packets among the writes plus the events.
fn drain(session: &mut PeerSession) -> (Vec<rmule_peer::PeerPacket>, Vec<PeerEvent>) {
    let mut packets = Vec::new();
    let mut events = Vec::new();
    for output in rmule_primitives::session::drain(|| session.poll_output()) {
        match output {
            PeerOutput::Write(bytes) => {
                let (packet, _) = Packet::decode(&bytes).expect("write decodes as a frame");
                packets.push(rmule_peer::PeerPacket::decode(&packet).expect("write decodes"));
            }
            PeerOutput::Event(event) => events.push(event),
            PeerOutput::Close(_) => panic!("session closed unexpectedly during SUI"),
        }
    }
    (packets, events)
}

fn config(key: &Arc<SecureIdentKey>, challenge: u32) -> SecureIdentConfig {
    SecureIdentConfig {
        key: key.clone(),
        challenge,
    }
}

/// Drive an outbound session through the hello + `OP_SECIDENTSTATE` +
/// `OP_PUBLICKEY` exchange, returning the session, the peer's key, and the
/// signature the session produced (so a test can assert its direction).
fn drive_to_our_signature(
    our_key: &Arc<SecureIdentKey>,
    peer_key: &SecureIdentKey,
    peer_user_hash: UserHash,
) -> (PeerSession, Vec<u8>) {
    let mut session = PeerSession::new_outbound(peer(), plain_ctx())
        .with_secure_ident(config(our_key, OUR_CHALLENGE));
    session.start();
    drain(&mut session); // our OP_HELLO

    // Peer answers advertising SUI → session identifies it and sends
    // OP_SECIDENTSTATE carrying our challenge.
    feed(
        &mut session,
        HelloAnswer::new(sui_answer_body(peer_user_hash)).encode_packet(),
    );
    let (packets, _) = drain(&mut session);
    let state = packets
        .iter()
        .find_map(|p| match p {
            rmule_peer::PeerPacket::SecIdentState(s) => Some(*s),
            _ => None,
        })
        .expect("session sent OP_SECIDENTSTATE");
    assert_eq!(state.state, SecIdentState::KeyAndSignNeeded);
    assert_eq!(
        state.challenge, OUR_CHALLENGE,
        "session sent our injected challenge"
    );

    // Peer sends its own state (wants our key + a signature over its challenge)
    // → session replies with our public key.
    feed(
        &mut session,
        SecIdentStatePacket {
            state: SecIdentState::KeyAndSignNeeded,
            challenge: PEER_CHALLENGE,
        }
        .encode_packet(),
    );
    let (packets, _) = drain(&mut session);
    let our_pub = packets
        .iter()
        .find_map(|p| match p {
            rmule_peer::PeerPacket::PublicKey(k) => Some(k.der.clone()),
            _ => None,
        })
        .expect("session sent OP_PUBLICKEY");
    assert_eq!(our_pub, our_key.public_key_der());

    // Peer sends its public key → session now has the verifier's key and can
    // sign, producing OP_SIGNATURE.
    feed(
        &mut session,
        PublicKeyPacket {
            der: peer_key.public_key_der(),
        }
        .encode_packet(),
    );
    let (packets, _) = drain(&mut session);
    let signature = packets
        .iter()
        .find_map(|p| match p {
            rmule_peer::PeerPacket::Signature(s) => {
                assert_eq!(
                    s.ip_kind, None,
                    "a V1-only peer must get a V1-shaped signature (lower-common-version)"
                );
                Some(s.signature.clone())
            }
            _ => None,
        })
        .expect("session sent OP_SIGNATURE");
    (session, signature)
}

const CRYPT_CIP_REMOTECLIENT: u8 = 10;
const CRYPT_CIP_LOCALCLIENT: u8 = 20;

/// `plain_ctx` with a Low-ID client id (below the 0x0100_0000 threshold).
fn low_id_ctx() -> PeerHandshakeContext {
    PeerHandshakeContext {
        client_id: ClientId::from_u32(4242),
        ..plain_ctx()
    }
}

/// Drive an outbound session against a *V2* peer through hello + state +
/// public-key exchange, returning the session and the full `OP_SIGNATURE`
/// packet it produced (kind byte included).
fn drive_v2_to_our_signature(
    ctx: PeerHandshakeContext,
    our_key: &Arc<SecureIdentKey>,
    peer_key: &SecureIdentKey,
    peer_user_hash: UserHash,
) -> (PeerSession, rmule_peer::SignaturePacket) {
    drive_v2_to_our_signature_at(peer(), ctx, our_key, peer_key, peer_user_hash)
}

/// The same drive against a peer at `endpoint`, so a suite can vary the
/// session's own Address Family.
fn drive_v2_to_our_signature_at(
    endpoint: rmule_primitives::PeerEndpoint,
    ctx: PeerHandshakeContext,
    our_key: &Arc<SecureIdentKey>,
    peer_key: &SecureIdentKey,
    peer_user_hash: UserHash,
) -> (PeerSession, rmule_peer::SignaturePacket) {
    let mut session =
        PeerSession::new_outbound(endpoint, ctx).with_secure_ident(config(our_key, OUR_CHALLENGE));
    session.start();
    drain(&mut session); // our OP_HELLO

    feed(
        &mut session,
        HelloAnswer::new(sui_answer_body_v(peer_user_hash, 2)).encode_packet(),
    );
    drain(&mut session);

    feed(
        &mut session,
        SecIdentStatePacket {
            state: SecIdentState::KeyAndSignNeeded,
            challenge: PEER_CHALLENGE,
        }
        .encode_packet(),
    );
    drain(&mut session);

    feed(
        &mut session,
        PublicKeyPacket {
            der: peer_key.public_key_der(),
        }
        .encode_packet(),
    );
    let (packets, _) = drain(&mut session);
    let packet = packets
        .into_iter()
        .find_map(|p| match p {
            rmule_peer::PeerPacket::Signature(s) => Some(s),
            _ => None,
        })
        .expect("session sent OP_SIGNATURE");
    (session, packet)
}

/// eMule's version selection is a *bitmask* rule, not lower-common-version
/// (pinned from `SendSignaturePacket`, capture-era source read 2026-07-06):
/// `bUseV2 = (peer_nibble & 1) == 0`. A peer advertising 3 (V1|V2 — what real
/// eMule/aMule send) therefore gets a **V1** signature, exactly as
/// eMule↔eMule does.
#[test]
fn a_bitmask_3_peer_gets_a_v1_signature_like_emule_to_emule() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let mut session = PeerSession::new_outbound(peer(), plain_ctx())
        .with_secure_ident(config(&our_key, OUR_CHALLENGE));
    session.start();
    drain(&mut session);
    feed(
        &mut session,
        HelloAnswer::new(sui_answer_body_v(peer_user_hash, 3)).encode_packet(),
    );
    drain(&mut session);
    feed(
        &mut session,
        SecIdentStatePacket {
            state: SecIdentState::KeyAndSignNeeded,
            challenge: PEER_CHALLENGE,
        }
        .encode_packet(),
    );
    drain(&mut session);
    feed(
        &mut session,
        PublicKeyPacket {
            der: peer_key.public_key_der(),
        }
        .encode_packet(),
    );
    let (packets, _) = drain(&mut session);
    let packet = packets
        .into_iter()
        .find_map(|p| match p {
            rmule_peer::PeerPacket::Signature(s) => Some(s),
            _ => None,
        })
        .expect("session sent OP_SIGNATURE");

    assert_eq!(
        packet.ip_kind, None,
        "a V1-bit peer gets a V1-shaped signature"
    );
    let our_public = SecureIdentPublicKey::from_der(&our_key.public_key_der()).expect("our pub");
    let mut expected_input = peer_key.public_key_der();
    expected_input.extend_from_slice(&PEER_CHALLENGE.to_le_bytes());
    assert!(
        our_public.verify(&expected_input, &packet.signature),
        "the signature is V1: no IP bytes in the input"
    );
}

/// V2 signing, High-ID side: a High-ID client signs its *own*
/// Client ID with `CRYPT_CIP_LOCALCLIENT`. The exact input layout —
/// `[verifier key ‖ challenge:u32-le ‖ ip:u32-le ‖ kind:u8]` — is asserted by
/// verifying against handwritten bytes, pinning the spec-derived layout until
/// a captured vector confirms it.
#[test]
fn a_high_id_v2_signature_binds_our_own_id_with_kind_local() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    // plain_ctx's client id 0x10000001 is High-ID.
    let (_session, packet) =
        drive_v2_to_our_signature(plain_ctx(), &our_key, &peer_key, peer_user_hash);

    assert_eq!(packet.ip_kind, Some(CRYPT_CIP_LOCALCLIENT));
    let our_public = SecureIdentPublicKey::from_der(&our_key.public_key_der()).expect("our pub");
    let mut expected_input = peer_key.public_key_der();
    expected_input.extend_from_slice(&PEER_CHALLENGE.to_le_bytes());
    expected_input.extend_from_slice(&0x1000_0001_u32.to_le_bytes()); // our own Client ID
    expected_input.push(CRYPT_CIP_LOCALCLIENT);
    assert!(
        our_public.verify(&expected_input, &packet.signature),
        "High-ID V2 signs [peer key ‖ peer challenge ‖ own id ‖ 20]"
    );
}

/// V2 signing, Low-ID side: behind NAT we have no usable public address, so we
/// sign the *remote* peer's IP with `CRYPT_CIP_REMOTECLIENT` — never a bogus
/// own address.
#[test]
fn a_low_id_v2_signature_binds_the_remote_ip_with_kind_remote() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let (_session, packet) =
        drive_v2_to_our_signature(low_id_ctx(), &our_key, &peer_key, peer_user_hash);

    assert_eq!(packet.ip_kind, Some(CRYPT_CIP_REMOTECLIENT));
    let our_public = SecureIdentPublicKey::from_der(&our_key.public_key_der()).expect("our pub");
    let mut expected_input = peer_key.public_key_der();
    expected_input.extend_from_slice(&PEER_CHALLENGE.to_le_bytes());
    expected_input.extend_from_slice(&[203, 0, 113, 1]); // the peer's IP, octet order
    expected_input.push(CRYPT_CIP_REMOTECLIENT);
    assert!(
        our_public.verify(&expected_input, &packet.signature),
        "Low-ID V2 signs [peer key ‖ peer challenge ‖ remote ip ‖ 10]"
    );
}

/// V2 verify, kind 20: the peer signed its *own* address, so we verify with
/// the IP we observe for it (the session's peer endpoint).
#[test]
fn a_v2_peer_signature_over_its_own_ip_yields_identity_verified() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let (mut session, _packet) =
        drive_v2_to_our_signature(plain_ctx(), &our_key, &peer_key, peer_user_hash);

    let mut peer_input = our_key.public_key_der();
    peer_input.extend_from_slice(&OUR_CHALLENGE.to_le_bytes());
    peer_input.extend_from_slice(&[203, 0, 113, 1]); // the peer's own IP as we observe it
    peer_input.push(CRYPT_CIP_LOCALCLIENT);
    let signature = peer_key.sign(&peer_input);

    feed(
        &mut session,
        SignaturePacket {
            signature,
            ip_kind: Some(CRYPT_CIP_LOCALCLIENT),
        }
        .encode_packet(),
    );
    let (_, events) = drain(&mut session);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PeerEvent::PeerIdentityVerified { user_hash, .. } if *user_hash == peer_user_hash)),
        "a V2 kind-20 signature over the peer's observed IP verifies"
    );
}

/// V2 verify, kind 10: the (Low-ID) peer signed *our* address — our High-ID
/// Client ID is our public IP, so verification plugs it in.
#[test]
fn a_v2_peer_signature_over_our_high_id_yields_identity_verified() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let (mut session, _packet) =
        drive_v2_to_our_signature(plain_ctx(), &our_key, &peer_key, peer_user_hash);

    let mut peer_input = our_key.public_key_der();
    peer_input.extend_from_slice(&OUR_CHALLENGE.to_le_bytes());
    peer_input.extend_from_slice(&0x1000_0001_u32.to_le_bytes()); // our High-ID Client ID
    peer_input.push(CRYPT_CIP_REMOTECLIENT);
    let signature = peer_key.sign(&peer_input);

    feed(
        &mut session,
        SignaturePacket {
            signature,
            ip_kind: Some(CRYPT_CIP_REMOTECLIENT),
        }
        .encode_packet(),
    );
    let (_, events) = drain(&mut session);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PeerEvent::PeerIdentityVerified { user_hash, .. } if *user_hash == peer_user_hash)),
        "a V2 kind-10 signature over our own High-ID verifies"
    );
}

/// A V2 signature computed over the wrong IP must not verify — that is the
/// entire point of IP-binding — and the failure stays non-terminal.
#[test]
fn a_v2_signature_over_the_wrong_ip_fails_non_terminally() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let (mut session, _packet) =
        drive_v2_to_our_signature(plain_ctx(), &our_key, &peer_key, peer_user_hash);

    let mut peer_input = our_key.public_key_der();
    peer_input.extend_from_slice(&OUR_CHALLENGE.to_le_bytes());
    peer_input.extend_from_slice(&[9, 9, 9, 9]); // not the address we observe
    peer_input.push(CRYPT_CIP_LOCALCLIENT);
    let signature = peer_key.sign(&peer_input);

    feed(
        &mut session,
        SignaturePacket {
            signature,
            ip_kind: Some(CRYPT_CIP_LOCALCLIENT),
        }
        .encode_packet(),
    );
    let (_, events) = drain(&mut session);
    assert!(
        events.iter().any(|e| matches!(
            e,
            PeerEvent::PeerSecureIdentFailed {
                reason: SecureIdentFailure::BadSignature
            }
        )),
        "an IP-mismatched V2 signature is rejected"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PeerEvent::PeerIdentityVerified { .. })),
    );
}

/// An unknown `byIPUsed` kind byte fails verification non-terminally — a
/// future eMule kind must never close the session.
#[test]
fn an_unknown_v2_ip_kind_fails_non_terminally() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let (mut session, _packet) =
        drive_v2_to_our_signature(plain_ctx(), &our_key, &peer_key, peer_user_hash);

    let mut peer_input = our_key.public_key_der();
    peer_input.extend_from_slice(&OUR_CHALLENGE.to_le_bytes());
    let signature = peer_key.sign(&peer_input);

    feed(
        &mut session,
        SignaturePacket {
            signature,
            ip_kind: Some(99),
        }
        .encode_packet(),
    );
    let (_, events) = drain(&mut session);
    assert!(
        events.iter().any(|e| matches!(
            e,
            PeerEvent::PeerSecureIdentFailed {
                reason: SecureIdentFailure::BadSignature
            }
        )),
        "an unknown kind byte is a failed verification, not a protocol violation"
    );
}

/// Wire-order regression: an inbound session answering a SUI-capable hello must
/// put `OP_HELLOANSWER` on the wire *before* `OP_SECIDENTSTATE`. The dialer is
/// still `AwaitingHelloAnswer` when our first packets arrive, and its dispatch
/// guard drops any SUI packet received before the hello exchange completes — a
/// state packet queued first therefore deadlocks the whole exchange.
#[test]
fn an_inbound_session_answers_the_hello_before_challenging_sui() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let mut session = PeerSession::new_inbound(peer(), plain_ctx())
        .with_secure_ident(config(&our_key, OUR_CHALLENGE));

    // The dialer's hello advertises SUI (same body shape as the answer).
    feed(
        &mut session,
        Hello::new(sui_answer_body(UserHash::from_bytes(
            [0x55; UserHash::BYTE_LEN],
        )))
        .encode_packet(),
    );
    let (packets, _) = drain(&mut session);

    let answer_pos = packets
        .iter()
        .position(|p| matches!(p, rmule_peer::PeerPacket::HelloAnswer(_)))
        .expect("inbound session answered the hello");
    let state_pos = packets
        .iter()
        .position(|p| matches!(p, rmule_peer::PeerPacket::SecIdentState(_)))
        .expect("inbound session challenged SUI");
    assert!(
        answer_pos < state_pos,
        "OP_HELLOANSWER must precede OP_SECIDENTSTATE on the wire \
         (got answer at {answer_pos}, state at {state_pos})"
    );
}

#[test]
fn our_signature_is_over_the_peer_key_and_peer_challenge() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let (_session, signature) = drive_to_our_signature(&our_key, &peer_key, peer_user_hash);

    // Direction guard: the peer (verifier) checks our signature with OUR public
    // key over `[peer public key ‖ peer challenge]`. If we had signed our own
    // key or our own challenge, this verification would fail.
    let our_public = SecureIdentPublicKey::from_der(&our_key.public_key_der()).expect("our pub");
    let mut expected_input = peer_key.public_key_der();
    expected_input.extend_from_slice(&PEER_CHALLENGE.to_le_bytes());
    assert!(
        our_public.verify(&expected_input, &signature),
        "our signature must verify over [peer public key ‖ peer challenge]"
    );
}

#[test]
fn a_valid_peer_signature_yields_identity_verified() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let (mut session, _sig) = drive_to_our_signature(&our_key, &peer_key, peer_user_hash);

    // The peer signs `[our public key ‖ our challenge]` with its private key.
    let mut peer_input = our_key.public_key_der();
    peer_input.extend_from_slice(&OUR_CHALLENGE.to_le_bytes());
    let peer_signature = peer_key.sign(&peer_input);

    feed(
        &mut session,
        SignaturePacket {
            signature: peer_signature,
            ip_kind: None,
        }
        .encode_packet(),
    );
    let (_, events) = drain(&mut session);

    let verified = events
        .iter()
        .find_map(|e| match e {
            PeerEvent::PeerIdentityVerified {
                user_hash,
                public_key,
            } => Some((*user_hash, public_key.clone())),
            _ => None,
        })
        .expect("PeerIdentityVerified emitted");
    assert_eq!(verified.0, peer_user_hash, "verified the peer's User Hash");
    assert_eq!(
        verified.1,
        peer_key.public_key_der(),
        "carries the peer's public key for core to bind"
    );
}

#[test]
fn a_forged_peer_signature_fails_non_terminally() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x55; UserHash::BYTE_LEN]);

    let (mut session, _sig) = drive_to_our_signature(&our_key, &peer_key, peer_user_hash);

    // An impostor signs with the WRONG key (not the key it advertised).
    let impostor_key = SecureIdentKey::generate().expect("impostor key");
    let mut peer_input = our_key.public_key_der();
    peer_input.extend_from_slice(&OUR_CHALLENGE.to_le_bytes());
    let forged = impostor_key.sign(&peer_input);

    feed(
        &mut session,
        SignaturePacket {
            signature: forged,
            ip_kind: None,
        }
        .encode_packet(),
    );
    let (_, events) = drain(&mut session);

    assert!(
        events.iter().any(|e| matches!(
            e,
            PeerEvent::PeerSecureIdentFailed {
                reason: SecureIdentFailure::BadSignature
            }
        )),
        "a signature under the wrong key is rejected"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PeerEvent::PeerIdentityVerified { .. })),
        "a forged signature must not verify"
    );
    // Non-terminal: no Close was drained (drain panics on Close), so the session
    // stayed open — the peer simply keeps unsecured credit.
}

/// A native-IPv6 session signs **V1** even against a V2-only peer (ADR-0087).
/// V2's signed message ends in a 4-byte `ChallengeIP`, and signed bytes must
/// match exactly — a 16-byte variant is not a skippable widening but its own
/// proposal, so the version that signs no address at all is the one that
/// works. The absent kind byte is how the peer can tell.
#[test]
fn a_native_ipv6_session_signs_v1_even_against_a_v2_only_peer() {
    let our_key = Arc::new(SecureIdentKey::generate().expect("our key"));
    let peer_key = SecureIdentKey::generate().expect("peer key");
    let peer_user_hash = UserHash::from_bytes([0x66; UserHash::BYTE_LEN]);

    // The identical drive over IPv4 picks V2 — so the family is doing the work
    // here, not the peer's advert.
    let (_, over_v4) = drive_v2_to_our_signature(plain_ctx(), &our_key, &peer_key, peer_user_hash);
    assert_eq!(over_v4.ip_kind, Some(CRYPT_CIP_LOCALCLIENT));

    let (_, over_v6) = drive_v2_to_our_signature_at(
        rmule_testkit::peer_session::peer_v6(),
        plain_ctx(),
        &our_key,
        &peer_key,
        peer_user_hash,
    );
    assert_eq!(over_v6.ip_kind, None, "no address in the signed message");

    // And the signed bytes really are the V1 shape: the verifier's key and its
    // challenge, with no address appended.
    let mut signed = peer_key.public_key_der();
    signed.extend_from_slice(&PEER_CHALLENGE.to_le_bytes());
    let ours = SecureIdentPublicKey::from_der(&our_key.public_key_der()).expect("our key");
    assert!(ours.verify(&signed, &over_v6.signature));
}
