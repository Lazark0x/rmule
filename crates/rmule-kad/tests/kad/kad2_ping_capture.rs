//! Captured **`0x60 KADEMLIA2_PING`** (genuine stock aMule 2.3.3, interop flow
//! H `http-bootstrap-cold-start`, run `1785277720`): the extern-port probe a
//! stock node fires at a freshly-helloed contact, which two independent rmule
//! nodes each received in one run. The ping is counterparty bytes; rmule's
//! `0x61` answer rides along as labelled stimulus (ADR-0045). Provenance and
//! the reason the pong stays deterministic live in `meta.toml`.

use rmule_kad::{Kad2Message, KadDecoded, decode_exact};

const FIXTURE_DIR: &str = "fixtures/ping/captured/amule-233-kad2-ping-20260729/";

/// The aMule Kad UDP port both nodes observed the ping arriving from.
const AMULE_KAD_UDP_PORT: u16 = 4672;

fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured(FIXTURE_DIR, name)
}

fn decode(bytes: &[u8]) -> Kad2Message {
    let KadDecoded::Plain(envelope) = decode_exact(bytes).expect("plain Kad envelope") else {
        panic!("the captured ping/pong are plain 0xE4, not packed");
    };
    Kad2Message::decode(&envelope).expect("Kad2 message decodes")
}

/// aMule's real ping is the two-byte null-payload form, and rmule's responder
/// codec both decodes and re-encodes it byte-identically.
#[test]
fn amule_kad2_ping_is_the_null_payload_form() {
    let captured = load("kad2_ping_0x60.bin");
    assert_eq!(captured, [0xE4, 0x60], "proto + opcode, nothing else");
    assert_eq!(decode(&captured), Kad2Message::Ping);
    assert_eq!(
        Kad2Message::Ping.encode().encode(),
        captured,
        "rmule re-encodes aMule's ping byte-for-byte"
    );
}

/// rmule's answer (stimulus, not evidence) reports the **observed sender UDP
/// port** — a fact readable only from the arriving datagram's source, which is
/// what makes the pong a genuine reading of the counterparty rather than an
/// echo of anything in its body (the ping has no body at all).
#[test]
fn rmule_pong_reports_the_observed_sender_port() {
    let captured = load("kad2_pong_0x61.bin");
    assert_eq!(
        decode(&captured),
        Kad2Message::Pong {
            udp_port: AMULE_KAD_UDP_PORT
        },
        "the pong names the port aMule's ping arrived from"
    );
    // The ping it answers carries no port at all, so the value cannot have been
    // copied out of the request.
    assert_eq!(load("kad2_ping_0x60.bin").len(), 2);
}

/// Vacuity guards: the decodes above are load-bearing.
#[test]
fn corrupted_frames_are_rejected() {
    // Wrong protocol byte fails the envelope.
    let mut ping = load("kad2_ping_0x60.bin");
    ping[0] = 0xE3;
    assert!(decode_exact(&ping).is_err());

    // A truncated pong body cannot yield a port.
    let KadDecoded::Plain(envelope) =
        decode_exact(&load("kad2_pong_0x61.bin")[..3]).expect("still a plain envelope")
    else {
        panic!("still plain");
    };
    assert!(
        Kad2Message::decode(&envelope).is_err(),
        "a one-byte pong body must fail the u16 port read"
    );
}
