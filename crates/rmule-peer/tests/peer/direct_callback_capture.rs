//! Direct-UDP-callback capture (genuine stock aMule 2.3.3, interop flow N `kad-direct-callback`,
//! run `1785273054`).
//!
//! rmule sent an `OP_DIRECTCALLBACKREQ` (`0x95`) to a TCP-firewalled / UDP-open
//! aMule's Kad UDP port; 1.6 ms later aMule dialed rmule's advertised TCP port
//! and spoke `OP_HELLO` on it. The hello is the **counterparty evidence** — it
//! only exists because `CClientUDPSocket::ProcessPacket`'s `0x95` arm
//! (`ClientUDPSocket.cpp:277-314`) built a client from our datagram and called
//! `TryToConnect`. rmule's own `0x95` is stimulus, re-decoded here as a
//! regression pin on the emit shape, never as evidence.
//!
//! Provenance, preconditions and the findings (the three-minute receive-side
//! window measured on the wire, the first-tick posture race, the undriven
//! reverse leg) live alongside in `meta.toml`.

use crate::fixture::load;
use rmule_peer::peer_udp::crypt;
use rmule_peer::{DirectCallbackReq, Hello, MiscOptions2, PeerIdentity};
use rmule_primitives::{CryptStance, Ipv4Endpoint, Packet, PeerEndpoint, UserHash};
use std::net::Ipv4Addr;

const FIXTURE_DIR: &str = "fixtures/direct_callback/captured/amule-233-directcallback-20260728/";

/// The serve listener rmule bound this run — the port its `0x95` invited the
/// counterparty to dial, and the port the counterparty's SYN landed on.
const RMULE_SERVE_PORT: u16 = 4663;

/// **Counterparty evidence.** The hello aMule spoke on the link it opened in
/// answer to the callback. Two facts matter beyond "it decodes":
///
/// * its `CT_EMULE_UDPPORTS` says the Kad UDP port and the client UDP port are
///   the same number — which is why addressing a `0xC5` peer-protocol frame to
///   the *Kad* port is the correct route, and not a happy accident;
/// * its `MiscOptions2` bit 12 is **clear**, so it honoured a direct callback it
///   never advertised it would honour. aMule's advert additionally demands a
///   *verified* open UDP surface (`BaseClient.cpp:1131`,
///   `CUDPFirewallTester::IsVerified`), which no two-node swarm settles, while
///   the receive gate (`ClientUDPSocket.cpp:286`) asks only for Kad running and
///   firewalled. The asymmetry is the finding; `meta.toml` carries it.
#[test]
fn amules_dial_back_hello_identifies_a_firewalled_peer_on_one_udp_socket() {
    let bytes = load(FIXTURE_DIR, "callback_dial_hello_0x01.bin");
    let (packet, consumed) =
        Packet::decode(&bytes).expect("the dialed-back link's first frame is a packet");
    assert_eq!(consumed, bytes.len(), "the hello is the whole segment");
    let hello = Hello::decode_packet(&packet).expect("it is an OP_HELLO");
    let body = hello.body();

    // The firewalled counterparty's own peer port — the one whose inbound is
    // DROPped, which is exactly why it had to be called back rather than dialed.
    assert_eq!(body.tcp_port, 4662);
    assert_eq!(
        body.connected_server,
        rmule_primitives::Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
        "a Config-A Kad swarm has no eD2k server, so the hello's trailing six bytes are zero"
    );

    // Read through rmule's own consume path, not a bespoke tag walk: whatever
    // this run proves about the counterparty is what production would conclude.
    let identity = PeerIdentity::from_hello_body(body);
    assert_eq!(
        identity.client_udp_reask(),
        Some((4674, 4)),
        "the client-UDP half of CT_EMULE_UDPPORTS, with the MiscOptions1 UDP nibble"
    );
    assert_eq!(
        identity.kad_bootstrap_port(),
        Some(4674),
        "the Kad half is the SAME port — one socket serves both surfaces, demuxed \
         on the protocol byte (CClientUDPSocket::OnPacketReceived). That is the \
         routing fact route 2 rests on: a 0xC5 frame sent to the Kad port lands \
         in the eMule handler that owns 0x95"
    );

    let misc2 = MiscOptions2::from_tags(&body.tags)
        .expect("aMule always advertises CT_EMULE_MISCOPTIONS2 in a peer hello");
    assert!(
        !misc2.supports_direct_udp_callback(),
        "bit 12 clear — the advert wants a VERIFIED open UDP surface the swarm \
         cannot settle, yet the callback was honoured anyway"
    );
    assert_eq!(misc2.kad_version(), 8, "a Kad2 citizen");
    assert!(misc2.supports_source_exchange2());
    // The crypt ladder was dark this run (no AMULE_CRYPT_* env), so the same word
    // must not be read as a crypt advert.
    assert!(!misc2.supports_crypt_layer());
}

/// **rmule stimulus**, re-decoded as a regression pin on the emit shape. The
/// counterparty acted on exactly these bytes, so the fields it read — our TCP
/// port and our user hash (`ClientUDPSocket.cpp:289-291`) — are what the dial it
/// opened was addressed and matched by.
#[test]
fn rmules_emitted_0x95_names_the_listener_it_actually_bound() {
    let bytes = load(FIXTURE_DIR, "directcallback_req_0x95.bin");
    assert_eq!(
        DirectCallbackReq::decode_udp(&bytes),
        Ok(DirectCallbackReq {
            our_tcp_port: RMULE_SERVE_PORT,
            our_user_hash: UserHash::from_bytes([0x42; UserHash::BYTE_LEN]),
            // No `--peer-crypt` policy this run. Bit 0x08 (direct callback) is
            // clear on aMule's own outbound `0x95` too: the byte says how to dial
            // US back, and accepting a callback is not issuing one.
            connect_options: 0x00,
        }),
        "the body carries the serve listener's real port, not a configured constant"
    );
}

/// The direct-callback framing rule rebuilds this run's `0x95` byte for byte:
/// addressed to the target's Kad UDP port, our serve port and user hash in the
/// body, and the connect-options byte of a run with no crypt policy. The byte
/// reads back as that same stance.
#[test]
fn the_direct_callback_is_framed_as_the_captured_0x95() {
    let captured = load(FIXTURE_DIR, "directcallback_req_0x95.bin");
    let amule_kad_udp = Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 2), 4674);
    let no_policy = CryptStance::disabled();
    assert_eq!(
        crypt::direct_callback(
            amule_kad_udp,
            RMULE_SERVE_PORT,
            UserHash::from_bytes([0x42; 16]),
            crypt::connect_options_from_stance(no_policy),
        ),
        (PeerEndpoint::V4(amule_kad_udp), captured.clone())
    );
    assert_eq!(
        crypt::stance_from_connect_options(captured[captured.len() - 1]),
        no_policy
    );
}
