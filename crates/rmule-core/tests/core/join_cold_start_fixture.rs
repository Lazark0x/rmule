//! Captured **cold-start join** evidence (flow H `http-bootstrap-cold-start`,
//! run `1785277720`): the counterparty bytes the production ADR-0067 Join
//! Sequence caller (`rmule-tools ed2k bootstrap-fetch` → [`run_join_sequence`]
//! → a live `Core`) drew from a genuine aMule 2.3.3 Kad node and a Lugdunum
//! 17.15 eserver on the fake-public bench. The verdict row this pins:
//! bootstrap "network-on-by-default / autoconnect" — the behaviour was
//! CI-proven all along; these are the wire's answers to the shipped caller.
//! Provenance + evidence classes live in `meta.toml` (ADR-0045).
//!
//! [`run_join_sequence`]: rmule_core::run_join_sequence

use rmule_ed2k::IdChange;
use rmule_kad::{Kad2Message, KadDecoded, KadId, decode_exact};
use rmule_primitives::Packet;

const FIXTURE_DIR: &str = "fixtures/join/captured/amule-233-coldstart-join-20260729/";

/// `OP_IDCHANGE` under `OP_EDONKEYPROT` — the eserver's login acceptance.
const OP_IDCHANGE: u8 = 0x40;

fn load(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(FIXTURE_DIR)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn decode_kad(bytes: &[u8]) -> Kad2Message {
    let KadDecoded::Plain(envelope) = decode_exact(bytes).expect("plain Kad envelope") else {
        panic!("cold-start bootstrap frames are plain 0xE4, not packed");
    };
    Kad2Message::decode(&envelope).expect("Kad2 message decodes")
}

/// The aMule's `0x09 KADEMLIA2_BOOTSTRAP_RES` decodes through rmule's own
/// consume path into the sender header + its one genuine routing row — the
/// datagram that flipped the runner's `HasHadContact` latch live.
#[test]
fn amule_bootstrap_res_carries_its_identity_and_its_real_routing_row() {
    let message = decode_kad(&load("kad_bootstrap_res_0x09.bin"));
    let Kad2Message::BootstrapRes { sender, contacts } = message else {
        panic!("expected BootstrapRes, got {message:?}");
    };

    // The counterparty's own header: its persisted Kad ID, its eD2k TCP port,
    // and the Kad2 version a stock 2.3.3 speaks.
    assert_eq!(
        sender.id,
        KadId::from_bytes([
            0x4E, 0xD6, 0x35, 0x56, 0x7E, 0xA6, 0xED, 0x00, 0x70, 0xD0, 0x93, 0xA3, 0xCC, 0xB1,
            0x7D, 0x22,
        ]),
        "the sender header names the aMule's own Kad ID"
    );
    assert_eq!(sender.tcp_port, 4662);
    assert_eq!(sender.version, 8, "stock aMule 2.3.3 speaks Kad2 v8");

    // The answer's contact list is the aMule's entire routing table at that
    // moment: the SEED it had learned live — not an echo of anything the
    // runner sent. Decoding it through rmule's reader also pins the
    // low-octet-first wire IP (047100cb → 203.0.113.4), the byte order the
    // Kad firewall-check capture first corrected.
    assert_eq!(contacts.len(), 1, "one genuine routing row: the seed");
    let contact = &contacts[0];
    assert_eq!(contact.id(), KadId::from_bytes([0x5E; 16]));
    let endpoint = contact.endpoint();
    assert_eq!(endpoint.ip().octets(), [203, 0, 113, 4]);
    assert_eq!(endpoint.udp_port(), 4679);
}

/// The runner's stimulus (kept beside the answer, never evidence): the first
/// dial the ADR-0067 Bootstrap Dial List fired is the empty-payload `0x01`.
#[test]
fn runner_bootstrap_req_is_the_empty_kad2_form() {
    let bytes = load("kad_bootstrap_req_0x01.bin");
    assert_eq!(bytes, [0xE4, 0x01], "proto + opcode, empty payload");
    assert!(matches!(decode_kad(&bytes), Kad2Message::BootstrapReq));
}

/// The eserver's s2c stream contains exactly one `OP_IDCHANGE` — the login
/// acceptance of the server the Join Sequence fetched, persisted, and
/// installed. The assigned id is Low (the runner binds no back-connect
/// listener), which the stream's own port-warning message corroborates.
#[test]
fn eserver_stream_accepts_the_login_with_a_low_id() {
    let mut stream = load("eserver_login_s2c.bin");
    let mut id_changes = Vec::new();
    let mut packets = 0usize;
    while !stream.is_empty() {
        let (packet, consumed) = Packet::decode(&stream).expect("well-framed eD2k packet");
        if packet.opcode() == OP_IDCHANGE {
            id_changes.push(IdChange::decode_packet(&packet).expect("IDCHANGE decodes"));
        }
        packets += 1;
        stream.drain(..consumed);
    }
    assert_eq!(packets, 4, "message + IDCHANGE + status + version message");

    let [accepted] = id_changes.as_slice() else {
        panic!("expected exactly one IDCHANGE, got {}", id_changes.len());
    };
    assert_eq!(accepted.client_id.as_u32(), 2);
    assert!(
        !accepted.client_id.is_high_id(),
        "no back-connect listener bound ⇒ the eserver assigns LowID"
    );
    assert!(
        accepted.tcp_flags.is_some(),
        "Lugdunum's IDCHANGE carries the SRV_TCPFLG grant word"
    );
}

/// Vacuity guards: each decode above is load-bearing, not shape-tolerant.
#[test]
fn corrupted_frames_are_rejected() {
    // A non-Kad protocol byte fails the envelope, not just the message.
    let mut res = load("kad_bootstrap_res_0x09.bin");
    res[0] = 0xE3;
    assert!(decode_exact(&res).is_err(), "wrong protocol byte must fail");

    // Overstating the contact count truncates the row read.
    let mut res = load("kad_bootstrap_res_0x09.bin");
    res[21] = 2; // count LE lives after proto+opcode+id(16)+tcp(2)+version(1)
    let KadDecoded::Plain(envelope) = decode_exact(&res).expect("still a plain envelope") else {
        panic!("still plain");
    };
    assert!(
        Kad2Message::decode(&envelope).is_err(),
        "a count the payload cannot satisfy must fail the message decode"
    );

    // Corrupting the eD2k frame length breaks the stream framing.
    let mut stream = load("eserver_login_s2c.bin");
    stream[1] = 0xFF;
    assert!(
        Packet::decode(&stream).is_err(),
        "an overstated eD2k packet size must fail framing"
    );
}
