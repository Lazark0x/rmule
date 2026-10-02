//! Buddy-relay capture (genuine stock aMule 2.3.3, interop
//! `kad-core-buddy --callback-downloader --callback-walk`, run `1790152605`).
//!
//! Two runs. In `1790152605` a `kad join-node` walker ran one Callback Walk
//! toward the firewalled aMule's own Kad ID and sent it the walk's `0x52`;
//! aMule's
//! `CKademliaUDPListener::ProcessCallbackRequest`
//! (`KademliaUDPListener.cpp:1489-1518`) relayed it as `OP_CALLBACK` over the
//! buddy link it held to rmule's Core-pumped stimulus. The `0x99` is aMule's
//! own bytes and the evidence; the `0x52` is rmule's stimulus, kept beside it
//! so the echo can be checked field by field. In `1790155933` (a `PASS`)
//! the road ran end to end: a download's `0x52` to rmule's buddy, the buddy's
//! `0x99` to aMule, aMule's dial-back and its hello. In `1790185890`
//! the download was a second stock aMule's, so the `0x52` rmule's
//! buddy relayed was aMule-authored too. Provenance and the findings live
//! alongside each fixture in `meta.toml`.

use std::net::Ipv4Addr;

use crate::fixture::load;
use rmule_peer::{Callback, Hello};
use rmule_primitives::{FileHash, Ipv4Endpoint, Packet, UserHash, kad_wire_id};

const FIXTURE_DIR: &str = "fixtures/buddy_callback/captured/amule-233-callback-relay-20260923/";
const DIAL_BACK_DIR: &str =
    "fixtures/buddy_callback/captured/amule-233-callback-dialback-20260923/";
const AMULE_REQUEST_DIR: &str =
    "fixtures/buddy_callback/captured/amule-233-callback-req-relay-20260923/";

/// The stock aMule requester of `1790185890`: its address, the `0x52`'s
/// datagram source, which rmule's buddy injects as the requester.
const AMULE_REQUESTER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

/// The High-ID downloader's fake-public address and listener in `1790155933`.
const DOWNLOADER: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 4662);

/// The walker's fake-public address this run — the `0x52`'s datagram source,
/// which aMule injects as the requester.
const WALKER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 8);

/// The synthetic file both sides shared, as its ed2k link names it.
const FILE_MD4: &str = "8E302DB5B806A25C9385FC23F21062D2";

/// **Counterparty evidence.** aMule's relay echoes the walk's buddy ID and
/// file field byte for byte — the relay rewrites neither — and injects the
/// requester's address as `WriteUInt32` of the Kad listener's **host-order**
/// IP, which puts its octets on the wire reversed. The `0x9A` relay is the
/// other way round: its address comes from the client UDP socket in eD2k
/// order (`ClientUDPSocket.cpp:161`), so the two relays disagree and each
/// codec must follow its own.
#[test]
fn amules_callback_relay_echoes_the_walk_and_reverses_the_requesters_octets() {
    let bytes = load(FIXTURE_DIR, "amule_callback_0x99.bin");
    let (packet, consumed) = Packet::decode(&bytes).expect("the segment is one eMule packet");
    assert_eq!(
        consumed,
        bytes.len(),
        "aMule wrote the relay alone on its link"
    );

    let walk = load(FIXTURE_DIR, "walk_callback_req_0x52.bin");
    let body = packet.payload();
    assert_eq!(
        &body[..32],
        &walk[2..34],
        "the relay echoes the 0x52's buddy ID and file field unchanged"
    );
    assert_eq!(
        &body[32..36],
        &[8, 113, 0, 203],
        "the requester's address rides host-order, octets reversed"
    );

    let relay = Callback::decode_packet(&packet).expect("rmule reads aMule's 0x99");
    assert_eq!(
        relay.requester,
        Ipv4Endpoint::new(WALKER, u16::from_le_bytes([walk[34], walk[35]])),
        "the requester is the walker, at the port its 0x52 named"
    );
    assert_eq!(relay.file_hash, FileHash::from_hex(FILE_MD4).unwrap());
    assert_eq!(
        relay.encode_packet().encode(),
        bytes,
        "rmule's own relay of the same callback is aMule's, byte for byte"
    );
}

/// **Counterparty evidence.** aMule's dial-back hello is its answer to the
/// `0x99` rmule's buddy relayed, and it names the identity aMule published:
/// the User Hash the download's **Dial-Back Claim** is keyed by is the `0x44`
/// row's source ID in Kad word order (`kad_wire_id`). That the hello arrived at
/// all proves the relay's requester field, host-order, named the downloader.
#[test]
fn amules_dial_back_answers_our_relay_and_names_the_identity_it_published() {
    let publish = load(DIAL_BACK_DIR, "publish_source_req_0x44.bin");
    let request = load(DIAL_BACK_DIR, "callback_req_0x52.bin");
    let relay_bytes = load(DIAL_BACK_DIR, "callback_0x99.bin");
    let hello_bytes = load(DIAL_BACK_DIR, "dial_back_hello_0x01.bin");

    let (relay_packet, _) = Packet::decode(&relay_bytes).expect("rmule's relay is one packet");
    assert_eq!(
        &relay_packet.payload()[..32],
        &request[2..34],
        "rmule's buddy echoes the download's 0x52 fields unchanged, as aMule's relay does"
    );
    let relay = Callback::decode_packet(&relay_packet).expect("rmule's 0x99 decodes");
    assert_eq!(
        relay.requester, DOWNLOADER,
        "the relay names the downloader"
    );

    let (hello_packet, consumed) = Packet::decode(&hello_bytes).expect("the hello is a packet");
    assert_eq!(
        consumed,
        hello_bytes.len(),
        "the dial-back's first segment is the hello"
    );
    let hello = Hello::decode_packet(&hello_packet).expect("aMule opens with OP_HELLO");
    let source_id: [u8; 16] = publish[18..34].try_into().unwrap();
    assert_eq!(
        hello.body().user_hash,
        UserHash::from_bytes(kad_wire_id(source_id)),
        "the dial-back names the User Hash the published row carried"
    );
}

/// **Counterparty evidence.** The same relay, reached by a Callback Walk whose
/// `0x52` left obfuscated under aMule's Kad ID (`1790155933`'s aMule tap held
/// no plaintext `0x52` from the walker): aMule decrypted it — its receive path
/// does so whatever its own crypt setting — and relayed it exactly as the
/// plaintext one, naming the walker host-order.
#[test]
fn amule_relays_an_obfuscated_walks_0x52_as_it_does_a_plain_one() {
    let bytes = load(DIAL_BACK_DIR, "walk_relay_0x99.bin");
    let (packet, _) = Packet::decode(&bytes).expect("aMule's relay is one packet");
    let relay = Callback::decode_packet(&packet).expect("rmule reads aMule's 0x99");
    assert_eq!(
        relay.buddy_id,
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF
        ],
        "the walk's target, aMule's own Kad ID, echoed"
    );
    assert_eq!(relay.requester, Ipv4Endpoint::new(WALKER, 4662));
    assert_eq!(relay.encode_packet().encode(), bytes);
}

/// **Relay pinned to a counterparty's request.** rmule's buddy relaying
/// **aMule's own** `0x52` (run `1790185890`): the relay echoes both
/// 128-bit fields byte for byte and names the requester host-order, and the
/// firewalled aMule consumed it — `Remote Client: OP_CALLBACK from
/// 203.0.113.3`, then a SYN onto the requester 0.71 ms after the relay and a
/// byte-equal transfer. The codec, fed what it reads off that `0x52`, writes
/// the captured segment exactly.
#[test]
fn our_relay_of_amules_own_callback_request_is_the_segment_amule_consumed() {
    let request = load(AMULE_REQUEST_DIR, "amule_callback_req_0x52.bin");
    let bytes = load(AMULE_REQUEST_DIR, "rmule_callback_0x99.bin");
    let (packet, consumed) = Packet::decode(&bytes).expect("the relay is one packet");
    assert_eq!(consumed, bytes.len(), "the relay went out alone");
    assert_eq!(
        &packet.payload()[..32],
        &request[2..34],
        "both 128-bit fields cross the relay unchanged"
    );
    assert_eq!(&packet.payload()[32..36], &[7, 113, 0, 203]);

    let relay = Callback {
        buddy_id: request[2..18].try_into().unwrap(),
        file_hash: FileHash::from_hex("009D91607B0D86D64FAFF631E02ED864").unwrap(),
        requester: Ipv4Endpoint::new(
            AMULE_REQUESTER,
            u16::from_le_bytes([request[34], request[35]]),
        ),
    };
    assert_eq!(relay.encode_packet().encode(), bytes);
    assert_eq!(Callback::decode_packet(&packet), Ok(relay));
}
