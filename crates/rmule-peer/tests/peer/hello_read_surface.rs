//! The hello read surface (docs/protocol/parity/peer-tcp.md *Hello read
//! surface*): every hello aMule's or eMule's reader accepts, rmule accepts and
//! identifies — and what it still refuses, it refuses because no reader could
//! go on, never by allocating on the peer's word.
//!
//! Hellos are bytes in; the decoded hello, the identification and whether the
//! session lives are what come out. Every vector here is **derived** from the
//! two readers' source: no archive holds an MLDonkey, eDonkey Hybrid or
//! pre-tag-era hello, nor a hello with an exotic tag type. The captured hellos
//! are swept at the end.

use rmule_peer::{
    ClientFamily, Hello, HelloAnswer, HelloRefusal, HelloRefusalCode, HelloTrailer, MiscOptions1,
    PeerEvent, PeerIdentity, PeerOutput, PeerPacket, PeerPacketDecodeError, PeerSession,
};
use rmule_primitives::session::drain;
use rmule_primitives::{Packet, PacketProtocol};
use rmule_testkit::peer_session::{peer_at, serverless_ctx};

use crate::fixture::{client_version as v, load};

/// A hash with no client's mark.
const PLAIN_HASH: [u8; 16] = [0x99; 16];

/// An MLDonkey user hash: `M` at 5, `L` at 14.
fn mldonkey_hash() -> [u8; 16] {
    let mut hash = PLAIN_HASH;
    hash[5] = b'M';
    hash[14] = b'L';
    hash
}

/// `CT_NAME` as a compact-name string tag.
fn name_tag(name: &str) -> Vec<u8> {
    let mut tag = vec![0x82, 0x01];
    tag.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    tag.extend_from_slice(name.as_bytes());
    tag
}

/// A compact-name `UINT32` tag.
fn u32_tag(id: u8, value: u32) -> Vec<u8> {
    let mut tag = vec![0x83, id];
    tag.extend_from_slice(&value.to_le_bytes());
    tag
}

/// An `OP_HELLO` frame with `count` declared over `tags`, then the connected
/// server, then `tail`.
fn hello_frame(hash: [u8; 16], count: u32, tags: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut payload = vec![16];
    payload.extend_from_slice(&hash);
    payload.extend_from_slice(&0x0200_0002_u32.to_le_bytes());
    payload.extend_from_slice(&4662_u16.to_le_bytes());
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(tags);
    payload.extend_from_slice(&[0; 6]);
    payload.extend_from_slice(tail);
    Packet::new(PacketProtocol::Edonkey, 0x01, payload).encode()
}

fn decode_hello(frame: &[u8]) -> Result<Hello, rmule_peer::PeerHelloDecodeError> {
    Hello::decode_packet(&Packet::decode_exact(frame).expect("a whole frame"))
}

/// What an accepting session makes of `frame`: the identity it emitted, or
/// `None` when it closed instead.
fn accepted(frame: &[u8]) -> Option<PeerIdentity> {
    let mut session = PeerSession::new_inbound(peer_at(9), serverless_ctx());
    session.handle_bytes(frame);
    let outputs = drain(|| session.poll_output());
    if outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))) {
        return None;
    }
    outputs.into_iter().find_map(|o| match o {
        PeerOutput::Event(PeerEvent::PeerIdentified { identity }) => Some(identity),
        _ => None,
    })
}

#[test]
fn an_mldonkey_hello_with_its_kdlm_word_is_accepted_and_named() {
    let tags = [name_tag("mldonkey"), u32_tag(0x11, 0x3C)].concat();
    let frame = hello_frame(mldonkey_hash(), 2, &tags, b"MLDK");

    let hello = decode_hello(&frame).expect("both references read the word and go on");
    assert_eq!(hello.trailer(), HelloTrailer::MlDonkey);
    let identity = accepted(&frame).expect("the session identifies it and stays open");
    assert_eq!(identity.software().family(), ClientFamily::MlDonkeyOld);
    assert_eq!(identity.software().version(), v(0, 60, 0));
}

#[test]
fn the_kdlm_word_names_mldonkey_even_behind_an_unmarked_hash() {
    let tags = [name_tag("ml"), u32_tag(0x11, 0x3C)].concat();
    let identity = accepted(&hello_frame(PLAIN_HASH, 2, &tags, b"MLDK")).expect("accepted");
    assert_eq!(identity.software().family(), ClientFamily::MlDonkeyOld);
}

#[test]
fn a_mule_hello_with_code_zero_and_the_kdlm_word_is_mldonkey_as_emule_reads_it() {
    let tags = [name_tag("ml"), u32_tag(0xFB, (2 << 17) | (7 << 10))].concat();
    let identity = accepted(&hello_frame(PLAIN_HASH, 2, &tags, b"MLDK")).expect("accepted");
    assert_eq!(identity.software().family(), ClientFamily::MlDonkey);
    assert_eq!(identity.software().version(), v(2, 7, 0));
}

#[test]
fn an_old_edonkey_hybrid_word_is_accepted_and_names_hybrid() {
    let tags = [name_tag("hybrid"), u32_tag(0x11, 10201)].concat();
    let frame = hello_frame(PLAIN_HASH, 2, &tags, &0x1234_5678_u32.to_le_bytes());

    assert_eq!(
        decode_hello(&frame).expect("accepted").trailer(),
        HelloTrailer::Hybrid(0x1234_5678)
    );
    let identity = accepted(&frame).expect("accepted");
    assert_eq!(identity.software().family(), ClientFamily::EdonkeyHybrid);
    assert_eq!(identity.software().version(), v(1, 2, 1));
}

#[test]
fn a_tail_of_any_other_length_is_ignored_as_both_readers_ignore_it() {
    let tags = [name_tag("donkey"), u32_tag(0x11, 0x3C)].concat();
    let bare = accepted(&hello_frame(PLAIN_HASH, 2, &tags, &[])).expect("accepted");
    for tail in [
        &[0x00][..],
        &[1, 2],
        &[1, 2, 3],
        &[1, 2, 3, 4, 5],
        &[0xFF; 6],
    ] {
        let frame = hello_frame(PLAIN_HASH, 2, &tags, tail);
        assert_eq!(
            decode_hello(&frame).expect("accepted").trailer(),
            HelloTrailer::Absent
        );
        assert_eq!(accepted(&frame).as_ref(), Some(&bare), "tail {tail:02x?}");
    }
}

#[test]
fn a_hello_with_its_trailer_reencodes_to_the_peers_bytes() {
    let tags = [name_tag("mldonkey"), u32_tag(0x11, 0x3C)].concat();
    let frame = hello_frame(mldonkey_hash(), 2, &tags, b"MLDK");
    assert_eq!(
        decode_hello(&frame).unwrap().encode_packet().encode(),
        frame
    );
    let answer = HelloAnswer::new(decode_hello(&frame).unwrap().into_body())
        .with_trailer(HelloTrailer::Hybrid(7));
    let read = HelloAnswer::decode_packet(&answer.encode_packet()).unwrap();
    assert_eq!(read.trailer(), HelloTrailer::Hybrid(7));
}

#[test]
fn a_declared_count_of_u32_max_is_refused_without_reserving_for_it() {
    // Four billion tags declared over one: the reader walks the frame and runs
    // out, as both references do, and never sizes a buffer from the word.
    let frame = hello_frame(PLAIN_HASH, u32::MAX, &name_tag("x"), &[]);
    assert!(decode_hello(&frame).is_err());
    assert!(accepted(&frame).is_none(), "the session closes on it");
}

#[test]
fn tags_of_the_types_rmule_never_reads_are_stepped_over() {
    let others = [
        vec![0x84, 0x70, 0, 0, 0x80, 0x3F],             // FLOAT32 1.0
        vec![0x85, 0x71, 0x01],                         // BOOL
        vec![0x86, 0x72, 0x10, 0x00, 0xAA, 0x55, 0x00], // BOOLARRAY of 16: 16/8+1 bytes
        vec![0x87, 0x73, 0x02, 0, 0, 0, 0xDE, 0xAD],    // BLOB of 2
        vec![0x8A, 0x74, 0x01, 0x42],                   // BSOB of 1 (emule-qt)
        [vec![0xA6, 0x75], vec![b'z'; 22]].concat(),    // STR22 (emule-qt)
    ];
    let misc = u32_tag(0xFA, MiscOptions1::rmule_advertised().bits());
    let tags = [
        name_tag("tolerant"),
        others.concat(),
        misc.clone(),
        u32_tag(0xFB, 0x0304_0D80),
    ]
    .concat();
    let frame = hello_frame(PLAIN_HASH, 1 + 6 + 2, &tags, &[]);

    let hello = decode_hello(&frame).expect("both references read every one of them");
    assert_eq!(hello.body().tags.len(), 3, "the six are not kept");
    let identity = accepted(&frame).expect("accepted");
    assert_eq!(identity.software().family(), ClientFamily::Amule);
    assert_eq!(
        MiscOptions1::from_tags(&hello.body().tags),
        Some(MiscOptions1::rmule_advertised()),
        "the tag after them is read at its right offset"
    );
}

#[test]
fn a_tag_name_that_is_not_utf8_is_stepped_over() {
    let odd_name = vec![0x03, 0x02, 0x00, 0xFF, 0xFE, 1, 0, 0, 0];
    let tags = [odd_name, name_tag("latin")].concat();
    let identity = accepted(&hello_frame(PLAIN_HASH, 2, &tags, &[])).expect("accepted");
    assert_eq!(
        identity.nickname().map(|n| n.as_bytes().to_vec()),
        Some(b"latin".to_vec())
    );
}

#[test]
fn a_type_byte_no_client_defines_still_ends_the_connection() {
    // Nobody knows its width, so no later offset is knowable (aMule throws).
    let tags = [name_tag("x"), vec![0xB0, 0x70, 1, 2, 3]].concat();
    assert!(accepted(&hello_frame(PLAIN_HASH, 2, &tags, &[])).is_none());
}

#[test]
fn a_blob_longer_than_the_frame_still_ends_the_connection() {
    let tags = [name_tag("x"), vec![0x87, 0x70, 0xFF, 0xFF, 0xFF, 0x7F, 0]].concat();
    assert!(accepted(&hello_frame(PLAIN_HASH, 2, &tags, &[])).is_none());
}

#[test]
fn a_repeated_tag_is_read_from_its_last_well_typed_copy() {
    let tags = [
        name_tag("first"),
        u32_tag(0xFB, 0x0304_0D80),
        name_tag("second"),
        u32_tag(0xFB, 0x0306_0080),
        // A wrong-typed last copy is passed over, as eMule's `IsInt` does.
        vec![0x82, 0xFB, 0x01, 0x00, b'?'],
        u32_tag(0xFA, 0),
        u32_tag(0xFA, MiscOptions1::rmule_advertised().bits()),
    ]
    .concat();
    let identity = accepted(&hello_frame(PLAIN_HASH, 7, &tags, &[])).expect("accepted");
    assert_eq!(
        identity.nickname().map(|n| n.as_bytes().to_vec()),
        Some(b"second".to_vec())
    );
    assert_eq!(identity.software().version(), v(3, 0, 1));
    assert_eq!(
        identity.extended_requests_version(),
        MiscOptions1::rmule_advertised().extended_requests_version()
    );
}

#[test]
fn a_capability_tag_in_a_compact_integer_is_read() {
    // Both references widen UINT8/UINT16 to UINT32 when they read the tag.
    let tags = [
        name_tag("compact"),
        vec![0x88, 0xFA, 0x00, 0x03], // MiscOptions1 as UINT16: ext-requests 3
        vec![0x88, 0xF9, 0x40, 0x12], // UDP ports as UINT16: client 4672, Kad 0
        vec![0x89, 0x11, 0x3C],       // CT_VERSION as UINT8
    ]
    .concat();
    let identity = accepted(&hello_frame(PLAIN_HASH, 4, &tags, &[])).expect("accepted");
    assert_eq!(identity.extended_requests_version(), 3);
    assert_eq!(identity.protocol_version(), Some(0x3C));
    assert_eq!(identity.software().version(), v(0, 60, 0));
}

#[test]
fn ct_port_overrides_the_port_field_as_both_readers_let_it() {
    let tags = [name_tag("donkey"), vec![0x88, 0x0F, 0x36, 0x12]].concat();
    let identity = accepted(&hello_frame(PLAIN_HASH, 2, &tags, &[])).expect("accepted");
    assert_eq!(identity.tcp_port(), 0x1236);
}

/// Every captured hello in this crate's fixtures: it decodes with no trailer,
/// keeps every tag (nothing stepped over), and re-encodes to its own bytes.
#[test]
fn every_captured_hello_still_reads_as_it_did() {
    for (dir, name) in [
        (
            "fixtures/direct_callback/captured/amule-233-directcallback-20260728",
            "callback_dial_hello_0x01.bin",
        ),
        (
            "fixtures/buddy_callback/captured/amule-233-callback-dialback-20260923",
            "dial_back_hello_0x01.bin",
        ),
        (
            "fixtures/reverse_serve/captured/amule-233-serve-consume-20260726",
            "hello_0x10.bin",
        ),
        (
            "fixtures/client_software/captured/amule-kno-ab483654-helloanswer-20260923",
            "amule_kno_op_helloanswer.bin",
        ),
        ("fixtures/ipv6_dialect", "emuleqt_op_helloanswer_ipv6.bin"),
    ] {
        let frame = load(dir, name);
        let packet = Packet::decode_exact(&frame).expect("a whole frame");
        let decoded = PeerPacket::decode(&packet).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (reencoded, trailer) = match &decoded {
            PeerPacket::Hello(h) => (h.encode_packet(), h.trailer()),
            PeerPacket::HelloAnswer(h) => (h.encode_packet(), h.trailer()),
            other => panic!("{name}: not a hello: {other:?}"),
        };
        assert_eq!(trailer, HelloTrailer::Absent, "{name}");
        assert_eq!(reencoded.encode(), frame, "{name}: byte-faithful");
    }
}

/// kno's answer that counts a tag it never wrote (captured): refused under its
/// own code, naming the nine tags it carried and the mod it wrote, and the
/// session raises the refusal before it closes.
#[test]
fn a_hello_counting_a_tag_it_never_wrote_is_refused_by_name() {
    let frame = load(
        "fixtures/hello_refusal/captured/amule-kno-ab483654-short-count-20260924",
        "amule_kno_op_helloanswer_short_count.bin",
    );
    let packet = Packet::decode_exact(&frame).expect("a whole frame");
    let Err(PeerPacketDecodeError::HelloAnswer { source }) = PeerPacket::decode(&packet) else {
        panic!("the short count must refuse the answer");
    };
    let refusal = HelloRefusal::from_decode_error(&source).expect("named");
    assert_eq!(
        refusal.code,
        HelloRefusalCode::TagCountShort {
            declared: 10,
            written: 9
        }
    );
    assert_eq!(
        refusal.name.map(|n| n.as_bytes().to_vec()),
        Some(b"https://amule-org.github.io".to_vec())
    );
    assert_eq!(
        refusal.client_mod.map(|m| m.as_bytes().to_vec()),
        Some(b"aMule GIT".to_vec())
    );

    let mut session = PeerSession::new_outbound(peer_at(2), serverless_ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&frame);
    let events: Vec<PeerEvent> = drain(|| session.poll_output())
        .into_iter()
        .filter_map(|out| match out {
            PeerOutput::Event(event) => Some(event),
            _ => None,
        })
        .collect();
    let refused = events
        .iter()
        .position(|e| matches!(e, PeerEvent::HelloRefused { .. }))
        .expect("the refusal is raised");
    let closed = events
        .iter()
        .position(|e| matches!(e, PeerEvent::Disconnected { .. }))
        .expect("the session closes");
    assert!(refused < closed);
}

/// A tag block broken some other way keeps its own error: no count below the
/// declared one ends at the connected server.
#[test]
fn a_broken_tag_that_is_not_a_short_count_keeps_its_error() {
    let tags = [name_tag("x"), vec![0xB0, 0x70, 1, 2, 3]].concat();
    let frame = hello_frame(PLAIN_HASH, 2, &tags, &[]);
    let packet = Packet::decode_exact(&frame).expect("a whole frame");
    let Err(PeerPacketDecodeError::Hello { source }) = PeerPacket::decode(&packet) else {
        panic!("refused");
    };
    assert_eq!(HelloRefusal::from_decode_error(&source), None);
}
