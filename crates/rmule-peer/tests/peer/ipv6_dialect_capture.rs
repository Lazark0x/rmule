//! Golden vectors from the IPv6 dialect bench (ADR-0087 / ADR-0092 `ipv6-hello-tags`,
//! `ipv6-extsx` and `ipv6-extsx-kno`): two real `OP_HELLOANSWER` frames drawn
//! over IPv6 from the dialect's two counterparty bodies, and each body's source
//! answer about a requester that named its IPv6, promoted with their body
//! prefixes. `ipv6-extsx-emit` adds emule-qt's own `0xA4` name ask to rmule,
//! whose `0x58` sub carries its part status at extended-requests level 1, and
//! `ipv6-download-rung0` emule-qt's record of a Low-ID source with its server
//! and IPv6 half — the input to a download's rung 0.
//!
//! They are kept together because what they prove is a *contrast*. emule-qt
//! `73fff714` answers with a whole tag block carrying `CT_MOD_IP_V6`, so the
//! reader must produce a peer with an IPv6 address. kno's aMule `ab483654`
//! answers with a tag block whose declared count is one more than it carries —
//! `SendHelloTypePacket()` counts the tag and emits it through
//! `CTag::WriteTagToFile(data)`, whose `restrictive` default silently refuses a
//! `TAGTYPE_HASH16` tag — so the reader must **refuse** it rather than read the
//! trailing connected-server endpoint as a tenth tag. A reader lenient enough to
//! accept the second would be reading six bytes of address as a tag header.

use std::net::Ipv4Addr;

use rmule_peer::{
    AnswerSources, AnswerSources2, ExtendedRequests, HelloAnswer, MultiPacketRequest, PartBitmap,
    PeerIdentity, RequestItem, SourceExchangeVersion,
};
use rmule_primitives::{ClientId, FileHash, Ipv4Endpoint, Packet, PeerSource, UserHash};

/// emule-qt's answer to an IPv6 dial, 2026-09-21 bench run `1789992543`.
const EMULEQT: &[u8] = include_bytes!("../fixtures/ipv6_dialect/emuleqt_op_helloanswer_ipv6.bin");

/// kno's aMule's answer to the same dial, same run — the tag-count overrun.
const AMULE_KNO: &[u8] =
    include_bytes!("../fixtures/ipv6_dialect/amule_kno_op_helloanswer_ipv6_tagcount_overrun.bin");

#[test]
fn emule_qt_names_its_own_ipv6_in_the_hello_answer() {
    let packet = Packet::decode_exact(EMULEQT).expect("the captured frame is a whole packet");
    let answer = HelloAnswer::decode_packet(&packet).expect("emule-qt's answer decodes");
    let identity = PeerIdentity::from_hello_body(answer.body());

    assert_eq!(
        identity.peer_ipv6(),
        Some("3fff:ed2:1::3".parse().expect("the address in the tag")),
        "CT_MOD_IP_V6 names the address the body held on the bench WAN",
    );
    assert_eq!(
        identity.reflected_ipv6(),
        Some("3fff:ed2:1::6".parse().expect("the reflected address")),
        "CT_MOD_YOUR_IP reflects the address rmule advertised — one Address \
         Observation vote, never an adopted address",
    );
    let claim = identity
        .mod_misc_options()
        .expect("emule-qt sends a Static Capability Claim");
    assert!(claim.supports_ipv6(), "the IPv6 claim bit rides the word");
    assert!(claim.supports_ext_sx(), "so does ExtSX");
}

#[test]
fn a_tag_block_shorter_than_its_own_count_is_refused() {
    let packet = Packet::decode_exact(AMULE_KNO).expect("the captured frame is a whole packet");
    // Ten tags declared, nine carried: the six bytes left are the connected-
    // server endpoint, and a reader that took them for a tenth tag would read
    // an address as a tag header.
    assert_eq!(
        u32::from_le_bytes(
            packet.payload()[22..26]
                .try_into()
                .expect("the tag count sits at body offset 22")
        ),
        10,
    );
    assert!(
        HelloAnswer::decode_packet(&packet).is_err(),
        "kno's answer must not decode: its declared tag count overruns its own block",
    );
}

/// emule-qt's `OP_ANSWERSOURCES2` to a bundled source ask, 2026-09-23 bench run
/// `1790195410`: one ExtSX record describing a requester queued on its
/// shared file, whose hello had named `3fff:ed2:1::7`.
const EMULEQT_EXTSX: &[u8] = include_bytes!(
    "../fixtures/source_exchange/captured/emule-qt-73fff714-extsx-ipv6-20260923/\
     emuleqt_op_answersources2_extsx_ipv6.bin"
);

#[test]
fn emule_qt_carries_a_queued_peers_ipv6_in_an_extsx_record() {
    let packet = Packet::decode_exact(EMULEQT_EXTSX).expect("the captured frame is a whole packet");
    let answer =
        AnswerSources2::decode_ext_packet(&packet).expect("emule-qt's ExtSX answer decodes");

    assert_eq!(
        answer.version,
        SourceExchangeVersion::V1,
        "ExtSX pins the version at 1"
    );
    assert_eq!(
        answer.file_hash,
        FileHash::from_bytes(0x879B_7240_FE00_815F_5431_AE70_86B8_C939_u128.to_be_bytes()),
    );
    let [record] = answer.sources.as_slice() else {
        panic!(
            "exactly one queued requester to describe: {:?}",
            answer.sources
        );
    };
    assert_eq!(
        record.ipv6().map(|endpoint| endpoint.to_string()),
        Some("[3fff:ed2:1::7]:4662".to_owned()),
        "CT_MOD_IP_V6 names the queued requester's own hello address, at the record's port",
    );
    assert_eq!(
        record.user_hash(),
        Some(UserHash::from_bytes([0x51; 16])),
        "CT_EMULE_USERHASH rides because the asker claimed EXTXS_SKIPTAGS",
    );
    // emule-qt writes htonl(userIDHybrid), and a peer that said id 0 in its
    // hello stays 0 — not the Low-ID placeholder rmule writes for an
    // IPv6-only source. The IPv4 half is therefore a Low ID with no server.
    assert_eq!(record.client_id(), Some(ClientId::from_u32(0)));
    assert_eq!(
        record.server(),
        None,
        "no server session, so no SERVERIP/SERVERTCP"
    );
    assert_eq!(
        record.crypt_options(),
        None,
        "a zero crypt byte is omitted, not sent"
    );
}

/// kno's aMule's `OP_ANSWERSOURCES` to rmule's standalone source ask,
/// 2026-09-23 bench run `1790202601`: the same question emule-qt
/// answered with an ExtSX record, about a requester queued over IPv4 whose
/// hello had named `3fff:ed2:1::8`.
const AMULE_KNO_SX1: &[u8] = include_bytes!(
    "../fixtures/source_exchange/captured/amule-kno-ab483654-sx1-no-ipv6-20260923/\
     amule_kno_op_answersources_dualstack_no_ipv6.bin"
);

#[test]
fn amule_kno_lists_a_dual_stack_source_by_its_ipv4_alone() {
    let packet = Packet::decode_exact(AMULE_KNO_SX1).expect("the captured frame is a whole packet");
    // No version byte on the SX1 opcode: read at kno's own claimed nibble, 3.
    let answer = AnswerSources::decode_packet(&packet, 3).expect("kno's classic answer decodes");

    let [record] = answer.sources.as_slice() else {
        panic!(
            "exactly one queued requester to describe: {:?}",
            answer.sources
        );
    };
    assert_eq!(
        record.source().peer_source(),
        Some(PeerSource::HighId(Ipv4Endpoint::new(
            [45, 55, 200, 8].into(),
            4662
        ))),
        "the requester's IPv4 hybrid id, at its listen port",
    );
    assert_eq!(record.user_hash(), Some(UserHash::from_bytes([0x51; 16])));
    assert_eq!(
        record.ipv6(),
        None,
        "a classic record has nowhere to put the IPv6 the requester's hello named",
    );
}

/// emule-qt's `0xA4` to rmule in run `1790220663`: its name sub
/// carries its part status because rmule claims extended-requests 1.
const EMULEQT_V1_NAME_ASK: &[u8] = include_bytes!(
    "../fixtures/multipacket/captured/emule-qt-73fff714-v1-name-ask-20260924/request_multipacket_ext_0xa4.bin"
);

/// The status is read only at the session's level: at 1 the walker takes
/// `<u16 count><bitmap>` into the name sub, which is what rmule's needed-part
/// filter reads; at 0 the walk stops on the count's first byte and every ask
/// after the name is lost.
#[test]
fn emule_qt_writes_its_part_status_into_the_name_sub_at_level_one() {
    let packet = Packet::decode_exact(EMULEQT_V1_NAME_ASK).expect("one whole frame");
    let request = MultiPacketRequest::decode_packet(&packet, ExtendedRequests::negotiated(1, 2))
        .expect("the bundle decodes at level 1");

    assert_eq!(request.file_size, Some(1_048_576));
    assert_eq!(
        request.items,
        vec![
            RequestItem::Name {
                part_status: Some(PartBitmap::downloader_empty(1_048_576)),
            },
            RequestItem::SetReqId,
            RequestItem::Sources2 {
                version: 1,
                options: 0,
            },
            RequestItem::AichRoot,
        ],
    );
    assert!(request.unknown_sub.is_none());
    assert_eq!(request.encode_packet().encode(), EMULEQT_V1_NAME_ASK);

    let at_level_zero = MultiPacketRequest::decode_packet(&packet, ExtendedRequests::NONE)
        .expect("the walker stops, it does not fail");
    assert_eq!(
        at_level_zero.items,
        vec![RequestItem::Name { part_status: None }]
    );
    assert_eq!(
        at_level_zero.unknown_sub.map(|sub| sub.opcode),
        Some(0x01),
        "the status count's low byte read as a sub-opcode ends the walk",
    );
}

/// emule-qt's answer about a Low-ID requester that named its IPv6 and our
/// server, run `1790223875`.
const EMULEQT_EXTSX_LOWID_SERVER: &[u8] = include_bytes!(
    "../fixtures/source_exchange/captured/emule-qt-73fff714-extsx-lowid-server-ipv6-20260924/emuleqt_op_answersources2_extsx_lowid_server_ipv6.bin"
);

/// The only record shape that reaches a download as a Low-ID candidate that
/// still carries its IPv6 half: a Low ID, the server it is on, and the half.
#[test]
fn emule_qt_describes_a_low_id_source_with_its_server_and_ipv6_half() {
    let packet = Packet::decode_exact(EMULEQT_EXTSX_LOWID_SERVER).expect("one whole frame");
    let answer =
        AnswerSources2::decode_ext_packet(&packet).expect("emule-qt's ExtSX answer decodes");
    let [record] = answer.sources.as_slice() else {
        panic!("one queued requester to describe: {:?}", answer.sources);
    };

    let id = record.client_id().expect("the record names an IPv4 id");
    assert_eq!(id, ClientId::from_u32(0x00AA_AA00));
    assert!(id.is_low_id());
    assert_eq!(
        record.server(),
        Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 5), 4661)),
    );
    assert_eq!(
        record.ipv6().map(|endpoint| endpoint.to_string()),
        Some("[3fff:ed2:1::7]:4662".to_owned()),
    );
    assert_eq!(record.user_hash(), Some(UserHash::from_bytes([0x4C; 16])));
}
