//! The **Reask Requester**'s rules on captured datagrams. The bench run where
//! stock aMule queued rmule and answered its UDP reask
//! (`amule-233-reask-ack-to-rmule-20261001`) holds both directions: the ping
//! rmule framed and the ack aMule wrote back. aMule's refusals come from
//! `amule-233-reask-answers-20260729`, and the rank-only ack shape from
//! `amule-233-peer-udp-reask-20260727`. The reask through a buddy, and the
//! firewalled aMule's answer to it, come from
//! `amule-233-reask-via-buddy-20261019`.

use crate::fixture::load;
use rmule_peer::PartBitmap;
use rmule_peer::peer_udp::requester::{self, HeardReply, IgnoredReply};
use rmule_primitives::FileHash;

const AMULE_ACK_DIR: &str =
    "fixtures/peer_udp_reask/captured/amule-233-reask-ack-to-rmule-20261001/";
const ANSWERS_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-reask-answers-20260729/";
const RANK_ONLY_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-peer-udp-reask-20260727/";
const VIA_BUDDY_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-reask-via-buddy-20261019/";

/// The file rmule was downloading in the bench run: 40 MiB, five ED2K parts.
const FILE_HASH: [u8; 16] = [
    0x06, 0x81, 0x8E, 0xCF, 0xAF, 0xD5, 0xEC, 0x44, 0x00, 0xD2, 0x8A, 0x53, 0xD7, 0xF8, 0x66, 0xD5,
];
const FILE_SIZE: u64 = 40 * 1024 * 1024;

/// The UDP version both ends advertised in the bench run.
const UDP_V4: u8 = 4;

/// To a UDPv4 sharer, the ping is the captured one byte for byte: the hash,
/// our status (holding nothing yet) and a complete-source count of `0`.
#[test]
fn the_ping_to_a_udpv4_sharer_is_the_captured_one() {
    assert_eq!(
        requester::ping(FileHash::from_bytes(FILE_HASH), UDP_V4, UDP_V4, || {
            PartBitmap::downloader_empty(FILE_SIZE)
        }),
        load(AMULE_ACK_DIR, "reask_ping_0x90.bin")
    );
}

/// The `0x94` through a buddy carries that same ping after the buddy-ID: the
/// tail a buddy relays as `0x9A`, re-framed as the firewalled source reads it,
/// is the captured `0x90` byte for byte (stock 2.3.3
/// `DownloadClient.cpp:1297-1318`).
#[test]
fn the_reask_through_a_buddy_relays_the_captured_ping() {
    let buddy_id = [0xB0; rmule_peer::BUDDY_ID_LEN];
    let datagram = requester::ping_via_buddy(
        buddy_id,
        FileHash::from_bytes(FILE_HASH),
        UDP_V4,
        UDP_V4,
        || PartBitmap::downloader_empty(FILE_SIZE),
    );
    let relayed = rmule_peer::ReaskCallbackUdp::decode_udp(&datagram).expect("a 0x94");
    assert_eq!(relayed.buddy_id, buddy_id);
    assert_eq!(
        rmule_peer::peer_udp::responder::relayed_ping(&relayed.forwarded),
        load(AMULE_ACK_DIR, "reask_ping_0x90.bin")
    );
}

/// The bench run where rmule, queued at a firewalled stock aMule and then
/// unreachable, reasked it through its buddy: the `0x94` is what the
/// requester frames for that run's file and buddy, and the aMule's answer to
/// the relayed reask reads as rank 1 (stock 2.3.3 `ClientTCPSocket.cpp:1695-1760`).
#[test]
fn the_firewalled_amule_answers_the_reask_relayed_through_its_buddy() {
    let buddy_id = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];
    let file_hash = [
        0x47, 0xAA, 0xA3, 0xAA, 0x0E, 0x7E, 0x07, 0x1F, 0xFF, 0xF6, 0xCC, 0x9A, 0xF5, 0xEB, 0x1E,
        0xCA,
    ];
    assert_eq!(
        requester::ping_via_buddy(
            buddy_id,
            FileHash::from_bytes(file_hash),
            UDP_V4,
            UDP_V4,
            || PartBitmap::downloader_empty(30 * 1024 * 1024),
        ),
        load(VIA_BUDDY_DIR, "reask_callback_udp_0x94.bin")
    );
    assert_eq!(
        requester::read_reply(
            &load(VIA_BUDDY_DIR, "reask_ack_0x91.bin"),
            UDP_V4,
            Some(UDP_V4)
        ),
        HeardReply::Rank {
            rank: 1,
            part_status: Some(PartBitmap::complete_source_sentinel()),
        }
    );
}

/// aMule's `0x91` to that ping reads as rank 1 with its complete-source status,
/// because both ends are UDPv4. Read as if one end were not UDPv4, it is
/// misframed.
#[test]
fn amules_ack_reads_as_rank_and_status_when_both_ends_are_udpv4() {
    let ack = load(AMULE_ACK_DIR, "reask_ack_0x91.bin");
    assert_eq!(
        requester::read_reply(&ack, UDP_V4, Some(UDP_V4)),
        HeardReply::Rank {
            rank: 1,
            part_status: Some(PartBitmap::complete_source_sentinel()),
        }
    );
    assert_eq!(
        requester::read_reply(&ack, 0, Some(UDP_V4)),
        HeardReply::Ignored(IgnoredReply::Misframed)
    );
}

/// A rank-only ack is what an uploader writes when either end is below UDPv4,
/// so it reads from a UDPv3 source. Between two UDPv4 ends it is misframed:
/// the defect the 2026-07-27 capture recorded.
#[test]
fn a_rank_only_ack_reads_only_where_one_end_is_below_udpv4() {
    let rank_only = load(RANK_ONLY_DIR, "reask_ack_0x91.bin");
    assert_eq!(
        requester::read_reply(&rank_only, UDP_V4, Some(3)),
        HeardReply::Rank {
            rank: 1,
            part_status: None,
        }
    );
    assert_eq!(
        requester::read_reply(&rank_only, UDP_V4, Some(UDP_V4)),
        HeardReply::Ignored(IgnoredReply::Misframed)
    );
}

/// aMule's `0x93` and `0x92` read as what they say, from a source we reask;
/// from an endpoint no source sits at they change nothing.
#[test]
fn amules_refusals_read_from_a_source_we_reask() {
    let queue_full = load(ANSWERS_DIR, "queuefull_0x93.bin");
    let not_found = load(ANSWERS_DIR, "filenotfound_0x92.bin");
    assert_eq!(
        requester::read_reply(&queue_full, UDP_V4, Some(UDP_V4)),
        HeardReply::QueueFull
    );
    assert_eq!(
        requester::read_reply(&not_found, UDP_V4, Some(UDP_V4)),
        HeardReply::FileNotFound
    );
    for reply in [queue_full, not_found] {
        assert_eq!(
            requester::read_reply(&reply, UDP_V4, None),
            HeardReply::Ignored(IgnoredReply::UnknownSource)
        );
    }
}

/// A datagram shorter than its header, or one that is no reply at all — a
/// ping arriving where replies are read — names its reason, whoever sent it.
#[test]
fn what_is_not_a_reply_says_why() {
    let queue_full = load(ANSWERS_DIR, "queuefull_0x93.bin");
    let ping = load(AMULE_ACK_DIR, "reask_ping_0x90.bin");
    for source in [Some(UDP_V4), None] {
        assert_eq!(
            requester::read_reply(&queue_full[..1], UDP_V4, source),
            HeardReply::Ignored(IgnoredReply::Runt)
        );
        assert_eq!(
            requester::read_reply(&ping, UDP_V4, source),
            HeardReply::Ignored(IgnoredReply::UnexpectedOpcode)
        );
    }
}
