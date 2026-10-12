//! The **Reask Responder**'s rules, each driven by captured datagrams: aMule's
//! own `0x90` from interop flow L (`amule-233-peer-udp-reask-20260727`) as the
//! stimulus, and as the expected answers aMule's own `0x91`
//! (`amule-233-reask-ack-to-rmule-20261001`), `0x92` and `0x93`
//! (`amule-233-reask-answers-20260729`) — the responder must say what aMule
//! said in the same position, byte for byte.
//!
//! No capture holds a malformed ping, so the cut-short pings below are the
//! captured one cut at the field boundaries aMule's reader throws on.

use crate::fixture::{AMULE_USER_HASH, FILE_HASH, load};
use rmule_peer::PartBitmap;
use rmule_peer::peer_udp::crypt::PeerUdpCryptTarget;
use rmule_peer::peer_udp::responder::{
    self, KnownWaiter, Pinger, QueueRoom, ReaskAnswer, ReaskReply, Silence, Standing,
};
use rmule_primitives::{CryptStance, FileHash, UserHash};

const PING_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-peer-udp-reask-20260727/";
const ANSWERS_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-reask-answers-20260729/";
const AMULE_ACK_DIR: &str =
    "fixtures/peer_udp_reask/captured/amule-233-reask-ack-to-rmule-20261001/";

/// The synthetic shared file the ping names: 40 MiB, five ED2K parts.
const FILE_SIZE: u64 = 40 * 1024 * 1024;

/// aMule's default queue (`QueueSizePref` 50, so 5000 places), empty.
const ROOMY: QueueRoom = QueueRoom {
    waiting: 0,
    max: 5000,
};

/// The reasking aMule as its hello identifies it in the crypt runs:
/// `MiscOptions2` `0x5B8`, supporting and requesting the layer.
fn amule_target() -> PeerUdpCryptTarget {
    PeerUdpCryptTarget::new(
        UserHash::from_bytes(AMULE_USER_HASH),
        CryptStance::new(true, true, false),
    )
}

/// The reasker as the queue knows it: waiting for the file its ping names,
/// at the head of the queue.
fn waiter(udp_version: u8, extended_requests: u8) -> Pinger {
    Pinger::Known(KnownWaiter {
        waiting_for: FileHash::from_bytes(FILE_HASH),
        rank: 1,
        udp_version,
        extended_requests,
        crypt_target: Some(amule_target()),
    })
}

fn amules_ping() -> Vec<u8> {
    load(PING_DIR, "reask_ping_0x90.bin")
}

/// What the captured ping says of the pinger's own parts: five, two held.
fn amules_status() -> PartBitmap {
    PartBitmap::decode(5, &[0x12]).expect("the captured status decodes")
}

fn answer(datagram: &[u8], pinger: Pinger, room: QueueRoom, shared: Option<u64>) -> ReaskAnswer {
    let ping = responder::read(datagram).expect("a ping naming a file");
    responder::answer(&ping, &pinger, room, shared)
}

fn send(datagram: Vec<u8>, encrypt_for: Option<PeerUdpCryptTarget>) -> ReaskReply {
    ReaskReply::Send {
        datagram,
        encrypt_for,
    }
}

/// A UDPv4 waiter asking about its own file is answered exactly as stock aMule
/// answered rmule in the same position: our complete-source status (the count
/// `0` alone) ahead of rank 1 — and the status its ping restated is handed
/// back for the queue to record.
#[test]
fn a_udpv4_waiters_ping_is_answered_as_amule_answers_one() {
    let ping = amules_ping();
    assert_eq!(
        responder::read(&ping).map(|ping| ping.file_hash()),
        Some(FileHash::from_bytes(FILE_HASH))
    );
    assert_eq!(
        answer(&ping, waiter(4, 2), ROOMY, Some(FILE_SIZE)),
        ReaskAnswer {
            reply: send(
                load(AMULE_ACK_DIR, "reask_ack_0x91.bin"),
                Some(amule_target())
            ),
            standing: Standing::Restated(Some(amules_status())),
        }
    );
}

/// The sender is resolved before the file: the not-found answer is aMule's
/// captured `0x92`, carrying a known waiter's identity so it may leave
/// obfuscated, and no identity for anyone else.
#[test]
fn an_unshared_file_is_not_found_for_the_sender_resolved_first() {
    let not_found = load(ANSWERS_DIR, "filenotfound_0x92.bin");
    for (pinger, encrypt_for) in [
        (waiter(4, 2), Some(amule_target())),
        (Pinger::Ambiguous, None),
        (Pinger::Unknown, None),
    ] {
        assert_eq!(
            answer(&amules_ping(), pinger, ROOMY, None),
            ReaskAnswer {
                reply: send(not_found.clone(), encrypt_for),
                standing: Standing::Untouched,
            }
        );
    }
}

/// An unknown pinger finds the queue full only while `waiting + 50 > max`.
/// The captured `0x93` came from an aMule with `QueueSizePref=0`, so its
/// condition was `0 + 50 > 0`.
#[test]
fn an_unknown_pinger_finds_the_queue_full_only_within_fifty_of_the_maximum() {
    let queue_full = load(ANSWERS_DIR, "queuefull_0x93.bin");
    let unknown = |waiting, max| {
        answer(
            &amules_ping(),
            Pinger::Unknown,
            QueueRoom { waiting, max },
            Some(FILE_SIZE),
        )
    };
    let full = ReaskAnswer {
        reply: send(queue_full, None),
        standing: Standing::Untouched,
    };
    assert_eq!(unknown(0, 0), full);
    assert_eq!(unknown(1, 50), full);
    assert_eq!(
        unknown(0, 50),
        ReaskAnswer {
            reply: ReaskReply::Silent(Silence::UnknownWithRoom),
            standing: Standing::Untouched,
        }
    );
}

/// A waiter queued for another file, and an IP several waiters share, hear
/// nothing and leave the queue untouched.
#[test]
fn a_waiter_for_another_file_and_an_ambiguous_ip_hear_silence() {
    let elsewhere = Pinger::Known(KnownWaiter {
        waiting_for: FileHash::from_bytes([0xEE; 16]),
        rank: 1,
        udp_version: 4,
        extended_requests: 2,
        crypt_target: Some(amule_target()),
    });
    for (pinger, why) in [
        (elsewhere, Silence::OtherFile),
        (Pinger::Ambiguous, Silence::AmbiguousIp),
    ] {
        assert_eq!(
            answer(&amules_ping(), pinger, ROOMY, Some(FILE_SIZE)),
            ReaskAnswer {
                reply: ReaskReply::Silent(why),
                standing: Standing::Untouched,
            }
        );
    }
}

/// A UDPv3 waiter's ping is read for its complete-source count alone, right
/// after the hash, and answered with the rank alone — the shape captured in
/// the 2026-07-27 run. The hash alone throws that read: silence, the standing
/// still heard.
#[test]
fn a_udpv3_waiter_is_read_for_its_complete_count_and_answered_by_rank_alone() {
    let ping = amules_ping();
    assert_eq!(
        answer(&ping, waiter(3, 2), ROOMY, Some(FILE_SIZE)),
        ReaskAnswer {
            reply: send(load(PING_DIR, "reask_ack_0x91.bin"), Some(amule_target())),
            standing: Standing::Heard,
        }
    );
    let hash_only = &ping[..2 + 16];
    assert_eq!(
        answer(hash_only, waiter(3, 2), ROOMY, Some(FILE_SIZE)),
        ReaskAnswer {
            reply: ReaskReply::Silent(Silence::Malformed),
            standing: Standing::Heard,
        }
    );
}

/// A UDPv4 waiter's ping is read as far as its hello's extended-requests claim
/// asks (stock 2.3.3 `UploadClient.cpp:397-456`): a claim of `0` reads nothing
/// and clears the status; a claim of `1` stops after the status; a claim of
/// `2` also reads the complete-source count. Cut short of what its claim
/// reads, the ping is silenced, and what was read before the throw stays.
#[test]
fn a_udpv4_ping_is_read_as_far_as_its_waiters_claim() {
    let ping = amules_ping();
    let ack = load(AMULE_ACK_DIR, "reask_ack_0x91.bin");
    let hash_only = &ping[..2 + 16];
    let no_count = &ping[..ping.len() - 2];
    let answered = |standing| ReaskAnswer {
        reply: send(ack.clone(), Some(amule_target())),
        standing,
    };
    let silenced = |standing| ReaskAnswer {
        reply: ReaskReply::Silent(Silence::Malformed),
        standing,
    };

    assert_eq!(
        answer(hash_only, waiter(4, 0), ROOMY, Some(FILE_SIZE)),
        answered(Standing::Restated(None))
    );
    assert_eq!(
        answer(hash_only, waiter(4, 2), ROOMY, Some(FILE_SIZE)),
        silenced(Standing::Restated(None))
    );
    assert_eq!(
        answer(no_count, waiter(4, 1), ROOMY, Some(FILE_SIZE)),
        answered(Standing::Restated(Some(amules_status())))
    );
    assert_eq!(
        answer(no_count, waiter(4, 2), ROOMY, Some(FILE_SIZE)),
        silenced(Standing::Restated(Some(amules_status())))
    );
}

/// Only a datagram long enough to name a file is a ping; anything else is
/// dropped before anyone is resolved.
#[test]
fn a_datagram_naming_no_file_is_not_a_ping() {
    let ping = amules_ping();
    assert!(responder::read(&ping[..2 + 15]).is_none());
    assert!(responder::read(&load(ANSWERS_DIR, "queuefull_0x93.bin")).is_none());
}
