//! Remote-queue unit tests over the reask ladder: the UDP ping leading the
//! TCP full ask, the latch barring a second ping, the grace fallthrough, each
//! reask reply shape (ack, queue-full, file-not-found, unknown source), the
//! gates that take a source straight to TCP (our UDP disabled, a firewalled
//! downloader, no UDP contact, no high ID and no open Kad), and the
//! insertion-order sweep.

use std::net::Ipv4Addr;

use rmule_peer::{PartBitmap, ReaskAck, file_not_found_datagram, queue_full_datagram};
use rmule_primitives::{Ipv4Endpoint, Ipv6Endpoint};

use super::*;
use crate::reachability::TcpReachability;

fn peer(n: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, n), 4662))
}

/// A `0x91 OP_REASKACK` as an uploader sharing the finished file sends it to
/// a UDPv4 pinger: its part status — aMule's part-count-0 complete-source
/// sentinel — rides ahead of the rank (`udp_capable_pool` advertises our
/// version 4, so this is the wire form we decode).
fn v4_ack(rank: u16) -> Vec<u8> {
    v4_ack_with(PartBitmap::complete_source_sentinel(), rank)
}

fn v4_ack_with(part_status: PartBitmap, rank: u16) -> Vec<u8> {
    ReaskAck {
        part_status: Some(part_status),
        rank,
    }
    .encode_udp()
}

/// The source's client-UDP endpoint: same IP as its TCP endpoint, a distinct
/// UDP port. Version 4 (UDPv4) so the ping carries the full body.
fn udp_contact(n: u8) -> UdpContact {
    UdpContact {
        endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, n), 5000)),
        version: 4,
    }
}

/// A pool with our own reask capabilities fully live (UDP enabled, reachable
/// via server High-ID, UDPv4) — the setup under which the UDP-first path is
/// reachable. The Kad verdict is left firewalled so the High-ID route alone
/// carries the gate.
fn udp_capable_pool() -> RemoteQueuedPool {
    RemoteQueuedPool::new(true)
}

/// `FILE_REASK_TIME − UDP_REASK_LEAD`: the instant, past the reask clock, the
/// UDP ping becomes due.
fn udp_due() -> Duration {
    FILE_REASK_TIME - UDP_REASK_LEAD
}

#[test]
fn the_udp_reask_ping_leads_the_tcp_full_ask() {
    // Invariant, not a constant echo: the UDP ping must fire strictly before
    // the TCP full ask, or the 20 s grace inverts and the lead computation
    // underflows (ADR-0057 / aMule Constants.h).
    assert!(FILE_REASK_TIME > UDP_REASK_LEAD);
}

#[test]
fn no_reask_before_the_udp_window_opens() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);
    // One second short of the UDP window: nothing is due yet.
    let actions = pool.tick(base + udp_due() - Duration::from_secs(1), true);
    assert_eq!(actions, vec![]);
    assert_eq!(pool.udp_pending(peer(1)), Some(false));
}

#[test]
fn udp_ping_fires_first_and_the_latch_bars_a_second_ping() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);

    // At period − 20 s the UDP ping fires to the source's UDP endpoint,
    // version-tagged, and the latch is set.
    let actions = pool.tick(base + udp_due(), true);
    assert_eq!(
        actions,
        vec![ReaskAction::UdpPing {
            peer: peer(1),
            udp_endpoint: udp_contact(1).endpoint,
            udp_version: 4,
        }]
    );
    assert_eq!(pool.udp_pending(peer(1)), Some(true));

    // A second tick still inside the window re-pings nothing — the latch
    // holds one ping in flight.
    let again = pool.tick(base + udp_due() + Duration::from_secs(5), true);
    assert_eq!(again, vec![]);
}

#[test]
fn silence_falls_through_to_the_tcp_full_ask_after_the_grace() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);

    // UDP ping at period − 20 s, then silence.
    let _ = pool.tick(base + udp_due(), true);
    // At the full period the TCP full ask fires — the lost datagram cost the
    // 20 s grace, not the standing — refreshing the clock and resetting the
    // latch.
    let fallback = pool.tick(base + FILE_REASK_TIME, true);
    assert_eq!(fallback, vec![ReaskAction::TcpFullAsk { peer: peer(1) }]);
    assert_eq!(pool.udp_pending(peer(1)), Some(false));

    // The refreshed clock re-opens the next cycle: a UDP ping one period on.
    let next = pool.tick(base + FILE_REASK_TIME + udp_due(), true);
    assert_eq!(
        next,
        vec![ReaskAction::UdpPing {
            peer: peer(1),
            udp_endpoint: udp_contact(1).endpoint,
            udp_version: 4,
        }]
    );
}

#[test]
fn a_reask_ack_records_the_rank_refreshes_the_clock_and_cancels_the_fallback() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);
    let _ = pool.tick(base + udp_due(), true); // UDP ping out, latch set.

    // The uploader answers 0x91 with a new rank 3 behind its complete-source
    // sentinel. The reply lands two seconds after the ping.
    let reply_at = base + udp_due() + Duration::from_secs(2);
    let outcome = pool.on_reply_datagram(reply_at, udp_contact(1).endpoint, &v4_ack(3));
    assert_eq!(
        outcome,
        ReplyOutcome::RankRecorded {
            peer: peer(1),
            rank: 3,
            complete: Some(true),
        }
    );
    assert_eq!(pool.rank(peer(1)), Some(3));
    assert_eq!(pool.is_queue_full(peer(1)), Some(false));
    assert_eq!(pool.udp_pending(peer(1)), Some(false));

    // The reply refreshed the clock, so the TCP full ask that would have
    // fired at the original period no longer does.
    assert_eq!(pool.tick(base + FILE_REASK_TIME, true), vec![]);
    // The next reask cycle is measured from the reply, not the original enter.
    let next = pool.tick(reply_at + udp_due(), true);
    assert_eq!(
        next,
        vec![ReaskAction::UdpPing {
            peer: peer(1),
            udp_endpoint: udp_contact(1).endpoint,
            udp_version: 4,
        }]
    );
}

/// Only the sentinel names a complete source (ADR-0108; stock 2.3.3
/// `DownloadClient.cpp:405-409`, `:428`, eMule `DownloadClient.cpp:516`): an
/// uploader that spells out every part of a three-part file is a part file
/// whose last part arrived, and one missing a part is plainly not complete.
#[test]
fn a_reask_ack_names_a_complete_source_only_by_the_sentinel() {
    let base = Instant::now();
    for (status, complete) in [
        (PartBitmap::decode(3, &[0b0000_0111]).unwrap(), false),
        (PartBitmap::decode(3, &[0b0000_0101]).unwrap(), false),
        (PartBitmap::complete_source_sentinel(), true),
    ] {
        let mut pool = udp_capable_pool();
        pool.enter(peer(1), Some(udp_contact(1)), 5, base);
        let _ = pool.tick(base + udp_due(), true);
        let outcome = pool.on_reply_datagram(
            base + udp_due(),
            udp_contact(1).endpoint,
            &v4_ack_with(status, 4),
        );
        assert_eq!(
            outcome,
            ReplyOutcome::RankRecorded {
                peer: peer(1),
                rank: 4,
                complete: Some(complete),
            }
        );
    }
}

#[test]
fn a_reask_ack_reply_clears_a_standing_queue_full_flag() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 0, base);
    // Queue-full arrives first (0x93), then a later ack (0x91) clears it.
    let _ = pool.on_reply_datagram(base, udp_contact(1).endpoint, &queue_full_datagram());
    assert_eq!(pool.is_queue_full(peer(1)), Some(true));
    let outcome = pool.on_reply_datagram(base, udp_contact(1).endpoint, &v4_ack(9));
    assert_eq!(
        outcome,
        ReplyOutcome::RankRecorded {
            peer: peer(1),
            rank: 9,
            complete: Some(true),
        }
    );
    assert_eq!(pool.is_queue_full(peer(1)), Some(false));
}

#[test]
fn a_queue_full_reply_keeps_the_source_deprioritized_and_refreshes_the_clock() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 7, base);
    let _ = pool.tick(base + udp_due(), true); // latch set.

    let reply_at = base + udp_due() + Duration::from_secs(1);
    let outcome = pool.on_reply_datagram(reply_at, udp_contact(1).endpoint, &queue_full_datagram());
    assert_eq!(outcome, ReplyOutcome::QueueFull { peer: peer(1) });
    // Kept, rank reset to 0, flagged, latch cleared, clock refreshed.
    assert!(pool.contains(peer(1)));
    assert_eq!(pool.rank(peer(1)), Some(0));
    assert_eq!(pool.is_queue_full(peer(1)), Some(true));
    assert_eq!(pool.udp_pending(peer(1)), Some(false));
    assert_eq!(pool.tick(base + FILE_REASK_TIME, true), vec![]);
}

#[test]
fn a_file_not_found_reply_drops_the_source_dead() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 4, base);
    let outcome = pool.on_reply_datagram(base, udp_contact(1).endpoint, &file_not_found_datagram());
    assert_eq!(outcome, ReplyOutcome::Dropped { peer: peer(1) });
    assert!(!pool.contains(peer(1)));
    assert_eq!(pool.len(), 0);
}

#[test]
fn a_reply_from_an_unknown_udp_source_is_ignored() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 4, base);
    // A well-formed 0x91 from a UDP endpoint no pooled source advertised:
    // it decodes cleanly, but matches nothing — ignored on the source key,
    // not on a decode failure.
    let stranger = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 99), 5000));
    assert_eq!(
        pool.on_reply_datagram(base, stranger, &v4_ack(2)),
        ReplyOutcome::Ignored {
            reason: IgnoredReaskReply::NoPooledSource
        }
    );
    // The pooled source is untouched.
    assert_eq!(pool.rank(peer(1)), Some(4));
}

#[test]
fn our_udp_disabled_takes_every_reask_straight_to_the_tcp_full_ask() {
    let base = Instant::now();
    // UDP advert off (the production default until the socket goes live).
    let mut pool = RemoteQueuedPool::new(false);
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);
    // No UDP ping in the window...
    assert_eq!(pool.tick(base + udp_due(), true), vec![]);
    // ...only the TCP full ask at the full period.
    assert_eq!(
        pool.tick(base + FILE_REASK_TIME, true),
        vec![ReaskAction::TcpFullAsk { peer: peer(1) }]
    );
}

#[test]
fn a_firewalled_downloader_never_udp_pings() {
    let base = Instant::now();
    // Neither route reachable: no server High-ID, Kad self-check firewalled —
    // we cannot receive the UDP reply.
    let mut pool = RemoteQueuedPool::new(true);
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);
    assert_eq!(pool.tick(base + udp_due(), false), vec![]);
    assert_eq!(
        pool.tick(base + FILE_REASK_TIME, false),
        vec![ReaskAction::TcpFullAsk { peer: peer(1) }]
    );
}

#[test]
fn the_reask_gate_reads_self_reach_at_every_sweep() {
    // The gate is aMule's `!IsFirewalled()`
    // (`DownloadClient.cpp:1269`) asked of Self Reach at the sweep — no copy
    // in the pool. A server High ID gained mid-run opens it on the very next
    // sweep, losing it closes it, and an open Kad TCP verdict opens it again.
    let kad = crate::reachability::SharedKadVerdicts::default();
    let own = crate::own_identity::SharedOwnIdentity::default();
    let reach = crate::reachability::SharedSelfReach::new(
        crate::KadReachLevel::published(kad.clone()),
        own.clone(),
        crate::natt::front::SharedNattFront::default(),
    );
    let ping = vec![ReaskAction::UdpPing {
        peer: peer(1),
        udp_endpoint: udp_contact(1).endpoint,
        udp_version: 4,
    }];
    let sweep = |reach: &crate::reachability::SharedSelfReach| {
        let base = Instant::now();
        let mut pool = RemoteQueuedPool::new(true);
        pool.enter(peer(1), Some(udp_contact(1)), 5, base);
        pool.tick(base + udp_due(), !reach.firewalled())
    };
    assert_eq!(sweep(&reach), vec![], "neither route reachable yet");

    own.set_connected_session(Some(crate::own_identity::ConnectedSession {
        server: None,
        client_id: rmule_primitives::ClientId::from_u32(0x0A00_0001),
    }));
    assert_eq!(sweep(&reach), ping, "a server High ID");
    own.reassign_client_id(rmule_primitives::ClientId::from_u32(7));
    assert_eq!(sweep(&reach), vec![], "re-assigned a Low ID");

    kad.set_tcp(TcpReachability::Open);
    assert_eq!(sweep(&reach), ping, "Kad TCP open");
}

#[test]
fn a_source_without_a_udp_contact_is_tcp_only() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    // The peer advertised no client-UDP port (the 0/0 production thread).
    pool.enter(peer(1), None, 5, base);
    assert_eq!(pool.tick(base + udp_due(), true), vec![]);
    assert_eq!(
        pool.tick(base + FILE_REASK_TIME, true),
        vec![ReaskAction::TcpFullAsk { peer: peer(1) }]
    );
}

#[test]
fn a_source_exchange_due_source_prefers_the_tcp_full_ask() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);
    // The ADR-0055 source-exchange ask is due: prefer TCP, suppress the UDP
    // ping (a datagram cannot carry source-exchange value).
    pool.set_sx_due(peer(1), true);
    assert_eq!(pool.tick(base + udp_due(), true), vec![]);
    assert_eq!(
        pool.tick(base + FILE_REASK_TIME, true),
        vec![ReaskAction::TcpFullAsk { peer: peer(1) }]
    );
}

#[test]
fn a_no_needed_parts_source_reasks_at_double_the_period_over_tcp() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);
    pool.set_no_needed_parts(peer(1), true);

    // No UDP ping in the base window, and — crucially — no TCP full ask at
    // one period: an NNP source is polled half as often.
    assert_eq!(pool.tick(base + udp_due(), true), vec![]);
    assert_eq!(pool.tick(base + FILE_REASK_TIME, true), vec![]);
    // The TCP recheck fires only at ×2 the period.
    assert_eq!(
        pool.tick(base + FILE_REASK_TIME * NO_NEEDED_PARTS_MULTIPLIER, true),
        vec![ReaskAction::TcpFullAsk { peer: peer(1) }]
    );
}

#[test]
fn a_tick_sweeps_every_source_in_insertion_order() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    // peer(1) is UDP-capable; peer(2) advertised no UDP contact; peer(3) is
    // UDP-capable. All three enter together, all due at the full period.
    pool.enter(peer(1), Some(udp_contact(1)), 1, base);
    pool.enter(peer(2), None, 2, base);
    pool.enter(peer(3), Some(udp_contact(3)), 3, base);

    // The UDP window: only the two UDP-capable sources ping, in order.
    assert_eq!(
        pool.tick(base + udp_due(), true),
        vec![
            ReaskAction::UdpPing {
                peer: peer(1),
                udp_endpoint: udp_contact(1).endpoint,
                udp_version: 4,
            },
            ReaskAction::UdpPing {
                peer: peer(3),
                udp_endpoint: udp_contact(3).endpoint,
                udp_version: 4,
            },
        ]
    );
    // At the full period: peer(2) (never pinged) and the two silent pingers
    // all fall to the TCP full ask, still in insertion order.
    assert_eq!(
        pool.tick(base + FILE_REASK_TIME, true),
        vec![
            ReaskAction::TcpFullAsk { peer: peer(1) },
            ReaskAction::TcpFullAsk { peer: peer(2) },
            ReaskAction::TcpFullAsk { peer: peer(3) },
        ]
    );
}

#[test]
fn removing_a_granted_source_takes_it_out_of_the_sweep() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);
    assert!(pool.remove(peer(1)));
    assert!(!pool.remove(peer(1))); // idempotent
    assert_eq!(pool.tick(base + FILE_REASK_TIME, true), vec![]);
}

/// An IPv6 source holds its queue standing exactly as an IPv4 one does
/// (ADR-0087): the reask quartet packs no address in any body, so the `0x90`
/// goes to the source's own v6 UDP endpoint and its `0x91` matches back on
/// all 128 bits. Two sources in the **same `/64`** stay apart — the `/64` is
/// an accounting bucket, never an identity — so a neighbour's ack never
/// credits the wrong source.
#[test]
fn an_ipv6_source_reasks_over_ipv6_and_its_reply_matches_on_all_128_bits() {
    fn v6_peer(last: u16) -> PeerEndpoint {
        PeerEndpoint::V6(Ipv6Endpoint::new(
            std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, last),
            4662,
        ))
    }
    fn v6_contact(last: u16) -> UdpContact {
        UdpContact {
            endpoint: v6_peer(last).with_port(5000),
            version: 4,
        }
    }

    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(v6_peer(1), Some(v6_contact(1)), 5, base);
    pool.enter(v6_peer(2), Some(v6_contact(2)), 9, base);

    // Both pings address their own source's v6 client-UDP endpoint.
    assert_eq!(
        pool.tick(base + udp_due(), true),
        vec![
            ReaskAction::UdpPing {
                peer: v6_peer(1),
                udp_endpoint: v6_contact(1).endpoint,
                udp_version: 4,
            },
            ReaskAction::UdpPing {
                peer: v6_peer(2),
                udp_endpoint: v6_contact(2).endpoint,
                udp_version: 4,
            },
        ]
    );

    // The second source's ack lands on the second source alone, though both
    // share a `/64`: the match is the whole address plus the UDP port.
    assert_eq!(
        pool.on_reply_datagram(base + udp_due(), v6_contact(2).endpoint, &v4_ack(3)),
        ReplyOutcome::RankRecorded {
            peer: v6_peer(2),
            rank: 3,
            complete: Some(true),
        }
    );
    assert_eq!(pool.rank(v6_peer(1)), Some(5), "the neighbour is untouched");
    assert_eq!(pool.rank(v6_peer(2)), Some(3));
}

/// A pre-UDPv4 uploader writes its rank alone, whatever we advertised — aMule's
/// pinger reads a status only from a UDPv4 uploader (stock 2.3.3 `4e8f2b3c`
/// `ClientUDPSocket.cpp:258-259`) — so its `0x91` is read by the lower of the
/// two versions and its rank lands.
#[test]
fn a_pre_udpv4_uploaders_rank_only_ack_is_read() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    let v3 = UdpContact {
        version: 3,
        ..udp_contact(1)
    };
    pool.enter(peer(1), Some(v3), 5, base);
    let _ = pool.tick(base + udp_due(), true);
    let rank_only = ReaskAck {
        part_status: None,
        rank: 2,
    }
    .encode_udp();
    assert_eq!(
        pool.on_reply_datagram(base + udp_due(), v3.endpoint, &rank_only),
        ReplyOutcome::RankRecorded {
            peer: peer(1),
            rank: 2,
            complete: None,
        }
    );
}

/// A ping another download holds the endpoint for is deferred (ADR-0107): the
/// next sweep inside the window pings again, and the TCP full ask still falls
/// due at the period, not a period after the deferral.
#[test]
fn a_deferred_ping_is_retried_in_its_window_and_the_tcp_ask_keeps_its_time() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 5, base);
    let due = base + udp_due();
    assert!(matches!(
        pool.tick(due, true).as_slice(),
        [ReaskAction::UdpPing { .. }]
    ));
    pool.defer_udp_ping(peer(1));
    assert!(matches!(
        pool.tick(due + Duration::from_secs(1), true).as_slice(),
        [ReaskAction::UdpPing { .. }]
    ));
    assert_eq!(
        pool.tick(base + FILE_REASK_TIME, true),
        vec![ReaskAction::TcpFullAsk { peer: peer(1) }]
    );
}

/// The bench run where stock aMule 2.3.3 queued rmule and answered its UDP
/// reask (`amule-233-reask-ack-to-rmule-20261001`): the ping rmule framed for
/// a UDPv4 sharer is the captured one byte for byte, and the sharer's `0x91` —
/// its complete-source status ahead of rank 1, written because rmule's hello
/// advertised UDP v4 — lands on the pooled source. The pool is built as the
/// download runner builds it, from whether a client-UDP socket is bound.
#[test]
fn the_captured_amule_reask_ack_lands_on_its_source() {
    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../rmule-peer/tests/fixtures/peer_udp_reask/captured/amule-233-reask-ack-to-rmule-20261001/"
    );
    let read = |name: &str| std::fs::read(format!("{DIR}{name}")).expect("captured datagram");
    let sharer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 6), 4662));
    let contact = UdpContact {
        endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 6), 4672)),
        version: 4,
    };
    let base = Instant::now();
    let mut pool = RemoteQueuedPool::new(true);
    pool.enter(sharer, Some(contact), 1, base);

    let due = base + udp_due();
    let [ReaskAction::UdpPing { udp_version, .. }] = pool.tick(due, true)[..] else {
        panic!("a UDP ping is due");
    };
    let ping = rmule_peer::ReaskFilePing {
        file_hash: rmule_primitives::FileHash::from_bytes([
            0x06, 0x81, 0x8E, 0xCF, 0xAF, 0xD5, 0xEC, 0x44, 0x00, 0xD2, 0x8A, 0x53, 0xD7, 0xF8,
            0x66, 0xD5,
        ]),
        part_status: (udp_version > 3).then(|| PartBitmap::downloader_empty(41_943_040)),
        complete_sources: (udp_version > 2).then_some(0),
    }
    .encode_udp();
    assert_eq!(ping, read("reask_ping_0x90.bin"));

    let outcome = pool.on_reply_datagram(
        due + Duration::from_millis(108),
        contact.endpoint,
        &read("reask_ack_0x91.bin"),
    );
    assert_eq!(
        outcome,
        ReplyOutcome::RankRecorded {
            peer: sharer,
            rank: 1,
            complete: Some(true),
        }
    );
    assert_eq!(pool.udp_pending(sharer), Some(false));
}

/// Each way a reply changes nothing names itself.
#[test]
fn an_ignored_reply_says_why() {
    let base = Instant::now();
    let mut pool = udp_capable_pool();
    pool.enter(peer(1), Some(udp_contact(1)), 4, base);
    let from = udp_contact(1).endpoint;
    let ignored = |reason| ReplyOutcome::Ignored { reason };
    assert_eq!(
        pool.on_reply_datagram(base, from, &[0xC5]),
        ignored(IgnoredReaskReply::Runt)
    );
    assert_eq!(
        pool.on_reply_datagram(base, from, &[0xC5, 0x90]),
        ignored(IgnoredReaskReply::UnexpectedOpcode)
    );
    // A rank-only body where both ends are UDPv4 and the status is owed.
    assert_eq!(
        pool.on_reply_datagram(base, from, &[0xC5, 0x91, 0x02, 0x00]),
        ignored(IgnoredReaskReply::Misframed)
    );
    assert_eq!(pool.rank(peer(1)), Some(4));
}
