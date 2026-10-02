//! Deterministic admit / score-rank / promote / rerank with a slot budget and
//! a queue cap. Time is injected as `Instant`s, and per-peer modifiers as a
//! map, so the queue's `wait * modifier` scoring is exercised without sockets,
//! a clock, or the credit store.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use rmule_core::{Admission, MAX_WAITING_PER_ADDRESS, UploadSlotQueue};
use rmule_primitives::{ClientId, FileHash, PeerEndpoint, PeerSource};

fn peer(port: u16) -> PeerEndpoint {
    // High-ID source -> connectable endpoint. Distinct ports give distinct peers.
    PeerSource::new(ClientId::from_u32(0x0100_007F), port)
        .as_peer_endpoint()
        .unwrap()
}

/// A peer at an explicit IPv4 address. The per-address cap's unit is the
/// address, so its tests cannot use [`peer`], which varies only the port.
fn v4_peer(ip: [u8; 4], port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
        std::net::Ipv4Addr::from(ip),
        port,
    ))
}

fn file() -> FileHash {
    FileHash::from_bytes([0x11; FileHash::BYTE_LEN])
}

fn modifiers(pairs: &[(PeerEndpoint, f64)]) -> HashMap<PeerEndpoint, f64> {
    pairs.iter().copied().collect()
}

#[test]
fn admits_within_budget_then_queues_a_newcomer_at_the_tail() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(2, 10);
    assert_eq!(q.admit(peer(1), file(), t0), Admission::Granted);
    assert_eq!(q.admit(peer(2), file(), t0), Admission::Granted);
    // A newcomer has ~zero wait, so its score is lowest -> it joins at the tail.
    assert_eq!(q.admit(peer(3), file(), t0), Admission::Queued { rank: 1 });
    assert_eq!(q.admit(peer(4), file(), t0), Admission::Queued { rank: 2 });
}

#[test]
fn refuses_beyond_the_queue_cap() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 1);
    assert_eq!(q.admit(peer(1), file(), t0), Admission::Granted); // takes the slot
    assert_eq!(q.admit(peer(2), file(), t0), Admission::Queued { rank: 1 }); // fills the cap
    assert_eq!(q.admit(peer(3), file(), t0), Admission::Refused); // cap full
}

#[test]
fn equal_credit_ranks_by_wait_time_oldest_first() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    assert_eq!(q.admit(peer(1), file(), t0), Admission::Granted);
    assert_eq!(q.admit(peer(2), file(), t0), Admission::Queued { rank: 1 });
    // peer 3 enqueues 5s later, so it has waited less.
    assert_eq!(
        q.admit(peer(3), file(), t0 + Duration::from_secs(5)),
        Admission::Queued { rank: 2 }
    );
    // Equal modifiers => score is pure wait time; order is unchanged at t+60s.
    let m = modifiers(&[(peer(2), 1.0), (peer(3), 1.0)]);
    assert!(q.rerank(t0 + Duration::from_secs(60), &m).is_empty());
}

#[test]
fn higher_credit_overtakes_a_longer_waiting_low_credit_peer() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    assert_eq!(q.admit(peer(1), file(), t0), Admission::Granted);
    assert_eq!(q.admit(peer(2), file(), t0), Admission::Queued { rank: 1 }); // low credit, oldest
    assert_eq!(
        q.admit(peer(3), file(), t0 + Duration::from_secs(10)),
        Admission::Queued { rank: 2 } // high credit, joined later
    );
    // At t+30s: score(2) = 30 * 1 = 30; score(3) = 20 * 2 = 40 -> 3 overtakes.
    let m = modifiers(&[(peer(2), 1.0), (peer(3), 2.0)]);
    let changes = q.rerank(t0 + Duration::from_secs(30), &m);
    assert_eq!(changes, vec![(peer(3), 1), (peer(2), 2)]);
}

#[test]
fn release_promotes_the_highest_score_waiter_not_the_fifo_head() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    assert_eq!(q.admit(peer(1), file(), t0), Admission::Granted);
    assert_eq!(q.admit(peer(2), file(), t0), Admission::Queued { rank: 1 }); // low credit, oldest
    assert_eq!(
        q.admit(peer(3), file(), t0 + Duration::from_secs(10)),
        Admission::Queued { rank: 2 } // high credit
    );
    // Slot frees at t+30s. score(2) = 30, score(3) = 40 -> peer 3 promoted.
    let m = modifiers(&[(peer(2), 1.0), (peer(3), 2.0)]);
    let promotion = q.release(peer(1), t0 + Duration::from_secs(30), &m);
    assert_eq!(promotion.granted, Some((peer(3), file())));
    // peer 2 is now the sole waiter; its rank was already 1, so nothing re-emits.
    assert!(promotion.reranked.is_empty());
}

#[test]
fn releasing_a_queued_peer_reranks_those_behind_it() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    assert_eq!(q.admit(peer(1), file(), t0), Admission::Granted);
    assert_eq!(q.admit(peer(2), file(), t0), Admission::Queued { rank: 1 });
    assert_eq!(q.admit(peer(3), file(), t0), Admission::Queued { rank: 2 });
    // peer 2 disconnects while waiting: no slot frees (peer 1 still granted),
    // but peer 3 moves from rank 2 to rank 1.
    let m = modifiers(&[(peer(3), 1.0)]);
    let promotion = q.release(peer(2), t0 + Duration::from_secs(5), &m);
    assert_eq!(promotion.granted, None);
    assert_eq!(promotion.reranked, vec![(peer(3), 1)]);
}

#[test]
fn releasing_an_unknown_peer_is_a_no_op() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    assert_eq!(q.admit(peer(1), file(), t0), Admission::Granted);
    let promotion = q.release(peer(99), t0, &HashMap::new());
    assert_eq!(promotion.granted, None);
    assert!(promotion.reranked.is_empty());
}

#[test]
fn purge_reclaims_a_dial_back_grant_whose_dial_never_connected() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    let holder = peer(1);
    let waiter = peer(2);
    assert_eq!(q.admit(holder, file(), t0), Admission::Granted);
    assert_eq!(q.admit(waiter, file(), t0), Admission::Queued { rank: 1 });

    // The waiter loses its socket (disconnected standing), then the holder frees
    // the slot: the sole waiter is promoted, but with no live connection it is a
    // dial-back grant — occupying the slot for a dial that has yet to connect.
    let _ = q.on_disconnect(waiter, t0, &HashMap::new());
    let disconnect = q.on_disconnect(holder, t0, &HashMap::new());
    assert!(
        disconnect.promotion.dial_back,
        "promoted over a dead socket -> dial-back"
    );
    assert_eq!(disconnect.promotion.granted, Some((waiter, file())));
    assert!(q.is_granted(waiter), "the dial-back grant holds the slot");

    // The outbound serve-dial never connects. One hour on, purge reclaims the
    // stale grant instead of leaking the slot forever (no Disconnected can ever
    // arrive for a peer that never held a socket).
    let hour = Duration::from_secs(3600);
    let purge = q.purge(
        t0 + hour + Duration::from_secs(1),
        hour,
        |_| true,
        &HashMap::new(),
    );
    assert_eq!(purge.reclaimed, Some(waiter));
    assert!(purge.removed.contains(&waiter));
    assert!(!q.is_granted(waiter), "the leaked slot is freed");
}

#[test]
fn a_dial_back_grant_that_reconnects_is_not_reclaimed() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    let holder = peer(1);
    let waiter = peer(2);
    assert_eq!(q.admit(holder, file(), t0), Admission::Granted);
    assert_eq!(q.admit(waiter, file(), t0), Admission::Queued { rank: 1 });
    let _ = q.on_disconnect(waiter, t0, &HashMap::new());
    let _ = q.on_disconnect(holder, t0, &HashMap::new()); // waiter promoted as dial-back

    // The dialed-back peer connects and re-asks — the grant is now live, so the
    // reclaim marker clears and a later purge leaves the slot alone.
    assert_eq!(
        q.admit(waiter, file(), t0 + Duration::from_secs(1)),
        Admission::Granted
    );
    let hour = Duration::from_secs(3600);
    let purge = q.purge(
        t0 + hour + Duration::from_secs(2),
        hour,
        |_| true,
        &HashMap::new(),
    );
    assert_eq!(
        purge.reclaimed, None,
        "a connected grant is never reclaimed"
    );
    assert!(q.is_granted(waiter));
}

#[test]
fn equal_score_release_promotes_the_oldest_waiter() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    assert_eq!(q.admit(peer(1), file(), t0), Admission::Granted);
    assert_eq!(q.admit(peer(2), file(), t0), Admission::Queued { rank: 1 }); // older
    assert_eq!(
        q.admit(peer(3), file(), t0 + Duration::from_secs(10)),
        Admission::Queued { rank: 2 }
    );
    // At t+30: score(2) = 30 * 2 = 60; score(3) = 20 * 3 = 60 -> exact tie.
    // The tie breaks to the oldest enqueue, so peer 2 is promoted.
    let m = modifiers(&[(peer(2), 2.0), (peer(3), 3.0)]);
    let promotion = q.release(peer(1), t0 + Duration::from_secs(30), &m);
    assert_eq!(promotion.granted, Some((peer(2), file())));
}

/// Reask attribution compares the whole 128-bit address (ADR-0087). Two peers
/// inside one `/64` differ only in the low bits — a 32-bit projection would
/// collapse them, and each would answer for the other's queue slot.
#[test]
fn an_ipv6_reask_is_attributed_by_the_full_address_not_a_projection() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 10);
    // The budget is clamped to one slot, so a filler takes it and everyone
    // after it waits — reask attribution reads the wait list.
    let _ = q.admit(peer(1), file(), t0);
    let first = v6_peer("2001:db8:0:1::a");
    let second = v6_peer("2001:db8:0:1::b");
    let _ = q.admit(first, file(), t0);
    let _ = q.admit(second, file(), t0);
    q.set_udp_contact(first, Some(6000), 4);
    q.set_udp_contact(second, Some(6001), 4);

    let resolved = |peer: PeerEndpoint, port: u16| match q.resolve_reask(peer.with_port(port)) {
        rmule_core::ReaskResolution::Known { peer, .. } => Some(peer),
        _ => None,
    };
    assert_eq!(resolved(first, 6000), Some(first));
    assert_eq!(resolved(second, 6001), Some(second));

    // The two share a `/64` and the low 32 bits of one do not name the other:
    // an address rmule never admitted resolves to nobody rather than to a
    // neighbour.
    assert_eq!(resolved(v6_peer("2001:db8:0:1::c"), 6000), None);

    // And an IPv4 pinger whose 32 bits happen to match the tail of a v6
    // waiter is a stranger, not that waiter.
    assert_eq!(
        resolved(
            PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
                std::net::Ipv4Addr::new(0, 0, 0, 0xa),
                6000
            )),
            6000
        ),
        None
    );
}

fn v6_peer(address: &str) -> PeerEndpoint {
    PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
        address.parse().unwrap(),
        4662,
    ))
}

/// The per-address queue cap (ADR-0088) at the reference count: three waiters
/// from one IPv4 address are admitted, the fourth is not — and the refusal is
/// its own outcome because it is its own *fact* (a different limit, a different
/// counter), not because the answer differs: both refusals are silent.
///
/// A peer at a different address is unaffected, which is the whole point of a
/// per-address cap over a global one.
#[test]
fn the_fourth_waiter_from_one_address_is_refused_and_the_third_is_not() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 100);
    let holder = v4_peer([198, 51, 100, 1], 4000);
    assert_eq!(q.admit(holder, file(), t0), Admission::Granted);

    for place in 1..=MAX_WAITING_PER_ADDRESS {
        assert_eq!(
            q.admit(v4_peer([203, 0, 113, 7], 4000 + place as u16), file(), t0),
            Admission::Queued { rank: place as u16 },
        );
    }
    assert_eq!(
        q.admit(v4_peer([203, 0, 113, 7], 4099), file(), t0),
        Admission::RefusedAddressCap,
    );
    // The wait list is nowhere near `max_queue_len`: only this address is.
    assert_eq!(
        q.admit(v4_peer([203, 0, 113, 8], 4000), file(), t0),
        Admission::Queued { rank: 4 },
    );
}

/// A granted slot is not a queue place. Both references count the waiting list
/// alone (aMule `IsOnUploadQueue`, `src/UploadQueue.cpp:341`; eMule's `cSameIP`
/// walks `waitinglist` only), so an address whose peer is being served may
/// still put three more in the queue behind it.
#[test]
fn a_granted_slot_does_not_spend_its_addresss_queue_budget() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 100);
    let address = [203, 0, 113, 7];
    assert_eq!(
        q.admit(v4_peer(address, 4000), file(), t0),
        Admission::Granted
    );
    for place in 1..=MAX_WAITING_PER_ADDRESS {
        assert_eq!(
            q.admit(v4_peer(address, 4000 + place as u16), file(), t0),
            Admission::Queued { rank: place as u16 },
        );
    }
    assert_eq!(
        q.admit(v4_peer(address, 4099), file(), t0),
        Admission::RefusedAddressCap,
    );
}

/// The `/64` is the IPv6 unit (ADR-0088): a host handed a prefix cannot buy a
/// fresh budget by minting a fresh address inside it, and two genuinely
/// different prefixes never share one.
#[test]
fn one_ipv6_prefix_is_one_budget_and_two_prefixes_are_two() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 100);
    assert_eq!(
        q.admit(v4_peer([198, 51, 100, 1], 4000), file(), t0),
        Admission::Granted,
    );

    for (place, tail) in ["::a", "::b", ":ffff:ffff:ffff:ffff"].iter().enumerate() {
        assert_eq!(
            q.admit(v6_peer(&format!("2001:db8:0:1{tail}")), file(), t0),
            Admission::Queued {
                rank: place as u16 + 1
            },
        );
    }
    // A fourth address in the same `/64` — the evasion the prefix exists to
    // close.
    assert_eq!(
        q.admit(v6_peer("2001:db8:0:1::d"), file(), t0),
        Admission::RefusedAddressCap,
    );
    // The neighbouring `/64` is a different end site and keeps its own budget.
    assert_eq!(
        q.admit(v6_peer("2001:db8:0:2::a"), file(), t0),
        Admission::Queued { rank: 4 },
    );
}

/// A queued peer's re-request is its existing place, not a fourth arrival
/// (ADR-0057): the cap is tested after the idempotent paths, so a reask can
/// neither be counted twice nor cost the waiter the place it is reasking for.
#[test]
fn a_queued_peers_re_request_is_not_counted_twice() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 100);
    let address = [203, 0, 113, 7];
    assert_eq!(
        q.admit(v4_peer([198, 51, 100, 1], 4000), file(), t0),
        Admission::Granted,
    );
    for place in 1..=MAX_WAITING_PER_ADDRESS {
        let _ = q.admit(v4_peer(address, 4000 + place as u16), file(), t0);
    }

    // Each of the three re-asks, repeatedly, and keeps its rank.
    for _ in 0..3 {
        for place in 1..=MAX_WAITING_PER_ADDRESS {
            assert_eq!(
                q.admit(
                    v4_peer(address, 4000 + place as u16),
                    file(),
                    t0 + Duration::from_secs(60),
                ),
                Admission::Queued { rank: place as u16 },
            );
        }
    }
    assert_eq!(q.waiting_len(), MAX_WAITING_PER_ADDRESS);
    // The cap still holds against a genuine newcomer from that address.
    assert_eq!(
        q.admit(v4_peer(address, 4099), file(), t0),
        Admission::RefusedAddressCap,
    );
}

/// Leaving the queue returns the place to the address that held it — whether
/// the waiter is released outright or reaped by the purge. A bare TCP
/// disconnect does **not**: ADR-0057's disconnected standing keeps the entry,
/// so it keeps costing its address a place until its reask heartbeat stops.
#[test]
fn a_place_returns_to_its_address_on_release_and_on_purge_but_not_on_disconnect() {
    let t0 = Instant::now();
    let mut q = UploadSlotQueue::new(1, 100);
    let address = [203, 0, 113, 7];
    let waiter = |place: u16| v4_peer(address, 4000 + place);
    assert_eq!(
        q.admit(v4_peer([198, 51, 100, 1], 4000), file(), t0),
        Admission::Granted,
    );
    for place in 1..=MAX_WAITING_PER_ADDRESS as u16 {
        let _ = q.admit(waiter(place), file(), t0);
    }
    let none = modifiers(&[]);

    // A disconnect leaves the entry standing, so the address is still full.
    let _ = q.on_disconnect(waiter(1), t0, &none);
    assert_eq!(
        q.admit(waiter(9), file(), t0),
        Admission::RefusedAddressCap,
        "a disconnected waiter still holds its place (ADR-0057)",
    );

    // An outright release frees exactly one place, and only one.
    let _ = q.release(waiter(2), t0, &none);
    assert_eq!(
        q.admit(waiter(9), file(), t0),
        Admission::Queued { rank: 3 },
    );
    assert_eq!(
        q.admit(waiter(10), file(), t0),
        Admission::RefusedAddressCap,
    );

    // The purge reaps the waiter whose heartbeat went silent, freeing its
    // place the same way.
    let purge_after = Duration::from_secs(3600);
    let later = t0 + purge_after + Duration::from_secs(1);
    let reaped = q.purge(later, purge_after, |_| true, &none);
    assert_eq!(reaped.removed.len(), 3, "every silent waiter is reaped");
    assert_eq!(
        q.admit(waiter(11), file(), later),
        Admission::Queued { rank: 1 },
    );
}
