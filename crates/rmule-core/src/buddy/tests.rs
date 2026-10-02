//! Buddy-service unit tests: the single buddy slot refusing a second recruit,
//! FINDBUDDY refused silently while our own surface is not open and refused
//! for a known client, a check collision or ourselves, the buddy ID verified
//! on both relayed opcodes, and the keepalive pong extending our buddy's link
//! while a stranger's is refused.

use std::net::Ipv4Addr;

use super::*;

fn kad_id(byte: u8) -> KadId {
    KadId::from_bytes([byte; KadId::BYTE_LEN])
}

fn endpoint(host: u8, port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, host), port)
}

/// The same address as a peer's — a ping arrives from a connection, which is
/// keyed by a family-generic endpoint.
fn peer(host: u8, port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(endpoint(host, port))
}

fn our_identity() -> BuddyIdentity {
    BuddyIdentity {
        our_hash: UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
        our_tcp_port: 4662,
    }
}

/// Both surfaces open — the only posture that may serve as a buddy.
fn open_posture() -> BuddyServePosture {
    BuddyServePosture {
        tcp_reachable: true,
        udp: BuddyUdpPosture::Open,
    }
}

/// A clean recruit: unknown requester, no collision, not us. The requester's
/// user hash is derived from its buddy-ID bytes so each recruit carries a
/// distinct, assertable identity.
fn recruit(buddy_id: KadId, requester: Ipv4Endpoint) -> FindBuddyReq {
    FindBuddyReq {
        buddy_id,
        requester_hash: UserHash::from_bytes(*buddy_id.as_bytes()),
        requester,
        requester_udp: requester,
        requester_known: false,
        check_collision: false,
        is_self: false,
    }
}

#[test]
fn a_fresh_service_has_no_buddy_and_the_single_slot_refuses_a_second_recruit() {
    let mut svc = BuddyService::new();
    let t0 = Instant::now();
    assert!(!svc.has_buddy(), "a fresh service holds no buddy");

    // The first clean recruit against an open posture is accepted: the slot
    // fills and the 0x5A answer echoes the buddy-ID and carries our identity.
    let first = kad_id(0x11);
    let outcome = svc.consider_findbuddy(
        &recruit(first, endpoint(1, 5000)),
        &open_posture(),
        our_identity(),
        t0,
    );
    assert_eq!(
        outcome,
        FindBuddyOutcome::Accept(FindBuddyAnswer {
            buddy_id: first,
            our_hash: our_identity().our_hash,
            our_tcp_port: our_identity().our_tcp_port,
        })
    );
    assert!(svc.has_buddy());
    assert_eq!(svc.buddy_id(), Some(first));
    assert_eq!(
        svc.buddy_hash(),
        Some(UserHash::from_bytes(*first.as_bytes())),
        "the recruit's user hash registers — the attach-matching identity"
    );

    // A second recruit — a different, equally valid requester — is refused:
    // the one slot is taken, and the incumbent buddy is untouched.
    let second = kad_id(0x22);
    assert_eq!(
        svc.consider_findbuddy(
            &recruit(second, endpoint(2, 5001)),
            &open_posture(),
            our_identity(),
            t0,
        ),
        FindBuddyOutcome::Refuse {
            reason: FindBuddyRefusal::SlotTaken
        }
    );
    assert_eq!(svc.buddy_id(), Some(first), "the incumbent buddy is kept");

    // Losing the buddy (its TCP link closed) frees the slot at once, and the
    // once-refused requester now recruits into it — the single slot recycles.
    svc.release();
    assert!(!svc.has_buddy());
    assert_eq!(
        svc.consider_findbuddy(
            &recruit(second, endpoint(2, 5001)),
            &open_posture(),
            our_identity(),
            t0,
        ),
        FindBuddyOutcome::Accept(FindBuddyAnswer {
            buddy_id: second,
            our_hash: our_identity().our_hash,
            our_tcp_port: our_identity().our_tcp_port,
        })
    );
    assert_eq!(svc.buddy_id(), Some(second));
}

#[test]
fn findbuddy_refuses_silently_while_our_own_surface_is_not_open() {
    // A node that is not open on both surfaces cannot relay for a third
    // party, so each unopen posture refuses — with its precise reason — and
    // never fills the slot.
    for (posture, reason) in [
        (
            BuddyServePosture {
                tcp_reachable: false,
                udp: BuddyUdpPosture::Open,
            },
            FindBuddyRefusal::TcpFirewalled,
        ),
        (
            BuddyServePosture {
                tcp_reachable: true,
                udp: BuddyUdpPosture::Firewalled,
            },
            FindBuddyRefusal::UdpFirewalled,
        ),
        (
            BuddyServePosture {
                tcp_reachable: true,
                udp: BuddyUdpPosture::Unverified,
            },
            FindBuddyRefusal::UdpUnverified,
        ),
    ] {
        let mut svc = BuddyService::new();
        assert_eq!(
            svc.consider_findbuddy(
                &recruit(kad_id(0x11), endpoint(1, 5000)),
                &posture,
                our_identity(),
                Instant::now(),
            ),
            FindBuddyOutcome::Refuse { reason }
        );
        assert!(!svc.has_buddy(), "an unopen node never takes a buddy");
    }
}

#[test]
fn findbuddy_refuses_a_known_client_a_check_collision_and_ourselves() {
    // The three requester-side guards, each isolated against an otherwise
    // acceptable open posture — none fills the slot.
    for (mutate, reason) in [
        (
            (|r: &mut FindBuddyReq| r.requester_known = true) as fn(&mut FindBuddyReq),
            FindBuddyRefusal::KnownClient,
        ),
        (
            (|r: &mut FindBuddyReq| r.check_collision = true) as fn(&mut FindBuddyReq),
            FindBuddyRefusal::CheckCollision,
        ),
        (
            (|r: &mut FindBuddyReq| r.is_self = true) as fn(&mut FindBuddyReq),
            FindBuddyRefusal::SelfRequest,
        ),
    ] {
        let mut svc = BuddyService::new();
        let mut req = recruit(kad_id(0x11), endpoint(1, 5000));
        mutate(&mut req);
        assert_eq!(
            svc.consider_findbuddy(&req, &open_posture(), our_identity(), Instant::now()),
            FindBuddyOutcome::Refuse { reason }
        );
        assert!(!svc.has_buddy());
    }
}

#[test]
fn the_relay_verifies_the_buddy_id_on_both_the_callback_and_the_reask_opcodes() {
    let requester = endpoint(9, 4662);
    let forwarded = vec![0xAB, 0xCD, 0xEF];
    let make = |kind, id| BuddyRelayRequest {
        kind,
        claimed_buddy_id: id,
        requester,
        forwarded: forwarded.clone(),
    };

    // With no buddy, either relay is rejected outright — there is no link.
    let mut svc = BuddyService::new();
    for kind in [RelayKind::Callback, RelayKind::ReaskCallback] {
        assert_eq!(
            svc.relay(&make(kind, kad_id(0x11))),
            RelayVerdict::Reject {
                reason: RelayReject::NoBuddy
            }
        );
    }

    // Recruit a buddy (id 0x11, its endpoint the relay link).
    let buddy = kad_id(0x11);
    let link = endpoint(1, 5000);
    svc.consider_findbuddy(
        &recruit(buddy, link),
        &open_posture(),
        our_identity(),
        Instant::now(),
    );

    // Both opcodes relay when the claimed buddy-ID matches, forwarding to the
    // buddy's link with the requester injected and the payload carried through.
    for kind in [RelayKind::Callback, RelayKind::ReaskCallback] {
        assert_eq!(
            svc.relay(&make(kind, buddy)),
            RelayVerdict::Relay {
                buddy_link: link,
                callback: RelayedCallback {
                    kind,
                    requester,
                    forwarded: forwarded.clone(),
                },
                swapped_spelling: false,
            }
        );
    }

    // The tightening: a mismatched buddy-ID is rejected on BOTH opcodes —
    // aMule filters this only on 0x94, letting a spoofed 0x52 through; rmule
    // kills it one hop before it reaches our buddy's own 0x99 checks.
    for kind in [RelayKind::Callback, RelayKind::ReaskCallback] {
        assert_eq!(
            svc.relay(&make(kind, kad_id(0x22))),
            RelayVerdict::Reject {
                reason: RelayReject::BuddyIdMismatch
            }
        );
    }
}

/// **Source-derived**: a requester that read our buddy's
/// aMule-spelled `TAG_BUDDYHASH` the eMule 0.70b / eMuleAI way claims the
/// registered buddy ID with each four-byte word reversed. On the `0x52` that
/// is still our buddy — relayed verbatim, as aMule relays every `0x52`, and
/// flagged so it is counted apart; the buddy's own `0x99` check decides the
/// rest. The `0x94` keeps its exact match (aMule's own check there), and any
/// third ID is still a mismatch.
#[test]
fn source_derived_the_callback_relay_accepts_the_other_spelling_of_our_buddys_id() {
    let requester = endpoint(9, 4662);
    let make = |kind, id| BuddyRelayRequest {
        kind,
        claimed_buddy_id: id,
        requester,
        forwarded: Vec::new(),
    };
    // Asymmetric per word, so the two spellings differ.
    let buddy = KadId::from_bytes([
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ]);
    let link = endpoint(1, 5000);
    let mut svc = BuddyService::new();
    svc.consider_findbuddy(
        &recruit(buddy, link),
        &open_posture(),
        our_identity(),
        Instant::now(),
    );

    assert_eq!(
        svc.relay(&make(RelayKind::Callback, buddy.word_swapped())),
        RelayVerdict::Relay {
            buddy_link: link,
            callback: RelayedCallback {
                kind: RelayKind::Callback,
                requester,
                forwarded: Vec::new(),
            },
            swapped_spelling: true,
        }
    );
    for (kind, id) in [
        (RelayKind::ReaskCallback, buddy.word_swapped()),
        (RelayKind::Callback, kad_id(0x22)),
    ] {
        assert_eq!(
            svc.relay(&make(kind, id)),
            RelayVerdict::Reject {
                reason: RelayReject::BuddyIdMismatch
            }
        );
    }
}

#[test]
fn keepalive_pongs_our_buddy_extends_the_link_and_refuses_a_stranger() {
    let window = Duration::from_secs(15 * 60);
    let link = endpoint(1, 5000);
    let stranger = peer(7, 5007);

    // A silent buddy goes stale after the keepalive window and frees the slot.
    let mut svc = BuddyService::new();
    let t0 = Instant::now();
    svc.consider_findbuddy(
        &recruit(kad_id(0x11), link),
        &open_posture(),
        our_identity(),
        t0,
    );
    assert!(
        !svc.drop_stale(t0 + window - Duration::from_secs(1), window),
        "still inside the window"
    );
    assert!(
        svc.drop_stale(t0 + window, window),
        "an un-pinged link goes stale"
    );
    assert!(!svc.has_buddy(), "the stale buddy freed the slot");

    // Re-recruit; a ping from our buddy pongs and refreshes the link, so the
    // window is measured from the ping — the timeout extension. The ping
    // arrives from the buddy's IP at an *ephemeral* source port (its dialed
    // TCP link), never the advertised port the recruit registered — the
    // IP-based match must still honor it.
    let mut svc = BuddyService::new();
    svc.consider_findbuddy(
        &recruit(kad_id(0x11), link),
        &open_posture(),
        our_identity(),
        t0,
    );
    let pinged = t0 + window - Duration::from_secs(1);
    let dialed_from = peer(1, 61234);
    assert_ne!(
        dialed_from.port(),
        link.port,
        "the dial-out port is ephemeral"
    );
    assert_eq!(
        svc.on_buddy_ping(dialed_from, pinged),
        BuddyPingOutcome::Pong
    );
    assert!(
        !svc.drop_stale(t0 + window, window),
        "the ping pushed the deadline out — the link survives past the un-pinged deadline"
    );
    assert!(svc.has_buddy());
    assert!(
        svc.drop_stale(pinged + window, window),
        "one window after the last ping it finally goes stale"
    );

    // A ping from a stranger is refused and never touches our buddy slot.
    let mut svc = BuddyService::new();
    svc.consider_findbuddy(
        &recruit(kad_id(0x11), link),
        &open_posture(),
        our_identity(),
        t0,
    );
    assert_eq!(
        svc.on_buddy_ping(stranger, t0),
        BuddyPingOutcome::NotOurBuddy
    );
    assert_eq!(
        svc.buddy_id(),
        Some(kad_id(0x11)),
        "the stranger ping left our buddy intact"
    );
}
