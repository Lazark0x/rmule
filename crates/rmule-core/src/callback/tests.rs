//! The route chooser's decision matrix: each rung of the ADR-0061 tree in
//! isolation, the two ADR-0091 Rendezvous coordinators and their order, and
//! the twelve-second callback-silence fallback — asserted as plain values,
//! because the whole point of the chooser is that it decides without
//! touching a socket.

use std::net::Ipv4Addr;

use super::*;

fn endpoint(a: u8, b: u8, c: u8, d: u8, port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), port)
}

fn peer(a: u8, b: u8, c: u8, d: u8, port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(endpoint(a, b, c, d, port))
}

/// A HighID client id (above the LowID threshold).
fn high_id() -> ClientId {
    ClientId::from_u32(0x0102_0304)
}

/// A LowID client id (a server-assigned id below `16_777_216`).
fn low_id() -> ClientId {
    ClientId::from_u32(42)
}

fn buddy() -> KadId {
    KadId::from_bytes([0x7A; KadId::BYTE_LEN])
}

/// A LowID candidate with every route foreclosed — each route test lights up
/// exactly the fact its branch needs, so no other branch can fire first.
fn bare_low_id_target() -> CallbackTarget {
    CallbackTarget {
        id: low_id(),
        tcp: peer(10, 0, 0, 9, 4662),
        supports_direct_udp_callback: false,
        kad_udp: None,
        on_our_server: false,
        buddy: None,
        ipv6: None,
        supports_natt: false,
    }
}

/// A peer's usable IPv6, past `IsUsableTagIdentity` before it got here.
fn v6() -> Ipv6Endpoint {
    Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662)
}

/// Fully reachable us, *and* holding a Known IPv6 — rung 0's half of the
/// AND.
fn holding_ipv6() -> SelfReach {
    SelfReach {
        dial: DialPosition {
            known_ipv6: Some("2001:db8::1".parse().unwrap()),
        },
        ..open_self()
    }
}

/// Fully reachable us: HighID, UDP up, Kad up — so a route is chosen by the
/// *target's* facts, not gated away by our own position.
fn open_self() -> SelfReach {
    SelfReach {
        reachable: true,
        udp_on: true,
        kad_running: true,
        dial: DialPosition::default(),
        // Off unless a leg turns it on, so the server coordinator never
        // pre-empts a route a leg is about something else.
        server_punch: false,
    }
}

#[test]
fn a_high_id_peer_is_dialed_directly_never_the_callback_tree() {
    let target = CallbackTarget {
        id: high_id(),
        tcp: peer(203, 0, 113, 4, 4662),
        // Even with a buddy and direct-callback advert, a HighID peer skips
        // the whole tree — a plain dial reaches it.
        supports_direct_udp_callback: true,
        kad_udp: Some(endpoint(203, 0, 113, 4, 4665)),
        on_our_server: true,
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 1, 9000)),
        }),
        ipv6: None,
        supports_natt: false,
    };
    assert_eq!(
        select_callback_route(&target, &open_self()),
        CallbackRoute::Direct {
            tcp: peer(203, 0, 113, 4, 4662)
        }
    );
}

#[test]
fn route_2_direct_udp_callback_when_advertised_and_our_udp_is_up() {
    let target = CallbackTarget {
        supports_direct_udp_callback: true,
        kad_udp: Some(endpoint(198, 51, 100, 7, 4665)),
        // On our server *and* buddy-capable too, yet the direct route wins —
        // it precedes the server and buddy routes in aMule's order.
        on_our_server: true,
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 2, 9000)),
        }),
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&target, &open_self()),
        CallbackRoute::DirectUdp {
            target_kad_udp: endpoint(198, 51, 100, 7, 4665)
        }
    );

    // Our UDP down demotes it to the next viable route (here, the server).
    assert_eq!(
        select_callback_route(
            &target,
            &SelfReach {
                udp_on: false,
                ..open_self()
            }
        ),
        CallbackRoute::Server { low_id: low_id() }
    );
    // Advert set but no Kad UDP port known: the direct route cannot address
    // the `0x95`, so it falls through to the server route.
    assert_eq!(
        select_callback_route(
            &CallbackTarget {
                kad_udp: None,
                ..target
            },
            &open_self()
        ),
        CallbackRoute::Server { low_id: low_id() }
    );
}

#[test]
fn route_3_server_callback_when_on_our_server_and_no_direct_route() {
    let target = CallbackTarget {
        on_our_server: true,
        // Buddy-capable, but the server route precedes the buddy route.
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 3, 9000)),
        }),
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&target, &open_self()),
        CallbackRoute::Server { low_id: low_id() }
    );
}

#[test]
fn route_4_buddy_callback_emits_to_a_known_endpoint_or_walks_toward_the_id() {
    // Buddy endpoint known: 0x52 straight to it.
    let known = CallbackTarget {
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 8, 9001)),
        }),
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&known, &open_self()),
        CallbackRoute::Buddy {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 8, 9001)),
        }
    );

    // Endpoint unknown: a FINDSOURCE walk toward the buddy id (buddy_udp None).
    let walk = CallbackTarget {
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: None,
        }),
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&walk, &open_self()),
        CallbackRoute::Buddy {
            buddy_id: buddy(),
            buddy_udp: None,
        }
    );
}

/// A firewalled us — the position rung 1 exists for.
fn firewalled_self() -> SelfReach {
    SelfReach {
        reachable: false,
        ..open_self()
    }
}

/// A LowID target off our server that speaks NAT-T and published a buddy
/// with a known endpoint: every fact rung 1 needs, and nothing else.
fn punchable_target() -> CallbackTarget {
    CallbackTarget {
        supports_natt: true,
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 2, 9000)),
        }),
        ..bare_low_id_target()
    }
}

fn natt_via_buddy(buddy_udp: Option<Ipv4Endpoint>) -> CallbackRoute {
    CallbackRoute::NatTraversal {
        coordinator: NattCoordinator::Buddy {
            buddy_id: buddy(),
            buddy_udp,
        },
    }
}

/// ADR-0091: the LowID↔LowID pair that used to be dropped is punched.
#[test]
fn rung_1_punches_a_low_to_low_pair_instead_of_dropping_it() {
    assert_eq!(
        select_callback_route(&punchable_target(), &firewalled_self()),
        natt_via_buddy(Some(endpoint(198, 51, 100, 2, 9000)))
    );
}

/// Rung 1's selection matrix — each row removes exactly one fact and the
/// pair is a `LowToLow` drop again. A buddy whose endpoint is unknown
/// costs a Kad walk, so *that* row needs Kad; a known one does not.
#[test]
fn rung_1_drops_only_when_no_punch_is_possible() {
    let dropped = CallbackRoute::Drop {
        reason: CallbackDrop::LowToLow,
    };
    let walk_needed = CallbackTarget {
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: None,
        }),
        ..punchable_target()
    };
    let kad_down = SelfReach {
        kad_running: false,
        ..firewalled_self()
    };
    let udp_down = SelfReach {
        udp_on: false,
        ..firewalled_self()
    };
    let no_natt = CallbackTarget {
        supports_natt: false,
        ..punchable_target()
    };
    let no_buddy = CallbackTarget {
        buddy: None,
        ..punchable_target()
    };

    assert_eq!(select_callback_route(&no_natt, &firewalled_self()), dropped);
    assert_eq!(
        select_callback_route(&no_buddy, &firewalled_self()),
        dropped
    );
    assert_eq!(
        select_callback_route(&punchable_target(), &udp_down),
        dropped
    );
    assert_eq!(select_callback_route(&walk_needed, &kad_down), dropped);

    assert_eq!(
        select_callback_route(&walk_needed, &firewalled_self()),
        natt_via_buddy(None)
    );
    assert_eq!(
        select_callback_route(&punchable_target(), &kad_down),
        natt_via_buddy(Some(endpoint(198, 51, 100, 2, 9000))),
        "a known buddy endpoint needs no walk, so no Kad"
    );
}

/// Rung order holds around the new rung: rung 0 still precedes it, and a
/// reachable us never punches first — a callback is cheaper and the
/// target's NAT-T support changes nothing about that.
#[test]
fn rung_1_sits_after_rung_0_and_never_pre_empts_a_callback() {
    let with_v6 = CallbackTarget {
        ipv6: Some(v6()),
        ..punchable_target()
    };
    let firewalled_holding_v6 = SelfReach {
        reachable: false,
        ..holding_ipv6()
    };
    assert!(matches!(
        select_callback_route(&with_v6, &firewalled_holding_v6),
        CallbackRoute::Direct { .. }
    ));
    assert!(matches!(
        select_callback_route(&punchable_target(), &open_self()),
        CallbackRoute::Buddy { .. }
    ));
}

/// The two coordinators, in order. A firewalled us and a target on our own
/// punch-capable server take the server — even with a perfectly good buddy
/// on offer, and even with the target's NAT-T support unknown, because the
/// server is the one that knows it. Take away any of the three facts and
/// the buddy is next; and a target on our server with *no* coordinator
/// still gets ADR-0061's server callback, exactly as before this rung.
#[test]
fn the_server_coordinates_first_and_the_buddy_is_what_is_left() {
    let ours = SelfReach {
        server_punch: true,
        ..firewalled_self()
    };
    let on_server = CallbackTarget {
        on_our_server: true,
        ..punchable_target()
    };
    let via_server = CallbackRoute::NatTraversal {
        coordinator: NattCoordinator::Server { low_id: low_id() },
    };
    assert_eq!(select_callback_route(&on_server, &ours), via_server);

    let unknown_caps = CallbackTarget {
        supports_natt: false,
        buddy: None,
        ..on_server
    };
    assert_eq!(select_callback_route(&unknown_caps, &ours), via_server);

    let via_buddy = natt_via_buddy(Some(endpoint(198, 51, 100, 2, 9000)));
    assert_eq!(select_callback_route(&punchable_target(), &ours), via_buddy);
    assert_eq!(
        select_callback_route(&on_server, &firewalled_self()),
        via_buddy
    );

    assert_eq!(
        select_callback_route(&unknown_caps, &firewalled_self()),
        CallbackRoute::Server { low_id: low_id() },
        "no coordinator: ADR-0061's route stands"
    );
}

/// Fallback ordering: a server that refused or stayed silent hands over to
/// the buddy when there is one; a buddy that failed hands over to nobody —
/// its retries are the schedule's, and going back up would loop.
#[test]
fn a_failed_server_introduction_falls_to_the_buddy_and_never_back() {
    let ours = SelfReach {
        server_punch: true,
        ..firewalled_self()
    };
    let target = CallbackTarget {
        on_our_server: true,
        ..punchable_target()
    };
    let server = NattCoordinator::Server { low_id: low_id() };
    let buddy = NattCoordinator::Buddy {
        buddy_id: buddy(),
        buddy_udp: Some(endpoint(198, 51, 100, 2, 9000)),
    };
    assert_eq!(
        next_natt_coordinator(&target.natt_facts(), &ours, &server),
        Some(buddy)
    );
    assert_eq!(
        next_natt_coordinator(&target.natt_facts(), &ours, &buddy),
        None
    );

    let no_buddy = CallbackTarget {
        buddy: None,
        ..target
    };
    assert_eq!(
        next_natt_coordinator(&no_buddy.natt_facts(), &ours, &server),
        None
    );
}

/// The target's half of rung 1, stated once: for every shape of candidate,
/// `admits_coordinator` agrees with the coordinator search run under a
/// position that gates nothing away. That agreement is what lets the
/// download brain decide whether a callback deserves a 12 s deadline
/// without holding a second copy of the rung's condition.
#[test]
fn natt_facts_admit_exactly_the_coordinators_the_selector_can_find() {
    let ours = SelfReach {
        server_punch: true,
        ..firewalled_self()
    };
    for on_our_server in [false, true] {
        for supports_natt in [false, true] {
            for buddy_contact in [
                None,
                Some(BuddyContact {
                    buddy_id: buddy(),
                    buddy_udp: None,
                }),
            ] {
                let target = CallbackTarget {
                    on_our_server,
                    supports_natt,
                    buddy: buddy_contact,
                    ..bare_low_id_target()
                };
                assert_eq!(
                    target.natt_facts().admits_coordinator(),
                    natt_coordinator(&target, &ours).is_some(),
                    "target facts and the coordinator search must agree: {target:?}"
                );
            }
        }
    }
}

/// The 12 s callback-silence fallback: only a callback falls back, only
/// after the full delay, and only onto a punch that is possible.
#[test]
fn a_silent_callback_falls_back_to_nat_traversal_after_twelve_seconds() {
    let target = punchable_target();
    let ours = open_self();
    let taken = select_callback_route(&target, &ours);
    assert!(matches!(taken, CallbackRoute::Buddy { .. }));

    let just_under = CALLBACK_SILENCE_FALLBACK - Duration::from_millis(1);
    assert_eq!(
        select_natt_fallback(&target, &ours, &taken, just_under),
        None
    );
    assert_eq!(
        select_natt_fallback(&target, &ours, &taken, CALLBACK_SILENCE_FALLBACK),
        Some(natt_via_buddy(Some(endpoint(198, 51, 100, 2, 9000))))
    );

    let long = CALLBACK_SILENCE_FALLBACK * 10;
    let legacy = CallbackTarget {
        supports_natt: false,
        ..target
    };
    assert_eq!(select_natt_fallback(&legacy, &ours, &taken, long), None);
    for not_a_callback in [
        CallbackRoute::Direct { tcp: target.tcp },
        natt_via_buddy(None),
        CallbackRoute::Drop {
            reason: CallbackDrop::NoBuddy,
        },
    ] {
        assert_eq!(
            select_natt_fallback(&target, &ours, &not_a_callback, long),
            None
        );
    }
}

#[test]
fn route_1_drops_low_to_low_off_our_server_but_the_server_relay_saves_on_server() {
    // We are LowID (not reachable). A LowID target not on our server is the
    // LowID→LowID dead end — drop.
    let off_server = bare_low_id_target();
    assert_eq!(
        select_callback_route(
            &off_server,
            &SelfReach {
                reachable: false,
                ..open_self()
            }
        ),
        CallbackRoute::Drop {
            reason: CallbackDrop::LowToLow
        }
    );

    // The same firewalled us reaches a LowID target that shares our server:
    // the server relays (route 3), so it is not a LowID→LowID drop.
    let on_server = CallbackTarget {
        on_our_server: true,
        ..off_server
    };
    assert_eq!(
        select_callback_route(
            &on_server,
            &SelfReach {
                reachable: false,
                ..open_self()
            }
        ),
        CallbackRoute::Server { low_id: low_id() }
    );
}

#[test]
fn no_buddy_or_kad_down_drops_an_otherwise_off_server_low_id_target() {
    // Reachable us, LowID target off our server, no direct support: only the
    // buddy route remains. No buddy contact ⇒ drop.
    assert_eq!(
        select_callback_route(&bare_low_id_target(), &open_self()),
        CallbackRoute::Drop {
            reason: CallbackDrop::NoBuddy
        }
    );

    // A buddy contact exists, but Kad is down ⇒ still a no-buddy drop.
    let with_buddy = CallbackTarget {
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 8, 9001)),
        }),
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(
            &with_buddy,
            &SelfReach {
                kad_running: false,
                ..open_self()
            }
        ),
        CallbackRoute::Drop {
            reason: CallbackDrop::NoBuddy
        }
    );
}

#[test]
fn the_low_id_grant_dial_back_routes_through_the_same_selector() {
    // ADR-0057's parked grant dial-back (ADR-0061 "one selector, every
    // caller"): promoting a *disconnected* upload waiter asks this chooser
    // how to reach it. A HighID waiter is dialed straight back — a
    // `DialBackGrant`.
    let high_waiter = CallbackTarget {
        id: high_id(),
        tcp: peer(203, 0, 113, 20, 4662),
        supports_direct_udp_callback: false,
        kad_udp: None,
        on_our_server: false,
        buddy: None,
        ipv6: None,
        supports_natt: false,
    };
    assert_eq!(
        select_callback_route(&high_waiter, &open_self()),
        CallbackRoute::Direct {
            tcp: peer(203, 0, 113, 20, 4662)
        }
    );

    // A LowID waiter that queued with us from our own server — a dead TCP
    // dial-back could never reach it, so it takes the server callback route
    // instead (the fix for ADR-0057's parked LowID grant dial-back).
    let low_waiter = CallbackTarget {
        id: low_id(),
        on_our_server: true,
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&low_waiter, &open_self()),
        CallbackRoute::Server { low_id: low_id() }
    );

    // A LowID waiter off our server, reachable only through its buddy —
    // the grant dial-back still finds the route, never a dead dial.
    let buddy_waiter = CallbackTarget {
        id: low_id(),
        on_our_server: false,
        buddy: Some(BuddyContact {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 9, 9002)),
        }),
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&buddy_waiter, &open_self()),
        CallbackRoute::Buddy {
            buddy_id: buddy(),
            buddy_udp: Some(endpoint(198, 51, 100, 9, 9002)),
        }
    );
}

/// Rung 0 (ADR-0087): a peer with a usable IPv6 is dialed directly while
/// we hold a Known one — **Low ID included**. The classic "Low ID ⇒
/// callback" rule governs the peer's IPv4 identity; its IPv6 address
/// stands on its own, so the firewalled peer that would otherwise need a
/// broker needs none.
#[test]
fn rung_zero_dials_a_low_id_peer_over_ipv6_and_skips_every_callback() {
    let target = CallbackTarget {
        ipv6: Some(v6()),
        // Every callback route is available and none of them fires.
        supports_direct_udp_callback: true,
        kad_udp: Some(endpoint(198, 51, 100, 7, 4665)),
        on_our_server: true,
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&target, &holding_ipv6()),
        CallbackRoute::Direct {
            tcp: PeerEndpoint::V6(v6())
        }
    );
}

/// The AND, from both sides. Without an address of our own the same peer
/// falls back through the ordinary tree; without the peer's address so
/// does everyone else.
#[test]
fn rung_zero_needs_both_halves_or_the_ordinary_tree_stands() {
    let with_v6 = CallbackTarget {
        ipv6: Some(v6()),
        on_our_server: true,
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&with_v6, &open_self()),
        CallbackRoute::Server { low_id: low_id() },
        "we hold no IPv6, so its address is one we cannot dial from"
    );

    let without = CallbackTarget {
        on_our_server: true,
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&without, &holding_ipv6()),
        CallbackRoute::Server { low_id: low_id() },
        "we hold one, the peer named none"
    );
}

/// Rung 0 is rung *zero*: it precedes even the plain High-ID dial, which
/// is the spec's dial preference — when both sides have an address in the
/// family, that is the family used.
#[test]
fn rung_zero_precedes_the_plain_high_id_dial() {
    let dual_stack = CallbackTarget {
        id: high_id(),
        tcp: peer(203, 0, 113, 4, 4662),
        ipv6: Some(v6()),
        ..bare_low_id_target()
    };
    assert_eq!(
        select_callback_route(&dual_stack, &holding_ipv6()),
        CallbackRoute::Direct {
            tcp: PeerEndpoint::V6(v6())
        }
    );
    // And with no address of our own the same peer is dialed over IPv4.
    assert_eq!(
        select_callback_route(&dual_stack, &open_self()),
        CallbackRoute::Direct {
            tcp: peer(203, 0, 113, 4, 4662)
        }
    );
}
