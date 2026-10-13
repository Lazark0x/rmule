//! Reachability unit tests: the per-endpoint engagement ticket and the
//! enactment budget guarding the broker, the two-ack TCP verdict and its
//! recheck, the Kad connect-back and UDP verdicts arriving through the event
//! projection, the two verdicts composing without disturbing each other, the
//! broker's version-gated dial plus its two engagement refusals, and the
//! two-reading crypt rule's obfuscated/plaintext/incompatible legs.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use rmule_primitives::{Ipv4Endpoint, OutboundCrypt};

use super::dial_back::*;
use super::*;

fn endpoint(ip: [u8; 4], port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port)
}

/// The registry's per-endpoint engagement: a second dial-back toward an
/// endpoint whose enactment is still in flight is refused, and the
/// ticket's drop (however the task ends) frees it for the next check.
#[test]
fn a_second_dial_back_to_an_engaged_endpoint_is_refused_until_the_ticket_drops() {
    let registry = DialBackRegistry::default();
    let requester = endpoint([203, 0, 113, 5], 4662);

    let ticket = registry.begin(requester).expect("a fresh endpoint engages");
    assert!(
        registry.begin(requester).is_none(),
        "an engaged endpoint must not engage twice"
    );

    drop(ticket);
    assert!(
        registry.begin(requester).is_some(),
        "the ticket's drop retires the engagement"
    );
}

/// The enactment budget: distinct requesters engage until
/// `MAX_CONCURRENT_DIAL_BACKS` are in flight, the next is refused, and one
/// retirement frees exactly one slot — a flood of distinct spoofed
/// requesters cannot fan out into unbounded outbound dials.
#[test]
fn the_enactment_budget_caps_concurrent_dial_backs() {
    let registry = DialBackRegistry::default();
    let tickets: Vec<_> = (0..MAX_CONCURRENT_DIAL_BACKS)
        .map(|i| {
            registry
                .begin(endpoint([203, 0, 113, i as u8], 4662))
                .expect("within the budget every distinct endpoint engages")
        })
        .collect();

    assert!(
        registry.begin(endpoint([198, 51, 100, 9], 4662)).is_none(),
        "the budget is spent — a further distinct endpoint is refused"
    );

    drop(tickets.into_iter().next());
    assert!(
        registry.begin(endpoint([198, 51, 100, 9], 4662)).is_some(),
        "one retirement frees one slot"
    );
}

/// The registry's snapshot IS the broker's `busy` guard feed: an engaged
/// endpoint's repeat request refuses through the broker with the
/// aMule-shaped `Busy` reason, not through ad-hoc pump logic.
#[test]
fn the_engaged_snapshot_feeds_the_brokers_busy_guard() {
    let registry = DialBackRegistry::default();
    let requester = endpoint([203, 0, 113, 5], 4662);
    let _ticket = registry.begin(requester).expect("engage the endpoint");

    let engaged = registry.engaged();
    let verdict = broker_dial_back(
        &DialBackRequest {
            requester,
            connect_options: Some(0),
            user_hash: None,
        },
        &DialBackGuards {
            own: OwnListenEndpoint::at(endpoint([192, 0, 2, 1], 4662)),
            busy: &engaged,
            crypt: None,
        },
    );
    assert_eq!(
        verdict,
        DialBackVerdict::Refuse {
            reason: DialBackRefusal::Busy
        },
        "the engaged snapshot rides the broker's aMule-shaped Busy guard"
    );
}

#[test]
fn two_acks_open_the_tcp_verdict_and_one_ack_does_not() {
    // The ≥2-ack boundary: a fresh node is firewalled; its first check
    // opens a recheck that only flips to open on the *second* ack.
    let mut r = Reachability::new();
    assert_eq!(r.tcp(), TcpReachability::Firewalled);

    r.begin_tcp_recheck(std::time::Instant::now());
    assert_eq!(
        r.tcp(),
        TcpReachability::Checking {
            last: StableTcp::Firewalled
        },
        "a fresh recheck reports the firewalled snapshot"
    );

    r.record_tcp_ack();
    assert_eq!(
        r.tcp(),
        TcpReachability::Checking {
            last: StableTcp::Firewalled
        },
        "one ack is below the threshold — still checking, not open"
    );

    r.record_tcp_ack();
    assert_eq!(
        r.tcp(),
        TcpReachability::Open,
        "the second ack crosses the ≥2 boundary and opens the verdict"
    );
}

#[test]
fn a_recheck_reports_the_open_snapshot_and_a_short_recheck_concludes_firewalled() {
    // Drive to Open (two acks), then start a recheck: consumers must read
    // the stable Open snapshot mid-recheck, never a premature firewalled.
    let mut r = Reachability::new();
    r.begin_tcp_recheck(std::time::Instant::now());
    r.record_tcp_ack();
    r.record_tcp_ack();
    assert_eq!(r.tcp(), TcpReachability::Open);

    r.begin_tcp_recheck(std::time::Instant::now());
    assert_eq!(
        r.tcp(),
        TcpReachability::Checking {
            last: StableTcp::Open
        },
        "the recheck preserves the proven-open snapshot"
    );
    r.record_tcp_ack();
    assert_eq!(
        r.tcp(),
        TcpReachability::Checking {
            last: StableTcp::Open
        },
        "one ack still holds the open snapshot"
    );

    // A recheck that never reconfirms concludes on the ≥2-ack rule:
    // fewer than two acks settles firewalled.
    r.conclude_tcp_recheck();
    assert_eq!(r.tcp(), TcpReachability::Firewalled);
}

#[test]
fn kad_connect_back_acks_drive_the_store_open_through_the_event_projection() {
    // The requester's typed Kad events project onto the ≥2-ack verdict: a
    // recheck start snapshots + zeroes, two connect-backs open it.
    let mut r = Reachability::new();
    r.observe(
        &rmule_kad::KadEvent::ReachabilityRecheckStarted,
        std::time::Instant::now(),
    );
    assert_eq!(
        r.tcp(),
        TcpReachability::Checking {
            last: StableTcp::Firewalled
        }
    );
    r.observe(
        &rmule_kad::KadEvent::ReachabilityConnectBack,
        std::time::Instant::now(),
    );
    assert_eq!(
        r.tcp(),
        TcpReachability::Checking {
            last: StableTcp::Firewalled
        },
        "one projected ack is below the threshold"
    );
    r.observe(
        &rmule_kad::KadEvent::ReachabilityConnectBack,
        std::time::Instant::now(),
    );
    assert_eq!(
        r.tcp(),
        TcpReachability::Open,
        "the second projected ack opens it"
    );
}

#[test]
fn a_recheck_that_falls_short_projects_back_to_firewalled() {
    // Proven open, then a recheck that never re-proves it: the store reads
    // the open snapshot mid-recheck, then settles firewalled on the conclude.
    let mut r = Reachability::new();
    r.observe(
        &rmule_kad::KadEvent::ReachabilityConnectBack,
        std::time::Instant::now(),
    );
    r.observe(
        &rmule_kad::KadEvent::ReachabilityConnectBack,
        std::time::Instant::now(),
    );
    assert_eq!(r.tcp(), TcpReachability::Open);

    r.observe(
        &rmule_kad::KadEvent::ReachabilityRecheckStarted,
        std::time::Instant::now(),
    );
    r.observe(
        &rmule_kad::KadEvent::ReachabilityConnectBack,
        std::time::Instant::now(),
    ); // only one this round
    assert_eq!(
        r.tcp(),
        TcpReachability::Checking {
            last: StableTcp::Open
        },
        "mid-recheck reads the proven-open snapshot"
    );
    r.observe(
        &rmule_kad::KadEvent::ReachabilityRecheckConcluded,
        std::time::Instant::now(),
    );
    assert_eq!(r.tcp(), TcpReachability::Firewalled);
}

#[test]
fn the_udp_verdict_projects_open_and_firewalled_from_the_node_events() {
    // A fresh store is UDP-unverified; the node's tester events set the
    // verdict outright (the tester already applied its 2-helper / timeout rule).
    let mut r = Reachability::new();
    assert_eq!(r.udp(), UdpReachability::Unverified);

    r.observe(
        &rmule_kad::KadEvent::UdpReachabilityOpen { port: 4672 },
        std::time::Instant::now(),
    );
    assert_eq!(r.udp(), UdpReachability::Open { port: 4672 });

    r.observe(
        &rmule_kad::KadEvent::UdpReachabilityFirewalled,
        std::time::Instant::now(),
    );
    assert_eq!(r.udp(), UdpReachability::Firewalled);
}

#[test]
fn the_tcp_and_udp_verdicts_compose_without_disturbing_each_other() {
    // The two self-checks compose by coexisting in one store: projecting the
    // UDP verdict never perturbs the TCP verdict, nor the reverse — aMule
    // keeps CKademlia's TCP firewalled state and CUDPFirewallTester's separate.
    let mut r = Reachability::new();
    r.observe(
        &rmule_kad::KadEvent::ReachabilityConnectBack,
        std::time::Instant::now(),
    );
    r.observe(
        &rmule_kad::KadEvent::ReachabilityConnectBack,
        std::time::Instant::now(),
    );
    assert_eq!(r.tcp(), TcpReachability::Open);

    r.observe(
        &rmule_kad::KadEvent::UdpReachabilityFirewalled,
        std::time::Instant::now(),
    );
    assert_eq!(r.udp(), UdpReachability::Firewalled);
    assert_eq!(
        r.tcp(),
        TcpReachability::Open,
        "projecting the UDP verdict leaves the TCP verdict untouched"
    );
}

#[test]
fn is_reachable_follows_the_open_snapshot_but_not_the_firewalled_one() {
    // The gate's "Kad-open" half: Open and a proven-open recheck read
    // reachable; a firewalled verdict or snapshot does not.
    assert!(TcpReachability::Open.is_reachable());
    assert!(
        TcpReachability::Checking {
            last: StableTcp::Open
        }
        .is_reachable()
    );
    assert!(!TcpReachability::Firewalled.is_reachable());
    assert!(
        !TcpReachability::Checking {
            last: StableTcp::Firewalled
        }
        .is_reachable()
    );
}

#[test]
fn the_broker_dials_with_the_version_gated_ack() {
    let guards = DialBackGuards {
        own: OwnListenEndpoint::at(endpoint([10, 0, 0, 1], 4662)),
        busy: &HashSet::new(),
        crypt: None,
    };

    // A v7+ 0x53 with no user hash threaded acks over the dialed TCP link,
    // plaintext (no hash ⇒ no crypt fact to read, see the incompatible-pair
    // tests below for the hash-present legs).
    let modern = DialBackRequest {
        requester: endpoint([203, 0, 113, 7], 5000),
        connect_options: Some(0x03),
        user_hash: None,
    };
    assert_eq!(
        broker_dial_back(&modern, &guards),
        DialBackVerdict::Dial {
            requester: endpoint([203, 0, 113, 7], 5000),
            requester_crypt: rmule_primitives::PeerCrypt::new(
                rmule_primitives::CryptStance::new(true, true, false),
                None,
            ),
            ack: FwCheckAck::TcpLink,
        }
    );

    // A legacy 0x50 (no connect-options) acks over UDP with 0x59.
    let legacy = DialBackRequest {
        requester: endpoint([203, 0, 113, 8], 4242),
        connect_options: None,
        user_hash: None,
    };
    assert_eq!(
        broker_dial_back(&legacy, &guards),
        DialBackVerdict::Dial {
            requester: endpoint([203, 0, 113, 8], 4242),
            requester_crypt: rmule_primitives::PeerCrypt::unknown(),
            ack: FwCheckAck::Udp,
        }
    );
}

#[test]
fn the_broker_silently_refuses_the_two_engagement_guards() {
    let own_endpoint = endpoint([10, 0, 0, 1], 4662);
    let requester_ip = Ipv4Addr::new(203, 0, 113, 9);

    // Self-connect: the requester endpoint is our own listen endpoint.
    let refusal = broker_dial_back(
        &DialBackRequest {
            requester: own_endpoint,
            connect_options: Some(0),
            user_hash: None,
        },
        &DialBackGuards {
            own: OwnListenEndpoint::at(own_endpoint),
            busy: &HashSet::new(),
            crypt: None,
        },
    );
    assert_eq!(
        refusal,
        DialBackVerdict::Refuse {
            reason: DialBackRefusal::SelfConnect
        }
    );

    // Busy: we are already engaged with that exact endpoint.
    let busy_endpoint = Ipv4Endpoint::new(requester_ip, 5000);
    let mut busy = HashSet::new();
    busy.insert(busy_endpoint);
    assert_eq!(
        broker_dial_back(
            &DialBackRequest {
                requester: busy_endpoint,
                connect_options: None,
                user_hash: None,
            },
            &DialBackGuards {
                own: OwnListenEndpoint::at(own_endpoint),
                busy: &busy,
                crypt: None,
            },
        ),
        DialBackVerdict::Refuse {
            reason: DialBackRefusal::Busy
        }
    );
}

/// The ADR-0058 self-connect guard's own value follows Address Learning's
/// live IPv4, the same `SharedOwnIdentity` read the Kad pump samples for the
/// node's verify-key level: with no public IPv4 known yet nothing is us, so a
/// requester at another IP that shares our port is dialed, as aMule's
/// `GetPublicIP() == 0` test reads; a requester at the old IP + our port stops
/// being a self-connect the moment the level moves, and one at the new IP
/// starts being one.
#[test]
fn the_self_connect_guard_follows_the_learned_public_ip() {
    let own_identity = crate::own_identity::SharedOwnIdentity::default();
    let port = 4662;
    let old_ip = Ipv4Addr::new(203, 0, 113, 4);
    let new_ip = Ipv4Addr::new(203, 0, 113, 9);
    let busy = HashSet::new();

    let is_self_connect = |ip: Ipv4Addr| {
        let request = DialBackRequest {
            requester: endpoint(ip.octets(), port),
            connect_options: Some(0),
            user_hash: None,
        };
        let guards = DialBackGuards {
            own: OwnListenEndpoint::current(&own_identity, port),
            busy: &busy,
            crypt: None,
        };
        broker_dial_back(&request, &guards)
            == DialBackVerdict::Refuse {
                reason: DialBackRefusal::SelfConnect,
            }
    };

    // No IPv4 known yet: a requester on our port is somebody else's node
    // that shares the default port, whatever IP it claims.
    assert!(!is_self_connect(old_ip), "no IP known: old IP is dialed");
    assert!(!is_self_connect(new_ip), "no IP known: new IP is dialed");

    // Address Learning settles on `old_ip` (the verify-key fixture): the guard now
    // matches exact IP + port.
    own_identity
        .addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            old_ip,
        ));
    assert!(is_self_connect(old_ip), "known IP: exact match");
    assert!(
        !is_self_connect(new_ip),
        "known IP: a different IP is not us"
    );

    // The level moves: a requester at the old IP is no longer a self-connect;
    // one at the new IP is.
    own_identity
        .addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            new_ip,
        ));
    assert!(
        !is_self_connect(old_ip),
        "the guard follows: old IP retired"
    );
    assert!(
        is_self_connect(new_ip),
        "the guard follows: new IP is now us"
    );
}

/// The two-reading crypt rule (lifted from the `0x95` route into the shared
/// `PeerCrypt::outbound` home): a `0x53` whose connect-options
/// require obfuscation, met by a node whose own policy supports it, draws a
/// verdict whose requester stance the dial obfuscates toward the requester's
/// own hash (the verdict carries the requester's `PeerCrypt`); a pair
/// neither side asks to obfuscate stays plaintext even though both support
/// it; and a requester that requires what this node's policy does not
/// support is refused — counted apart from the two engagement guards above.
#[test]
fn the_broker_reads_the_two_reading_crypt_rule_off_a_v7_check() {
    let own = endpoint([10, 0, 0, 1], 4662);
    let requester = endpoint([203, 0, 113, 7], 5000);
    let hash = rmule_primitives::UserHash::from_bytes([0xAB; rmule_primitives::UserHash::BYTE_LEN]);

    // connect_options 0x07: supports + requests + requires. Met by a node
    // that merely supports (`Supported`): both support, the requester asks —
    // obfuscated, keyed on the requester's own hash.
    let guards_supported = DialBackGuards {
        own: OwnListenEndpoint::at(own),
        busy: &HashSet::new(),
        crypt: Some(rmule_net::peer::ObfuscationPolicy::Supported),
    };
    let requires = DialBackRequest {
        requester,
        connect_options: Some(0x07),
        user_hash: Some(hash),
    };
    let supported = rmule_net::peer::ObfuscationPolicy::stance_of(guards_supported.crypt);
    let dial_crypt = |request: &DialBackRequest| match broker_dial_back(request, &guards_supported)
    {
        DialBackVerdict::Dial {
            requester_crypt,
            ack: FwCheckAck::TcpLink,
            ..
        } => requester_crypt,
        other => panic!("a v7+ check the policy can meet is dialed: {other:?}"),
    };
    assert_eq!(
        dial_crypt(&requires).outbound(supported),
        OutboundCrypt::Obfuscated { toward: hash },
        "both sides support and the requester requires: obfuscated toward its own hash, as a must"
    );

    // connect_options 0x01: supports only, nobody requests. Plaintext even
    // though both sides could obfuscate — someone has to ask.
    let supports_only = DialBackRequest {
        requester,
        connect_options: Some(0x01),
        user_hash: Some(hash),
    };
    assert_eq!(
        dial_crypt(&supports_only).outbound(supported),
        OutboundCrypt::Plaintext,
        "supports-only on both sides, nobody requests: plaintext"
    );

    // connect_options 0x07 (requires) against a node with obfuscation off
    // entirely: incompatible, refused and distinguishable from the two
    // engagement guards.
    let guards_off = DialBackGuards {
        own: OwnListenEndpoint::at(own),
        busy: &HashSet::new(),
        crypt: None,
    };
    assert_eq!(
        broker_dial_back(&requires, &guards_off),
        DialBackVerdict::Refuse {
            reason: DialBackRefusal::CryptIncompatible
        },
        "a requester that requires crypt this node's policy cannot supply is refused"
    );
}

#[test]
fn a_recheck_start_stamps_the_clock_the_buddy_recruit_gate_keeps_clear_of() {
    // ADR-0061's recruit gate refuses for five minutes after a recheck starts,
    // because a recheck may be about to prove we need no relay at all. That
    // guard needs an instant to measure from, and only the recheck lifecycle
    // knows it. ADR-0086's externally triggered recheck is what made this a
    // real edge rather than an hourly one.
    let mut r = Reachability::new();
    assert_eq!(r.last_recheck(), None, "a fresh node has never rechecked");
    let at = std::time::Instant::now();
    r.observe(&rmule_kad::KadEvent::ReachabilityRecheckStarted, at);
    assert_eq!(r.last_recheck(), Some(at));
    // Nothing else in the lifecycle moves it — an ack is not a new recheck.
    r.observe(
        &rmule_kad::KadEvent::ReachabilityConnectBack,
        at + std::time::Duration::from_secs(30),
    );
    assert_eq!(r.last_recheck(), Some(at));
}

/// The why beside the TCP verdict, walked through the event projection: a
/// fresh node has run no check, a running one counts its connect-backs, and
/// an ended one keeps the count it drew — one ack stays firewalled, two open.
#[test]
fn the_tcp_check_says_whether_a_check_ran_and_what_it_drew() {
    use crate::diagnostics::KadFirewallCheck as Check;
    use rmule_kad::KadEvent as E;
    let now = std::time::Instant::now();
    let mut store = Reachability::new();
    assert_eq!(store.tcp_check(), Check::NotYetRun);

    store.observe(&E::ReachabilityRecheckStarted, now);
    assert_eq!(store.tcp_check(), Check::Running { acks: 0 });
    store.observe(&E::ReachabilityConnectBack, now);
    assert_eq!(store.tcp_check(), Check::Running { acks: 1 });
    store.observe(&E::ReachabilityRecheckConcluded, now);
    assert_eq!(store.tcp_check(), Check::Ended { acks: 1 });
    assert_eq!(store.tcp(), TcpReachability::Firewalled);

    store.observe(&E::ReachabilityRecheckStarted, now);
    store.observe(&E::ReachabilityConnectBack, now);
    store.observe(&E::ReachabilityConnectBack, now);
    assert_eq!(store.tcp_check(), Check::Ended { acks: 2 });
    assert_eq!(store.tcp(), TcpReachability::Open);
}
