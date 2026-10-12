//! Firewalled-node unit tests: the recruit rule's gating on both surfaces
//! being firewalled, its one walk at a time, the twenty-minute pacing and its
//! instant retry after a published buddy loss, the XOR inversion checked on
//! adoption, the relayed and direct
//! callback refusal matrices (Kad gating, file knowledge, per-IP rate limit
//! and its capped tracker), and the buddy facts published only while
//! firewalled with a slot filled.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_kad::KadId;
use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, UserHash};

use super::direct_callback::*;
use super::link::{BuddySnapshot, BuddyState};
use super::recruit::*;
use super::relayed_callback::*;
use super::*;
use crate::buddy::BuddyUdpPosture;
use crate::reachability::TcpReachability;

fn kad_id(byte: u8) -> KadId {
    KadId::from_bytes([byte; KadId::BYTE_LEN])
}

fn endpoint(host: u8, port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, host), port)
}

/// Our own Kad ID for the node under test; its inverse (`~ourKadID`) is the
/// walk target and the value every buddy-ID check must invert back to.
fn our_id() -> KadId {
    kad_id(0x11)
}

/// Both surfaces firewalled, Kad up, no recent recheck, no crypt — the only
/// context that recruits.
fn both_firewalled() -> RecruitContext {
    RecruitContext {
        kad_connected: true,
        tcp: TcpReachability::Firewalled,
        udp: BuddyUdpPosture::Firewalled,
        last_recheck: None,
        crypt_required: false,
    }
}

/// A verified FINDBUDDY answer: the buddy-ID is the walk target (`~ourKadID`).
fn valid_answer() -> FindBuddyRes {
    FindBuddyRes {
        buddy_id: inverted(&our_id()),
        buddy_endpoint: endpoint(9, 9000),
    }
}

/// The slot as its owner publishes it with nothing held and nothing lost.
fn empty() -> BuddySnapshot {
    BuddySnapshot::default()
}

#[test]
fn recruitment_fires_only_when_both_surfaces_are_firewalled() {
    let t0 = Instant::now();

    // Both firewalled (and Kad up, no buddy, pacing due, no crypt): recruit,
    // walking toward ~ourKadID.
    let mut rule = Recruiter::new(our_id());
    assert_eq!(
        rule.consider(&both_firewalled(), &empty(), t0),
        RecruitDecision::Recruit {
            walk_target: inverted(&our_id())
        }
    );

    // Either surface open forecloses recruitment, each with its own reason —
    // an open node needs no buddy; a UDP-open node takes the direct-callback
    // path. This is the headline gate.
    for (ctx, reason) in [
        (
            RecruitContext {
                tcp: TcpReachability::Open,
                ..both_firewalled()
            },
            RecruitRefusal::TcpOpen,
        ),
        (
            RecruitContext {
                udp: BuddyUdpPosture::Open,
                ..both_firewalled()
            },
            RecruitRefusal::UdpOpen,
        ),
        (
            RecruitContext {
                udp: BuddyUdpPosture::Unverified,
                ..both_firewalled()
            },
            RecruitRefusal::UdpUnverified,
        ),
        (
            RecruitContext {
                kad_connected: false,
                ..both_firewalled()
            },
            RecruitRefusal::KadNotConnected,
        ),
        (
            RecruitContext {
                crypt_required: true,
                ..both_firewalled()
            },
            RecruitRefusal::CryptRequired,
        ),
    ] {
        let mut rule = Recruiter::new(our_id());
        assert_eq!(
            rule.consider(&ctx, &empty(), t0),
            RecruitDecision::Refuse { reason },
            "context {ctx:?} must refuse"
        );
        assert_eq!(
            rule.status(),
            RecruitStatus {
                walking: false,
                refusal: Some(reason)
            },
            "the refusal is the status a reader sees"
        );
    }
}

#[test]
fn one_walk_runs_at_a_time_and_its_end_does_not_re_arm_the_pacing() {
    let t0 = Instant::now();
    let mut rule = Recruiter::new(our_id());

    assert!(matches!(
        rule.consider(&both_firewalled(), &empty(), t0),
        RecruitDecision::Recruit { .. }
    ));
    assert!(rule.status().walking);
    // A second tick while the first walk runs must not start another: two
    // walks would ask two open nodes for a slot that holds one buddy — even
    // with the slot publishing a loss the walk has not answered yet.
    let lost_meanwhile = BuddySnapshot {
        lost_at: Some(t0 + Duration::from_secs(1)),
        ..empty()
    };
    assert_eq!(
        rule.consider(
            &both_firewalled(),
            &lost_meanwhile,
            t0 + Duration::from_secs(2)
        ),
        RecruitDecision::Refuse {
            reason: RecruitRefusal::PacingNotDue
        }
    );

    // The walk ending clears the flag but not the clock: a cold routing table
    // is not a reason to walk again every tick.
    rule.walk_ended();
    assert!(!rule.status().walking);
    assert_eq!(
        rule.consider(&both_firewalled(), &empty(), t0 + Duration::from_secs(60)),
        RecruitDecision::Refuse {
            reason: RecruitRefusal::PacingNotDue
        }
    );
    assert!(matches!(
        rule.consider(&both_firewalled(), &empty(), t0 + FIND_BUDDY_INTERVAL),
        RecruitDecision::Recruit { .. }
    ));
}

#[test]
fn recruitment_paces_at_twenty_minutes_clears_a_recheck_and_recruits_instantly_after_a_loss() {
    let t0 = Instant::now();
    let mut rule = Recruiter::new(our_id());

    // First recruit stamps the pacing clock.
    assert!(matches!(
        rule.consider(&both_firewalled(), &empty(), t0),
        RecruitDecision::Recruit { .. }
    ));
    rule.walk_ended();

    // Inside the 20-minute tick a second walk is paced off.
    assert_eq!(
        rule.consider(&both_firewalled(), &empty(), t0 + Duration::from_secs(60)),
        RecruitDecision::Refuse {
            reason: RecruitRefusal::PacingNotDue
        }
    );
    // At the 20-minute boundary the walk may retry.
    assert!(matches!(
        rule.consider(&both_firewalled(), &empty(), t0 + FIND_BUDDY_INTERVAL),
        RecruitDecision::Recruit { .. }
    ));
    rule.walk_ended();

    // A recent firewall recheck holds recruitment off even when the interval
    // is due — the recheck could flip our verdict.
    let after_interval = t0 + FIND_BUDDY_INTERVAL + FIND_BUDDY_INTERVAL;
    assert_eq!(
        rule.consider(
            &RecruitContext {
                last_recheck: Some(after_interval - Duration::from_secs(60)),
                ..both_firewalled()
            },
            &empty(),
            after_interval,
        ),
        RecruitDecision::Refuse {
            reason: RecruitRefusal::PacingNotDue
        }
    );
    // ≥5 minutes clear of the recheck, it recruits.
    assert!(matches!(
        rule.consider(
            &RecruitContext {
                last_recheck: Some(after_interval - POST_RECHECK_GUARD),
                ..both_firewalled()
            },
            &empty(),
            after_interval,
        ),
        RecruitDecision::Recruit { .. }
    ));
    rule.walk_ended();

    // The slot publishes a buddy held → recruitment refuses regardless of
    // pacing.
    let held = BuddySnapshot {
        state: BuddyState::Held,
        held_since: Some(after_interval),
        ..empty()
    };
    let later = after_interval + Duration::from_secs(1);
    assert_eq!(
        rule.consider(&both_firewalled(), &held, later),
        RecruitDecision::Refuse {
            reason: RecruitRefusal::AlreadyHaveBuddy
        }
    );

    // The slot publishes the buddy lost after the last walk began: an instant
    // recruit — no waiting out another 20 minutes (aMule resets its tick),
    // the recheck guard still clear here.
    let lost = BuddySnapshot {
        lost_at: Some(later),
        ..empty()
    };
    assert!(matches!(
        rule.consider(&both_firewalled(), &lost, later + Duration::from_secs(1)),
        RecruitDecision::Recruit { .. }
    ));
}

#[test]
fn adopting_a_buddy_verifies_the_xor_inversion_and_fills_the_slot() {
    let mut node = FirewalledNode::new(our_id());
    assert!(!node.has_buddy());

    // A `0x5A` whose buddy-ID does not invert to our KadID is a stray/spoofed
    // answer — rejected, slot untouched.
    let stray = FindBuddyRes {
        buddy_id: kad_id(0x33),
        buddy_endpoint: endpoint(8, 9000),
    };
    assert_eq!(node.adopt_buddy(&stray), AdoptOutcome::Rejected);
    assert!(!node.has_buddy());

    // The genuine answer (buddy-ID = ~ourKadID) fills the slot.
    assert_eq!(node.adopt_buddy(&valid_answer()), AdoptOutcome::Adopted);
    assert!(node.has_buddy());
}

#[test]
fn the_callback_relay_consume_gates_on_kad_the_xor_check_and_a_known_file() {
    let node = FirewalledNode::new(our_id());
    let requester = endpoint(20, 4662);

    // A callback for us (check inverts to our KadID) naming a file we hold:
    // dial the requester.
    let ours = CallbackConsume {
        check_id: inverted(&our_id()),
        file_shared_or_downloading: true,
        requester,
    };
    assert_eq!(
        node.consume_callback(&ours, true),
        CallbackVerdict::Dial {
            requester,
            swapped_spelling: false
        }
    );

    // Kad down drops it — the mechanism is Kad-scoped.
    assert_eq!(
        node.consume_callback(&ours, false),
        CallbackVerdict::Drop {
            reason: CallbackDrop::KadDown
        }
    );
    // A check that does not invert to our KadID is not for us.
    assert_eq!(
        node.consume_callback(
            &CallbackConsume {
                check_id: kad_id(0x44),
                ..ours
            },
            true
        ),
        CallbackVerdict::Drop {
            reason: CallbackDrop::NotForUs
        }
    );
    // A file we neither share nor download: nothing to serve back.
    assert_eq!(
        node.consume_callback(
            &CallbackConsume {
                file_shared_or_downloading: false,
                ..ours
            },
            true
        ),
        CallbackVerdict::Drop {
            reason: CallbackDrop::FileUnknown
        }
    );
}

/// **Source-derived**: a requester that read our aMule-spelled
/// `TAG_BUDDYHASH` the eMule 0.70b / eMuleAI way (`GetData()`, a per-word
/// swap away) addresses `~ourKadID` with each four-byte word reversed. That
/// spelling is still us — dialed, and flagged so the relay counts it apart.
/// Anything else, a whole-ID byte reversal included, stays `NotForUs`.
#[test]
fn source_derived_the_callback_consume_accepts_either_spelling_of_our_own_id() {
    // Asymmetric per word, so the two spellings differ (a palindrome would
    // hide which one matched).
    let ours = KadId::from_bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);
    let node = FirewalledNode::new(ours);
    let requester = endpoint(20, 4662);
    let consume = |check_id| {
        node.consume_callback(
            &CallbackConsume {
                check_id,
                file_shared_or_downloading: true,
                requester,
            },
            true,
        )
    };

    assert_eq!(
        consume(inverted(&ours)),
        CallbackVerdict::Dial {
            requester,
            swapped_spelling: false
        }
    );
    assert_eq!(
        consume(inverted(&ours).word_swapped()),
        CallbackVerdict::Dial {
            requester,
            swapped_spelling: true
        }
    );
    let mut reversed = *inverted(&ours).as_bytes();
    reversed.reverse();
    for stranger in [kad_id(0x44), KadId::from_bytes(reversed)] {
        assert_eq!(
            consume(stranger),
            CallbackVerdict::Drop {
                reason: CallbackDrop::NotForUs
            }
        );
    }
}

#[test]
fn the_direct_callback_consume_is_firewalled_gated_kad_gated_and_rate_limited_per_ip() {
    let t0 = Instant::now();
    let mut node = FirewalledNode::new(our_id());
    let hash = UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]);
    let from_a = DirectCallbackConsume {
        requester: PeerEndpoint::V4(endpoint(30, 4662)),
        user_hash: hash,
        connect_options: 0x03,
    };
    let firewalled = DirectCallbackContext {
        tcp: TcpReachability::Firewalled,
        kad_running: true,
        crypt: None,
    };

    // Firewalled + Kad up + first request from this IP: dial back. Plaintext,
    // because this node's own obfuscation is off however loudly the requester
    // asks — the crypt matrix is the next test's subject.
    assert_eq!(
        node.consume_direct_callback(&from_a, &firewalled, t0),
        DirectCallbackVerdict::DialBack {
            requester: from_a.requester,
            obfuscate_toward: None,
        }
    );

    // A second request from the same IP inside the window is a flood — refused.
    assert_eq!(
        node.consume_direct_callback(&from_a, &firewalled, t0 + Duration::from_secs(10)),
        DirectCallbackVerdict::Refuse {
            reason: DirectCallbackRefusal::RateLimited
        }
    );
    // A different IP is not rate-limited by the first one.
    let from_b = DirectCallbackConsume {
        requester: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 4662)),
        ..from_a
    };
    assert!(matches!(
        node.consume_direct_callback(&from_b, &firewalled, t0 + Duration::from_secs(10)),
        DirectCallbackVerdict::DialBack { .. }
    ));
    // Once the window elapses the first IP is allowed again.
    assert!(matches!(
        node.consume_direct_callback(&from_a, &firewalled, t0 + DIRECT_CALLBACK_MIN_INTERVAL),
        DirectCallbackVerdict::DialBack { .. }
    ));

    // Reachability gate: once our TCP verdict reads open we are no longer
    // firewalled, so a direct callback to us is spurious — refused before the
    // rate limit is even consulted (a fresh node, fresh IP).
    let mut open_node = FirewalledNode::new(our_id());
    assert_eq!(
        open_node.consume_direct_callback(
            &from_a,
            &DirectCallbackContext {
                tcp: TcpReachability::Open,
                kad_running: true,
                crypt: None,
            },
            t0,
        ),
        DirectCallbackVerdict::Refuse {
            reason: DirectCallbackRefusal::NotFirewalled
        }
    );
    // Kad down refuses too.
    assert_eq!(
        open_node.consume_direct_callback(
            &from_a,
            &DirectCallbackContext {
                tcp: TcpReachability::Firewalled,
                kad_running: false,
                crypt: None,
            },
            t0,
        ),
        DirectCallbackVerdict::Refuse {
            reason: DirectCallbackRefusal::KadDown
        }
    );
}

/// aMule's two crypt readings for an outbound dial, applied to the stance the
/// requester put in its own `0x95` body: `TryToConnect`'s refusal
/// of a pair that cannot meet, then `Connect`'s choice — which needs *somebody*
/// to ask, so two nodes that merely support obfuscation still speak plaintext.
#[test]
fn the_direct_callback_dial_back_obfuscates_per_both_crypt_stances() {
    let hash = UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]);
    let obfuscated = DirectCallbackVerdict::DialBack {
        requester: PeerEndpoint::V4(endpoint(30, 4662)),
        obfuscate_toward: Some(hash),
    };
    let plaintext = DirectCallbackVerdict::DialBack {
        requester: PeerEndpoint::V4(endpoint(30, 4662)),
        obfuscate_toward: None,
    };
    let incompatible = DirectCallbackVerdict::Refuse {
        reason: DirectCallbackRefusal::CryptIncompatible,
    };

    // `connect_options`: bit 0 supports, bit 1 requests, bit 2 requires.
    for (connect_options, ours, expected) in [
        (0x00, None, &plaintext),
        (0x03, None, &plaintext),
        (0x07, None, &incompatible),
        (0x00, Some(ObfuscationPolicy::Supported), &plaintext),
        (0x01, Some(ObfuscationPolicy::Supported), &plaintext),
        (0x03, Some(ObfuscationPolicy::Supported), &obfuscated),
        (0x07, Some(ObfuscationPolicy::Supported), &obfuscated),
        (0x01, Some(ObfuscationPolicy::Requested), &obfuscated),
        (0x00, Some(ObfuscationPolicy::Required), &incompatible),
        (0x01, Some(ObfuscationPolicy::Required), &obfuscated),
    ] {
        // A fresh node per row: the rate limiter stamps the source IP on every
        // honored request, and this leg is about the crypt reading alone.
        let mut node = FirewalledNode::new(our_id());
        assert_eq!(
            &node.consume_direct_callback(
                &DirectCallbackConsume {
                    requester: PeerEndpoint::V4(endpoint(30, 4662)),
                    user_hash: hash,
                    connect_options,
                },
                &DirectCallbackContext {
                    tcp: TcpReachability::Firewalled,
                    kad_running: true,
                    crypt: ours,
                },
                Instant::now(),
            ),
            expected,
            "connect_options {connect_options:#04x} against {ours:?}"
        );
    }
}

#[test]
fn the_direct_callback_tracker_is_capped_and_evicts_the_oldest_honored_ip() {
    let t0 = Instant::now();
    let mut node = FirewalledNode::new(our_id());
    let firewalled = DirectCallbackContext {
        tcp: TcpReachability::Firewalled,
        kad_running: true,
        crypt: None,
    };
    let hash = UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]);
    let from_nth = |n: u32| DirectCallbackConsume {
        requester: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::from(0x0A00_0000 + n), 4662)),
        user_hash: hash,
        connect_options: 0x00,
    };

    // Fill the tracker to its cap with distinct honored source IPs (the
    // spoofed-flood shape: the source IP is unauthenticated).
    for n in 0..DIRECT_CALLBACK_TRACKED_MAX as u32 {
        assert!(matches!(
            node.consume_direct_callback(&from_nth(n), &firewalled, t0),
            DirectCallbackVerdict::DialBack { .. }
        ));
    }
    // A fresh IP inside the window is still honored — the cap admits it by
    // evicting the oldest entry, never by refusing the newcomer (a flood
    // must not lock genuine requesters out for the whole window).
    let newcomer = DIRECT_CALLBACK_TRACKED_MAX as u32;
    assert!(matches!(
        node.consume_direct_callback(
            &from_nth(newcomer),
            &firewalled,
            t0 + Duration::from_secs(1)
        ),
        DirectCallbackVerdict::DialBack { .. }
    ));

    // Exactly the oldest was evicted: the second-oldest is still
    // rate-limited inside the window...
    assert_eq!(
        node.consume_direct_callback(&from_nth(1), &firewalled, t0 + Duration::from_secs(2)),
        DirectCallbackVerdict::Refuse {
            reason: DirectCallbackRefusal::RateLimited
        }
    );
    // ...while the evicted oldest is honorable again — the documented
    // earlier-than-window re-honor the cap trades for bounded memory.
    assert!(matches!(
        node.consume_direct_callback(&from_nth(0), &firewalled, t0 + Duration::from_secs(2)),
        DirectCallbackVerdict::DialBack { .. }
    ));
}

#[test]
fn publish_buddy_info_carries_the_buddy_only_while_firewalled_with_a_buddy() {
    let mut node = FirewalledNode::new(our_id());

    // No buddy yet: nothing to publish.
    assert_eq!(node.publish_buddy_info(true), None);

    // Firewalled with a buddy: publish the buddy's endpoint and the
    // relationship ID (~ourKadID) a searcher addresses its 0x52 with.
    node.adopt_buddy(&valid_answer());
    assert_eq!(
        node.publish_buddy_info(true),
        Some(BuddyPublish {
            buddy_udp: valid_answer().buddy_endpoint,
            buddy_id: inverted(&our_id()),
            buddy_ipv6: None,
        })
    );

    // A node that reads reachable publishes a direct source — no buddy info,
    // even while the slot is (transiently) still filled.
    assert_eq!(node.publish_buddy_info(false), None);
}

/// The publish row reads **Self Reach**'s
/// `IsFirewalled()` union (`Search.cpp:596-633`, `4e8f2b3c`), never the Kad
/// TCP verdict alone and never a copy: a server High ID gained mid-session
/// flips the next row from buddy (3) to direct (1), losing it flips it back,
/// and a Kad TCP verdict opening flips it to direct again — each read at the
/// publish, with no fresh buddy adoption.
#[test]
fn the_publish_row_follows_self_reach_on_the_high_id_and_the_kad_verdict() {
    let mut node = FirewalledNode::new(our_id());
    node.adopt_buddy(&valid_answer());
    let kad = crate::reachability::SharedKadVerdicts::default();
    let own = crate::own_identity::SharedOwnIdentity::default();
    let reach = crate::reachability::SharedSelfReach::new(
        crate::KadReachLevel::published(kad.clone()),
        own.clone(),
        crate::natt::front::SharedNattFront::default(),
    );
    let buddy_row = Some(BuddyPublish {
        buddy_udp: valid_answer().buddy_endpoint,
        buddy_id: inverted(&our_id()),
        buddy_ipv6: None,
    });
    assert_eq!(
        node.publish_buddy_info(reach.firewalled()),
        buddy_row,
        "Low-ID, Kad-firewalled, holding a buddy: the buddy row"
    );

    let high = crate::own_identity::ConnectedSession {
        server: None,
        client_id: rmule_primitives::ClientId::from_u32(0x0A00_0001),
    };
    own.set_connected_session(Some(high));
    assert_eq!(
        node.publish_buddy_info(reach.firewalled()),
        None,
        "a server High ID: the direct row, the Kad verdict unmoved"
    );
    own.set_connected_session(None);
    assert_eq!(node.publish_buddy_info(reach.firewalled()), buddy_row);

    kad.set_tcp(crate::reachability::TcpReachability::Open);
    assert_eq!(
        node.publish_buddy_info(reach.firewalled()),
        None,
        "Kad TCP open: the direct row"
    );
}
