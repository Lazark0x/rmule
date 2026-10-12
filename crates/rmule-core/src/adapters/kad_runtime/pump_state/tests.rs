//! The Kad Pump State through its one interface: scripted inputs and instants
//! in, effects out — no socket, no runtime, no clock.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_kad::{KadBuddyContact, KadEvent, KadId, KadPublishPosture};
use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{FileHash, Ipv4Endpoint, SourceCryptOptions, SourceLookupTarget, UserHash};

use super::*;
use crate::address_learning::AddressObservation;
use crate::firewalled::BuddyPublish;
use crate::firewalled::link::BuddySnapshot;
use crate::reachability::TcpReachability;

mod asks;
mod buddy;
mod keywords;

const OWN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 4);

/// The Kad UDP Key an armed node's verify keys derive from.
const KAD_UDP_KEY: u32 = 0x5EED_1234;

fn config() -> KadPumpConfig {
    KadPumpConfig {
        kad_udp_key: KAD_UDP_KEY,
        kad_udp_port: 4672,
        assume_open_reachability: false,
        kad_id: OUR_KAD_ID,
    }
}

/// Our Kad ID; the FINDBUDDY walk targets its inverse.
const OUR_KAD_ID: KadId = KadId::from_bytes([0xAA; KadId::BYTE_LEN]);

/// A home node just up behind a NAT: firewalled on the server and on Kad,
/// UDP not yet tested, no address learned, no buddy.
fn behind_nat() -> KadPumpSample {
    KadPumpSample {
        reach: ReachSample {
            firewalled: true,
            accepts_direct_udp_callback: false,
            natt_live: false,
            kad_tcp: TcpReachability::Firewalled,
            kad_udp: UdpReachability::Unverified,
        },
        own_address: OwnAddressSample {
            public_ip: None,
            learned_udp_port: None,
        },
        buddy: BuddySnapshot::default(),
        crypt: None,
        advertised_ipv6: None,
    }
}

fn buddy() -> BuddyPublish {
    BuddyPublish {
        buddy_udp: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672),
        buddy_id: KadId::from_bytes([0x55; KadId::BYTE_LEN]),
        buddy_ipv6: None,
    }
}

/// The levels among `effects`, in the order the node is told them.
fn levels(effects: &[KadPumpEffect]) -> Vec<NodeLevel> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            KadPumpEffect::Node(NodeCommand::Level(level)) => Some(*level),
            _ => None,
        })
        .collect()
}

/// Hand `input` in and carry out what it asks for as the driver does, depth
/// first, every node command landing as on a node with room in its inbox:
/// every effect, in the order carried out.
fn step(state: &mut KadPumpState, input: KadPumpInput, now: Instant) -> Vec<KadPumpEffect> {
    let mut queue: VecDeque<_> = state.handle(input, now).into();
    let mut carried = Vec::new();
    while let Some(effect) = queue.pop_front() {
        if let KadPumpEffect::Node(command) = &effect {
            let landed = KadPumpInput::Delivered(command.clone(), Delivery::Landed);
            for next in state.handle(landed, now).into_iter().rev() {
                queue.push_front(next);
            }
        }
        carried.push(effect);
    }
    carried
}

/// A brain started on `sample` under the `crypt` policy, every start-time
/// level landed.
fn started(crypt: Option<ObfuscationPolicy>, sample: KadPumpSample, now: Instant) -> KadPumpState {
    let mut state = KadPumpState::new(config());
    step(
        &mut state,
        KadPumpInput::Start(KadPumpSample { crypt, ..sample }),
        now,
    );
    state
}

/// A firewalled node is told its TCP verdict at start, as a level: a fresh
/// store reads firewalled and never moves unaided, and the node is built
/// believing it is open, so an edge-only feed never told it — and the UDP
/// tester's conclude gate, which composes on this very bit, never fired
/// (the recruit was measured 9.5 minutes late behind a proven cone gateway).
#[test]
fn a_firewalled_node_is_told_its_tcp_level_at_start_without_an_edge() {
    let mut state = KadPumpState::new(config());
    let effects = step(
        &mut state,
        KadPumpInput::Start(behind_nat()),
        Instant::now(),
    );

    assert!(effects.contains(&KadPumpEffect::Verdict(VerdictWrite::Tcp(
        TcpReachability::Firewalled
    ))));
    assert_eq!(
        levels(&effects),
        [
            NodeLevel::TcpFirewalled(true),
            NodeLevel::OwnPublicIp(Ipv4Addr::UNSPECIFIED),
            NodeLevel::ExternUdpPort(0),
            NodeLevel::PublishConnectOptions(0x00),
            NodeLevel::PublishPosture(KadPublishPosture::Firewalled { buddy: None }),
            NodeLevel::DatagramCrypt(KadCryptArm {
                kad_udp_key: KAD_UDP_KEY,
                public_ip: Ipv4Addr::UNSPECIFIED,
                sends: false,
            }),
        ],
        "the whole node state, the TCP level included, before the first tick"
    );
}

/// The stimulus posture declares both verdicts open, and the node — built
/// believing it is open — is told nothing about TCP at all.
#[test]
fn the_stimulus_posture_declares_open_and_tells_the_node_no_tcp_level() {
    let mut state = KadPumpState::new(KadPumpConfig {
        assume_open_reachability: true,
        ..config()
    });
    let effects = step(
        &mut state,
        KadPumpInput::Start(behind_nat()),
        Instant::now(),
    );

    assert!(effects.contains(&KadPumpEffect::Verdict(VerdictWrite::Udp(
        UdpReachability::Open { port: 4672 }
    ))));
    assert!(effects.contains(&KadPumpEffect::Verdict(VerdictWrite::Tcp(
        TcpReachability::Open
    ))));
    assert!(
        !levels(&effects)
            .iter()
            .any(|level| matches!(level, NodeLevel::TcpFirewalled(_)))
    );
}

/// Once told, an unchanged world costs the node nothing: a tick restates the
/// published verdict and asks the recruit trigger, and sends no level.
#[test]
fn a_tick_over_an_unchanged_world_tells_the_node_nothing() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);

    let effects = step(&mut state, KadPumpInput::Tick(behind_nat()), now);
    assert_eq!(levels(&effects), []);
    assert!(effects.contains(&KadPumpEffect::Verdict(VerdictWrite::Tcp(
        TcpReachability::Firewalled
    ))));
}

/// A level a full inbox turned away stays owed: the node holds what it held,
/// and the very next input — whatever it is — restates it, until it lands.
#[test]
fn a_level_a_full_inbox_turned_away_is_restated_on_the_next_input() {
    let now = Instant::now();
    let mut state = KadPumpState::new(config());
    let effects = state.handle(KadPumpInput::Start(behind_nat()), now);
    for level in levels(&effects) {
        let delivery = if level == NodeLevel::TcpFirewalled(true) {
            Delivery::InboxFull
        } else {
            Delivery::Landed
        };
        state.handle(
            KadPumpInput::Delivered(NodeCommand::Level(level), delivery),
            now,
        );
    }

    let unrelated = KadEvent::KeywordIndexExpired { stored: 3 };
    let retried = step(&mut state, KadPumpInput::Event(unrelated.clone()), now);
    assert_eq!(levels(&retried), [NodeLevel::TcpFirewalled(true)]);

    let landed = step(&mut state, KadPumpInput::Event(unrelated), now);
    assert_eq!(levels(&landed), []);
}

/// A level on its way is not asked for twice: the driver carries a batch out
/// one effect at a time, answering each, so a sample handed in mid-batch
/// reconciles against what is already sent.
#[test]
fn a_level_on_its_way_to_the_node_is_not_asked_for_twice() {
    let now = Instant::now();
    let mut state = KadPumpState::new(config());
    let start = state.handle(KadPumpInput::Start(behind_nat()), now);
    assert_eq!(levels(&start).len(), 6);

    let mid_batch = state.handle(KadPumpInput::Sampled(behind_nat()), now);
    assert_eq!(levels(&mid_batch), []);
}

/// The node's own-IPv4 cache follows its owner on the change event (ADR-0084
/// "Own address ownership"), and a Low-ID withdrawal is a change too: the
/// node is re-bound to `0.0.0.0`, the value it is armed with when no address
/// is known, so a key learned under the withdrawn address retires.
#[test]
fn the_own_ipv4_follows_every_own_address_change_including_a_withdrawal() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let mut learned = behind_nat();
    learned.own_address.public_ip = Some(OWN_IP);

    let moved = step(&mut state, KadPumpInput::Sampled(learned), now);
    let receive_only = |public_ip| {
        NodeLevel::DatagramCrypt(KadCryptArm {
            kad_udp_key: KAD_UDP_KEY,
            public_ip,
            sends: false,
        })
    };
    assert_eq!(
        levels(&moved),
        [NodeLevel::OwnPublicIp(OWN_IP), receive_only(OWN_IP)],
        "the verify keys are held under off, so they follow the address too"
    );

    let withdrawn = step(&mut state, KadPumpInput::Sampled(behind_nat()), now);
    assert_eq!(
        levels(&withdrawn),
        [
            NodeLevel::OwnPublicIp(Ipv4Addr::UNSPECIFIED),
            receive_only(Ipv4Addr::UNSPECIFIED)
        ]
    );
}

/// The Extern Kad Port follows a store write the pump did not cause — a
/// mapping grant on the port mapper's task — on its sample, and every `0x61`
/// observation is answered with the store's port once written, even when the
/// node already holds it: the node's helper gate waits on exactly that answer.
#[test]
fn the_extern_port_follows_the_store_and_every_observation_is_answered() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let mut granted = behind_nat();
    granted.own_address.learned_udp_port = Some(24672);

    let grant = step(&mut state, KadPumpInput::Sampled(granted), now);
    assert_eq!(levels(&grant), [NodeLevel::ExternUdpPort(24672)]);

    let observer = Ipv4Addr::new(203, 0, 113, 10);
    let observed = step(
        &mut state,
        KadPumpInput::Event(KadEvent::UdpPortObserved {
            observer,
            port: 24672,
        }),
        now,
    );
    assert_eq!(
        observed,
        [KadPumpEffect::Address(AddressWrite::Observe(
            AddressObservation::kad_observed_port(observer, 24672)
        ))],
        "the report is written first; the answer is the store's, not the report's"
    );
    let answered = step(&mut state, KadPumpInput::Sampled(granted), now);
    assert_eq!(levels(&answered), [NodeLevel::ExternUdpPort(24672)]);

    let after = step(&mut state, KadPumpInput::Sampled(granted), now);
    assert_eq!(levels(&after), [], "one answer per observation");
}

/// Kad's own address reports are Address Learning writes and nothing more:
/// a `0x58` is one rung of the ladder, and a round boundary forgets the UDP
/// role's Kad port reports — neither tells the node anything until the store
/// answers.
#[test]
fn address_reports_and_a_round_boundary_are_writes_to_the_store_alone() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let observer = Ipv4Addr::new(203, 0, 113, 10);

    assert_eq!(
        step(
            &mut state,
            KadPumpInput::Event(KadEvent::AddressObserved {
                observer,
                address: OWN_IP,
            }),
            now,
        ),
        [KadPumpEffect::Address(AddressWrite::Observe(
            AddressObservation::kad_observed_address(observer, OWN_IP)
        ))]
    );
    assert_eq!(
        step(
            &mut state,
            KadPumpInput::Event(KadEvent::ExternPortRoundStarted),
            now
        ),
        [KadPumpEffect::Address(AddressWrite::ForgetKadPortRound)]
    );
}

/// The connect-options byte follows the NAT-T front's own liveness, read on
/// every sample: the front ending drops uTP while the crypt ladder, which has
/// its own owner, stays.
#[test]
fn a_front_that_ends_drops_the_utp_bit_while_the_crypt_ladder_stays() {
    let now = Instant::now();
    let mut armed = behind_nat();
    armed.reach.natt_live = true;
    armed.crypt = Some(ObfuscationPolicy::Requested);
    let mut state = KadPumpState::new(config());

    let start = step(&mut state, KadPumpInput::Start(armed), now);
    let [NodeLevel::PublishConnectOptions(armed_byte)] = levels(&start)[3..4] else {
        panic!("the start states the byte");
    };
    let armed_byte = SourceCryptOptions::from_byte(armed_byte);
    assert!(armed_byte.supports_natt_utp());
    assert!(armed_byte.requests_crypt() && !armed_byte.requires_crypt());

    let ended = step(
        &mut state,
        KadPumpInput::Sampled(KadPumpSample {
            crypt: armed.crypt,
            ..behind_nat()
        }),
        now,
    );
    let [NodeLevel::PublishConnectOptions(ended_byte)] = levels(&ended)[..] else {
        panic!("only the byte moved: {ended:?}");
    };
    let ended_byte = SourceCryptOptions::from_byte(ended_byte);
    assert!(!ended_byte.supports_natt_utp());
    assert_eq!(
        (ended_byte.requests_crypt(), ended_byte.requires_crypt()),
        (true, false)
    );
}

/// The obfuscation policy changes live (ADR-0046): a change is a sample like
/// any owner's move, and the node is re-armed — obfuscation with verify keys
/// bound to the address it holds — and states the new crypt ladder in the
/// same reconcile; off disarms it whole. Nothing else moves.
#[test]
fn a_live_policy_change_re_arms_the_node_and_restates_the_crypt_ladder() {
    let now = Instant::now();
    let mut known = behind_nat();
    known.own_address.public_ip = Some(OWN_IP);
    let mut state = started(None, known, now);

    let armed = step(
        &mut state,
        KadPumpInput::Sampled(KadPumpSample {
            crypt: Some(ObfuscationPolicy::Requested),
            ..known
        }),
        now,
    );
    assert_eq!(
        levels(&armed),
        [
            NodeLevel::PublishConnectOptions(0x03),
            NodeLevel::DatagramCrypt(KadCryptArm {
                kad_udp_key: KAD_UDP_KEY,
                public_ip: OWN_IP,
                sends: true,
            }),
        ]
    );
    let re_arm = NodeCommand::Level(levels(&armed)[1]).command();
    let rmule_kad::KadCommand::SetObfuscation {
        obfuscation: Some(_),
    } = re_arm
    else {
        panic!("the node is re-armed, not left as it was: {re_arm:?}");
    };

    let off = step(&mut state, KadPumpInput::Sampled(known), now);
    let receive_only = KadCryptArm {
        kad_udp_key: KAD_UDP_KEY,
        public_ip: OWN_IP,
        sends: false,
    };
    assert_eq!(
        levels(&off),
        [
            NodeLevel::PublishConnectOptions(0x00),
            NodeLevel::DatagramCrypt(receive_only),
        ]
    );
    assert_eq!(
        NodeCommand::Level(NodeLevel::DatagramCrypt(receive_only)).command(),
        rmule_kad::KadCommand::SetObfuscation {
            obfuscation: Some(rmule_kad::KadObfuscation::receive_only(KAD_UDP_KEY, OWN_IP))
        },
        "off keeps the verify keys and drops only the send side"
    );
}

/// A Reach Generation that brings a server High ID withdraws both the buddy
/// row and the direct-callback bit: each reads aMule's `IsFirewalled()`
/// union, never the Kad TCP verdict alone.
#[test]
fn a_server_high_id_withdraws_the_buddy_row_and_the_direct_callback_bit() {
    let now = Instant::now();
    let mut buddied = behind_nat();
    buddied.reach.kad_udp = UdpReachability::Open { port: 4672 };
    buddied.reach.accepts_direct_udp_callback = true;
    buddied.buddy.publish = Some(buddy());
    let mut state = KadPumpState::new(config());

    let start = step(&mut state, KadPumpInput::Start(buddied), now);
    assert_eq!(
        levels(&start)[3..],
        [
            NodeLevel::PublishConnectOptions(0x08),
            NodeLevel::PublishPosture(KadPublishPosture::Firewalled {
                buddy: Some(KadBuddyContact {
                    buddy_id: buddy().buddy_id,
                    buddy_udp: Some(buddy().buddy_udp),
                    buddy_ipv6: None,
                    buddy_udp_ipv6: None,
                }),
            }),
            NodeLevel::DatagramCrypt(KadCryptArm {
                kad_udp_key: KAD_UDP_KEY,
                public_ip: Ipv4Addr::UNSPECIFIED,
                sends: false,
            }),
        ]
    );

    let mut high_id = buddied;
    high_id.reach.firewalled = false;
    high_id.reach.accepts_direct_udp_callback = false;
    let login = step(&mut state, KadPumpInput::Sampled(high_id), now);
    assert_eq!(
        levels(&login),
        [
            NodeLevel::PublishConnectOptions(0x00),
            NodeLevel::PublishPosture(KadPublishPosture::Reachable),
        ]
    );
}

/// A `0x5A` answer is a node command like a level: a full inbox never holds
/// the pump (every input still answers at once), and the refused answer goes
/// out ahead of the next input's effects until the node takes it.
#[test]
fn a_refused_findbuddy_answer_waits_for_room_and_never_holds_the_pump() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let answer = NodeCommand::AnswerFindBuddy {
        requester: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4672),
        buddy_id: KadId::from_bytes([0x77; KadId::BYTE_LEN]),
    };

    let accepted = state.handle(
        KadPumpInput::SlotAnswered(SlotAnswer::BuddyServed {
            requester: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4672),
            buddy_id: KadId::from_bytes([0x77; KadId::BYTE_LEN]),
        }),
        now,
    );
    assert_eq!(accepted, [KadPumpEffect::Node(answer.clone())]);

    // The inbox is full: the delivery answer asks for nothing further.
    assert!(
        state
            .handle(
                KadPumpInput::Delivered(answer.clone(), Delivery::InboxFull),
                now
            )
            .is_empty()
    );
    // Still full on the next input and the one after: each input resends it,
    // and each refusal keeps exactly one copy waiting.
    for _ in 0..2 {
        let next = step(&mut state, KadPumpInput::Sampled(behind_nat()), now);
        assert_eq!(next, [KadPumpEffect::Node(answer.clone())]);
        state.handle(
            KadPumpInput::Delivered(answer.clone(), Delivery::InboxFull),
            now,
        );
    }
    // Room at last: it lands once and nothing resends it.
    let next = step(&mut state, KadPumpInput::Sampled(behind_nat()), now);
    assert_eq!(next, [KadPumpEffect::Node(answer.clone())]);
    state.handle(
        KadPumpInput::Delivered(answer.clone(), Delivery::Landed),
        now,
    );
    assert!(step(&mut state, KadPumpInput::Sampled(behind_nat()), now).is_empty());
}

/// The ≥2-ack rule settles open on the second connect-back: the verdict is
/// published and the node told its level in the same step.
#[test]
fn a_recheck_that_draws_two_connect_backs_publishes_open_and_tells_the_node() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    step(
        &mut state,
        KadPumpInput::Event(KadEvent::ReachabilityRecheckStarted),
        now,
    );
    let first = step(
        &mut state,
        KadPumpInput::Event(KadEvent::ReachabilityConnectBack),
        now,
    );
    assert_eq!(levels(&first), [], "one ack proves nothing");

    let second = step(
        &mut state,
        KadPumpInput::Event(KadEvent::ReachabilityConnectBack),
        now,
    );
    assert!(second.contains(&KadPumpEffect::Verdict(VerdictWrite::Tcp(
        TcpReachability::Open
    ))));
    assert_eq!(levels(&second), [NodeLevel::TcpFirewalled(false)]);
}

/// Each helper asked opens a window in the Awaited Testers until its answer
/// lapses; a recheck closes this node's windows, and the stop closes the rest
/// — never a successor's.
#[test]
fn a_helper_window_opens_on_the_ask_and_closes_with_the_recheck_or_the_stop() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let asked = |helper| {
        KadPumpInput::Event(KadEvent::ReachabilityCheckAsked {
            helper,
            helper_id: KadId::from_bytes([0x42; KadId::BYTE_LEN]),
            helper_udp_port: 4672,
            connect_options: Some(0x00),
            answerable_for: Duration::from_secs(180),
        })
    };
    let first = Ipv4Addr::new(198, 51, 100, 1);
    let until = now + Duration::from_secs(180);
    assert_eq!(
        step(&mut state, asked(first), now),
        [KadPumpEffect::Testers(TesterWrite::Asked {
            helper: first,
            until
        })]
    );

    let recheck = step(
        &mut state,
        KadPumpInput::Event(KadEvent::ReachabilityRecheckStarted),
        now,
    );
    assert_eq!(
        recheck.first(),
        Some(&KadPumpEffect::Testers(TesterWrite::Dropped {
            helpers: vec![(first, until)],
        }))
    );

    let second = Ipv4Addr::new(198, 51, 100, 2);
    step(&mut state, asked(second), now);
    assert_eq!(
        state.handle(KadPumpInput::Stop, now),
        [KadPumpEffect::Testers(TesterWrite::Dropped {
            helpers: vec![(second, until)],
        })]
    );
}

/// A source walk answers under the file it was issued for, read off the
/// target the node echoes; a walk that decoded only refusals still answers,
/// and a walk that found no row says nothing.
#[test]
fn a_source_walk_answers_under_its_target_and_an_empty_walk_says_nothing() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let file_hash = FileHash::from_bytes([0x5B; FileHash::BYTE_LEN]);
    let target = SourceLookupTarget::new(file_hash, 1_024);

    assert_eq!(
        step(
            &mut state,
            KadPumpInput::Event(KadEvent::SourcesFound {
                target,
                candidates: Vec::new(),
            }),
            now,
        ),
        []
    );
    assert_eq!(
        step(
            &mut state,
            KadPumpInput::Event(KadEvent::SourcesFound {
                target,
                candidates: vec![rmule_kad::KadSourceCandidate::diagnostic(
                    rmule_kad::KadSourceDiagnostic::Firewalled
                )],
            }),
            now,
        ),
        [KadPumpEffect::Sources {
            file_hash,
            answer: Vec::new(),
        }]
    );
}

/// A datagram that opens with the Kad byte but does not decode is counted
/// and logged, not lost in a catch-all: the count is what makes a crypt-armed
/// bench verdict falsifiable in either direction.
#[test]
fn an_undecodable_kad_envelope_counts_and_warns() {
    let (log, _tracing) = rmule_testkit::capture_tracing(tracing::Level::WARN);
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let error = rmule_kad::decode_exact(&[0xE4]).expect_err("too short for an opcode");

    let effects = step(
        &mut state,
        KadPumpInput::Event(KadEvent::Diagnostic(
            rmule_kad::KadNodeDiagnostic::UndecodableEnvelope {
                from: rmule_kad::KadNodeEndpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4672),
                error,
            },
        )),
        now,
    );
    assert_eq!(
        effects,
        [KadPumpEffect::Diagnostics(
            DiagnosticsWrite::UndecodableEnvelope
        )]
    );
    let text = log.text();
    assert!(
        text.contains("UndecodableEnvelope"),
        "the warn line names the reason; captured log: {text}"
    );
}

/// The node's facts the snapshot reads: the contact latch is stated once,
/// the table size is adds minus evictions and never below zero, and a flood
/// offender becomes a ban stamped with the instant it was reported.
#[test]
fn contacts_are_counted_and_a_flood_offender_is_banned_when_reported() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let id = KadId::from_bytes([0x01; KadId::BYTE_LEN]);
    let from = rmule_kad::KadNodeEndpoint::new(Ipv4Addr::new(198, 51, 100, 3), 4672);
    let mut facts = Vec::new();
    for event in [
        KadEvent::HadContact { from },
        KadEvent::ContactResponded { id },
        KadEvent::ContactAdded { id, endpoint: from },
        KadEvent::ContactEvicted { id },
        KadEvent::ContactEvicted { id },
    ] {
        facts.extend(step(&mut state, KadPumpInput::Event(event), now));
    }
    assert_eq!(
        facts,
        [
            KadPumpEffect::Verdict(VerdictWrite::Joined),
            KadPumpEffect::Diagnostics(DiagnosticsWrite::ContactCount(1)),
            KadPumpEffect::Diagnostics(DiagnosticsWrite::ContactCount(0)),
            KadPumpEffect::Diagnostics(DiagnosticsWrite::ContactCount(0)),
        ]
    );

    let offender = Ipv4Addr::new(198, 51, 100, 66);
    let later = now + Duration::from_secs(5);
    assert_eq!(
        step(
            &mut state,
            KadPumpInput::Event(KadEvent::FloodOffenderDetected {
                ip: offender,
                opcode: 0x60,
            }),
            later,
        ),
        [KadPumpEffect::Ban {
            ip: offender,
            at: later
        }]
    );
}
