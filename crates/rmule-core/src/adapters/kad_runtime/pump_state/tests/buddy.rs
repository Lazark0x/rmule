//! The ADR-0061 firewalled half of the Kad Pump State: the recruit rule over
//! the slot's published snapshot, the walk it starts and hears end, the
//! Recruit Status it states, and the `0x5A` it hands the Firewalled Front —
//! whose verdict comes back as an input.

use super::*;
use crate::firewalled::front::AdoptVerdict;
use crate::firewalled::link::BuddyState;
use crate::firewalled::recruit::{RecruitRefusal, RecruitStatus};

/// Both surfaces firewalled, Kad up, nothing held.
fn firewalled_everywhere() -> KadPumpSample {
    let mut sample = behind_nat();
    sample.reach.kad_udp = UdpReachability::Firewalled;
    sample
}

/// The walks among `effects`.
fn walks(effects: &[KadPumpEffect]) -> Vec<KadId> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            KadPumpEffect::Node(NodeCommand::FindBuddyWalk { target }) => Some(*target),
            _ => None,
        })
        .collect()
}

/// The Recruit Status `effects` state, if they state one.
fn stated(effects: &[KadPumpEffect]) -> Option<RecruitStatus> {
    effects.iter().find_map(|effect| match effect {
        KadPumpEffect::Recruit(status) => Some(*status),
        _ => None,
    })
}

/// The recruit tick walks toward `~ourKadID` and states the walk; a second
/// tick while it runs walks nothing, and a walk the node never took ends at
/// once rather than leave the rule walking — without re-arming the pacing.
#[test]
fn the_recruit_tick_walks_once_and_a_walk_the_node_never_took_ends() {
    let now = Instant::now();
    let mut state = started(None, firewalled_everywhere(), now);
    let later = now + Duration::from_secs(30);
    let target = KadId::from_bytes([0x55; KadId::BYTE_LEN]);

    let tick = state.handle(KadPumpInput::Tick(firewalled_everywhere()), later);
    assert_eq!(walks(&tick), [target]);
    assert_eq!(
        stated(&tick),
        Some(RecruitStatus {
            walking: true,
            refusal: None
        })
    );
    let again = state.handle(KadPumpInput::Tick(firewalled_everywhere()), later);
    assert_eq!(walks(&again), []);
    assert_eq!(
        stated(&again),
        Some(RecruitStatus {
            walking: true,
            refusal: Some(RecruitRefusal::PacingNotDue)
        })
    );

    assert_eq!(
        state.handle(
            KadPumpInput::Delivered(NodeCommand::FindBuddyWalk { target }, Delivery::InboxFull),
            later,
        ),
        [KadPumpEffect::Recruit(RecruitStatus {
            walking: false,
            refusal: Some(RecruitRefusal::PacingNotDue)
        })]
    );
    let paced = state.handle(KadPumpInput::Tick(firewalled_everywhere()), later);
    assert_eq!(walks(&paced), [], "a cold table does not walk every tick");
}

/// The rule reads the slot only through its published snapshot: a buddy
/// held refuses a walk, and a loss newer than the last walk re-arms one at
/// once — aMule's FindBuddy tick reset — where a loss older than it does not.
#[test]
fn the_recruit_rule_reads_the_slot_through_its_snapshot() {
    let now = Instant::now();
    let mut held = firewalled_everywhere();
    held.buddy = BuddySnapshot {
        state: BuddyState::Held,
        held_since: Some(now),
        publish: Some(buddy()),
        ..BuddySnapshot::default()
    };
    let mut state = started(None, held, now);
    let refused = state.handle(KadPumpInput::Tick(held), now);
    assert_eq!(walks(&refused), []);
    assert_eq!(
        stated(&refused).and_then(|status| status.refusal),
        Some(RecruitRefusal::AlreadyHaveBuddy)
    );

    let mut lost = firewalled_everywhere();
    lost.buddy.lost_at = Some(now);
    let walked = state.handle(KadPumpInput::Tick(lost), now);
    assert_eq!(walks(&walked).len(), 1, "never walked: due at once");
    state.handle(
        KadPumpInput::Event(KadEvent::BuddyWalkEnded { asked: true }),
        now,
    );

    let soon = now + Duration::from_secs(60);
    assert_eq!(
        walks(&state.handle(KadPumpInput::Tick(lost), soon)),
        [],
        "a loss before the last walk is spent"
    );
    lost.buddy.lost_at = Some(soon);
    let re_armed = soon + Duration::from_secs(30);
    assert_eq!(
        walks(&state.handle(KadPumpInput::Tick(lost), re_armed)).len(),
        1
    );
}

/// A `Required` obfuscation policy never walks, and says why.
#[test]
fn crypt_required_never_walks_and_states_the_refusal() {
    let now = Instant::now();
    let required = Some(ObfuscationPolicy::Required);
    let mut state = started(required, firewalled_everywhere(), now);
    let tick = state.handle(
        KadPumpInput::Tick(KadPumpSample {
            crypt: required,
            ..firewalled_everywhere()
        }),
        now,
    );
    assert_eq!(walks(&tick), []);
    assert_eq!(
        stated(&tick).and_then(|status| status.refusal),
        Some(RecruitRefusal::CryptRequired)
    );
}

/// A stopped node walks nothing: the walk in flight is dropped from the
/// status it publishes, and its successor starts from a fresh one.
#[test]
fn a_stop_drops_the_walk_and_a_restart_states_a_fresh_status() {
    let now = Instant::now();
    let mut state = started(None, firewalled_everywhere(), now);
    state.handle(KadPumpInput::Tick(firewalled_everywhere()), now);
    assert_eq!(
        stated(&state.handle(KadPumpInput::Stop, now)),
        Some(RecruitStatus {
            walking: false,
            refusal: None
        })
    );

    let mut successor = KadPumpState::new(config());
    assert_eq!(
        stated(&successor.handle(KadPumpInput::Start(firewalled_everywhere()), now)),
        Some(RecruitStatus::default()),
        "a fresh node restates whatever its predecessor left"
    );
}

fn buddy_found(connect_options: Option<u8>) -> KadEvent {
    KadEvent::BuddyFound {
        buddy: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672),
        // `~0xAA…`: the buddy-ID our walk's answer echoes.
        buddy_id: KadId::from_bytes([0x55; KadId::BYTE_LEN]),
        buddy_hash: UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
        buddy_tcp_port: 4662,
        connect_options,
    }
}

fn adopt_write(effects: &[KadPumpEffect]) -> RecruitedBuddy {
    match effects {
        [KadPumpEffect::AdoptBuddy { buddy, .. }] => *buddy,
        other => panic!("one adopt write expected, got {other:?}"),
    }
}

/// A `0x5A` our walk drew goes to the Firewalled Front with the stance its
/// connect-options byte stated (`0x07`: requires the crypt layer) — the
/// front, which owns the slot, meets it with ours. The walk is over.
#[test]
fn a_found_buddy_goes_to_the_front_with_its_stated_stance() {
    let now = Instant::now();
    let mut state = started(None, firewalled_everywhere(), now);
    state.handle(KadPumpInput::Tick(firewalled_everywhere()), now);

    let found = state.handle(KadPumpInput::Event(buddy_found(Some(0x07))), now);
    let (seated, status) = match &found[..] {
        [
            KadPumpEffect::AdoptBuddy { buddy, .. },
            KadPumpEffect::Recruit(status),
        ] => (*buddy, *status),
        other => panic!("an adopt and the walk's end expected, got {other:?}"),
    };
    assert_eq!(
        seated.crypt,
        Some(SourceCryptOptions::from_byte(0x07).crypt_stance())
    );
    assert_eq!(
        seated.tcp,
        Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4662)
    );
    assert!(!status.walking);
}

/// A pre-v7 `0x5A` that carries no connect-options byte seats a buddy whose
/// stance is silence, not a stated "off" (ADR-0049).
#[test]
fn a_pre_v7_buddys_missing_connect_options_byte_seats_as_silence() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let seated = adopt_write(&step(
        &mut state,
        KadPumpInput::Event(buddy_found(None)),
        now,
    ));
    assert_eq!(seated.crypt, None);
}

/// The front's verdict carries the snapshot it published after the adopt:
/// the next source publish names the buddy, and a refused buddy names none.
#[test]
fn the_fronts_verdict_moves_the_publish_posture() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let seated = adopt_write(&step(
        &mut state,
        KadPumpInput::Event(buddy_found(None)),
        now,
    ));

    let refused = step(
        &mut state,
        KadPumpInput::BuddyVerdict(AdoptVerdict {
            buddy: seated,
            outcome: AdoptOutcome::CryptIncompatible,
            snapshot: BuddySnapshot::default(),
        }),
        now,
    );
    assert_eq!(refused, [], "nothing seated, nothing to tell");

    let adopted = step(
        &mut state,
        KadPumpInput::BuddyVerdict(AdoptVerdict {
            buddy: seated,
            outcome: AdoptOutcome::Adopted,
            snapshot: BuddySnapshot {
                state: BuddyState::Recruited,
                publish: Some(buddy()),
                ..BuddySnapshot::default()
            },
        }),
        now,
    );
    assert!(matches!(
        adopted[..],
        [KadPumpEffect::Node(NodeCommand::Level(
            NodeLevel::PublishPosture(KadPublishPosture::Firewalled { buddy: Some(_) })
        ))]
    ));
}
