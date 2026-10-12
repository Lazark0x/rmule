//! The core's asks of the node through the Kad Pump State: each core command
//! becomes one node command, told one at a time in the order the core sent
//! them and only once the node holds the whole desired state; a full inbox
//! holds the core back rather than the pump, and the ask goes out on room.

use std::net::Ipv6Addr;

use rmule_kad::{KadCallbackWalkEnd, KadCommand};
use tokio::sync::mpsc;

use super::*;
use crate::adapters::CallbackKey;
use crate::adapters::kad_runtime::{CallbackWalkAsk, CallbackWalkReply, KadPumpCommand};
use crate::diagnostics::NattRetirement;

fn target(byte: u8) -> SourceLookupTarget {
    SourceLookupTarget::new(FileHash::from_bytes([byte; FileHash::BYTE_LEN]), 1_024)
}

fn search(byte: u8) -> KadCommand {
    KadCommand::SearchSources {
        request: rmule_kad::KadSourceLookupRequest::new(target(byte)),
    }
}

/// Hand the core's `command` in, the sources standing as `sample` says.
fn command(command: KadPumpCommand, sample: KadPumpSample) -> KadPumpInput {
    KadPumpInput::Command(Box::new(command), sample)
}

fn ask(command: KadCommand) -> KadPumpEffect {
    KadPumpEffect::Node(NodeCommand::Ask(command))
}

fn delivered(command: KadCommand, delivery: Delivery) -> KadPumpInput {
    KadPumpInput::Delivered(NodeCommand::Ask(command), delivery)
}

/// An ask the node's full inbox turned away waits in the brain, and while it
/// waits the core is held back — the driver takes no further command, so the
/// pump's own bounded queue is the backlog — and the driver waits for room
/// beside the node's events. Room sends it again, and once it lands the core
/// is heard again.
#[test]
fn an_ask_a_full_inbox_turned_away_holds_the_core_back_and_goes_out_on_room() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    assert!(state.takes_commands());

    let asked = state.handle(
        command(KadPumpCommand::Search(target(1)), behind_nat()),
        now,
    );
    assert_eq!(asked, [ask(search(1))]);
    assert_eq!(
        state.handle(delivered(search(1), Delivery::InboxFull), now),
        []
    );
    assert!(!state.takes_commands(), "the core waits while the ask does");
    assert!(state.awaits_room());

    assert_eq!(state.handle(KadPumpInput::Room, now), [ask(search(1))]);
    assert_eq!(
        state.handle(delivered(search(1), Delivery::Landed), now),
        []
    );
    assert!(state.takes_commands());
    assert!(!state.awaits_room());
}

/// The node takes the core's asks in the order the core sent them, one at a
/// time: an ask behind a turned-away one waits behind it, and goes out the
/// moment the one ahead lands.
#[test]
fn asks_reach_the_node_one_at_a_time_in_the_order_the_core_sent_them() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let withdraw = KadCommand::WithdrawSource {
        request: rmule_kad::KadPublishRequest::new(target(2)),
    };

    state.handle(
        command(KadPumpCommand::Search(target(1)), behind_nat()),
        now,
    );
    state.handle(delivered(search(1), Delivery::InboxFull), now);
    assert_eq!(
        state.handle(
            command(KadPumpCommand::Withdraw(target(2)), behind_nat()),
            now
        ),
        [ask(search(1))],
        "the next input resends the ask ahead; the later one waits behind it"
    );
    assert_eq!(
        state.handle(delivered(search(1), Delivery::Landed), now),
        [ask(withdraw.clone())]
    );
    assert_eq!(state.handle(delivered(withdraw, Delivery::Landed), now), []);
}

/// The `ip6` tag is the chooser's verdict read fresh at the advertisement
/// (ADR-0087): a publish's own sample carries it, the reconciler tells the
/// node first, and the publish leaves only once the node holds it — a full
/// inbox that turns the level away holds the publish too.
#[test]
fn a_publish_leaves_only_once_the_node_holds_the_advertised_ipv6_it_names() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x45);
    let reachable_over_ipv6 = KadPumpSample {
        advertised_ipv6: Some(address),
        ..behind_nat()
    };
    let level = NodeCommand::Level(NodeLevel::AdvertisedIpv6(Some(address)));
    let publish = KadCommand::PublishSource {
        request: rmule_kad::KadPublishRequest::new(target(3)),
    };

    assert_eq!(
        state.handle(
            command(KadPumpCommand::Publish(target(3)), reachable_over_ipv6),
            now
        ),
        [KadPumpEffect::Node(level.clone())]
    );
    assert_eq!(
        state.handle(
            KadPumpInput::Delivered(level.clone(), Delivery::InboxFull),
            now
        ),
        []
    );
    assert!(state.awaits_room());
    assert_eq!(
        state.handle(KadPumpInput::Room, now),
        [KadPumpEffect::Node(level.clone())]
    );
    assert_eq!(
        state.handle(KadPumpInput::Delivered(level, Delivery::Landed), now),
        [ask(publish.clone())]
    );
    state.handle(delivered(publish.clone(), Delivery::Landed), now);

    // The node holds it now: the next publish under the same verdict is the
    // publish alone.
    assert_eq!(
        state.handle(
            command(KadPumpCommand::Publish(target(3)), reachable_over_ipv6),
            now
        ),
        [ask(publish)]
    );
}

fn walk_ask(reply: CallbackWalkReply) -> KadPumpCommand {
    KadPumpCommand::CallbackWalk(CallbackWalkAsk {
        buddy_id: BUDDY_ID,
        file_hash: FileHash::from_bytes([0x5C; FileHash::BYTE_LEN]),
        tcp_port: 4662,
        reply,
    })
}

const BUDDY_ID: KadId = KadId::from_bytes([0x7A; KadId::BYTE_LEN]);

fn waiter(low: u32) -> CallbackWalkReply {
    // The brain never sends on it; the driver does.
    let (retire_tx, _) = mpsc::channel(1);
    CallbackWalkReply {
        key: CallbackKey {
            server: None,
            low_id: rmule_primitives::ClientId::from_u32(low),
        },
        retire_tx,
    }
}

fn walk_ended(end: KadCallbackWalkEnd) -> KadPumpInput {
    KadPumpInput::Event(KadEvent::CallbackWalkEnded {
        buddy_id: BUDDY_ID,
        end,
    })
}

/// Two downloads walk toward one buddy. The node refuses the second while the
/// first runs, and each verdict retires the download it belongs to — the
/// refusal the newest, the walk's own end the oldest — because the node took
/// the walks in the order the brain told them.
#[test]
fn each_callback_walk_verdict_retires_the_download_that_asked() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let (first, second) = (waiter(1), waiter(2));
    step(
        &mut state,
        command(walk_ask(first.clone()), behind_nat()),
        now,
    );
    step(
        &mut state,
        command(walk_ask(second.clone()), behind_nat()),
        now,
    );

    assert_eq!(
        state.handle(walk_ended(KadCallbackWalkEnd::AlreadyWalking), now),
        [KadPumpEffect::CallbackWalkRetired {
            reply: second,
            reason: NattRetirement::CallbackWalkBusy,
        }]
    );
    assert_eq!(
        state.handle(walk_ended(KadCallbackWalkEnd::NoneNear), now),
        [KadPumpEffect::CallbackWalkRetired {
            reply: first,
            reason: NattRetirement::BuddyNotFound,
        }]
    );
}

/// A walk that sent its `0x52` retires nothing — the dial-back may yet come,
/// and the slot's own deadline waits for it — and a walk the node never took
/// has nobody waiting on a verdict.
#[test]
fn a_walk_that_asked_retires_nothing_and_one_never_taken_has_no_waiter() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    step(&mut state, command(walk_ask(waiter(1)), behind_nat()), now);
    assert_eq!(
        state.handle(walk_ended(KadCallbackWalkEnd::Asked(2)), now),
        []
    );

    let refused = state.handle(command(walk_ask(waiter(2)), behind_nat()), now);
    let [KadPumpEffect::Node(walk)] = refused.as_slice() else {
        panic!("one walk asked for: {refused:?}");
    };
    state.handle(
        KadPumpInput::Delivered(walk.clone(), Delivery::NodeGone),
        now,
    );
    assert_eq!(
        state.handle(walk_ended(KadCallbackWalkEnd::NoneNear), now),
        []
    );
    assert!(!state.awaits_room(), "a gone node is never waited on");
}
