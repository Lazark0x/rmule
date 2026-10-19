//! The core's asks of the Kad node, as the **Kad Pump State** tells them.
//!
//! Each core command becomes at most one node command, queued in the order the
//! core sent them. One is out at a time — the driver answers a node command at
//! once, so this costs no latency — and none goes out while a level is on its
//! way or turned away, so the node always takes an ask over the whole desired
//! state and in the core's order, which is what lets a Callback Walk's verdict
//! name its download.
//!
//! **The bound, and why nothing is lost.** The driver never waits for room in
//! the node's inbox while it holds the event loop. An ask the full inbox turns
//! away stays at the front of the queue, and while any ask waits the brain
//! [takes no further command](KadPumpState::takes_commands): the core's
//! commands wait in the pump's own bounded channel instead — an awaited send
//! waits, a non-waiting one is refused with its reason, exactly as when that
//! channel is full — so the queue here holds at most the one ask of the one
//! command the brain last took. Meanwhile the driver keeps draining the node's
//! events and [waits for room](KadPumpState::awaits_room) beside them, and the
//! ask goes out again the moment there is some. Nothing the pump took is ever
//! dropped, and the node never drops an event because the pump stalled.

use std::collections::VecDeque;

use rmule_kad::{KadCommand, KadId};

use super::keyword_subscribers::{SearchSink, lead_keyword};
use super::{Delivery, KadPumpEffect, KadPumpState, NodeCommand};
use crate::adapters::kad_runtime::{CallbackWalkReply, KadPumpCommand};
use crate::search::KadKeywordEnd;

/// The core's asks the node has not taken yet, in the order the core sent
/// them.
#[derive(Default)]
pub(super) struct Asks {
    queue: VecDeque<Ask>,
    /// The front is with the driver, its delivery not yet answered.
    out: bool,
    /// The node's full inbox turned the front away; the next input that is
    /// not a delivery answer sends it again.
    turned_away: bool,
}

struct Ask {
    command: KadCommand,
    then: Then,
}

/// What an ask's outcome means beyond the node.
enum Then {
    Nothing,
    /// The walk every search on this keyword rides: a walk the node never
    /// took ends them as not taken.
    KeywordWalk(KadId),
    /// The download waiting on a Callback Walk, remembered once the node took
    /// the walk.
    CallbackWaiter(KadId, CallbackWalkReply),
}

impl Asks {
    fn push(&mut self, command: KadCommand, then: Then) {
        self.queue.push_back(Ask { command, then });
    }

    /// Whether an ask waits for the node.
    pub(super) fn waiting(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Whether the node's full inbox turned the front away.
    pub(super) fn turned_away(&self) -> bool {
        self.turned_away
    }

    /// An input that is not a delivery answer: an ask turned away may go again.
    pub(super) fn retry(&mut self) {
        self.turned_away = false;
    }
}

impl KadPumpState {
    /// Queue the core's `command` as the node command that enacts it.
    pub(super) fn on_command(&mut self, command: KadPumpCommand, out: &mut Vec<KadPumpEffect>) {
        let (command, then) = match command {
            KadPumpCommand::Search(target) => (
                KadCommand::SearchSources {
                    request: rmule_kad::KadSourceLookupRequest::new(target),
                },
                Then::Nothing,
            ),
            KadPumpCommand::Publish(target) => (
                KadCommand::PublishSource {
                    request: rmule_kad::KadPublishRequest::new(target),
                },
                Then::Nothing,
            ),
            KadPumpCommand::Withdraw(target) => (
                KadCommand::WithdrawSource {
                    request: rmule_kad::KadPublishRequest::new(target),
                },
                Then::Nothing,
            ),
            // ADR-0062 requester: the node walks the lead keyword alone and
            // emits the plain `0x33`; every search on that keyword subscribes
            // to the one walk and hears its `KeywordsFound` rows screened by
            // its own query. A query with no lead keyword, or a walk the node
            // never took, ends the leg with why rather than strand it.
            KadPumpCommand::SearchKeyword { query, results } => {
                let request = lead_keyword(&query).map(rmule_kad::KadKeywordSearchRequest::new);
                let target = request
                    .as_ref()
                    .and_then(rmule_kad::KadKeywordSearchRequest::target);
                let walk = self
                    .keywords
                    .subscribe(target, query, SearchSink::new(results), out);
                match (walk, target, request) {
                    (true, Some(target), Some(request)) => (
                        KadCommand::SearchKeywords { request },
                        Then::KeywordWalk(target),
                    ),
                    _ => return,
                }
            }
            // The ed2k→Kad handoff (ADR-0067): the node applies aMule's
            // not-joined + shared 10 s throttle gate before it seeds the one
            // Bootstrap Dial List.
            KadPumpCommand::BootstrapFromPeer(peer) => (
                KadCommand::BootstrapFromPeer {
                    endpoint: rmule_kad::KadNodeEndpoint::new(peer.ip, peer.port),
                },
                Then::Nothing,
            ),
            // ADR-0086: the node owns the guards — one recheck at a time, at
            // most one per five minutes — so a burst of triggers costs one
            // round of helper lookups.
            KadPumpCommand::RecheckReachability => (KadCommand::RecheckReachability, Then::Nothing),
            // ADR-0058 requester, the v7+ ack path: the node checks the IP
            // against its own 180 s outstanding-check windows before it
            // counts a leg, so an unrequested `0xA8` proves nothing.
            KadPumpCommand::TcpFirewallAck(peer_ip) => {
                (KadCommand::TcpFirewallAck { peer_ip }, Then::Nothing)
            }
            KadPumpCommand::UdpFirewallRequest {
                requester,
                request,
                caller_known,
            } => (
                KadCommand::UdpFirewallRequest {
                    requester_ip: requester,
                    request,
                    caller_known,
                },
                Then::Nothing,
            ),
            KadPumpCommand::UdpFirewallCheckFailed(helper_ip) => (
                KadCommand::UdpFirewallCheckFailed { helper_ip },
                Then::Nothing,
            ),
            KadPumpCommand::UdpFirewallCheckCancelled(helper_ip) => (
                KadCommand::UdpFirewallCheckCancelled { helper_ip },
                Then::Nothing,
            ),
            // ADR-0061 route 4: the `0x52` to a firewalled source's buddy,
            // which relays it over the link it holds.
            KadPumpCommand::BuddyCallback(ask) => (ask.node_command(), Then::Nothing),
            KadPumpCommand::CallbackWalk(ask) => (
                ask.node_command(),
                Then::CallbackWaiter(ask.buddy_id, ask.reply),
            ),
        };
        self.asks.push(command, then);
    }

    /// Hand the driver the front ask, when none is out, none was turned away
    /// since the last input, and the node holds every level.
    pub(super) fn release_ask(&mut self, out: &mut Vec<KadPumpEffect>) {
        let asks = &mut self.asks;
        if asks.out || asks.turned_away || !self.levels.settled() {
            return;
        }
        if let Some(front) = asks.queue.front() {
            asks.out = true;
            out.push(KadPumpEffect::Node(NodeCommand::Ask(front.command.clone())));
        }
    }

    /// What became of the front ask.
    pub(super) fn ask_delivered(&mut self, delivery: Delivery, out: &mut Vec<KadPumpEffect>) {
        self.asks.out = false;
        if delivery == Delivery::InboxFull {
            self.asks.turned_away = true;
            return;
        }
        let Some(ask) = self.asks.queue.pop_front() else {
            return;
        };
        match (ask.then, delivery) {
            (Then::CallbackWaiter(buddy_id, reply), Delivery::Landed) => {
                self.callback_walks.took(buddy_id, reply);
            }
            (Then::KeywordWalk(target), Delivery::NodeGone) => {
                self.keywords.complete(target, KadKeywordEnd::NotTaken, out);
            }
            _ => {}
        }
    }

    /// The pump is going away: every ask the node never took is refused, and
    /// every keyword walk still running ends as stopped.
    pub(super) fn asks_stopped(&mut self, out: &mut Vec<KadPumpEffect>) {
        for ask in std::mem::take(&mut self.asks.queue) {
            if let Then::KeywordWalk(target) = ask.then {
                self.keywords.complete(target, KadKeywordEnd::NotTaken, out);
            }
        }
        self.keywords.stopped(out);
    }
}
