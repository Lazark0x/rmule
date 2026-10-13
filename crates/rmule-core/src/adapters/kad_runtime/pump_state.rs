//! **Kad Pump State**: the Kad pump's sans-I/O brain, the Kad-side mirror of
//! **Download State** and **Serve State**.
//!
//! Every input arrives through [`KadPumpState::handle`] with an explicit `now`
//! (ADR-0043) — the core's commands, the node's events, the recruit tick,
//! samples of the sources it reads, the answers to its own effects and room in
//! the node's inbox — and everything leaves as a [`KadPumpEffect`] the driver
//! in `node/pump.rs` carries out. The brain reads no clock, socket, channel or
//! shared cell, so each behaviour below is a sequence of inputs and the effects
//! they produce.
//!
//! One reconciler ([`levels`]) runs after every input: it composes the whole
//! desired node state and tells the node only what it does not hold. The
//! core's commands become node commands told one at a time ([`asks`]), and
//! the brain holds who rides each keyword walk ([`keyword_subscribers`]) and
//! who waits on each Callback Walk ([`callback_walks`]).

use std::collections::VecDeque;
use std::time::Instant;

use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{Ipv4Endpoint, SourceCryptOptions};

use crate::buddy::BuddyUdpPosture;
use crate::firewalled::front::AdoptVerdict;
use crate::firewalled::link::RecruitedBuddy;
use crate::firewalled::recruit::{
    AdoptOutcome, FindBuddyRes, RecruitContext, RecruitDecision, RecruitStatus, Recruiter,
};
use crate::reachability::UdpReachability;

mod asks;
mod callback_walks;
mod effect;
mod input;
mod keyword_subscribers;
mod levels;
mod self_check;

pub(crate) use effect::{
    AddressWrite, DiagnosticsWrite, KadCryptArm, KadPumpEffect, NodeCommand, NodeLevel, SearchNews,
    Spawn, TesterWrite, VerdictWrite,
};
pub(crate) use input::{
    Delivery, KadPumpInput, KadPumpSample, OwnAddressSample, ReachSample, SlotAnswer,
};

/// What a Kad Pump State is fixed with for its node's whole life.
#[derive(Clone, Copy)]
pub(crate) struct KadPumpConfig {
    /// The **Kad UDP Key** an armed node's verify keys derive from; whether
    /// the node is armed is the obfuscation policy's, sampled live.
    pub(crate) kad_udp_key: u32,
    /// The one bound UDP port (ADR-0057) — the port the stimulus posture
    /// declares open.
    pub(crate) kad_udp_port: u16,
    /// The **Core-Pumped Stimulus Node** posture: the verdicts are declared
    /// open at start rather than derived.
    pub(crate) assume_open_reachability: bool,
    /// The node's own Kad ID: the FINDBUDDY walk targets its inverse.
    pub(crate) kad_id: rmule_kad::KadId,
}

/// The Kad pump's brain for one running node.
pub(crate) struct KadPumpState {
    config: KadPumpConfig,
    self_check: self_check::SelfCheck,
    levels: levels::NodeLevels,
    /// The latest sources, `None` until `Start`: nothing is reconciled
    /// before the node is up.
    sample: Option<KadPumpSample>,
    /// aMule's `HasHadContact` (ADR-0067): monotonic while the node runs.
    had_contact: bool,
    /// Adds minus evictions: the node pairs every eviction with its event.
    contacts: usize,
    /// `0x5A` answers the node's full inbox refused, resent ahead of the
    /// next input's effects; the oldest goes when more wait than the cap.
    refused_answers: VecDeque<NodeCommand>,
    /// The ADR-0061 recruit rule: its pacing, its walk, its status.
    recruiter: Recruiter,
    /// The Recruit Status last stated, so an unmoved one is not restated;
    /// `None` until the start states the fresh node's.
    stated_recruit: Option<RecruitStatus>,
    /// The core's asks the node has not taken yet.
    asks: asks::Asks,
    /// Who rides each keyword walk.
    keywords: keyword_subscribers::KeywordSubscribers,
    /// Who waits on each Callback Walk.
    callback_walks: callback_walks::CallbackWalks,
    /// The node's driver is gone: nothing is waited for again.
    node_gone: bool,
}

/// How many refused FINDBUDDY answers wait for room. A firewalled requester
/// re-asks, so a flood loses the oldest rather than growing.
const REFUSED_ANSWERS_CAP: usize = 8;

impl KadPumpState {
    /// The brain of a node that has just been constructed.
    pub(crate) fn new(config: KadPumpConfig) -> Self {
        Self {
            config,
            self_check: self_check::SelfCheck::new(),
            levels: levels::NodeLevels::fresh(),
            sample: None,
            had_contact: false,
            contacts: 0,
            refused_answers: VecDeque::new(),
            recruiter: Recruiter::new(config.kad_id),
            stated_recruit: None,
            asks: asks::Asks::default(),
            keywords: keyword_subscribers::KeywordSubscribers::default(),
            callback_walks: callback_walks::CallbackWalks::default(),
            node_gone: false,
        }
    }

    /// Whether the driver may hand in the core's next command: no ask waits
    /// for the node. While one does, the core's commands wait in the pump's
    /// own bounded channel ([`asks`]).
    pub(crate) fn takes_commands(&self) -> bool {
        !self.asks.waiting()
    }

    /// Whether something the node's full inbox turned away waits to go again:
    /// the driver waits for room beside the node's events and hands in
    /// [`KadPumpInput::Room`].
    pub(crate) fn awaits_room(&self) -> bool {
        !self.node_gone
            && (self.asks.turned_away()
                || self.levels.waiting_for_room()
                || !self.refused_answers.is_empty())
    }

    /// Take one input and say what the world must do about it, in order.
    pub(crate) fn handle(&mut self, input: KadPumpInput, now: Instant) -> Vec<KadPumpEffect> {
        let mut out = Vec::new();
        // A delivery's answer is not an input to retry on; any other is.
        if !matches!(input, KadPumpInput::Delivered(..) | KadPumpInput::Stop) {
            out.extend(self.refused_answers.drain(..).map(KadPumpEffect::Node));
            self.asks.retry();
        }
        let mut tick = false;
        // Only a sample read after the store's write carries the store's
        // answer to a `0x61` observation.
        let sampled = matches!(
            input,
            KadPumpInput::Start(_)
                | KadPumpInput::Tick(_)
                | KadPumpInput::Sampled(_)
                | KadPumpInput::Command(..)
        );
        match input {
            KadPumpInput::Start(sample) => {
                self.sample = Some(sample);
                if self.config.assume_open_reachability {
                    self.self_check
                        .assume_open(self.config.kad_udp_port, &mut out);
                }
                // The published verdict is restated with the node's level at
                // start and on every tick, as one write.
                out.push(KadPumpEffect::Verdict(VerdictWrite::Tcp(
                    self.self_check.tcp(),
                )));
            }
            KadPumpInput::Command(command, sample) => {
                self.sample = Some(sample);
                self.on_command(*command, &mut out);
            }
            KadPumpInput::Event(event) => self.on_event(event, now, &mut out),
            KadPumpInput::Tick(sample) => {
                self.sample = Some(sample);
                out.push(KadPumpEffect::Verdict(VerdictWrite::Tcp(
                    self.self_check.tcp(),
                )));
                tick = true;
            }
            KadPumpInput::Sampled(sample) => self.sample = Some(sample),
            // Whatever waited for room goes again below.
            KadPumpInput::Room => {}
            // The answer to this brain's own command moved nothing outside
            // it: a refused level or ask waits for the next input rather than
            // spin against a full inbox — and the next ask goes out once the
            // node holds every level.
            KadPumpInput::Delivered(command, delivery) => {
                self.on_delivered(command, delivery, &mut out);
                self.release_ask(&mut out);
                return out;
            }
            KadPumpInput::SlotAnswered(answer) => self.on_slot_answer(answer, &mut out),
            KadPumpInput::BuddyVerdict(verdict) => self.on_buddy_verdict(verdict),
            KadPumpInput::Stop => {
                self.refused_answers.clear();
                self.asks_stopped(&mut out);
                self.self_check.stopped(&mut out);
                // A stopped node walks nothing; its last refusal stands.
                self.recruiter.walk_ended();
                self.state_recruit(&mut out);
                return out;
            }
        }
        self.reconcile(sampled, &mut out);
        if tick {
            self.consider_recruitment(now, &mut out);
        }
        self.release_ask(&mut out);
        self.state_recruit(&mut out);
        out
    }

    /// State the Recruit Status when it moved — and at the start, where a
    /// fresh node's restates whatever a predecessor left.
    fn state_recruit(&mut self, out: &mut Vec<KadPumpEffect>) {
        let status = self.recruiter.status();
        if self.stated_recruit != Some(status) {
            self.stated_recruit = Some(status);
            out.push(KadPumpEffect::Recruit(status));
        }
    }

    /// Tell the node every level of the desired state it does not hold.
    fn reconcile(&mut self, sampled: bool, out: &mut Vec<KadPumpEffect>) {
        let Some(sample) = self.sample else {
            return;
        };
        let desired = levels::desired(self.self_check.tcp(), &sample, self.config.kad_udp_key);
        out.extend(
            self.levels
                .reconcile(desired, sampled)
                .into_iter()
                .map(|level| KadPumpEffect::Node(NodeCommand::Level(level))),
        );
    }

    /// ADR-0061 firewalled-node recruitment, on the tick: the rule reads both
    /// verdicts, the recheck clock and the slot's published snapshot, and
    /// starts the walk itself.
    fn consider_recruitment(&mut self, now: Instant, out: &mut Vec<KadPumpEffect>) {
        let Some(sample) = self.sample else {
            return;
        };
        let context = RecruitContext {
            // The pump only runs while a node does.
            kad_connected: true,
            tcp: sample.reach.kad_tcp,
            udp: match sample.reach.kad_udp {
                UdpReachability::Open { .. } => BuddyUdpPosture::Open,
                UdpReachability::Firewalled => BuddyUdpPosture::Firewalled,
                UdpReachability::Unverified => BuddyUdpPosture::Unverified,
            },
            last_recheck: self.self_check.last_recheck(),
            crypt_required: sample.crypt == Some(ObfuscationPolicy::Required),
        };
        if let RecruitDecision::Recruit { walk_target } =
            self.recruiter.consider(&context, &sample.buddy, now)
        {
            out.push(KadPumpEffect::Node(NodeCommand::FindBuddyWalk {
                target: walk_target,
            }));
        }
    }

    fn on_delivered(
        &mut self,
        command: NodeCommand,
        delivery: Delivery,
        out: &mut Vec<KadPumpEffect>,
    ) {
        self.node_gone |= delivery == Delivery::NodeGone;
        match (command, delivery) {
            (NodeCommand::Ask(_), delivery) => self.ask_delivered(delivery, out),
            (NodeCommand::Level(level), Delivery::Landed) => self.levels.landed(level),
            (NodeCommand::Level(level), Delivery::InboxFull) => self.levels.refused(level, true),
            (NodeCommand::Level(level), Delivery::NodeGone) => self.levels.refused(level, false),
            (NodeCommand::FindBuddyWalk { .. }, Delivery::Landed) => {
                tracing::debug!("firewalled node: FINDBUDDY walk started (ADR-0061)");
            }
            // A walk that never started costs one walk; the next tick
            // re-decides, and the pacing clock already stamped means it waits
            // out the interval.
            (NodeCommand::FindBuddyWalk { .. }, Delivery::InboxFull | Delivery::NodeGone) => {
                self.recruiter.walk_ended();
                self.state_recruit(out);
            }
            (NodeCommand::AnswerFindBuddy { .. }, Delivery::Landed | Delivery::NodeGone) => {}
            // The slot already seated the recruit: the answer waits for room
            // and goes out on the next input.
            (answer @ NodeCommand::AnswerFindBuddy { .. }, Delivery::InboxFull) => {
                if self.refused_answers.len() == REFUSED_ANSWERS_CAP {
                    self.refused_answers.pop_front();
                }
                self.refused_answers.push_back(answer);
            }
        }
    }

    fn on_slot_answer(&mut self, answer: SlotAnswer, out: &mut Vec<KadPumpEffect>) {
        match answer {
            SlotAnswer::BuddyServed {
                requester,
                buddy_id,
            } => out.push(KadPumpEffect::Node(NodeCommand::AnswerFindBuddy {
                requester,
                buddy_id,
            })),
        }
    }

    /// The Firewalled Front's verdict on a `0x5A` this brain handed it: the
    /// slot it published after the adopt is the one every publish names from
    /// here — the reconciler runs next.
    fn on_buddy_verdict(&mut self, verdict: AdoptVerdict) {
        if let Some(sample) = &mut self.sample {
            sample.buddy = verdict.snapshot;
        }
        let buddy = verdict.buddy;
        match verdict.outcome {
            AdoptOutcome::Adopted => {
                tracing::info!(?buddy.tcp, "buddy recruited; dialing its link (ADR-0061)");
            }
            AdoptOutcome::Rejected => tracing::debug!(
                ?buddy.udp,
                "0x5A rejected: its buddy-ID does not invert to our Kad ID"
            ),
            AdoptOutcome::CryptIncompatible => tracing::info!(
                ?buddy.udp,
                stance = ?buddy.crypt,
                "buddy refused: CryptLayer-Settings (Obfuscation) incompatible (ADR-0049)"
            ),
        }
    }

    fn on_event(&mut self, event: rmule_kad::KadEvent, now: Instant, out: &mut Vec<KadPumpEffect>) {
        use rmule_kad::{KadEvent, KadNodeDiagnostic};
        match event {
            KadEvent::SourcesFound {
                target,
                storer,
                candidates,
            } => {
                // Every row that names a road crosses, not just the dialable
                // ones — a firewalled row carries the buddy that is the only
                // way to reach it — and a walk that decoded only refusals
                // still answers. Each row is the storer's word (ADR-0085).
                if !candidates.is_empty() {
                    let informant =
                        rmule_primitives::Informant::Party(std::net::IpAddr::V4(storer.ip()));
                    out.push(KadPumpEffect::Sources {
                        file_hash: target.file_hash(),
                        answer: candidates
                            .into_iter()
                            .filter_map(rmule_kad::KadSourceCandidate::sighting)
                            .map(|sighting| sighting.with_informant(informant))
                            .collect(),
                    });
                }
            }
            KadEvent::KeywordsFound { keyword, results } => {
                // ADR-0062 requester merge: the node already residual-filtered
                // and deduped by file ID; each dual-form row projects to a
                // `SearchResult`, and a row that does not stand travels as its
                // reason.
                let (rows, skipped) = super::project_keyword_rows(&results);
                self.keywords.deliver(keyword, rows, skipped, out);
            }
            KadEvent::KeywordSearchComplete {
                keyword, ended_by, ..
            } => self.keywords.complete(keyword, ended_by.into(), out),
            KadEvent::Diagnostic(KadNodeDiagnostic::KeywordPublishPreempted { keyword }) => {
                self.keywords.publish_deferred(keyword, out);
            }
            KadEvent::DialBackRequested {
                requester,
                connect_options,
                user_hash,
            } => out.push(KadPumpEffect::Spawn(Spawn::DialBack {
                requester,
                connect_options,
                user_hash,
            })),
            // The `0x62` comes back on the Kad socket, and the link's end
            // returns to this node's own inbox.
            KadEvent::UdpFirewallCheckRequested { helper, request } => {
                out.push(KadPumpEffect::Spawn(Spawn::UdpFirewallCheck {
                    helper,
                    request,
                }));
            }
            KadEvent::FwCheckUdpAnswered { requester, biased } => tracing::info!(
                %requester,
                biased,
                "kad UDP firewall helper: 0x62 sent (ADR-0058)"
            ),
            KadEvent::FindBuddyRequested {
                requester,
                buddy_id,
                requester_hash,
                requester_tcp_port,
            } => out.push(KadPumpEffect::Spawn(Spawn::FindBuddy {
                requester,
                buddy_id,
                requester_hash,
                requester_tcp_port,
            })),
            KadEvent::CallbackRelayRequested {
                requester,
                buddy_id,
                file_hash,
                requester_tcp_port,
            } => out.push(KadPumpEffect::Spawn(Spawn::CallbackRelay {
                requester,
                buddy_id,
                file_hash,
                requester_tcp_port,
            })),
            KadEvent::FloodOffenderDetected { ip, opcode } => {
                // ADR-0064: the node only reports a flood offender; this is
                // where the report becomes a peer-TCP ban.
                out.push(KadPumpEffect::Ban { ip, at: now });
                tracing::debug!(
                    %ip,
                    opcode,
                    "flood offender banned at the peer-TCP surface"
                );
            }
            event @ (KadEvent::ReachabilityRecheckStarted
            | KadEvent::ReachabilityConnectBack
            | KadEvent::ReachabilityRecheckConcluded
            | KadEvent::UdpReachabilityOpen { .. }
            | KadEvent::UdpReachabilityFirewalled) => self.self_check.observe(&event, now, out),
            KadEvent::ReachabilityCheckAsked {
                helper,
                helper_id,
                helper_udp_port,
                connect_options,
                answerable_for,
            } => self.self_check.check_asked(
                &self_check::CheckAsked {
                    helper,
                    helper_id,
                    helper_udp_port,
                    connect_options,
                    answerable_for,
                },
                now,
                out,
            ),
            KadEvent::Diagnostic(KadNodeDiagnostic::UnrequestedFirewallAck { from }) => {
                self.self_check.ack_discarded(from);
            }
            // One rung of the IPv4 ladder (ADR-0084). The store owns the
            // two-agree rule and the 30-minute window, so a single stranger's
            // `0x58` moves nothing on its own and the server's assignment
            // still outranks a quorum of them.
            KadEvent::AddressObserved { observer, address } => {
                out.push(KadPumpEffect::Address(AddressWrite::Observe(
                    crate::address_learning::AddressObservation::kad_observed_address(
                        observer, address,
                    ),
                )));
            }
            KadEvent::UdpPortObserved { observer, port } => {
                out.push(KadPumpEffect::Address(AddressWrite::Observe(
                    crate::address_learning::AddressObservation::kad_observed_port(observer, port),
                )));
                // The store's answer to this very observation, once written:
                // the round ends on it whether or not it repeats.
                self.levels.owe_port_answer();
            }
            // The round boundary sends nothing on its own: the node's cache
            // stands until the new round settles an answer, exactly as aMule's
            // does.
            KadEvent::ExternPortRoundStarted => {
                out.push(KadPumpEffect::Address(AddressWrite::ForgetKadPortRound));
            }
            // aMule's `HasHadContact` (ADR-0067): any counterparty datagram
            // marks the node joined; never cleared while running.
            KadEvent::HadContact { .. } | KadEvent::ContactResponded { .. } => {
                if !std::mem::replace(&mut self.had_contact, true) {
                    out.push(KadPumpEffect::Verdict(VerdictWrite::Joined));
                }
            }
            KadEvent::ContactAdded { .. } => {
                self.contacts += 1;
                out.push(KadPumpEffect::Diagnostics(DiagnosticsWrite::ContactCount(
                    self.contacts,
                )));
            }
            KadEvent::ContactEvicted { .. } => {
                self.contacts = self.contacts.saturating_sub(1);
                out.push(KadPumpEffect::Diagnostics(DiagnosticsWrite::ContactCount(
                    self.contacts,
                )));
            }
            KadEvent::KeywordPublishServed { stored, .. }
            | KadEvent::KeywordIndexExpired { stored } => {
                out.push(KadPumpEffect::Diagnostics(
                    DiagnosticsWrite::KeywordsStored(stored),
                ));
            }
            // Whether to try again sooner than the 20-minute tick is the
            // trigger's pacing to decide: re-arming on an empty walk would
            // start one per tick on a node whose routing table is merely cold.
            KadEvent::BuddyWalkEnded { asked } => {
                self.recruiter.walk_ended();
                tracing::debug!(asked, "FINDBUDDY walk ended (ADR-0061)");
            }
            KadEvent::CallbackWalkEnded { buddy_id, end } => {
                if let Some((reply, reason)) = self.callback_walks.ended(buddy_id, end) {
                    out.push(KadPumpEffect::CallbackWalkRetired { reply, reason });
                }
            }
            KadEvent::BuddyFound {
                buddy,
                buddy_id,
                buddy_hash,
                buddy_tcp_port,
                connect_options,
            } => out.push(self.adopt_walked(
                buddy,
                buddy_id,
                buddy_hash,
                buddy_tcp_port,
                connect_options,
            )),
            KadEvent::Diagnostic(KadNodeDiagnostic::UndecodableEnvelope { from, error }) => {
                // A hostile or malformed datagram never panics the node; the
                // count is what makes a crypt-armed run's own decode failures
                // falsifiable in either direction.
                out.push(KadPumpEffect::Diagnostics(
                    DiagnosticsWrite::UndecodableEnvelope,
                ));
                tracing::warn!(?from, ?error, "kad: UndecodableEnvelope");
            }
            _ => {}
        }
    }

    /// The `0x5A` our walk drew, put to the Firewalled Front to adopt; the
    /// walk that produced it is over either way.
    ///
    /// The node already applied the tracked-packet and XOR-inversion guards;
    /// the front's slot applies the same XOR check against its own Kad ID —
    /// one gate, two owners, because a slot that trusted the event could be
    /// filled by a node it was never re-seated for. The `0x5A`'s
    /// connect-options byte rides in as the buddy's stance, which the front
    /// meets with ours.
    fn adopt_walked(
        &mut self,
        buddy: Ipv4Endpoint,
        buddy_id: rmule_kad::KadId,
        buddy_hash: rmule_primitives::UserHash,
        buddy_tcp_port: u16,
        connect_options: Option<u8>,
    ) -> KadPumpEffect {
        self.recruiter.walk_ended();
        KadPumpEffect::AdoptBuddy {
            answer: FindBuddyRes {
                buddy_id,
                buddy_endpoint: buddy,
            },
            buddy: RecruitedBuddy {
                udp: buddy,
                tcp: Ipv4Endpoint::new(buddy.ip, buddy_tcp_port),
                hash: buddy_hash,
                // No byte (a pre-v7 buddy) is silence, not a stated "off"
                // (ADR-0049): `peer_crypt` folds it to all lights dark at the
                // dial, the same read aMule's own `connectOptions = 0` gets
                // (`KademliaUDPListener.cpp:1756`), but the record does not
                // itself claim the buddy said so.
                crypt: connect_options
                    .map(|byte| SourceCryptOptions::from_byte(byte).crypt_stance()),
            },
        }
    }
}

#[cfg(test)]
mod tests;
