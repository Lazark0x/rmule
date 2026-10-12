//! The world the Kad pump's driver reads and writes for the **Kad Pump
//! State**: the samples it hands the brain, and each effect carried out
//! against the cell, channel or task it names.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rmule_primitives::FileHash;
use tokio::sync::mpsc;

use super::{BuddyService, DialBack};
use crate::adapters::kad_runtime::KadPumpCommand;
use crate::adapters::kad_runtime::pump_state::{
    AddressWrite, DiagnosticsWrite, KadPumpEffect, KadPumpInput, KadPumpSample, OwnAddressSample,
    ReachSample, SearchNews, SlotAnswer, Spawn, TesterWrite, VerdictWrite,
};
use crate::address_learning::SocketRole;

/// What carrying out one effect left for the brain.
pub(super) enum Enacted {
    /// Nothing to answer.
    Done,
    /// The effect's answer, for the brain before the next effect.
    Answer(KadPumpInput),
    /// The discovery task dropped its sources: the pump ends.
    SourcesClosed,
}

/// Every cell, channel and service the brain's effects reach, and the
/// sources its samples read.
pub(crate) struct Enactor {
    /// The discovery task's answers.
    pub(crate) sources_tx: mpsc::Sender<(FileHash, crate::kad_sources::KadAnswer)>,
    pub(crate) dial_back: DialBack,
    pub(crate) buddy_service: BuddyService,
    pub(crate) ban_store: crate::ban_store::SharedBanStore,
    pub(crate) awaited_testers: crate::awaited_testers::SharedAwaitedTesters,
    /// The Firewalled Front, the buddy slot's one owner: where a `0x5A` our
    /// walk drew is put to adopt, and where the Recruit Status is published.
    pub(crate) firewalled_front: crate::firewalled::front::SharedFirewalledFront,
    /// This pump's own verdict inbox, whose weak half every adopt the front
    /// is asked for carries back.
    pub(crate) verdicts: mpsc::Sender<crate::firewalled::front::AdoptVerdict>,
    pub(crate) diagnostics: crate::diagnostics::DiagnosticsState,
    /// The Kad family of Self Reach, which this pump alone writes — and only
    /// while its node's lease is the current one.
    pub(crate) published: crate::reachability::KadVerdictsWriter,
    pub(crate) contact_count: Arc<AtomicUsize>,
    pub(crate) keywords_stored: Arc<AtomicUsize>,
    pub(crate) addresses: crate::address_learning::SharedAddressLearning,
    pub(crate) own: crate::own_identity::SharedOwnIdentity,
    pub(crate) reach: crate::reachability::SharedSelfReach,
    /// Every hello this pump's own dials send — the firewall-check dial-back
    /// and the UDP-check helper dial — starts from the one read every other
    /// hello does.
    pub(crate) hello: crate::adapters::HelloAdverts,
    /// Where a helper's refused hello is counted and raised (ADR-0050).
    pub(crate) hello_refusals: crate::hello_refusals::SharedHelloRefusals,
    /// The ADR-0058 requester gate, consulted before dialling an engaged
    /// helper.
    pub(crate) peer_roster: crate::peer_roster::SharedPeerRoster,
    /// This node's own command sink, where a UDP-check link reports its end;
    /// weak, so a stopped node's is closed and a restart's is another.
    pub(crate) pump_sink: mpsc::WeakSender<KadPumpCommand>,
}

impl Enactor {
    /// The sources the brain composes the node's state from, read now.
    pub(super) fn sample(&self) -> KadPumpSample {
        let reach = &self.reach;
        KadPumpSample {
            reach: ReachSample {
                firewalled: reach.firewalled(),
                accepts_direct_udp_callback: reach.accepts_direct_udp_callback(),
                natt_live: reach.natt_live(),
                kad_tcp: reach.kad_tcp(),
                kad_udp: reach.kad_udp(),
            },
            own_address: OwnAddressSample {
                public_ip: self.own.public_ip(),
                learned_udp_port: self.addresses.learned_port(SocketRole::Udp),
            },
            buddy: self.hello.buddy.snapshot(),
            crypt: self.hello.obfuscation.get(),
            advertised_ipv6: self.hello.ipv6.get(),
        }
    }

    /// The obfuscation policy's live changes the pump wakes on (ADR-0046).
    pub(super) fn obfuscation_changed(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<rmule_net::peer::ObfuscationPolicy>> {
        self.hello.obfuscation.changes()
    }

    /// The **Own Address Generation** the pump wakes on.
    pub(super) fn own_address_changed(&self) -> tokio::sync::watch::Receiver<u64> {
        self.addresses.own_address_changed()
    }

    /// Carry out one effect.
    pub(super) async fn enact(
        &mut self,
        effect: KadPumpEffect,
        handle: &rmule_net::kad::KadNetHandle,
    ) -> Enacted {
        match effect {
            KadPumpEffect::Node(command) => {
                let delivery = match handle.try_command(command.command()) {
                    Ok(true) => crate::adapters::kad_runtime::pump_state::Delivery::Landed,
                    Ok(false) => crate::adapters::kad_runtime::pump_state::Delivery::InboxFull,
                    Err(_) => crate::adapters::kad_runtime::pump_state::Delivery::NodeGone,
                };
                return Enacted::Answer(KadPumpInput::Delivered(command, delivery));
            }
            KadPumpEffect::Sources { file_hash, answer } => {
                if self.sources_tx.send((file_hash, answer)).await.is_err() {
                    return Enacted::SourcesClosed;
                }
            }
            KadPumpEffect::Search { sink, news } => match news {
                SearchNews::Rows(rows) => sink.offer(rows),
                SearchNews::Fact(fact) => sink.tell(fact),
            },
            KadPumpEffect::CallbackWalkRetired { reply, reason } => {
                let _ = reply.retire_tx.try_send((reply.key, reason));
            }
            KadPumpEffect::Address(write) => {
                match write {
                    AddressWrite::Observe(observation) => {
                        self.addresses.observe(observation);
                    }
                    AddressWrite::ForgetKadPortRound => {
                        self.addresses.forget_kad_port_round(SocketRole::Udp);
                    }
                }
                return Enacted::Answer(KadPumpInput::Sampled(self.sample()));
            }
            KadPumpEffect::Ban { ip, at } => self.ban_store.lock().await.ban(IpAddr::V4(ip), at),
            KadPumpEffect::Verdict(write) => match write {
                VerdictWrite::Tcp(tcp) => self.published.set_tcp(tcp),
                VerdictWrite::Udp(udp) => self.published.set_udp(udp),
                VerdictWrite::TcpCheck(check) => self.published.set_tcp_check(check),
                VerdictWrite::Joined => self.published.set_joined(),
            },
            KadPumpEffect::Testers(write) => match write {
                TesterWrite::Asked { helper, until } => {
                    self.awaited_testers.kad_check_asked(helper, until);
                }
                TesterWrite::Dropped { helpers } => {
                    self.awaited_testers.kad_checks_dropped(&helpers);
                }
            },
            KadPumpEffect::Diagnostics(write) => self.diagnostics(write),
            KadPumpEffect::AdoptBuddy { answer, buddy } => {
                let asked = self.firewalled_front.send(
                    crate::firewalled::front::FirewalledCommand::AdoptBuddy {
                        answer,
                        buddy,
                        verdict: self.verdicts.downgrade(),
                    },
                );
                if !asked {
                    // No front (no client-UDP socket) or a full inbox: the
                    // answer is lost as a walk that found nobody is, and the
                    // recruit rule's pacing decides when to walk again.
                    tracing::debug!(?buddy.udp, "0x5A not adopted: no firewalled front took it");
                }
            }
            KadPumpEffect::Recruit(status) => self.firewalled_front.publish_recruit(status),
            KadPumpEffect::Spawn(spawn) => {
                if let Some(answer) = self.spawn(spawn) {
                    return Enacted::Answer(answer);
                }
            }
        }
        Enacted::Done
    }

    fn diagnostics(&self, write: DiagnosticsWrite) {
        match write {
            DiagnosticsWrite::ContactCount(count) => {
                self.contact_count.store(count, Ordering::Relaxed);
            }
            DiagnosticsWrite::KeywordsStored(stored) => {
                self.keywords_stored.store(stored, Ordering::Relaxed);
            }
            DiagnosticsWrite::UndecodableEnvelope => {
                self.diagnostics.count_kad_undecodable_envelope();
            }
        }
    }

    /// Work that runs beside the pump's path; a FINDBUDDY the slot accepted
    /// is the one that answers.
    fn spawn(&self, spawn: Spawn) -> Option<KadPumpInput> {
        match spawn {
            Spawn::DialBack {
                requester,
                connect_options,
                user_hash,
            } => self
                .dial_back
                .requested(requester, connect_options, user_hash),
            // Off the pump's path: the `0x62` comes back on the Kad socket,
            // and the link's end returns to this node's own inbox, which a
            // stopped node has closed (a restart's node has another).
            Spawn::UdpFirewallCheck { helper, request } => {
                tokio::spawn(
                    crate::adapters::kad_runtime::udp_firewall_check::run_udp_firewall_check(
                        helper,
                        request,
                        self.dial_back.presents.now(),
                        self.hello.clone(),
                        self.hello_refusals.clone(),
                        self.pump_sink.clone(),
                        self.peer_roster.clone(),
                    ),
                );
            }
            Spawn::FindBuddy {
                requester,
                buddy_id,
                requester_hash,
                requester_tcp_port,
            } => {
                return self
                    .buddy_service
                    .find_buddy_requested(
                        requester,
                        buddy_id,
                        requester_hash,
                        requester_tcp_port,
                        &self.reach,
                    )
                    .map(|(requester, buddy_id)| {
                        KadPumpInput::SlotAnswered(SlotAnswer::BuddyServed {
                            requester,
                            buddy_id,
                        })
                    });
            }
            Spawn::CallbackRelay {
                requester,
                buddy_id,
                file_hash,
                requester_tcp_port,
            } => self.buddy_service.callback_relay_requested(
                requester,
                buddy_id,
                file_hash,
                requester_tcp_port,
            ),
        }
        None
    }
}
