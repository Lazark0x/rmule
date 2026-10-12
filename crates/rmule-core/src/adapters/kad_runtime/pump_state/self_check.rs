//! The ADR-0058 self-checks as the **Kad Pump State** folds them: what its
//! node's TCP and UDP firewall self-checks have drawn.
//!
//! The sans-I/O node owns the recheck cadence, the emission budget, the 180 s
//! windows and the UDP tester, and emits the reachability lifecycle; this fold
//! settles those events onto the core [`Reachability`] store (the ≥2-ack TCP
//! verdict and the UDP verdict), publishes every change as the Kad family of
//! **Self Reach**, and mirrors each asked helper into the listener's Awaited
//! Testers (ADR-0046 "Test Connections") — the helper half's one writer. The
//! node's TCP level is the reconciler's, read from [`tcp`](SelfCheck::tcp).

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::{KadPumpEffect, TesterWrite, VerdictWrite};
use crate::reachability::{Reachability, TcpReachability};

/// One `ReachabilityCheckAsked`, as the brain reads it.
pub(super) struct CheckAsked {
    pub(super) helper: Ipv4Addr,
    pub(super) helper_id: rmule_kad::KadId,
    pub(super) helper_udp_port: u16,
    pub(super) connect_options: Option<u8>,
    pub(super) answerable_for: Duration,
}

/// A Kad ID's first four bytes in hex — enough to tell helpers apart in the
/// Run Log.
fn kad_id_prefix(id: &rmule_kad::KadId) -> String {
    id.as_bytes()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The self-checks' store and the helper windows this node opened, held
/// together so a recheck never starts without those windows closing.
pub(super) struct SelfCheck {
    reachability: Reachability,
    /// Each helper this node asked and when its window lapses: the windows
    /// it may close. The Awaited Testers cell is shared across Kad
    /// restarts, so a stop or recheck closes these and no others.
    asked: Vec<(Ipv4Addr, Instant)>,
}

impl SelfCheck {
    /// A fresh fold: TCP firewalled, UDP unverified, no helper awaited.
    pub(super) fn new() -> Self {
        Self {
            reachability: Reachability::new(),
            asked: Vec::new(),
        }
    }

    /// The stimulus posture: declare the surface open so the
    /// ADR-0061 recruit gate can accept, since neither self-check can converge
    /// in a stimulus swarm. rmule's own posture only — every counterparty byte
    /// stays genuine (ADR-0045).
    pub(super) fn assume_open(&mut self, udp_port: u16, out: &mut Vec<KadPumpEffect>) {
        self.reachability.assume_open(udp_port);
        out.push(KadPumpEffect::Verdict(VerdictWrite::Udp(
            self.reachability.udp(),
        )));
        out.push(KadPumpEffect::Verdict(VerdictWrite::TcpCheck(
            self.reachability.tcp_check(),
        )));
        tracing::info!(
            udp_port,
            "kad stimulus posture: reachability declared open (Core-Pumped Stimulus Node)"
        );
    }

    /// The settled TCP verdict.
    pub(super) fn tcp(&self) -> TcpReachability {
        self.reachability.tcp()
    }

    /// When the last TCP recheck started — the ADR-0061 recruit gate's
    /// five-minute clearance input.
    pub(super) fn last_recheck(&self) -> Option<Instant> {
        self.reachability.last_recheck()
    }

    /// Fold one reachability lifecycle event (a recheck start, a counted
    /// connect-back, a conclude, a UDP verdict) and publish every verdict
    /// change.
    pub(super) fn observe(
        &mut self,
        event: &rmule_kad::KadEvent,
        now: Instant,
        out: &mut Vec<KadPumpEffect>,
    ) {
        if *event == rmule_kad::KadEvent::ReachabilityRecheckStarted {
            out.push(KadPumpEffect::Testers(TesterWrite::Dropped {
                helpers: std::mem::take(&mut self.asked),
            }));
        }
        let before_tcp = self.reachability.tcp();
        let before_udp = self.reachability.udp();
        self.reachability.observe(event, now);
        out.push(KadPumpEffect::Verdict(VerdictWrite::TcpCheck(
            self.reachability.tcp_check(),
        )));
        tracing::debug!(
            ?event,
            tally = ?self.reachability.tcp_check(),
            tcp = ?self.reachability.tcp(),
            udp = ?self.reachability.udp(),
            "kad self-check: lifecycle event folded"
        );
        if self.reachability.tcp() != before_tcp {
            tracing::info!(
                before = ?before_tcp,
                after = ?self.reachability.tcp(),
                "kad TCP reachability verdict changed (ADR-0058 self-check)"
            );
            // Publishing the verdict wakes the Reach Generation, whose sample
            // re-derives the byte and the buddy row from the owner; the
            // node's own TCP level rides the reconcile that follows this
            // input, so the six-minute UDP-timeout gate composes on the live
            // verdict (aMule's `IsFirewalled && !m_isFWVerifiedUDP`).
            out.push(KadPumpEffect::Verdict(VerdictWrite::Tcp(
                self.reachability.tcp(),
            )));
        }
        if self.reachability.udp() != before_udp {
            tracing::info!(
                before = ?before_udp,
                after = ?self.reachability.udp(),
                "kad UDP reachability verdict changed (ADR-0058 self-check)"
            );
            out.push(KadPumpEffect::Verdict(VerdictWrite::Udp(
                self.reachability.udp(),
            )));
        }
    }

    /// A TCP check was asked of `helper`: its connect-back may dial plain under
    /// `Required` for `answerable_for`.
    pub(super) fn check_asked(
        &mut self,
        asked: &CheckAsked,
        now: Instant,
        out: &mut Vec<KadPumpEffect>,
    ) {
        tracing::debug!(
            helper = %asked.helper,
            helper_udp_port = asked.helper_udp_port,
            helper_kad_id = %kad_id_prefix(&asked.helper_id),
            request = if asked.connect_options.is_some() { "0x53" } else { "0x50" },
            connect_options = ?asked.connect_options.map(|byte| format!("{byte:#04x}")),
            names_our_user_hash = asked.connect_options.is_some(),
            window_secs = asked.answerable_for.as_secs(),
            "kad TCP check asked of a helper (ADR-0058 requester)"
        );
        let until = now + asked.answerable_for;
        self.asked.retain(|(_, lapses)| now < *lapses);
        self.asked.push((asked.helper, until));
        out.push(KadPumpEffect::Testers(TesterWrite::Asked {
            helper: asked.helper,
            until,
        }));
    }

    /// An `OP_KAD_FWTCPCHECK_ACK` the node did not count: no check of ours is
    /// outstanding against `from`.
    pub(super) fn ack_discarded(&self, from: Ipv4Addr) {
        tracing::debug!(
            %from,
            tally = ?self.reachability.tcp_check(),
            "kad TCP check: OP_KAD_FWTCPCHECK_ACK discarded — no check outstanding against \
             that address (never asked, window lapsed, or a recheck dropped it)"
        );
    }

    /// The node is going away: the helper windows it asked close with it,
    /// and a successor's stay.
    pub(super) fn stopped(&mut self, out: &mut Vec<KadPumpEffect>) {
        out.push(KadPumpEffect::Testers(TesterWrite::Dropped {
            helpers: std::mem::take(&mut self.asked),
        }));
    }
}
