//! The ADR-0058 **self-check projection**: the pump's one owner of what its
//! node's TCP and UDP firewall self-checks have drawn.
//!
//! The sans-I/O node owns the recheck cadence, the emission budget, the 180 s
//! windows and the UDP tester, and emits the reachability lifecycle; this
//! projection folds those events onto the core [`Reachability`] store (the
//! ≥2-ack TCP verdict and the UDP verdict), publishes every change, tells the
//! node its TCP level back ([`TcpVerdictFeed`]), and mirrors each asked helper
//! into the listener's Awaited Testers (ADR-0046 "Test Connections") — the
//! helper half's one writer.

use std::time::{Duration, Instant};

use crate::awaited_testers::SharedAwaitedTesters;
use crate::reachability::{Reachability, SharedKadVerdicts};

use super::tcp_verdict::TcpVerdictFeed;

/// One `ReachabilityCheckAsked`, as the pump hands it over.
pub(super) struct CheckAsked {
    pub(super) helper: std::net::Ipv4Addr,
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

/// The self-checks' store, its published cell and the Awaited Testers' Kad
/// half, held together so a verdict is never folded without being published
/// and a recheck never starts without the helpers' windows closing.
pub(super) struct SelfCheckProjection {
    reachability: Reachability,
    tcp_feed: TcpVerdictFeed,
    published: SharedKadVerdicts,
    awaited_testers: SharedAwaitedTesters,
}

impl SelfCheckProjection {
    /// A fresh projection: TCP firewalled, UDP unverified, no helper awaited.
    pub(super) fn new(published: SharedKadVerdicts, awaited_testers: SharedAwaitedTesters) -> Self {
        Self {
            reachability: Reachability::new(),
            tcp_feed: TcpVerdictFeed::new(published.clone()),
            published,
            awaited_testers,
        }
    }

    /// The stimulus posture: declare the surface open so the
    /// ADR-0061 recruit gate can accept, since neither self-check can converge
    /// in a stimulus swarm. rmule's own posture only — every counterparty byte
    /// stays genuine (ADR-0045).
    pub(super) fn assume_open(&mut self, udp_port: u16) {
        self.reachability.assume_open(udp_port);
        self.published.set_udp(self.reachability.udp());
        self.published.set_tcp_check(self.reachability.tcp_check());
    }

    /// Publish the current TCP verdict and restate it to the node as a level
    /// — at Kad start and on every recruit tick.
    pub(super) fn sync_tcp(&mut self, handle: &rmule_net::kad::KadNetHandle) {
        self.tcp_feed.sync(self.reachability.tcp(), handle);
    }

    /// When the last TCP recheck started — the ADR-0061 recruit gate's
    /// five-minute clearance input.
    pub(super) fn last_recheck(&self) -> Option<Instant> {
        self.reachability.last_recheck()
    }

    /// Fold one reachability lifecycle event (a recheck start, a counted
    /// connect-back, a conclude, a UDP verdict) and log every verdict change.
    pub(super) fn observe(
        &mut self,
        event: &rmule_kad::KadEvent,
        handle: &rmule_net::kad::KadNetHandle,
    ) {
        if *event == rmule_kad::KadEvent::ReachabilityRecheckStarted {
            self.awaited_testers.kad_checks_dropped("a recheck started");
        }
        let before_tcp = self.reachability.tcp();
        let before_udp = self.reachability.udp();
        self.reachability.observe(event, Instant::now());
        self.published.set_tcp_check(self.reachability.tcp_check());
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
            // The TCP→node verdict feedback path (ADR-0058): the
            // node emits the TCP lifecycle, this store settles the
            // ≥2-ack verdict, and the settled result rides back so the node's
            // six-minute UDP-timeout gate composes on the *live* verdict — the
            // one place the two self-checks meet (aMule's
            // `IsFirewalled && !m_isFWVerifiedUDP`). `is_reachable` reads the
            // pre-recheck snapshot mid-recheck, so a proven-open node
            // mid-recheck never spuriously fires it. Publishing the verdict
            // wakes the Reach Generation, whose arm re-derives the byte and the
            // buddy row from the owner.
            self.tcp_feed.sync(self.reachability.tcp(), handle);
        }
        if self.reachability.udp() != before_udp {
            tracing::info!(
                before = ?before_udp,
                after = ?self.reachability.udp(),
                "kad UDP reachability verdict changed (ADR-0058 self-check)"
            );
            self.published.set_udp(self.reachability.udp());
        }
    }

    /// A TCP check was asked of `helper`: its connect-back may dial plain under
    /// `Required` for `answerable_for`.
    pub(super) fn check_asked(&self, asked: &CheckAsked) {
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
        self.awaited_testers
            .kad_check_asked(asked.helper, Instant::now() + asked.answerable_for);
    }

    /// An `OP_KAD_FWTCPCHECK_ACK` the node did not count: no check of ours is
    /// outstanding against `from`.
    pub(super) fn ack_discarded(&self, from: std::net::Ipv4Addr) {
        tracing::debug!(
            %from,
            tally = ?self.reachability.tcp_check(),
            "kad TCP check: OP_KAD_FWTCPCHECK_ACK discarded — no check outstanding against \
             that address (never asked, window lapsed, or a recheck dropped it)"
        );
    }

    /// The node is going away: every asked helper's window closes with it.
    pub(super) fn stopped(&self) {
        self.awaited_testers
            .kad_checks_dropped("the Kad node stopped");
    }
}
