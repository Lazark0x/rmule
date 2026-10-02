//! The ADR-0058 **TCP verdict**'s two consumers, held as one object: the
//! published cell the rest of core reads, and the level the sans-I/O node is
//! told.
//!
//! The node holds an *injected* `KadReachability::tcp_firewalled` — it derives
//! no verdict of its own — and that injection is what arms
//! `UdpFirewallTester::check_timeout`'s conclude gate, the only live path to a
//! verified-firewalled UDP verdict and so to the ADR-0061 recruit gate. The
//! pump used to send it on a verdict **change** alone. A fresh store reads
//! `Firewalled` and stays there, so behind a NAT no edge ever fired: the
//! tester's six minutes never started and a firewalled node could not recruit
//! a buddy at all until the hourly recheck moved something.
//!
//! So the injection is a **level**, not an edge, and it travels with the
//! verdict rather than beside it — the lesson of the serve start that once told
//! the Port Mapper before the listener recorded its bind, one file over: you
//! cannot publish the verdict without the node hearing it, because both are
//! this one call. The pump re-derives the level on its own recruit tick as
//! well, so a level dropped by a momentarily full inbox repairs itself
//! instead of being lost in silence.

use crate::reachability::{SharedKadVerdicts, TcpReachability};

/// The pump's single writer of the TCP verdict: the published cell plus what
/// the running node has been told.
pub(super) struct TcpVerdictFeed {
    /// The published half — the Kad family of Self Reach.
    published: SharedKadVerdicts,
    /// The level the node currently holds. A freshly constructed node holds
    /// `KadReachability::default()` — assume-open — so an open node is told
    /// nothing extra at start and a firewalled one is told once.
    told_firewalled: bool,
}

impl TcpVerdictFeed {
    /// A feed for a node that has just been constructed (and so believes it is
    /// open), publishing into `published`.
    pub(super) fn new(published: SharedKadVerdicts) -> Self {
        Self {
            published,
            told_firewalled: false,
        }
    }

    /// Publish `verdict` and, when the node's level moved, inject it.
    ///
    /// Called at Kad start, on every verdict change, and on the pump's recruit
    /// tick. Idempotent: a level the node already holds costs no command.
    ///
    /// Non-blocking: the pump is the handle's sole event drainer, so an
    /// awaited command here can deadlock against a driver blocked emitting
    /// events. A momentarily full inbox leaves `told_firewalled` where it was,
    /// so the next tick sends the level again rather than assuming it landed.
    pub(super) fn sync(&mut self, verdict: TcpReachability, handle: &rmule_net::kad::KadNetHandle) {
        self.published.set_tcp(verdict);
        let firewalled = !verdict.is_reachable();
        if firewalled == self.told_firewalled {
            return;
        }
        match handle.try_command(rmule_kad::KadCommand::SetTcpReachability { firewalled }) {
            Ok(true) => self.told_firewalled = firewalled,
            // The driver is gone; the pump is about to end with it.
            Err(_) => {}
            Ok(false) => tracing::warn!(
                firewalled,
                "kad command inbox full; TCP-verdict level deferred to the next recruit tick"
            ),
        }
    }
}
