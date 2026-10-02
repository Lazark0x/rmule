//! The **Kad half of Self Reach**: the two ADR-0058 self-check verdicts as one
//! published cell, and the level a reader carries.
//!
//! The Kad pump folds the node's lifecycle events into its ≥2-ack
//! [`Reachability`](super::Reachability) accumulator and is the one writer of
//! this cell; every other reader reaches the verdicts through
//! [`SharedSelfReach`](super::SharedSelfReach). One cell for both verdicts
//! because they are one family's writes and one generation: a `watch`, so a
//! subscriber wakes on either.
//!
//! The cell is reset to the fresh-node posture at a node's start **and** its
//! end ([`KadVerdictsLease`], held by the Kad Activity's one lease — ADR-0093):
//! aMule's `IsFirewalledKad` reads a Kad that is not
//! running as firewalled (`amule.cpp:1677-1681`, `4e8f2b3c`), and a verdict left
//! over from a stopped node is exactly the stale snapshot Self Reach rules out.

use std::sync::Arc;

use tokio::sync::watch;

use super::{TcpReachability, UdpReachability};
use crate::diagnostics::KadFirewallCheck;

/// Both Kad self-check verdicts, as the pump last published them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KadVerdicts {
    /// The TCP verdict under the ≥2-ack rule.
    pub(crate) tcp: TcpReachability,
    /// The UDP tester's verdict.
    pub(crate) udp: UdpReachability,
    /// What the TCP check has drawn — the why beside `tcp`. Carried, never
    /// woken on: a reader that gates on reachability gates on the verdicts.
    pub(crate) tcp_check: KadFirewallCheck,
}

impl KadVerdicts {
    /// The fresh-node posture — also a stopped node's: nothing proven.
    pub(crate) const FRESH: Self = Self {
        tcp: TcpReachability::Firewalled,
        udp: UdpReachability::Unverified,
        tcp_check: KadFirewallCheck::NotYetRun,
    };
}

/// The published Kad verdicts: single writer (the Kad pump), read through
/// [`KadReachLevel`].
#[derive(Clone, Debug)]
pub(crate) struct SharedKadVerdicts(Arc<watch::Sender<KadVerdicts>>);

impl Default for SharedKadVerdicts {
    fn default() -> Self {
        Self(Arc::new(watch::Sender::new(KadVerdicts::FRESH)))
    }
}

impl SharedKadVerdicts {
    /// The verdicts now.
    pub(crate) fn get(&self) -> KadVerdicts {
        *self.0.borrow()
    }

    /// Publish the TCP verdict; wakes subscribers only when it moved.
    pub(crate) fn set_tcp(&self, tcp: TcpReachability) {
        self.0.send_if_modified(|verdicts| {
            let moved = verdicts.tcp != tcp;
            verdicts.tcp = tcp;
            moved
        });
    }

    /// Publish the UDP verdict; wakes subscribers only when it moved.
    pub(crate) fn set_udp(&self, udp: UdpReachability) {
        self.0.send_if_modified(|verdicts| {
            let moved = verdicts.udp != udp;
            verdicts.udp = udp;
            moved
        });
    }

    /// Publish what the TCP check has drawn. Wakes nobody: the count moves on
    /// every connect-back, and no gate reads it.
    pub(crate) fn set_tcp_check(&self, check: KadFirewallCheck) {
        self.0.send_if_modified(|verdicts| {
            verdicts.tcp_check = check;
            false
        });
    }

    /// Back to the fresh-node posture.
    fn reset(&self) {
        self.0.send_if_modified(|verdicts| {
            let moved = *verdicts != KadVerdicts::FRESH;
            *verdicts = KadVerdicts::FRESH;
            moved
        });
    }

    /// Take the cell for one node's life: reset now, and again when the
    /// returned lease drops — the pump's end, a panic's unwind included.
    pub(crate) fn lease(&self) -> KadVerdictsLease {
        self.reset();
        KadVerdictsLease(self.clone())
    }
}

/// One running node's hold on the published verdicts: dropping it states
/// "no node, nothing proven".
pub(crate) struct KadVerdictsLease(SharedKadVerdicts);

impl Drop for KadVerdictsLease {
    fn drop(&mut self) {
        self.0.reset();
    }
}

/// The Kad verdicts as a value a reader can carry: a running node's published
/// cell, read at the moment of the question — or a fixed level, for a runtime
/// that runs no self-check (and for a test stating a verdict a real node would
/// have reached).
///
/// Cheap to clone; every clone reads the same cell.
#[derive(Clone, Debug)]
pub struct KadReachLevel(Source);

#[derive(Clone, Debug)]
enum Source {
    Fixed(KadVerdicts),
    Published(SharedKadVerdicts),
}

impl KadReachLevel {
    /// A level that never moves: TCP open or firewalled, UDP unverified.
    #[must_use]
    pub const fn fixed(tcp_open: bool) -> Self {
        Self(Source::Fixed(KadVerdicts {
            tcp: if tcp_open {
                TcpReachability::Open
            } else {
                TcpReachability::Firewalled
            },
            udp: UdpReachability::Unverified,
            tcp_check: KadFirewallCheck::NotYetRun,
        }))
    }

    /// The level a running node publishes into `cell`, read live.
    pub(crate) const fn published(cell: SharedKadVerdicts) -> Self {
        Self(Source::Published(cell))
    }

    /// The verdicts now.
    pub(crate) fn get(&self) -> KadVerdicts {
        match &self.0 {
            Source::Fixed(verdicts) => *verdicts,
            Source::Published(cell) => cell.get(),
        }
    }

    /// Take the published cell for one node's life ([`SharedKadVerdicts::lease`]);
    /// `None` for a fixed level, which no node writes.
    pub(crate) fn lease(&self) -> Option<KadVerdictsLease> {
        match &self.0 {
            Source::Fixed(_) => None,
            Source::Published(cell) => Some(cell.lease()),
        }
    }

    /// A subscription to the published cell; `None` for a fixed level, which
    /// never moves.
    pub(crate) fn subscribe(&self) -> Option<watch::Receiver<KadVerdicts>> {
        match &self.0 {
            Source::Fixed(_) => None,
            Source::Published(cell) => Some(cell.0.subscribe()),
        }
    }
}
