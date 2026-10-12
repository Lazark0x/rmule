//! The **Kad half of Self Reach**: the two ADR-0058 self-check verdicts and
//! whether the node has joined, as one published cell, and the level a reader
//! carries.
//!
//! The Kad pump folds the node's lifecycle events into its ≥2-ack
//! [`Reachability`](super::Reachability) accumulator and its join latch, and is
//! the one writer of this cell; every other reader reaches them through
//! [`SharedSelfReach`](super::SharedSelfReach). One cell because they are one
//! family's writes and one generation: a `watch`, so a subscriber wakes on any
//! of them.
//!
//! The cell is reset to the fresh-node posture at a node's start **and** its
//! end ([`KadVerdictsLease`], held by the Kad Activity's one lease — ADR-0093):
//! aMule's `IsFirewalledKad` reads a Kad that is not
//! running as firewalled (`amule.cpp:1677-1681`, `4e8f2b3c`), and a verdict left
//! over from a stopped node is exactly the stale snapshot Self Reach rules out.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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
    /// aMule's `CKademlia::IsConnected()` (`HasHadContact`, `Kademlia.h:76`):
    /// a counterparty Kad datagram has been heard since the node started —
    /// latched for the node's life (ADR-0067's joined observable).
    pub(crate) joined: bool,
}

impl KadVerdicts {
    /// The fresh-node posture — also a stopped node's: nothing proven,
    /// nobody heard.
    pub(crate) const FRESH: Self = Self {
        tcp: TcpReachability::Firewalled,
        udp: UdpReachability::Unverified,
        tcp_check: KadFirewallCheck::NotYetRun,
        joined: false,
    };
}

/// The published Kad verdicts: one node's pump writes at a time, read through
/// [`KadReachLevel`].
///
/// The cell outlives any one node, and a node whose stop timed out can still
/// run a step after its successor started. Each [`lease`](Self::lease) is a
/// new **generation**; the only way to write is a [`KadVerdictsWriter`] bound
/// to the generation it was taken in, and a lease's end retires it, so a
/// predecessor's late write — or late reset — never touches its successor's
/// verdicts.
#[derive(Clone, Debug)]
pub(crate) struct SharedKadVerdicts {
    cell: Arc<watch::Sender<KadVerdicts>>,
    /// The generation now current; held across a write so a lease cannot
    /// slip between the check and the store.
    generation: Arc<Mutex<u64>>,
}

impl Default for SharedKadVerdicts {
    fn default() -> Self {
        Self {
            cell: Arc::new(watch::Sender::new(KadVerdicts::FRESH)),
            generation: Arc::new(Mutex::new(0)),
        }
    }
}

impl SharedKadVerdicts {
    /// The verdicts now.
    pub(crate) fn get(&self) -> KadVerdicts {
        *self.cell.borrow()
    }

    /// Publish the TCP verdict, whatever the generation — a test stating the
    /// verdict a real node would have reached.
    #[cfg(test)]
    pub(crate) fn set_tcp(&self, tcp: TcpReachability) {
        self.write_tcp(tcp);
    }

    /// Publish the UDP verdict, whatever the generation.
    #[cfg(test)]
    pub(crate) fn set_udp(&self, udp: UdpReachability) {
        self.write_udp(udp);
    }

    /// Wakes subscribers only when the verdict moved.
    fn write_tcp(&self, tcp: TcpReachability) {
        self.cell.send_if_modified(|verdicts| {
            let moved = verdicts.tcp != tcp;
            verdicts.tcp = tcp;
            moved
        });
    }

    fn write_udp(&self, udp: UdpReachability) {
        self.cell.send_if_modified(|verdicts| {
            let moved = verdicts.udp != udp;
            verdicts.udp = udp;
            moved
        });
    }

    /// Wakes nobody: the count moves on every connect-back, and no gate reads
    /// it.
    fn write_tcp_check(&self, check: KadFirewallCheck) {
        self.cell.send_if_modified(|verdicts| {
            verdicts.tcp_check = check;
            false
        });
    }

    /// Wakes subscribers once per node: the latch never opens twice.
    fn write_joined(&self) {
        self.cell
            .send_if_modified(|verdicts| !std::mem::replace(&mut verdicts.joined, true));
    }

    /// Back to the fresh-node posture.
    fn reset(&self) {
        self.cell.send_if_modified(|verdicts| {
            let moved = *verdicts != KadVerdicts::FRESH;
            *verdicts = KadVerdicts::FRESH;
            moved
        });
    }

    fn generation(&self) -> MutexGuard<'_, u64> {
        self.generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Take the cell for one node's life: a new generation, reset now, and
    /// reset again when the returned lease drops — the pump's end, a panic's
    /// unwind included.
    pub(crate) fn lease(&self) -> KadVerdictsLease {
        let mut generation = self.generation();
        *generation += 1;
        self.reset();
        KadVerdictsLease {
            cell: self.clone(),
            generation: *generation,
        }
    }

    /// The pen of the generation now current: the node started under the
    /// latest [`lease`](Self::lease) holds it, and it goes dead the moment a
    /// successor leases or its own lease ends.
    pub(crate) fn writer(&self) -> KadVerdictsWriter {
        KadVerdictsWriter {
            cell: self.clone(),
            generation: *self.generation(),
        }
    }
}

/// One node's write access to the published verdicts, good for the
/// generation it was taken in and no other.
pub(crate) struct KadVerdictsWriter {
    cell: SharedKadVerdicts,
    generation: u64,
}

impl KadVerdictsWriter {
    /// Run `write` only while this writer's generation is the current one.
    fn if_current(&self, write: impl FnOnce(&SharedKadVerdicts)) {
        if *self.cell.generation() == self.generation {
            write(&self.cell);
        }
    }

    /// Publish the TCP verdict; wakes subscribers only when it moved.
    pub(crate) fn set_tcp(&self, tcp: TcpReachability) {
        self.if_current(|cell| cell.write_tcp(tcp));
    }

    /// Publish the UDP verdict; wakes subscribers only when it moved.
    pub(crate) fn set_udp(&self, udp: UdpReachability) {
        self.if_current(|cell| cell.write_udp(udp));
    }

    /// Publish what the TCP check has drawn.
    pub(crate) fn set_tcp_check(&self, check: KadFirewallCheck) {
        self.if_current(|cell| cell.write_tcp_check(check));
    }

    /// Publish that the node has heard a counterparty; wakes subscribers the
    /// first time only.
    pub(crate) fn set_joined(&self) {
        self.if_current(SharedKadVerdicts::write_joined);
    }
}

/// One running node's hold on the published verdicts: dropping it states
/// "no node, nothing proven" — unless a successor already holds the cell.
pub(crate) struct KadVerdictsLease {
    cell: SharedKadVerdicts,
    generation: u64,
}

impl Drop for KadVerdictsLease {
    fn drop(&mut self) {
        let mut generation = self.cell.generation();
        if *generation == self.generation {
            // The node's writers die with its generation.
            *generation += 1;
            self.cell.reset();
        }
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
    /// A level that never moves: TCP open or firewalled, UDP unverified, and
    /// joined — a settled verdict is one a node that heard the network
    /// reached. Whether a node runs is **Kad Presence**'s answer, not this.
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
            joined: true,
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
            Source::Published(cell) => Some(cell.cell.subscribe()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KadVerdicts, SharedKadVerdicts};
    use crate::reachability::{TcpReachability, UdpReachability};

    /// A predecessor whose stop timed out can still run a step after its
    /// successor started: its late verdict, and its late lease end, leave the
    /// successor's verdicts as they are.
    #[test]
    fn a_predecessors_late_tick_leaves_the_successors_verdict_untouched() {
        let cell = SharedKadVerdicts::default();
        let predecessor_lease = cell.lease();
        let predecessor = cell.writer();
        predecessor.set_tcp(TcpReachability::Open);
        assert_eq!(cell.get().tcp, TcpReachability::Open);

        let _successor_lease = cell.lease();
        let successor = cell.writer();
        assert_eq!(cell.get(), KadVerdicts::FRESH, "the restart starts fresh");
        successor.set_udp(UdpReachability::Open { port: 4672 });

        predecessor.set_tcp(TcpReachability::Open);
        predecessor.set_udp(UdpReachability::Firewalled);
        drop(predecessor_lease);
        assert_eq!(
            cell.get(),
            KadVerdicts {
                udp: UdpReachability::Open { port: 4672 },
                ..KadVerdicts::FRESH
            },
            "only the successor's writes stand"
        );

        successor.set_tcp(TcpReachability::Open);
        assert_eq!(cell.get().tcp, TcpReachability::Open);
    }

    /// A node whose own lease ended has no verdict left to state.
    #[test]
    fn a_retired_nodes_writer_is_dead() {
        let cell = SharedKadVerdicts::default();
        let lease = cell.lease();
        let writer = cell.writer();
        drop(lease);
        writer.set_tcp(TcpReachability::Open);
        assert_eq!(cell.get(), KadVerdicts::FRESH);
    }
}
