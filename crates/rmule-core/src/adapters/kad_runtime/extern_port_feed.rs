//! The **Extern Kad Port**'s single owner: the Address
//! Learning store, with the sans-I/O node holding a cache the pump refreshes
//! — the same shape [`PublicIpFeed`](super::public_ip_feed::PublicIpFeed) and
//! [`TcpVerdictFeed`](super::tcp_verdict::TcpVerdictFeed) already give the
//! other levels the node is told rather than left to derive.
//!
//! Before this feed, [`KadCommand::SetExternalUdpPort`](rmule_kad::KadCommand::SetExternalUdpPort)
//! only ever went out in answer to a `UdpPortObserved` event:
//! the round the pump answers every observation for. That answer must stay
//! unconditional — the round's own settle-on-every-answer accounting depends
//! on it — but nothing re-stated the store's verdict once the observations
//! stopped. So a `KadCheck` rung's 30-minute window aging out with no fresh
//! observer left the node's cache holding a port the store no longer
//! considered fresh, disagreeing with the store's own `port()` (which falls
//! back to the bound port the moment nothing is fresh) until the next round
//! happened to run.
//!
//! [`observed`](ExternPortFeed::observed) keeps the observation answer
//! exactly as unconditional as before; [`sync`](ExternPortFeed::sync) is the
//! idempotent sibling called at Kad start, on every **Own Address
//! Generation** (a store write that moved the port — a mapping grant, a round forget)
//! and on the pump's recruit tick, the time edge: an
//! expiry the store already reflects reconciles within one tick instead of
//! waiting for a round that may not run again soon.

use crate::address_learning::{SharedAddressLearning, SocketRole};

/// The pump's single writer of the Extern Kad Port level: what the store
/// currently answers, and what the running node was last told.
pub(super) struct ExternPortFeed {
    addresses: SharedAddressLearning,
    /// The port the node was last told, so an idempotent re-derive that
    /// changes nothing costs no command.
    told: Option<u16>,
}

impl ExternPortFeed {
    /// A feed reading `addresses`' learned Kad UDP port, for a node that has
    /// been told nothing yet.
    pub(super) fn new(addresses: SharedAddressLearning) -> Self {
        Self {
            addresses,
            told: None,
        }
    }

    /// Re-state the store's learned port only when it moved since the node
    /// was last told (Kad start, an Own Address Generation, the recruit tick).
    /// Unlike
    /// [`observed`](Self::observed) this may cost no command at all: a tick
    /// that finds no change is meant to be free, and every observation
    /// already restates the value on its own.
    pub(super) fn sync(&mut self, handle: &rmule_net::kad::KadNetHandle) {
        let port = self.learned();
        if self.told == Some(port) {
            return;
        }
        self.send(port, handle);
    }

    /// Re-state the store's learned port unconditionally, because the
    /// self-check's round ends on this very answer regardless of whether the
    /// value repeats. Called for every `UdpPortObserved` event.
    pub(super) fn observed(&mut self, handle: &rmule_net::kad::KadNetHandle) {
        self.send(self.learned(), handle);
    }

    /// Forget the UDP role's Kad port votes at a round boundary:
    /// aMule starts every **Extern Port Round** with empty observer lists
    /// (`FindExternKadPort(true)`, `Prefs.cpp:305-322`), and a `KadCheck`
    /// report from before the boundary must not back one named after it.
    /// Called for `KadEvent::ExternPortRoundStarted`; sends nothing on its
    /// own — the node's cache stands until the new round settles an answer,
    /// exactly as aMule's does, and `set_extern_udp_port`'s collecting guard
    /// already stands a zero answer aside while a fresh round runs.
    pub(super) fn round_started(&mut self) {
        self.addresses.forget_kad_port_round(SocketRole::Udp);
    }

    fn learned(&self) -> u16 {
        self.addresses.learned_port(SocketRole::Udp).unwrap_or(0)
    }

    fn send(&mut self, port: u16, handle: &rmule_net::kad::KadNetHandle) {
        match handle.try_command(rmule_kad::KadCommand::SetExternalUdpPort { port }) {
            Ok(true) => self.told = Some(port),
            // The driver is gone; the pump is about to end with it.
            Err(_) => {}
            Ok(false) => tracing::warn!(
                "kad command inbox full; extern-Kad-port level deferred to the next change or tick"
            ),
        }
    }

    /// What the node was last told, for `sync`'s idempotence to be tested
    /// without a protocol-level probe of the node's own cache.
    #[cfg(test)]
    pub(super) fn told(&self) -> Option<u16> {
        self.told
    }
}
