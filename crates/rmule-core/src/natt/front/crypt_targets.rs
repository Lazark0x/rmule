//! The **Crypt Targets**: the one place a punch learns how it goes out
//! (ADR-0091, security rule 13).
//!
//! `OP_HOLEPUNCH` is a client-UDP datagram like any other, so a peer that
//! requires the crypt layer drops a plain one and the send gate needs its
//! stance. Who knows the stance changes as a traversal goes: the reach's source
//! record, a `0x61`'s byte 29, a relayed rendezvous's connect options, and at
//! last the peer's own hello. Each states what it knows here, and every burst
//! the front fires reads the latest.
//!
//! The hello binds the target to the path, because a path outlives the attempt
//! that opened it and a keepalive names an endpoint, not a peer.

use std::collections::HashMap;

use rmule_peer::peer_udp::crypt::PeerUdpCryptTarget;
use rmule_primitives::{CryptStance, Ipv4Endpoint, UserHash};

/// Every stance a traversal in flight was told, and every held path's target.
#[derive(Debug, Default)]
pub(super) struct CryptTargets {
    stated: HashMap<UserHash, CryptStance>,
    paths: HashMap<Ipv4Endpoint, PeerUdpCryptTarget>,
}

impl CryptTargets {
    /// Somebody stated `peer`'s stance. The latest statement stands.
    pub(super) fn state(&mut self, peer: UserHash, stance: CryptStance) {
        self.stated.insert(peer, stance);
    }

    /// What a punch toward `peer` carries.
    pub(super) fn of_peer(&self, peer: &UserHash) -> Option<PeerUdpCryptTarget> {
        self.stated
            .get(peer)
            .map(|stance| PeerUdpCryptTarget::new(*peer, *stance))
    }

    /// A hello named `target` on `path`.
    pub(super) fn bind_path(&mut self, path: Ipv4Endpoint, target: PeerUdpCryptTarget) {
        self.paths.insert(path, target);
    }

    /// What a keepalive on `path` carries.
    pub(super) fn of_path(&self, path: Ipv4Endpoint) -> Option<PeerUdpCryptTarget> {
        self.paths.get(&path).copied()
    }

    /// `path` closed.
    pub(super) fn path_closed(&mut self, path: Ipv4Endpoint) {
        self.paths.remove(&path);
    }

    /// Keep the stances of the peers something could still punch.
    pub(super) fn prune(&mut self, punching: impl Fn(&UserHash) -> bool) {
        self.stated.retain(|peer, _| punching(peer));
    }
}
