//! The own-IPv4 level the sans-I/O node is told: the node's
//! Kad-UDP verify-key state binds a counterparty's *learned* key to the
//! public IP we held when we learned it (aMule's `CKadUDPKey`,
//! `KadUDPKey.h`), and aMule re-reads `theApp->GetPublicIP()` on every send
//! rather than pinning it at Kad start (`CPrefs::GetUDPVerifyKey`,
//! `Prefs.cpp:235-243`). Until this feed the node's binding never moved once
//! armed, so a key learned before an address change stayed authoritative
//! forever instead of retiring the way aMule's does.
//!
//! The node is a **subscriber** of Address Learning, the owner (ADR-0084's "Own address
//! ownership"): the pump re-derives this level on
//! every **Own Address Generation** — a server `OP_IDCHANGE`, a mapping
//! grant, an override, an interface refresh or this node's own `0x58`, each
//! written on a different task and each announced by the one event — and on
//! the recruit tick's 30 s clock, which is the edge a freshness window lapsing
//! with nobody writing needs. A withdrawn verdict is a change too: the node
//! is re-bound to `0.0.0.0`, the value it is armed with when no address is
//! known, so a key learned under the withdrawn address retires as aMule's does
//! when `GetPublicIP()` drops to 0.

use crate::own_identity::SharedOwnIdentity;

/// The pump's single reader of Address Learning's IPv4 verdict: what the
/// running node currently holds, checked against the live verdict.
pub(super) struct PublicIpFeed {
    own: SharedOwnIdentity,
    /// The address the node was last told, so a re-derive that changes
    /// nothing costs no command.
    told: Option<std::net::Ipv4Addr>,
}

impl PublicIpFeed {
    /// A feed reading `own`'s Address Learning projection, for a node that
    /// has been told nothing yet.
    pub(super) fn new(own: SharedOwnIdentity) -> Self {
        Self { own, told: None }
    }

    /// Re-read Address Learning's IPv4 verdict and, when it moved since the
    /// node was last told, re-bind the node's verify-key state to it.
    ///
    /// Called at Kad start, on every Own Address Generation and on the pump's
    /// recruit tick. Non-blocking for the reason
    /// [`TcpVerdictFeed::sync`](super::tcp_verdict::TcpVerdictFeed::sync)
    /// gives: a full inbox leaves `told` where it was, so the next call sends
    /// it again. No verdict (none ever held, or a Low-ID re-assignment
    /// withdrew it, ADR-0084) is `0.0.0.0` — the arming value `start` uses for
    /// the same case — never "keep the last one".
    pub(super) fn sync(&mut self, handle: &rmule_net::kad::KadNetHandle) {
        let public_ip = self
            .own
            .public_ip()
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        if self.told == Some(public_ip) {
            return;
        }
        match handle.try_command(rmule_kad::KadCommand::SetOwnPublicIp { public_ip }) {
            Ok(true) => self.told = Some(public_ip),
            Err(_) => {}
            Ok(false) => tracing::warn!(
                "kad command inbox full; own-IPv4 level deferred to the next change or tick"
            ),
        }
    }

    /// What the node was last told, for the feed's follow-the-owner contract
    /// to be tested without a protocol-level probe of the node's own cache.
    #[cfg(test)]
    pub(super) fn told(&self) -> Option<std::net::Ipv4Addr> {
        self.told
    }
}
