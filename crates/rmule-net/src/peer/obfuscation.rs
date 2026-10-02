//! Peer obfuscation runtime adapter and policy (ADR-0042).
//!
//! Bridges rmule-peer's sans-I/O [`PeerObfuscation`] handshake to the
//! [`ObfuscationTransport`] trait that `CryptStream` drives — the same
//! newtype-adapter pattern as `PeerDriven`. Per-connection entropy (marker,
//! random key, padding) is drawn from the OS CSPRNG here, where I/O lives, so
//! `rmule-peer` stays deterministic and sans-I/O.

use crate::driver::{HandshakeProgress, ObfuscationTransport, random_marker, random_padding};
use rand::RngCore;
use rand::rngs::OsRng;
use rmule_peer::{MiscOptions2, PeerObfuscation, PeerObfuscationStep};
use rmule_primitives::UserHash;

// The obfuscation policy/config are shared with the server runtime, so they
// live in the shared `driver` module (the crypt-layer home); re-exported here so
// `rmule_net::peer::ObfuscationPolicy` stays a stable path.
pub use crate::driver::{ObfuscationConfig, ObfuscationPolicy};

/// The addresses a listener under [`ObfuscationPolicy::Required`] still
/// accepts a **plain** connection from: a party rmule asked to test whether it
/// is reachable, and is awaiting that test from (ADR-0046 "Test Connections").
///
/// aMule's `AwaitingTestFromIP || IsKadFirewallCheckIP`
/// (`EncryptedStreamSocket.cpp:388-390`): the server a login answer is awaited
/// from, whose High-ID port test dials plain, and the Kad contacts a TCP
/// firewall check was asked of inside its window. Read synchronously per
/// accept — the set is a level its owners publish, never a question asked of
/// them — so an implementation must answer without awaiting anything.
pub trait AwaitedTesters: Send + Sync {
    /// Whether a plain dial from `ip` is a test rmule is awaiting now.
    fn awaits_test_from(&self, ip: std::net::IpAddr) -> bool;
}

/// The `MiscOptions2` crypt stance rmule advertises in its peer hello for an
/// obfuscation `policy` (ADR-0042). rmule accepts obfuscated inbound whenever a
/// policy is set, so `supports` is always honest; `requests`/`requires`
/// follow the policy ladder. A real aMule reads this to decide whether to
/// obfuscate-dial rmule (the advert's only validator).
pub(crate) fn crypt_advertisement(policy: ObfuscationPolicy) -> MiscOptions2 {
    MiscOptions2::from_stance(policy.crypt_stance())
}

/// Runtime adapter: an [`ObfuscationTransport`] backed by rmule-peer's
/// [`PeerObfuscation`], with CSPRNG entropy drawn here.
pub struct PeerObfuscationTransport {
    inner: PeerObfuscation,
    initial: Vec<u8>,
    /// Which side this is and the user hash its keys derive from, for the Run
    /// Log line a failed handshake writes.
    keyed_on: (&'static str, UserHash),
}

impl PeerObfuscationTransport {
    /// Accepter side: keys derive from our own **User Hash** once the dialer's
    /// random key arrives; no opening is emitted.
    #[must_use]
    pub fn responder(own: UserHash) -> Self {
        Self {
            inner: PeerObfuscation::respond(own, &random_padding()),
            initial: Vec::new(),
            keyed_on: ("responder", own),
        }
    }

    /// Dialer side: keys derive from the `target` peer's **User Hash**, and the
    /// opening is emitted from [`initial_output`](ObfuscationTransport::initial_output).
    #[must_use]
    pub fn initiator(target: UserHash) -> Self {
        let mut random_key = [0u8; 4];
        OsRng.fill_bytes(&mut random_key);
        let (inner, initial) =
            PeerObfuscation::initiate(target, random_marker(), random_key, &random_padding());
        Self {
            inner,
            initial,
            keyed_on: ("initiator", target),
        }
    }
}

impl ObfuscationTransport for PeerObfuscationTransport {
    fn initial_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.initial)
    }
    fn feed_handshake(&mut self, input: &[u8]) -> HandshakeProgress {
        match self.inner.feed(input) {
            PeerObfuscationStep::NeedMore => HandshakeProgress::NeedMore { write: Vec::new() },
            PeerObfuscationStep::Done { write, leftover } => {
                HandshakeProgress::Done { write, leftover }
            }
            PeerObfuscationStep::Failed => {
                let (role, hash) = self.keyed_on;
                tracing::debug!(
                    role,
                    keyed_on_hash_prefix = %hash.as_bytes()[..4]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    "peer obfuscation handshake failed: the decrypted sync word is not \
                     MAGICVALUE_SYNC — the other side keyed its stream on another user hash"
                );
                HandshakeProgress::Failed
            }
        }
    }
    fn transform_outgoing(&mut self, buf: &mut [u8]) {
        self.inner.transform_send(buf);
    }
    fn transform_incoming(&mut self, buf: &mut [u8]) {
        self.inner.transform_recv(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::{ObfuscationPolicy, crypt_advertisement};

    #[test]
    fn crypt_advertisement_follows_the_policy_ladder() {
        let supported = crypt_advertisement(ObfuscationPolicy::Supported);
        assert!(supported.supports_crypt_layer());
        assert!(!supported.requests_crypt_layer());
        assert!(!supported.requires_crypt_layer());

        let requested = crypt_advertisement(ObfuscationPolicy::Requested);
        assert!(requested.supports_crypt_layer());
        assert!(requested.requests_crypt_layer());
        assert!(!requested.requires_crypt_layer());

        let required = crypt_advertisement(ObfuscationPolicy::Required);
        assert!(required.supports_crypt_layer());
        assert!(required.requests_crypt_layer());
        assert!(required.requires_crypt_layer());
    }
}
