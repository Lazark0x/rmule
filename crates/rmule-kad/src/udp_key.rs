//! The Kad UDP verify-key model (ADR-0046 key families / ADR-0064): aMule's
//! `CKadUDPKey` learned-key pair and the `CPrefs::GetUDPVerifyKey` per-IP
//! derivation, cite-and-rewritten from aMule 2.3.3 @`4e8f2b3c`
//! (`src/kademlia/utils/KadUDPKey.h`, `src/kademlia/kademlia/Prefs.cpp#L234`).
//!
//! Two keys ride the 8-byte trailer of every obfuscated Kad datagram
//! (`<receiverVerifyKey><senderVerifyKey>`, `EncryptedDatagramSocket.cpp#L242`):
//!
//! - the **sender key** is the sender's own [`udp_verify_key`] for the target
//!   IP — the key it *hands out* so the target can prove itself back later;
//! - the **receiver key** is the sender echoing the key the *receiver* once
//!   handed it — matching it against the receiver's own derivation is
//!   `validReceiverKey`, the IP-spoof-proof every verification path gates on
//!   (`ClientUDPSocket.cpp#L100`).
//!
//! A learned key is only meaningful while our own public IP is unchanged (the
//! counterparty derived it *from our IP*), which is exactly what [`KadUdpKey`]'s
//! binding models: aMule stores `(key, ip)` and `GetKeyValue(myIP)` collapses to
//! `0` the moment `myIP` moves.

use std::net::Ipv4Addr;

use md5::{Digest, Md5};

/// A Kad UDP verify key learned from a counterparty, bound to the public IP
/// this node had when it was learned — aMule's `CKadUDPKey`
/// (`kademlia/utils/KadUDPKey.h#L35`): `(m_key, m_ip)` where `m_ip` is **our
/// own** public IP at learn time, never the counterparty's.
///
/// Key value `0` means "no key" throughout the protocol (aMule hands out keys
/// from `[1, 0xFFFF_FFFE]`, see [`udp_verify_key`]), so an [`EMPTY`](Self::EMPTY)
/// pair and a zeroed trailer read identically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadUdpKey {
    key: u32,
    bound_ip: Ipv4Addr,
}

impl KadUdpKey {
    /// No key learned — aMule's default-constructed `CKadUDPKey`.
    pub const EMPTY: Self = Self {
        key: 0,
        bound_ip: Ipv4Addr::UNSPECIFIED,
    };

    /// A key learned from a counterparty's trailer, bound to `bound_ip` — the
    /// public IP *this node* presented when the key arrived.
    #[must_use]
    pub const fn new(key: u32, bound_ip: Ipv4Addr) -> Self {
        Self { key, bound_ip }
    }

    /// The raw key value, uninterpreted (persistence and diagnostics; protocol
    /// decisions go through [`key_value`](Self::key_value)).
    #[must_use]
    pub const fn key(&self) -> u32 {
        self.key
    }

    /// The public IP the key is bound to (persistence; see [`key_value`](Self::key_value)).
    #[must_use]
    pub const fn bound_ip(&self) -> Ipv4Addr {
        self.bound_ip
    }

    /// The key as valid at `my_ip`, or `0` if it was learned under a different
    /// own-IP — aMule `GetKeyValue(myIP)`: a counterparty derives our key *from
    /// our IP*, so an IP change silently retires every learned key.
    #[must_use]
    pub fn key_value(&self, my_ip: Ipv4Addr) -> u32 {
        if my_ip == self.bound_ip { self.key } else { 0 }
    }

    /// aMule `IsEmpty`: no key value or no binding IP.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.key == 0 || self.bound_ip.is_unspecified()
    }
}

impl Default for KadUdpKey {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// The UDP verify key this node hands `target_ip`, modelled on aMule
/// `CPrefs::GetUDPVerifyKey` (`Prefs.cpp#L234`): `MD5` over the 8-byte
/// little-endian image of `secret << 32 | target_ip`, the four hash words
/// XOR-folded, then `% 0xFFFF_FFFE + 1` so the result is never `0` (the no-key
/// sentinel) and never `0xFFFF_FFFF`.
///
/// **Not an interop surface.** `secret` is aMule's `thePrefs::GetKadUDPKey()` —
/// a random `u32` minted once per installation, persisted, and never
/// transmitted — so no counterparty can predict, reproduce, or check this
/// value. It only ever *echoes back* a key we handed it, and the only
/// requirement is that we re-derive the same key for the same IP. The
/// observable facts the wire actually pins are the trailer layout, the echo
/// protocol, and the zero sentinel; this formula is aMule-shaped for kinship,
/// not for compatibility, and byte-order choices inside it are consequently
/// free (a divergence here is unobservable by construction).
#[must_use]
pub fn udp_verify_key(secret: u32, target_ip: Ipv4Addr) -> u32 {
    let mut image = [0u8; 8];
    // Low u64 half: the address octets in order; high half: the secret.
    image[..4].copy_from_slice(&target_ip.octets());
    image[4..].copy_from_slice(&secret.to_le_bytes());
    let digest = Md5::digest(image);
    let word = |at: usize| {
        u32::from_le_bytes(
            digest[at..at + 4]
                .try_into()
                .expect("four bytes of an MD5 digest"),
        )
    };
    let folded = word(0) ^ word(4) ^ word(8) ^ word(12);
    folded % 0xFFFF_FFFE + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, d)
    }

    #[test]
    fn a_derived_key_is_never_the_no_key_sentinel() {
        // The `% 0xFFFF_FFFE + 1` range clamp: 0 means "no key" on the wire, so
        // the derivation must never mint it — probe a spread of inputs.
        for secret in [0u32, 1, 0xDEAD_BEEF, u32::MAX] {
            for host in 0..=u8::MAX {
                let key = udp_verify_key(secret, ip(host));
                assert_ne!(key, 0, "secret {secret:#X} host {host}");
                assert_ne!(key, u32::MAX, "secret {secret:#X} host {host}");
            }
        }
    }

    #[test]
    fn the_derivation_separates_targets_and_secrets() {
        // Different targets (and different secrets) yield different keys — the
        // per-IP separation the anti-spoof model rests on. Not a cryptographic
        // claim, a wiring guard: a formula that ignored its inputs would pass
        // every echo test.
        assert_ne!(
            udp_verify_key(0x1234_5678, ip(1)),
            udp_verify_key(0x1234_5678, ip(2))
        );
        assert_ne!(
            udp_verify_key(0x1234_5678, ip(1)),
            udp_verify_key(0x8765_4321, ip(1))
        );
        // Deterministic: the same inputs re-derive the same key.
        assert_eq!(
            udp_verify_key(0x1234_5678, ip(1)),
            udp_verify_key(0x1234_5678, ip(1))
        );
    }

    #[test]
    fn a_learned_key_retires_when_our_own_ip_moves() {
        let learned_at = ip(9);
        let key = KadUdpKey::new(0xABCD_EF01, learned_at);
        assert_eq!(key.key_value(learned_at), 0xABCD_EF01);
        assert_eq!(
            key.key_value(ip(10)),
            0,
            "a key learned under another own-IP is worthless"
        );
        assert!(!key.is_empty());
        assert!(KadUdpKey::EMPTY.is_empty());
        assert!(
            KadUdpKey::new(0, learned_at).is_empty(),
            "key 0 is the no-key sentinel even with a binding IP"
        );
        assert!(
            KadUdpKey::new(7, Ipv4Addr::UNSPECIFIED).is_empty(),
            "an unbound key is empty (aMule IsEmpty checks both halves)"
        );
    }
}
