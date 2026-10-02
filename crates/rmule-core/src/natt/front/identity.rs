//! Who rmule is on the NAT-T surface: the transports it will actually serve,
//! the self-facts an obfuscated `0xB2` frame is keyed on, and the jitter draw
//! the rendezvous schedule clamps.
//!
//! Three small things that share one subject — rmule's own identity on this
//! surface — and none of which belongs in the front's loop.

use rmule_net::natt::{NattCrypt, NattOwnHash};
use rmule_peer::natt::{HelloNattClaim, PunchJitter};
use rmule_primitives::{AddressFamily, DatagramNonce, DatagramSenderAddress, UserHash};

/// rmule's NAT-T posture on this surface: uTP served, QUIC dark until a live
/// handshake with another implementation is proven (ADR-0091 — an optimistic
/// bit 4 costs every peer a 1500 ms stall).
pub(crate) const RMULE_NATT_CLAIM: HelloNattClaim = HelloNattClaim {
    utp: true,
    quic: false,
};

/// A jitter draw from the OS, clamped into the dialect's 50–150 ms window by
/// the type that owns it.
pub(super) fn os_punch_jitter() -> PunchJitter {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("OS entropy for the rendezvous jitter");
    PunchJitter::from_random(u32::from_le_bytes(bytes))
}

/// The **NAT-T Front**'s crypt half over rmule's own identity (ADR-0046's
/// key family, ADR-0087's per-family layout): armed exactly when
/// `CoreConfig::peer_crypt` is, like [`PeerUdpCrypt`](crate::client_udp).
///
/// The address is the *key* cell rather than the advert cell, and deliberately
/// An advert is a claim about where we can be reached and is
/// gated accordingly, while a key is a value the recipient will independently
/// derive from the source address it observes. Keying on an address we held a
/// minute ago costs at worst a frame the peer reads as plaintext; refusing to
/// key because an advert gate said no would cost every frame.
pub(crate) struct OwnIdentityNattCrypt(pub(crate) crate::own_identity::SharedOwnIdentity);

impl NattCrypt for OwnIdentityNattCrypt {
    fn own_user_hash(&self) -> UserHash {
        self.0.user_hash().unwrap_or(UserHash::from_bytes([0; 16]))
    }

    fn sender_address(&self, family: AddressFamily) -> Option<DatagramSenderAddress> {
        match family {
            AddressFamily::V4 => self
                .0
                .public_ip()
                .map(|ip| DatagramSenderAddress::V4(ip.octets())),
            AddressFamily::V6 => self
                .0
                .public_ipv6()
                .map(|ip| DatagramSenderAddress::V6(ip.octets())),
        }
    }

    fn nonce(&self) -> DatagramNonce {
        crate::client_udp::os_datagram_nonce()
    }
}

/// The demux's live identity source: read per CAPS frame and per
/// QUIC handshake, never captured at the front's own start, which runs at
/// client-UDP socket bind — ahead of whichever credentialed activity first
/// supplies the cell a hash. The same self-facts cell [`OwnIdentityNattCrypt`]
/// reads, but fallibly: the KEY frame tolerates a zero-hash placeholder
/// before login, a CAPS answer must not invent one.
impl NattOwnHash for crate::own_identity::SharedOwnIdentity {
    fn user_hash(&self) -> Option<UserHash> {
        self.user_hash()
    }
}
