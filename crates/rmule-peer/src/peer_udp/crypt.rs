//! The pure rules of peer-UDP obfuscation (ADR-0046) and of the one plaintext
//! peer-UDP request, the direct callback (ADR-0061 route 2).
//!
//! An ed2k client-UDP datagram leaves obfuscated only when two of aMule's gates
//! agree: the per-peer predicate `CUpDownClient::ShouldReceiveCryptUDPPackets()`
//! (`BaseClient.cpp`), decided from both sides' crypt stances and the peer's
//! user hash, and the public-IP gate of `CMuleUDPSocket::SendControlData`
//! (`MuleUDPSocket.cpp`: `GetPublicIP() > 0` on this, the non-Kad, path),
//! because our own address is half the key. Both are here; drawing the nonce,
//! knowing our own identity and running the cipher are the runtime's.
//!
//! The crypt bits of the **Connect-Options Byte** are read and written here
//! too, for the `0x95` this module frames and for every other carrier of the
//! byte.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_primitives::{
    CryptStance, DatagramSenderAddress, Ipv4Endpoint, PeerEndpoint, SourceCryptOptions, UserHash,
};

use super::codec::DirectCallbackReq;

/// What the send gate must know about **one target peer** to obfuscate a
/// datagram for it: the inputs of aMule's per-peer predicate, carried with the
/// queued datagram as aMule queues `pachTargetClientHashORKadID` on its
/// `UDPPack` (`MuleUDPSocket.cpp`).
///
/// Built from the peer's hello: its user hash is the key basis (aMule keys a
/// send on the *recipient's* hash), its `MiscOptions2` crypt bits say whether
/// it accepts and asks for obfuscated datagrams. A peer we hold no identity
/// for has no target, and its datagrams go out plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerUdpCryptTarget {
    /// The target's user hash.
    pub user_hash: UserHash,
    /// The target's advertised crypt stance (`MiscOptions2` bits 7/8/9).
    pub stance: CryptStance,
}

impl PeerUdpCryptTarget {
    /// A target from a peer's advertised identity facts.
    #[must_use]
    pub const fn new(user_hash: UserHash, stance: CryptStance) -> Self {
        Self { user_hash, stance }
    }

    /// aMule's `ShouldReceiveCryptUDPPackets()` without its public-IP term,
    /// which [`sender_address`] carries: we support the layer, the peer does,
    /// its hash is real key material (`HasValidHash()`: an all-zero hash is
    /// empty), and one side asks for it
    /// (`IsClientCryptLayerRequested() || RequestsCryptLayer()`).
    #[must_use]
    pub fn should_receive_crypt_udp_packets(&self, ours: CryptStance) -> bool {
        ours.supports()
            && self.stance.supports()
            && self.user_hash.as_bytes().iter().any(|byte| *byte != 0)
            && (ours.requests() || self.stance.requests())
    }

    /// Both gates together: the address a datagram to `to` is keyed on when
    /// it may leave obfuscated, `None` when it leaves plaintext. `own_ipv4`
    /// and `own_ipv6` are our own external addresses as far as we know them.
    #[must_use]
    pub fn obfuscation_sender(
        &self,
        ours: CryptStance,
        to: PeerEndpoint,
        own_ipv4: Option<Ipv4Addr>,
        own_ipv6: Option<Ipv6Addr>,
    ) -> Option<DatagramSenderAddress> {
        if !self.should_receive_crypt_udp_packets(ours) {
            return None;
        }
        sender_address(to, own_ipv4, own_ipv6)
    }
}

/// The public-IP gate: the sender address an obfuscated datagram to `to` is
/// keyed on — our own external address **in the family the datagram leaves
/// by**, or `None` when we hold none there.
///
/// The recipient keys its decrypt on its own user hash and the source address
/// it sees, which is whichever half of our socket pair carried the datagram
/// (ADR-0085 binds `IPV6_V6ONLY`, so a v6 send is never reported as a mapped
/// v4). A key derived from an address the peer will not see is a key it
/// cannot reproduce, so such a datagram goes plaintext — aMule's
/// `GetPublicIP() != 0` generalised to two families (ADR-0087).
#[must_use]
pub fn sender_address(
    to: PeerEndpoint,
    own_ipv4: Option<Ipv4Addr>,
    own_ipv6: Option<Ipv6Addr>,
) -> Option<DatagramSenderAddress> {
    match to {
        PeerEndpoint::V4(_) => own_ipv4.map(|ip| DatagramSenderAddress::V4(ip.octets())),
        PeerEndpoint::V6(_) => own_ipv6.map(|ip| DatagramSenderAddress::V6(ip.octets())),
    }
}

/// The crypt bits of the Connect-Options Byte for our own `stance`: bit 0
/// supported, bit 1 requested, bit 2 required, everything else clear (aMule
/// `CPrefs::GetMyConnectOptions(encryption = true, callback = false)`,
/// `Prefs.cpp:217`). Carriers that also advertise a direct callback or a NAT-T
/// transport OR their own bits in.
#[must_use]
pub fn connect_options_from_stance(stance: CryptStance) -> u8 {
    u8::from(stance.requires()) << 2
        | u8::from(stance.requests()) << 1
        | u8::from(stance.supports())
}

/// A requester's crypt stance out of the Connect-Options Byte it sent — what
/// aMule's `CUpDownClient::SetConnectOptions` (`BaseClient.cpp#L2987`) does
/// before `TryToConnect` decides how to dial back. Only the three crypt bits
/// are read, and a dishonest ladder (`requires` without `supports`) collapses
/// rather than being trusted.
#[must_use]
pub fn stance_from_connect_options(connect_options: u8) -> CryptStance {
    SourceCryptOptions::from_byte(connect_options).crypt_stance()
}

/// The `OP_DIRECTCALLBACKREQ` (`0x95`) that asks a firewalled peer to dial us
/// back, and where it goes: the target's **Kad** UDP port, where aMule sends
/// its own (`BaseClient.cpp:1520`). Always plaintext — aMule never obfuscates
/// a callback request — while `connect_options` still tells the target how far
/// we follow it into obfuscation on the dial-back.
///
/// The destination is IPv4 because Kad is (ADR-0087).
#[must_use]
pub fn direct_callback(
    target_kad_udp: Ipv4Endpoint,
    our_tcp_port: u16,
    our_user_hash: UserHash,
    connect_options: u8,
) -> (PeerEndpoint, Vec<u8>) {
    let datagram = DirectCallbackReq {
        our_tcp_port,
        our_user_hash,
        connect_options,
    }
    .encode_udp();
    (PeerEndpoint::V4(target_kad_udp), datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUESTED: CryptStance = CryptStance::new(true, true, false);
    const SUPPORTED: CryptStance = CryptStance::new(true, false, false);

    fn target(stance: CryptStance) -> PeerUdpCryptTarget {
        PeerUdpCryptTarget::new(UserHash::from_bytes([0x44; 16]), stance)
    }

    /// Every leg of aMule's per-peer predicate.
    #[test]
    fn the_per_peer_predicate_needs_both_sides_able_and_one_asking() {
        // We do not support the layer: nothing is obfuscated.
        assert!(!target(REQUESTED).should_receive_crypt_udp_packets(CryptStance::disabled()));
        // The peer never advertised `SupportsCryptLayer`.
        assert!(!target(CryptStance::disabled()).should_receive_crypt_udp_packets(REQUESTED));
        // An all-zero hash is no key material.
        let empty = PeerUdpCryptTarget::new(UserHash::from_bytes([0; 16]), REQUESTED);
        assert!(!empty.should_receive_crypt_udp_packets(REQUESTED));
        // Both merely support it: plaintext.
        assert!(!target(SUPPORTED).should_receive_crypt_udp_packets(SUPPORTED));
        // Either side asking is enough.
        assert!(target(REQUESTED).should_receive_crypt_udp_packets(SUPPORTED));
        assert!(target(SUPPORTED).should_receive_crypt_udp_packets(REQUESTED));
    }

    /// The key's address follows the family the datagram leaves by, and a
    /// family we hold no address in leaves plaintext.
    #[test]
    fn the_sender_address_is_ours_in_the_destinations_family() {
        let v4 = Ipv4Addr::new(192, 0, 2, 44);
        let v6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x44);
        let to_v4 = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4665));
        let to_v6 = PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x7),
            4665,
        ));
        assert_eq!(
            sender_address(to_v4, Some(v4), Some(v6)),
            Some(DatagramSenderAddress::V4(v4.octets()))
        );
        assert_eq!(
            sender_address(to_v6, Some(v4), Some(v6)),
            Some(DatagramSenderAddress::V6(v6.octets()))
        );
        assert_eq!(sender_address(to_v6, Some(v4), None), None);
        assert_eq!(sender_address(to_v4, None, Some(v6)), None);
        // The predicate gates first: an able address does not open a send the
        // peer cannot read.
        assert_eq!(
            target(CryptStance::disabled()).obfuscation_sender(REQUESTED, to_v4, Some(v4), None),
            None
        );
    }

    /// The crypt bits round-trip through the byte for every honest ladder.
    #[test]
    fn the_connect_options_crypt_bits_round_trip() {
        for (stance, byte) in [
            (CryptStance::disabled(), 0x00),
            (SUPPORTED, 0x01),
            (REQUESTED, 0x03),
            (CryptStance::new(true, true, true), 0x07),
        ] {
            assert_eq!(connect_options_from_stance(stance), byte);
            assert_eq!(stance_from_connect_options(byte), stance);
        }
        // The direct-callback and NAT-T bits are not crypt facts.
        assert_eq!(stance_from_connect_options(0x08 | 0x80 | 0x01), SUPPORTED);
    }
}
