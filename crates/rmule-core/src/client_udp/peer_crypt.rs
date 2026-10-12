//! The I/O half of per-datagram crypt for the shared client-UDP socket
//! (ADR-0046), the **ed2k user-hash key family** (`MAGICVALUE_UDP`): our own
//! identity and public address, the per-packet OS nonce, and the key calls into
//! `rmule-primitives`. Whether a datagram may leave obfuscated, and which of
//! our addresses keys it, are `rmule_peer::peer_udp::crypt`'s rules; this
//! carries them out at the send boundary, on the queued unit that holds the
//! plaintext and its crypt target to that boundary (aMule's `UDPPack`).

use rmule_peer::peer_udp::crypt::PeerUdpCryptTarget;
use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, DatagramNonce, DatagramSenderAddress, PeerEndpoint,
    decrypt_datagram_client, encrypt_datagram_client,
};

use crate::obfuscation_policy::SharedObfuscationPolicy;
use crate::own_identity::SharedOwnIdentity;

/// One datagram leaving the shared client-UDP socket: where it goes, its
/// **plaintext** bytes, and the crypt target (if any) the send gate keys on.
///
/// This is aMule's `UDPPack` — the queued item carries the target hash and the
/// encrypt intent, and obfuscation happens at *send* time in
/// `CMuleUDPSocket::SendControlData`, not where the packet was built. rmule
/// keeps the same split: the reply matrix and the reask scheduler produce
/// plaintext plus a target, and [`encrypt_client_udp_send`] at the socket
/// boundary decides and draws the per-packet entropy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientUdpSend {
    /// Where it goes, in the destination's own **Address Family** — the
    /// Family Pair picks the socket (ADR-0085). The reask quartet reaches
    /// either family; the opcodes that do not are refused at the front, not
    /// here (`crate::client_udp`'s ruling table).
    pub(crate) to: PeerEndpoint,
    pub(crate) datagram: Vec<u8>,
    /// The peer this datagram is *for*, when we hold its identity — `None` for
    /// a stranger (aMule: "we cannot answer this one encrypted since we dont
    /// know this client") or for an opcode that is never obfuscated.
    pub(crate) crypt_target: Option<PeerUdpCryptTarget>,
}

impl ClientUdpSend {
    /// A datagram with no crypt target: always plaintext.
    pub(crate) const fn plaintext(to: PeerEndpoint, datagram: Vec<u8>) -> Self {
        Self {
            to,
            datagram,
            crypt_target: None,
        }
    }

    /// A datagram addressed to a peer whose crypt facts we may hold.
    pub(crate) const fn to_peer(
        to: PeerEndpoint,
        datagram: Vec<u8>,
        crypt_target: Option<PeerUdpCryptTarget>,
    ) -> Self {
        Self {
            to,
            datagram,
            crypt_target,
        }
    }
}

/// Per-datagram crypt for the shared client-UDP (peer-UDP) socket (ADR-0046):
/// the **ed2k user-hash + sender-IP key family** (`MAGICVALUE_UDP`), this
/// surface's own family — distinct from the Kad NodeID / verify-key families
/// the Kad-UDP socket keys on, which are
/// deliberately absent here just as the ed2k family is absent there. It holds
/// this node's own crypt identity plus our policy, used asymmetrically by the
/// two paths (aMule `EncryptedDatagramSocket::DecryptReceivedClient` /
/// `EncryptSendClient`):
///
/// - **Receive** keys on *our own* user hash + the datagram's UDP **source** IP —
///   a counterparty encrypts its reply to us on our user hash + its own sender
///   IP, so we decrypt with our hash + the source IP the datagram arrived from.
///   Our public IP is irrelevant here, so an armed layer decrypts from the
///   moment credentials exist, login or not.
/// - **Send** keys on the *target* peer's user hash + *our own* public IP, and
///   is therefore gated on a High-ID login having reported that IP (aMule
///   `MuleUDPSocket.cpp`: `item.bEncrypt && (theApp->GetPublicIP() > 0 ||
///   item.bKad)`, with `bKad` false on this ed2k path).
///
/// Armed while [`CoreSettings::obfuscation`](crate::CoreSettings::obfuscation)
/// is set, read per datagram as aMule reads `IsClientCryptLayerSupported()`
/// in `SendControlData`: disarmed, every send leaves as the plaintext it is,
/// and a live change reaches the next one. The receive is not gated: aMule
/// trial-decrypts whatever its setting.
pub(crate) struct PeerUdpCrypt {
    /// Our own user hash + public IP, both learned after this socket bound.
    own: SharedOwnIdentity,
    /// Our own crypt policy: `supports` is what arming means (we send
    /// obfuscated datagrams), `requests` is aMule's
    /// `thePrefs::IsClientCryptLayerRequested()` — the half of the per-peer
    /// predicate that lets us obfuscate toward a merely-supporting peer.
    policy: SharedObfuscationPolicy,
}

impl PeerUdpCrypt {
    /// The layer over the shared self-facts and the one obfuscation policy.
    pub(crate) const fn new(own: SharedOwnIdentity, policy: SharedObfuscationPolicy) -> Self {
        Self { own, policy }
    }

    /// A layer that is never armed, for a front a test builds with no
    /// policy behind it.
    #[cfg(test)]
    pub(crate) fn disarmed() -> Self {
        Self::new(
            SharedOwnIdentity::default(),
            SharedObfuscationPolicy::default(),
        )
    }

    /// Whether the layer is armed now.
    pub(crate) fn armed(&self) -> bool {
        self.policy.armed()
    }

    /// Dual-path receive (ADR-0046), mirroring aMule `DecryptReceivedClient`:
    /// trial-decrypt under **every** policy, `off` included — the policy gates
    /// what we send and require, never whether we can open a datagram
    /// (`EncryptedDatagramSocket.cpp:136`, where the
    /// `IsClientCryptLayerSupported()` guard is commented out). Trial-decrypt
    /// keyed on our user hash + the datagram's own source address, whose
    /// family selects the key layout (ADR-0087). The primitive returns `None` — so
    /// the original datagram passes through — when the first byte is a known
    /// plaintext marker (bypass) *or* no held key validates the sync word
    /// (garbage / a datagram for another peer's hash); the caller then diagnoses
    /// that plaintext through the demux. A hit yields the recovered inner packet
    /// (for the ed2k family, exactly the plaintext the sender framed — no
    /// verify-key trailer).
    pub(crate) fn receive(&self, sender: DatagramSenderAddress, datagram: Vec<u8>) -> Vec<u8> {
        let Some(our_user_hash) = self.own.user_hash() else {
            return datagram; // no identity yet ⇒ no key ⇒ nothing to try
        };
        let keys = ClientDecryptKeys {
            // The Kad NodeID / verify-key families are the Kad socket's, so both
            // stay `None` — this socket only ever tries the ed2k family.
            user_hash: Some(&our_user_hash),
            sender,
            ..Default::default()
        };
        match decrypt_datagram_client(&datagram, &keys) {
            Some(decrypted) => decrypted.payload,
            None => datagram,
        }
    }

    /// The address a datagram for `target` to `to` is keyed on, when the
    /// per-peer predicate and the public-IP gate both let it leave obfuscated.
    fn obfuscation_sender(
        &self,
        target: &PeerUdpCryptTarget,
        to: PeerEndpoint,
    ) -> Option<DatagramSenderAddress> {
        target.obfuscation_sender(
            self.policy.stance(),
            to,
            self.own.public_ip(),
            self.own.public_ipv6(),
        )
    }
}

/// Send-gate one outbound client-UDP datagram (ADR-0046 send rule) at the
/// socket boundary, where aMule encrypts it: obfuscate only when the layer is
/// armed now, the datagram carries a crypt target, and the peer-UDP crypt rules
/// (aMule's per-peer predicate and its public-IP gate) key it on our own
/// address. Anything else rides as the plaintext it already is — aMule sends
/// plaintext whenever it holds no usable crypt key for the recipient, and
/// legacy peers depend on that.
///
/// `nonce` is drawn lazily so the OS entropy is touched only on a datagram that
/// is actually obfuscated.
pub(crate) fn encrypt_client_udp_send(
    crypt: &PeerUdpCrypt,
    send: ClientUdpSend,
    nonce: impl FnOnce() -> DatagramNonce,
) -> (PeerEndpoint, Vec<u8>) {
    let ClientUdpSend {
        to,
        datagram,
        crypt_target,
    } = send;
    if !crypt.armed() {
        return (to, datagram);
    }
    let Some(target) = crypt_target else {
        return (to, datagram);
    };
    let Some(sender) = crypt.obfuscation_sender(&target, to) else {
        return (to, datagram);
    };
    let key = ClientEncryptKey::Ed2k {
        user_hash: &target.user_hash,
        sender,
    };
    let obfuscated = encrypt_datagram_client(&datagram, &key, &nonce());
    (to, obfuscated)
}

/// The per-packet entropy a live obfuscated send draws from the OS: the
/// semi-random marker byte (its low bits are overwritten with the key-family
/// index), the 2-byte key seed sent in the clear, and the padding. aMule
/// disables UDP padding outright (`EncryptSendClient`: "padding disabled for UDP
/// currently"), so rmule emits none either — a padded datagram would still
/// decode, but it would not be byte-shaped like aMule's.
pub(crate) fn os_datagram_nonce() -> DatagramNonce {
    let mut raw = [0u8; 3];
    getrandom::fill(&mut raw).expect("OS entropy for the peer-UDP crypt nonce");
    DatagramNonce {
        marker_byte: raw[0],
        random_key: u16::from_le_bytes([raw[1], raw[2]]),
        padding: Vec::new(),
    }
}

/// Send-gate unit tests: what the runtime half adds to the crypt rules — the
/// armed layer and the target a send carries, our own address as the IDCHANGE
/// and a LowID re-assignment move it, and the key layout each family's address
/// yields — each with a decrypt round trip proving the key.
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::{Ipv4Endpoint, UserHash};

    use super::super::tests::{
        a_nonce, a_reask_ping, armed_requesting, own, requesting, supporting_target,
    };
    use super::*;

    #[test]
    fn the_send_gate_obfuscates_an_armed_send_for_its_target_and_round_trips() {
        let our_hash = UserHash::from_bytes([0x33; 16]);
        let our_ip = [192u8, 0, 2, 44];
        let sender = armed_requesting(our_hash, our_ip);
        let target_hash = UserHash::from_bytes([0x44; 16]);
        let to = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4665));
        let plain = a_reask_ping(0x55);
        let gate = |crypt: &PeerUdpCrypt, target: Option<PeerUdpCryptTarget>| {
            encrypt_client_udp_send(
                crypt,
                ClientUdpSend::to_peer(to, plain.clone(), target),
                a_nonce,
            )
            .1
        };

        // Disarmed (no obfuscation policy): plaintext rides untouched, even
        // toward a crypt-capable target.
        let disarmed = PeerUdpCrypt::new(own(our_hash, our_ip), SharedObfuscationPolicy::default());
        assert_eq!(gate(&disarmed, Some(supporting_target(target_hash))), plain);
        // Armed but the datagram carries no target — a stranger's reask, a
        // callback: still plaintext.
        assert_eq!(gate(&sender, None), plain);

        // Armed with a crypt-capable target: the datagram is obfuscated, and
        // the recipient — holding the target hash, keyed on our sender IP —
        // recovers exactly the plaintext.
        let crypt = gate(&sender, Some(supporting_target(target_hash)));
        assert_ne!(crypt, plain);
        assert!(!rmule_primitives::is_udp_plaintext_marker(crypt[0]));
        let recipient = armed_requesting(target_hash, [0; 4]);
        assert_eq!(
            recipient.receive(DatagramSenderAddress::V4(our_ip), crypt),
            plain
        );
    }

    #[test]
    fn the_send_gate_needs_our_own_public_ip() {
        // Our own address is part of the key the peer derives, so a LowID
        // login (or none) leaves every datagram plaintext, and the High-ID
        // IDCHANGE switches it on with no other change.
        let our_hash = UserHash::from_bytes([0x77; 16]);
        let own = SharedOwnIdentity::default();
        own.set_user_hash(our_hash);
        let crypt = PeerUdpCrypt::new(own.clone(), requesting());
        let target = supporting_target(UserHash::from_bytes([0x88; 16]));
        let to = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4665));
        let plain = a_reask_ping(0x55);
        let gate = || {
            encrypt_client_udp_send(
                &crypt,
                ClientUdpSend::to_peer(to, plain.clone(), Some(target)),
                a_nonce,
            )
            .1
        };

        assert_eq!(gate(), plain, "no public IP ⇒ plaintext");

        own.addresses()
            .observe(crate::address_learning::AddressObservation::server_high_id(
                Ipv4Addr::new(203, 0, 113, 9),
            ));
        let obfuscated = gate();
        assert_ne!(obfuscated, plain, "the IDCHANGE public IP arms the send");
        // And it is keyed on that exact IP: the peer derives the key from the
        // address it saw the datagram arrive from, so a different one recovers
        // nothing.
        let recipient = armed_requesting(target.user_hash, [0; 4]);
        assert_eq!(
            recipient.receive(
                DatagramSenderAddress::V4([203, 0, 113, 9]),
                obfuscated.clone()
            ),
            plain
        );
        assert_eq!(
            recipient.receive(
                DatagramSenderAddress::V4([203, 0, 113, 10]),
                obfuscated.clone()
            ),
            obfuscated,
            "a wrong sender IP recovers nothing (the datagram passes through)",
        );

        // A mid-session drop back to LowID disarms the send again.
        own.addresses().observe_server_assigned(
            rmule_primitives::ClientId::from_u32(0),
            None,
            None,
        );
        assert_eq!(gate(), plain, "a LowID re-assignment disarms the send");
    }

    /// The policy changes live (ADR-0046): the very next datagram after a
    /// change follows it on the send gate, which obfuscates once armed and
    /// stops once disarmed; the receive opens an obfuscated datagram under
    /// every policy, as aMule's `DecryptReceivedClient` does.
    #[test]
    fn a_live_policy_change_reaches_the_next_send_and_never_closes_the_receive() {
        let our_hash = UserHash::from_bytes([0x33; 16]);
        let our_ip = [192u8, 0, 2, 44];
        let policy = SharedObfuscationPolicy::default();
        let layer = PeerUdpCrypt::new(own(our_hash, our_ip), policy.clone());
        let target = supporting_target(UserHash::from_bytes([0x44; 16]));
        let to = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4665));
        let plain = a_reask_ping(0x55);
        let send = || {
            encrypt_client_udp_send(
                &layer,
                ClientUdpSend::to_peer(to, plain.clone(), Some(target)),
                a_nonce,
            )
            .1
        };
        // What a requesting peer obfuscates toward us, keyed on our hash and
        // its own address.
        let theirs = encrypt_client_udp_send(
            &armed_requesting(target.user_hash, [198, 51, 100, 7]),
            ClientUdpSend::to_peer(to, plain.clone(), Some(supporting_target(our_hash))),
            a_nonce,
        )
        .1;
        let from_them = DatagramSenderAddress::V4([198, 51, 100, 7]);

        assert_eq!(send(), plain, "off: the send stays plaintext");
        assert_eq!(layer.receive(from_them, theirs.clone()), plain);

        policy.set(Some(rmule_net::peer::ObfuscationPolicy::Requested));
        assert_ne!(send(), plain, "armed: the next send is obfuscated");
        assert_eq!(layer.receive(from_them, theirs.clone()), plain);

        policy.set(None);
        assert_eq!(send(), plain, "off again: the next send is plaintext");
        assert_eq!(layer.receive(from_them, theirs.clone()), plain);
    }

    /// A dual-stack node keys a v4 send on its IPv4 and a v6 send on its IPv6
    /// (ADR-0087), and each opens only under the layout its own family yields.
    #[test]
    fn a_dual_stack_send_is_keyed_on_our_address_in_its_family() {
        use super::super::tests::armed_requesting_dual_stack;

        let our_hash = UserHash::from_bytes([0x33; 16]);
        let our_v4 = [192u8, 0, 2, 44];
        let our_v6 = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x44);
        let target = supporting_target(UserHash::from_bytes([0x44; 16]));
        let plain = a_reask_ping(0x55);

        let to_v4 = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4665));
        let to_v6 = PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
            std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x7),
            4665,
        ));
        let dual = armed_requesting_dual_stack(our_hash, our_v4, our_v6);
        let seal = |to| {
            encrypt_client_udp_send(
                &dual,
                ClientUdpSend::to_peer(to, plain.clone(), Some(target)),
                a_nonce,
            )
            .1
        };
        let over_v4 = seal(to_v4);
        let over_v6 = seal(to_v6);

        let recipient = armed_requesting(target.user_hash, [0; 4]);
        assert_eq!(
            recipient.receive(DatagramSenderAddress::V4(our_v4), over_v4.clone()),
            plain
        );
        assert_eq!(
            recipient.receive(DatagramSenderAddress::V6(our_v6.octets()), over_v6.clone()),
            plain
        );
        assert_eq!(
            recipient.receive(DatagramSenderAddress::V4(our_v4), over_v6.clone()),
            over_v6,
            "the 23-byte layout recovers nothing from a 35-byte key",
        );
    }
}
