//! Per-datagram crypt for the shared client-UDP socket and its send boundary
//! (ADR-0046): the **ed2k user-hash key family** (`MAGICVALUE_UDP`),
//! this surface's own — receive keys on our user hash + the sender's IP, send
//! on the target's hash + our public IP behind aMule's per-peer predicate and
//! public-IP gate. Holds the queued-send unit that carries plaintext plus its
//! crypt target to the socket boundary (aMule's `UDPPack`), the send gate
//! that obfuscates it there, the per-packet OS nonce, and the plaintext
//! direct-callback (`0x95`) framing that rides the same send half.

use rmule_peer::DirectCallbackReq;
use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, CryptStance, DatagramNonce, DatagramSenderAddress,
    Ipv4Endpoint, PeerEndpoint, SourceCryptOptions, UserHash, decrypt_datagram_client,
    encrypt_datagram_client,
};

use crate::own_identity::SharedOwnIdentity;

/// What the send gate must know about **one target peer** to obfuscate a
/// datagram for it — the inputs of aMule's per-peer predicate
/// `CUpDownClient::ShouldReceiveCryptUDPPackets()` (`BaseClient.cpp`), carried
/// alongside the queued datagram exactly as aMule queues
/// `pachTargetClientHashORKadID` on its `UDPPack` (`MuleUDPSocket.cpp`).
///
/// Built from the peer's hello: its user hash is the ed2k family's key, its
/// `MiscOptions2` crypt bits say whether it accepts (and asks for) obfuscated
/// datagrams. A peer we hold no identity for has no target at all, and its
/// datagrams go out plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerUdpCryptTarget {
    /// The target's user hash — the outbound key basis (aMule keys the send on
    /// the *recipient's* hash).
    pub(crate) user_hash: UserHash,
    /// The target's advertised crypt stance (`MiscOptions2` bits 7/8/9). aMule
    /// reads `SupportsCryptLayer()` and `RequestsCryptLayer()` from it.
    pub(crate) stance: CryptStance,
}

impl PeerUdpCryptTarget {
    /// Build a target from a peer's advertised identity facts.
    pub(crate) const fn new(user_hash: UserHash, stance: CryptStance) -> Self {
        Self { user_hash, stance }
    }

    /// aMule's `HasValidHash()`: an all-zero user hash is `CMD4Hash::IsEmpty()`
    /// — no key material, so no obfuscation (`EncryptSendClient` asserts on it).
    fn has_valid_hash(&self) -> bool {
        self.user_hash.as_bytes().iter().any(|byte| *byte != 0)
    }
}

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
/// Off unless [`CoreConfig::peer_crypt`](crate::CoreConfig) is set: the engine
/// then holds `None` and every datagram stays plaintext. The datagram byte facts
/// are source-read and `[pending]` until an ADR-0046 peer-UDP capture ratifies
/// them.
pub(crate) struct PeerUdpCrypt {
    /// Our own user hash + public IP, both learned after this socket bound.
    own: SharedOwnIdentity,
    /// Our own crypt policy: `supports` is what arming means (we accept
    /// obfuscated datagrams), `requests` is aMule's
    /// `thePrefs::IsClientCryptLayerRequested()` — the half of the per-peer
    /// predicate that lets us obfuscate toward a merely-supporting peer.
    stance: CryptStance,
}

impl PeerUdpCrypt {
    /// Arm the layer over the shared self-facts and our own crypt stance.
    pub(crate) const fn new(own: SharedOwnIdentity, stance: CryptStance) -> Self {
        Self { own, stance }
    }

    /// Dual-path receive (ADR-0046), mirroring aMule `DecryptReceivedClient`
    /// and the sibling server-UDP and Kad-UDP surfaces: trial-decrypt
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

    /// The sender address an obfuscated datagram to `to` must be keyed on: our
    /// own external address **in the family the datagram will leave by**.
    ///
    /// The recipient decrypts with its own user hash plus the source address
    /// it sees, and what it sees is whichever half of our Family Pair carried
    /// the datagram (ADR-0085 binds `IPV6_V6ONLY`, so a v6 send is never
    /// reported as a mapped v4). Selecting the layout from the destination's
    /// family is therefore the same selection the receive path makes from the
    /// source's — ADR-0087's rule, read from the wire rather than probed.
    ///
    /// `None` — we hold no address in that family — is aMule's
    /// `theApp->GetPublicIP() != 0` gate generalised: a key derived from an
    /// address the peer will not see is a key it cannot reproduce, so the
    /// datagram goes plaintext instead.
    fn sender_address(&self, to: PeerEndpoint) -> Option<DatagramSenderAddress> {
        match to {
            PeerEndpoint::V4(_) => self
                .own
                .public_ip()
                .map(|ip| DatagramSenderAddress::V4(ip.octets())),
            PeerEndpoint::V6(_) => self
                .own
                .public_ipv6()
                .map(|ip| DatagramSenderAddress::V6(ip.octets())),
        }
    }

    /// Whether this datagram may be obfuscated — aMule's two gates, together:
    /// the per-peer predicate `ShouldReceiveCryptUDPPackets()` (`BaseClient.cpp`)
    /// that decides `bEncrypt` when the packet is queued, and the send-time
    /// public-IP check in `CMuleUDPSocket::SendControlData`.
    fn should_encrypt(&self, target: &PeerUdpCryptTarget, to: PeerEndpoint) -> bool {
        // `IsClientCryptLayerSupported()` is implied by being armed at all.
        target.stance.supports()
            && target.has_valid_hash()
            // `theApp->GetPublicIP() != 0` — this is the ed2k path (`bKad`
            // false), so our own address is required, not optional, and it
            // must be the one in the family this datagram leaves by: it is
            // the key's sender address, and obfuscating without it would
            // derive a key the peer cannot reproduce.
            && self.sender_address(to).is_some()
            // `thePrefs::IsClientCryptLayerRequested() || RequestsCryptLayer()`
            && (self.stance.requests() || target.stance.requests())
    }

    /// Send-encrypt one plaintext client-UDP datagram for `target`, keyed on the
    /// target's user hash + our own external address in `to`'s family (the
    /// `Ed2kUserHash` family — aMule keys the send on the recipient's user hash
    /// and its own IP). `nonce` injects the per-packet entropy (marker byte,
    /// 2-byte key seed, padding) the sans-I/O layer cannot draw itself.
    fn encrypt(
        &self,
        target: &PeerUdpCryptTarget,
        to: PeerEndpoint,
        payload: &[u8],
        nonce: &DatagramNonce,
    ) -> Option<Vec<u8>> {
        Some(encrypt_datagram_client(
            payload,
            &ClientEncryptKey::Ed2k {
                user_hash: &target.user_hash,
                sender: self.sender_address(to)?,
            },
            nonce,
        ))
    }
}

/// Send-gate one outbound client-UDP datagram (ADR-0046 send rule) at the
/// socket boundary, where aMule encrypts it: obfuscate only when the layer is
/// armed, the datagram carries a crypt target we hold a valid hash for, that
/// target advertises `SupportsCryptLayer`, our own public IP is known, and
/// either side requests obfuscation. Anything else rides as the plaintext it
/// already is — aMule sends plaintext whenever it holds no usable crypt key for
/// the recipient, and legacy peers depend on that.
///
/// `nonce` is drawn lazily so the OS entropy is touched only on a datagram that
/// is actually obfuscated.
pub(crate) fn encrypt_client_udp_send(
    crypt: Option<&PeerUdpCrypt>,
    send: ClientUdpSend,
    nonce: impl FnOnce() -> DatagramNonce,
) -> (PeerEndpoint, Vec<u8>) {
    let ClientUdpSend {
        to,
        datagram,
        crypt_target,
    } = send;
    let Some(crypt) = crypt else {
        return (to, datagram);
    };
    let Some(target) = crypt_target else {
        return (to, datagram);
    };
    if !crypt.should_encrypt(&target, to) {
        return (to, datagram);
    }
    match crypt.encrypt(&target, to, &datagram, &nonce()) {
        Some(obfuscated) => (to, obfuscated),
        // Reachable: `should_encrypt` and `encrypt` each read the shared
        // address cell once, and the server-session task clears it between
        // the two on a mid-session LowID re-assignment. Plaintext is then
        // exactly right — aMule's own send double-reads `GetPublicIP()` the
        // same way, and a datagram keyed on a cleared IP could not be
        // decrypted by the peer anyway. Never drop a reask reply over it.
        None => (to, datagram),
    }
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

/// Build the outbound datagram for a chosen **direct UDP callback** (ADR-0061
/// route 2): the callback chooser's [`DirectUdp`](crate::callback) verdict
/// carries the target's Kad UDP endpoint, and this frames the peer-UDP
/// `OP_DIRECTCALLBACKREQ` (`0x95`) — our TCP port, user hash, and connect-options
/// — addressed to it. aMule sends the direct callback to the target's **Kad** UDP
/// port, not its peer-UDP port. It rides the same client-UDP send half the serve
/// reply matrix uses ([`ServeDecision::SendClientUdp`](crate::serve)); the live
/// send lands with the firewalled-node front. **Plaintext** — aMule does not
/// obfuscate callback requests (ADR-0061), so it carries no crypt target and
/// [`encrypt_client_udp_send`] leaves it alone (the connect-options byte still
/// advertises our crypt stance so the target may obfuscate its dial-back).
/// The connect-options byte an outbound `0x95` carries (aMule
/// `CPrefs::GetMyConnectOptions(true, false)`, `Prefs.cpp:217`): four reserved
/// high bits, then direct-callback / crypt-required / crypt-requested /
/// crypt-supported.
///
/// aMule passes `callback = false` when it writes its own direct callback — the
/// byte tells the target how to dial *us* back, and the direct-callback bit is
/// about accepting a `0x95`, not about issuing one — so bit `0x08` is always
/// clear here and only our crypt stance lights up. A target reading it obfuscates
/// its dial-back exactly as far as we said we would follow.
pub(crate) fn direct_callback_connect_options(stance: CryptStance) -> u8 {
    u8::from(stance.requires()) << 2
        | u8::from(stance.requests()) << 1
        | u8::from(stance.supports())
}

/// The inverse read: the **requester's** crypt stance out of the connect-options
/// byte its `OP_DIRECTCALLBACKREQ` (`0x95`) carried — what aMule's
/// `CUpDownClient::SetConnectOptions` ([`BaseClient.cpp#L2987`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L2987))
/// does with the same byte before `TryToConnect` decides how to dial back.
///
/// It lives beside its forward twin on purpose: one module owns this byte's
/// layout, so the pack and the unpack cannot drift apart. The reserved and
/// direct-callback bits are ignored here — this read answers only "how far will
/// the requester follow us into obfuscation", and [`CryptStance::new`] collapses
/// a dishonest ladder (a byte claiming `requires` without `supports`) rather
/// than trusting a stranger's datagram to be internally consistent.
pub(crate) fn crypt_stance_from_connect_options(connect_options: u8) -> CryptStance {
    SourceCryptOptions::from_byte(connect_options).crypt_stance()
}

/// `target_kad_udp` stays an [`Ipv4Endpoint`] rather than a family-generic one:
/// the destination is the target's **Kad** UDP port, and Kad is IPv4-only end
/// to end (ADR-0087 changes no Kad opcode, version or contact format). A type
/// exactly as wide as its wire meaning — so the `V4` wrap below is the whole
/// truth, not a narrowing.
pub(crate) fn direct_callback_datagram(
    target_kad_udp: Ipv4Endpoint,
    our_tcp_port: u16,
    our_user_hash: &UserHash,
    connect_options: u8,
) -> ClientUdpSend {
    let datagram = DirectCallbackReq {
        our_tcp_port,
        our_user_hash: *our_user_hash,
        connect_options,
    }
    .encode_udp();
    ClientUdpSend::plaintext(PeerEndpoint::V4(target_kad_udp), datagram)
}

/// Send-gate unit tests: every leg of aMule's per-peer predicate (disarmed,
/// no target, unsupporting target, empty hash, nobody-requests, public-IP
/// precondition) with a decrypt round trip proving the key shape, and the
/// plaintext `0x95` direct-callback emit.
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::engine::{ClientUdpRoute, demux_protocol};
    use super::super::tests::{a_nonce, a_reask_ping, armed_requesting, own, supporting_target};
    use super::*;

    #[test]
    fn the_send_gate_encrypts_only_for_a_crypt_capable_target_and_round_trips() {
        let our_hash = UserHash::from_bytes([0x33; 16]);
        let our_ip = [192u8, 0, 2, 44];
        let sender = armed_requesting(our_hash, our_ip);
        let target_hash = UserHash::from_bytes([0x44; 16]);
        let to = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4665));
        let plain = a_reask_ping(0x55);
        let gate = |crypt: Option<&PeerUdpCrypt>, target: Option<PeerUdpCryptTarget>| {
            encrypt_client_udp_send(
                crypt,
                ClientUdpSend::to_peer(to, plain.clone(), target),
                a_nonce,
            )
            .1
        };

        // Disarmed (no `peer_crypt` policy): plaintext rides untouched, even
        // toward a crypt-capable target.
        assert_eq!(gate(None, Some(supporting_target(target_hash))), plain);
        // Armed but the datagram carries no target — a stranger's reask, a
        // callback: still plaintext (aMule sends plaintext when it holds no
        // crypt key for the recipient).
        assert_eq!(gate(Some(&sender), None), plain);
        // Armed, target known — but it never advertised `SupportsCryptLayer`:
        // obfuscating would be undecodable noise to it (aMule's
        // `SupportsCryptLayer()` leg).
        assert_eq!(
            gate(
                Some(&sender),
                Some(PeerUdpCryptTarget::new(
                    target_hash,
                    CryptStance::disabled()
                ))
            ),
            plain,
        );
        // Armed, target supports — but its hash is empty, so there is no key
        // material at all (aMule's `HasValidHash()` leg).
        assert_eq!(
            gate(
                Some(&sender),
                Some(supporting_target(UserHash::from_bytes([0; 16])))
            ),
            plain,
        );
        // Neither side *requests* obfuscation, only supports it: aMule stays
        // plaintext (`IsClientCryptLayerRequested() || RequestsCryptLayer()`).
        let merely_supporting =
            PeerUdpCrypt::new(own(our_hash, our_ip), CryptStance::new(true, false, false));
        assert_eq!(
            gate(
                Some(&merely_supporting),
                Some(supporting_target(target_hash))
            ),
            plain,
        );
        // …and a target that *requests* it flips that same gate on.
        assert_ne!(
            gate(
                Some(&merely_supporting),
                Some(PeerUdpCryptTarget::new(
                    target_hash,
                    CryptStance::new(true, true, false)
                ))
            ),
            plain,
        );

        // Armed with a crypt-capable target: the datagram is obfuscated (not the
        // plaintext, nor a plaintext-marker first byte), and the recipient —
        // holding the target hash, keyed on our sender IP — recovers exactly the
        // plaintext.
        let crypt = gate(Some(&sender), Some(supporting_target(target_hash)));
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
        // The public-IP prerequisite, as a gate: aMule refuses to obfuscate an ed2k
        // datagram before `theApp->GetPublicIP()` is known (`MuleUDPSocket.cpp`),
        // because that IP *is* part of the key the peer will derive. A LowID
        // login (or none) must therefore leave every datagram plaintext, and the
        // High-ID IDCHANGE must switch it on with no other change.
        let our_hash = UserHash::from_bytes([0x77; 16]);
        let own = SharedOwnIdentity::default();
        own.set_user_hash(our_hash);
        let crypt = PeerUdpCrypt::new(own.clone(), CryptStance::new(true, true, false));
        let target = supporting_target(UserHash::from_bytes([0x88; 16]));
        let to = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4665));
        let plain = a_reask_ping(0x55);
        let gate = || {
            encrypt_client_udp_send(
                Some(&crypt),
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

    #[test]
    fn the_direct_callback_emit_frames_0x95_plaintext_to_the_targets_kad_udp_port() {
        // The chooser's DirectUdp verdict → the outbound `0x95`. It addresses the
        // target's *Kad* UDP endpoint (not its peer-UDP port), carries our TCP
        // port + user hash + connect-options, and is plaintext (aMule does not
        // obfuscate callback requests): the first byte is the `0xC5` peer-UDP
        // protocol marker, never a crypt byte.
        let target_kad_udp = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4665);
        let our_hash = UserHash::from_bytes([0x5A; 16]);
        let send = direct_callback_datagram(target_kad_udp, 0x4CE2, &our_hash, 0x03);

        assert_eq!(send.to, PeerEndpoint::V4(target_kad_udp));
        let mut expected = vec![0xC5, 0x95, 0xE2, 0x4C];
        expected.extend_from_slice(&[0x5A; 16]);
        expected.push(0x03);
        assert_eq!(send.datagram, expected);
        assert_eq!(demux_protocol(&send.datagram), ClientUdpRoute::PeerUdp);
        // It carries no crypt target, so even a fully armed layer sends it in
        // the clear (aMule never obfuscates a callback request).
        assert_eq!(
            encrypt_client_udp_send(
                Some(&armed_requesting(our_hash, [203, 0, 113, 9])),
                send,
                a_nonce
            ),
            (PeerEndpoint::V4(target_kad_udp), expected),
        );
    }

    /// The send key's layout follows the family the datagram **leaves by**
    /// (ADR-0087), because that is the source address the recipient will see
    /// and key its own decrypt on. A dual-stack sender picks 35 bytes for a v6
    /// destination and 23 for a v4 one, off the destination alone; an
    /// IPv4-only sender holds no v6 to key with and sends plaintext rather
    /// than deriving a key the peer cannot reproduce.
    #[test]
    fn the_send_key_layout_follows_the_destinations_family() {
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
        let seal = |crypt: &PeerUdpCrypt, to| {
            encrypt_client_udp_send(
                Some(crypt),
                ClientUdpSend::to_peer(to, plain.clone(), Some(target)),
                a_nonce,
            )
            .1
        };

        let dual = armed_requesting_dual_stack(our_hash, our_v4, our_v6);
        let over_v4 = seal(&dual, to_v4);
        let over_v6 = seal(&dual, to_v6);
        assert_ne!(over_v4, plain, "the v4 destination arms the send");
        assert_ne!(over_v6, plain, "the v6 destination arms it too");
        assert_ne!(
            over_v4, over_v6,
            "one nonce, one target, one payload: only the key layout differs",
        );

        // And each is keyed on our address in that family — the recipient
        // recovers it with the layout its own socket reports and no other.
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

        // IPv4-only: nothing to key a v6 send with, so it leaves in the clear.
        let v4_only = armed_requesting(our_hash, our_v4);
        assert_ne!(seal(&v4_only, to_v4), plain);
        assert_eq!(
            seal(&v4_only, to_v6),
            plain,
            "no IPv6 of our own ⇒ plaintext, never a key the peer cannot reproduce",
        );
    }
}
