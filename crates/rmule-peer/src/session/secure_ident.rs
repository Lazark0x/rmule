//! Secure User Identification (ADR-0041): the bidirectional
//! challenge/response that proves a peer owns the user hash it claims, so
//! credit survives an impostor.
//!
//! Both halves progress independently — each handler fires once its own
//! preconditions are met, so packet order does not matter. A failed
//! exchange costs the peer its secured credit, never the connection.

use rmule_primitives::SecureIdentPublicKey;

use super::{PeerEvent, PeerSession, SecureIdentFailure, State};
use crate::capability::{MiscOptions1, MiscOptions2, ModMiscOptions};
use crate::hello::PeerHelloBody;
use crate::identity::PeerIdentity;
use crate::secure_ident::{
    CRYPT_CIP_LOCALCLIENT, CRYPT_CIP_NONECLIENT, CRYPT_CIP_REMOTECLIENT, PublicKeyPacket,
    SecIdentState, SecIdentStatePacket, SignaturePacket,
};

/// Per-connection Secure User Identification exchange state (ADR-0041). Fields
/// fill in as the bidirectional exchange progresses, in whatever order the
/// packets arrive; `try_send_our_signature` and `try_verify_peer` fire once
/// their preconditions are met, so the handlers are order-independent.
#[derive(Default)]
pub(super) struct SuiState {
    /// The challenge we sent the peer (from our `SecureIdentConfig`); the peer
    /// signs it and we verify the result with the peer's key.
    our_challenge: Option<u32>,
    /// The challenge the peer sent us; we sign it with our key.
    peer_challenge: Option<u32>,
    /// The peer's public key DER (`OP_PUBLICKEY`), validated on receipt. We
    /// verify the peer's signature with it and hand it to core to bind.
    peer_public_key_der: Option<Vec<u8>>,
    /// The peer's signature (`OP_SIGNATURE`), awaiting verification.
    peer_signature: Option<Vec<u8>>,
    /// The V2 `byIPUsed` kind byte the peer's signature carried, or `None` for
    /// a V1-shaped signature. Names whose address to fold into the
    /// verification input.
    peer_signature_ip_kind: Option<u8>,
    /// The peer's state was `SignatureNeeded` or `KeyAndSignNeeded`, so it wants
    /// us to sign its challenge.
    peer_wants_signature: bool,
    /// We have already sent our signature (send exactly once).
    our_signature_sent: bool,
    /// We have already verified the peer and emitted `PeerIdentityVerified`.
    verified: bool,
}

impl PeerSession {
    /// Role-neutral identify step shared by the inbound `OP_HELLO` and
    /// outbound `OP_HELLOANSWER` paths: project the peer's hello body to a
    /// `PeerIdentity`, enter the session, and emit `PeerIdentified`. The
    /// caller has already folded the hello into `peer_software`, on top of
    /// what an `OP_EMULEINFO` said before it — which only a dialed peer can
    /// send before its answer; the capabilities a legacy block named stand
    /// when the hello names none.
    pub(super) fn identify_peer(&mut self, body: &PeerHelloBody) {
        let mut identity =
            PeerIdentity::from_hello_body(body).with_software(self.peer_software.software());
        self.peer_hello_named_reask = identity.client_udp_reask().is_some();
        if let Some((udp_port, udp_version)) = self.peer_legacy_reask {
            identity = identity.with_reask_contact_if_unnamed(udp_port, udp_version);
        }
        self.peer_user_hash = Some(body.user_hash);
        self.peer_misc_options = MiscOptions1::from_tags(&body.tags).or(self.peer_misc_options);
        self.peer_misc_options2 = MiscOptions2::from_tags(&body.tags);
        self.peer_mod_misc = ModMiscOptions::from_tags(&body.tags);
        let identity = identity.with_source_exchange(self.source_exchange_support());
        self.state = State::Identified;
        self.core.push_event(PeerEvent::PeerIdentified { identity });
        self.maybe_start_secure_ident();
    }

    /// After the hello exchange, kick off Secure User Identification when both
    /// we (`ctx.secure_ident`) and the peer advertised it (ADR-0041). We always
    /// send `KeyAndSignNeeded`: the sans-I/O session is per-connection and does
    /// not remember peer keys across connections, so it re-asks each time.
    pub(super) fn maybe_start_secure_ident(&mut self) {
        if self.sui.our_challenge.is_some() {
            return;
        }
        let Some(config) = self.secure_ident.as_ref() else {
            return;
        };
        let peer_supports = self
            .peer_misc_options
            .is_some_and(|opts| opts.secure_identification_version() > 0);
        if !peer_supports {
            return;
        }
        let challenge = config.challenge;
        self.sui.our_challenge = Some(challenge);
        self.write_packet(
            SecIdentStatePacket {
                state: SecIdentState::KeyAndSignNeeded,
                challenge,
            }
            .encode_packet(),
        );
    }

    /// Inbound `OP_SECIDENTSTATE`: the peer told us what it needs and gave us a
    /// challenge to sign. Only reached once `Identified` (guarded in dispatch).
    pub(super) fn on_secident_state(&mut self, packet: SecIdentStatePacket) {
        self.sui.peer_challenge = Some(packet.challenge);
        match packet.state {
            SecIdentState::Unavailable => {}
            SecIdentState::SignatureNeeded => self.sui.peer_wants_signature = true,
            SecIdentState::KeyAndSignNeeded => {
                self.sui.peer_wants_signature = true;
                if let Some(config) = self.secure_ident.as_ref() {
                    let der = config.key.public_key_der();
                    self.write_packet(PublicKeyPacket { der }.encode_packet());
                }
            }
        }
        self.try_send_our_signature();
    }

    /// Inbound `OP_PUBLICKEY`: validate and store the peer's key, then try to
    /// make progress on signing (we sign the peer's key) and verifying (we
    /// verify with the peer's key).
    pub(super) fn on_public_key(&mut self, packet: PublicKeyPacket) {
        if SecureIdentPublicKey::from_der(&packet.der).is_err() {
            self.emit_sui_failed(SecureIdentFailure::BadPublicKey);
            return;
        }
        self.sui.peer_public_key_der = Some(packet.der);
        self.try_send_our_signature();
        self.try_verify_peer();
    }

    /// Inbound `OP_SIGNATURE`: the peer's proof over the challenge we sent.
    pub(super) fn on_signature(&mut self, packet: SignaturePacket) {
        self.sui.peer_signature = Some(packet.signature);
        self.sui.peer_signature_ip_kind = packet.ip_kind;
        self.try_verify_peer();
    }

    /// Whether Secure User Identification runs as **V2** on this connection.
    /// The SecIdent nibble is a *bitmask* (bit 0 = V1, bit 1 = V2; real
    /// eMule/aMule advertise 3), and eMule's selection rule — pinned from
    /// `SendSignaturePacket` at the 2026-07-06 capture — is
    /// `bUseV2 = (peer_nibble & 1) == 0`: V2 only for a peer that does *not*
    /// claim V1. eMule↔eMule therefore runs V1; so does rmule↔aMule.
    ///
    /// A **native-IPv6 session selects V1 outright** (ADR-0087). V2's signed
    /// message ends in a 4-byte `ChallengeIP`, and signed bytes must match
    /// exactly — there is no skippable widening of it, and a 16-byte variant
    /// would need its own capability bit and its own proposal. V1 signs no
    /// address at all, which is the whole reason it still works here; and
    /// since every implementation advertises 3 and then picks V1 anyway, this
    /// is the branch the network actually runs.
    fn sui_v2_negotiated(&self) -> bool {
        if self.peer.family() == rmule_primitives::AddressFamily::V6 {
            return false;
        }
        self.peer_misc_options.is_some_and(|opts| {
            let nibble = opts.secure_identification_version();
            (nibble & 0b10) != 0 && (nibble & 0b01) == 0
        })
    }

    /// The V2 address material *we* sign (pinned from aMule
    /// `SendSignaturePacket`): High-ID → our own Client ID with
    /// `CRYPT_CIP_LOCALCLIENT`; Low-ID (no usable public address) → the remote
    /// peer's IP with `CRYPT_CIP_REMOTECLIENT` — never a bogus own address.
    fn v2_challenge_ip_and_kind(&self) -> (u32, u8) {
        if self.ctx.client_id.is_high_id() {
            (self.ctx.client_id.as_u32(), CRYPT_CIP_LOCALCLIENT)
        } else {
            match self.peer.as_v4() {
                Some(peer) => (u32::from_le_bytes(peer.ip.octets()), CRYPT_CIP_REMOTECLIENT),
                // Unreachable while `sui_v2_negotiated` refuses V2 on a
                // native-IPv6 session (ADR-0087); kept because the *verify*
                // side still has to read this kind from a peer that sends it.
                None => (0, CRYPT_CIP_NONECLIENT),
            }
        }
    }

    /// The address to fold into V2 *verification*, per the kind byte the
    /// signer sent: kind 20 = the signer signed its own address (use the IP we
    /// observe for it); kind 10 = the signer signed *ours* (our High-ID Client
    /// ID is our public address; a Low-ID verifier knows none and uses 0,
    /// which correctly fails); kind 30 = the placeholder 0. An unknown kind
    /// has no defined input — `None` fails the verification non-terminally;
    /// so does kind 20 from an IPv6 peer, whose 32-bit address we never observe.
    fn v2_verify_ip(&self, ip_kind: u8) -> Option<u32> {
        match ip_kind {
            CRYPT_CIP_LOCALCLIENT => self
                .peer
                .as_v4()
                .map(|peer| u32::from_le_bytes(peer.ip.octets())),
            CRYPT_CIP_REMOTECLIENT => Some(if self.ctx.client_id.is_high_id() {
                self.ctx.client_id.as_u32()
            } else {
                0
            }),
            CRYPT_CIP_NONECLIENT => Some(0),
            _ => None,
        }
    }

    /// Sign once we hold the peer's public key (the verifier's key) and the
    /// peer's challenge. We sign `[peer public key ‖ peer challenge (LE)]` with
    /// our private key — pinned from aMule `CreateSignature` (ADR-0041). On a
    /// V2 connection the input gains `‖ ip (u32-LE) ‖ kind (u8)`
    /// and the packet carries the kind byte; a V1-only peer gets the V1 shape
    /// (lower-common-version).
    fn try_send_our_signature(&mut self) {
        if self.sui.our_signature_sent || !self.sui.peer_wants_signature {
            return;
        }
        let v2 = self
            .sui_v2_negotiated()
            .then(|| self.v2_challenge_ip_and_kind());
        let signature = {
            let (Some(config), Some(peer_der), Some(challenge)) = (
                self.secure_ident.as_ref(),
                self.sui.peer_public_key_der.as_ref(),
                self.sui.peer_challenge,
            ) else {
                return;
            };
            let mut signing_input = peer_der.clone();
            signing_input.extend_from_slice(&challenge.to_le_bytes());
            if let Some((ip, kind)) = v2 {
                signing_input.extend_from_slice(&ip.to_le_bytes());
                signing_input.push(kind);
            }
            config.key.sign(&signing_input)
        };
        self.sui.our_signature_sent = true;
        self.write_packet(
            SignaturePacket {
                signature,
                ip_kind: v2.map(|(_, kind)| kind),
            }
            .encode_packet(),
        );
    }

    /// Verify the peer once we hold its signature, its public key, and the
    /// challenge we sent. The peer signed `[our public key ‖ our challenge
    /// (LE)]`, so we verify that with the peer's key (ADR-0041). A V2-shaped
    /// signature folds in the address its kind byte names — an IP
    /// mismatch (or an unknown kind) simply fails, non-terminally.
    fn try_verify_peer(&mut self) {
        if self.sui.verified {
            return;
        }
        let verified = {
            let (Some(config), Some(peer_der), Some(our_challenge), Some(signature)) = (
                self.secure_ident.as_ref(),
                self.sui.peer_public_key_der.as_ref(),
                self.sui.our_challenge,
                self.sui.peer_signature.as_ref(),
            ) else {
                return;
            };
            let verify_ip = match self.sui.peer_signature_ip_kind {
                None => None, // V1 shape: no address in the input
                Some(kind) => match self.v2_verify_ip(kind) {
                    Some(ip) => Some((ip, kind)),
                    None => {
                        // Unknown kind: no defined input to verify against.
                        self.emit_sui_failed(SecureIdentFailure::BadSignature);
                        return;
                    }
                },
            };
            let peer_key = SecureIdentPublicKey::from_der(peer_der)
                .expect("peer public key was validated when OP_PUBLICKEY arrived");
            let mut verify_input = config.key.public_key_der();
            verify_input.extend_from_slice(&our_challenge.to_le_bytes());
            if let Some((ip, kind)) = verify_ip {
                verify_input.extend_from_slice(&ip.to_le_bytes());
                verify_input.push(kind);
            }
            peer_key.verify(&verify_input, signature)
        };
        if verified {
            self.sui.verified = true;
            let public_key = self
                .sui
                .peer_public_key_der
                .clone()
                .expect("peer public key present in the verified branch");
            let user_hash = self
                .peer_user_hash
                .expect("peer identified before a signature can be verified");
            self.core.push_event(PeerEvent::PeerIdentityVerified {
                user_hash,
                public_key,
            });
        } else {
            self.emit_sui_failed(SecureIdentFailure::BadSignature);
        }
    }

    fn emit_sui_failed(&mut self, reason: SecureIdentFailure) {
        self.core
            .push_event(PeerEvent::PeerSecureIdentFailed { reason });
    }
}
