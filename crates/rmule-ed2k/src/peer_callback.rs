//! `OP_CALLBACKREQUESTED` (0x35) and its IPv6 counterpart
//! `OP_CALLBACKREQUESTED_IPV6` (0x26): the server telling this node to dial a
//! reachable requester, because this node is the firewalled one.
//!
//! The two live together because they are one role in two families, and the
//! difference between them is the whole of the dialect's server half in
//! miniature: `0x35` packs the requester into 32 bits, `0x26` carries the
//! sixteen address bytes and the same little-endian port, and nothing else
//! about the exchange changes.
//!
//! The crypt extension (ADR-0061) widens `0x35` with the requester's crypt
//! stance and user hash; rmule threads both into the dial's provenance so the
//! obfuscation decision is made from what the server actually said. `0x26`
//! defines no such extension, so bytes past its eighteen are ignored rather
//! than guessed at.

use std::net::Ipv4Addr;

use rmule_primitives::{
    Ipv4Endpoint, Ipv6Endpoint, Packet, PacketProtocol, PeerCrypt, SourceCryptOptions, UserHash,
};

use crate::{Ed2kError, Opcode, Result};

const MIN_PAYLOAD_LEN: usize = 6;
/// The crypt extension adds a connect-options byte and a 16-byte user hash after
/// the base IP+port, so a `size >= 23` datagram carries it (aMule
/// `ServerSocket.cpp` `OP_CALLBACKREQUESTED`).
const CRYPT_PAYLOAD_LEN: usize = MIN_PAYLOAD_LEN + 1 + UserHash::BYTE_LEN;

/// The `OP_CALLBACKREQUESTED` (`0x35`) crypt extension (ADR-0061): the
/// High-ID requester's crypt stance and user hash, present in the `>= 23`-byte
/// form. rmule threads it into the ADR-0046/0042 dial provenance so the
/// firewalled-node dial-back can obfuscate the connect-back. The three low
/// bits of `connect_options` are the same crypt-stance layout
/// [`SourceCryptOptions`] models on the source-exchange surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerCallbackCrypt {
    /// The requester's connect options (crypt-stance bits 0-2). `supports_crypt`
    /// gates whether we may obfuscate the dial-back to it.
    pub connect_options: SourceCryptOptions,
    /// The requester's user hash — the key basis for an obfuscated dial-back.
    pub user_hash: UserHash,
}

impl PeerCallbackCrypt {
    /// This extension's crypt side, ready for
    /// [`PeerCrypt::outbound`](rmule_primitives::PeerCrypt::outbound)
    /// (ADR-0049): the connect-options stance and the requester's hash.
    #[must_use]
    pub const fn peer_crypt(self) -> PeerCrypt {
        PeerCrypt::new(self.connect_options.crypt_stance(), Some(self.user_hash))
    }
}

/// Decoded body of an `OP_CALLBACKREQUESTED` (`0x35`) server-pushed packet.
/// Carries the dialable High ID peer endpoint that asked the server to relay an
/// invitation back to us (we are Low ID). The field is exactly as wide as the
/// wire: `0x35` packs an IPv4 address (the IPv6 counterpart is the separate
/// `0x26`, ADR-0087); the session's event wraps it as a peer.
///
/// The minimum 6-byte form (IPv4 + TCP port) carries only the endpoint. The
/// `>= 23`-byte crypt extension (`crypt_options` + `user_hash`) is consumed into
/// [`PeerCallbackCrypt`] (ADR-0061) rather than discarded — it is the dial
/// provenance an obfuscated dial-back keys on; see
/// `docs/reference/notes/ed2k-welcome-packets.md` for the citation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerCallback {
    /// Where to dial the peer that asked for the callback.
    pub peer: Ipv4Endpoint,
    /// The crypt extension when the server relayed the `>= 23`-byte form, else
    /// `None` (a legacy 6-byte callback — dialed back plaintext).
    pub crypt: Option<PeerCallbackCrypt>,
}

impl PeerCallback {
    /// A base (6-byte form) callback for `peer`, no crypt provenance.
    #[must_use]
    pub const fn new(peer: Ipv4Endpoint) -> Self {
        Self { peer, crypt: None }
    }

    /// This callback with the crypt extension's dial provenance attached — the
    /// `>= 23`-byte form.
    #[must_use]
    pub const fn with_crypt(peer: Ipv4Endpoint, crypt: PeerCallbackCrypt) -> Self {
        Self {
            peer,
            crypt: Some(crypt),
        }
    }

    /// The crypt side of the dial-back this callback carries: the
    /// extension's stance and hash when present (ADR-0061), or
    /// [`PeerCrypt::unknown`](rmule_primitives::PeerCrypt::unknown) for a
    /// legacy (6-byte) callback — the pair
    /// [`PeerCrypt::outbound`](rmule_primitives::PeerCrypt::outbound)
    /// (ADR-0049) meets with ours to decide whether the dial-back may be
    /// obfuscated.
    #[must_use]
    pub const fn peer_crypt(&self) -> PeerCrypt {
        match self.crypt {
            Some(crypt) => crypt.peer_crypt(),
            None => PeerCrypt::unknown(),
        }
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::PeerCallback.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_CALLBACKREQUESTED",
            });
        }
        let payload = packet.payload();
        if payload.len() < MIN_PAYLOAD_LEN {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_CALLBACKREQUESTED payload shorter than 6 bytes",
            });
        }
        let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
        let port = u16::from_le_bytes([payload[4], payload[5]]);
        // The `>= 23`-byte form carries the crypt extension: a connect-options
        // byte then the 16-byte user hash. A size between 6 and 23 is the base
        // form with trailing bytes we ignore (aMule reads exactly its fields).
        let crypt = (payload.len() >= CRYPT_PAYLOAD_LEN).then(|| {
            let connect_options = SourceCryptOptions::from_byte(payload[MIN_PAYLOAD_LEN]);
            let mut hash = [0u8; UserHash::BYTE_LEN];
            hash.copy_from_slice(&payload[MIN_PAYLOAD_LEN + 1..CRYPT_PAYLOAD_LEN]);
            PeerCallbackCrypt {
                connect_options,
                user_hash: UserHash::from_bytes(hash),
            }
        });
        Ok(Self {
            peer: Ipv4Endpoint::new(ip, port),
            crypt,
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let endpoint = self.peer;
        let mut payload = Vec::with_capacity(match self.crypt {
            Some(_) => CRYPT_PAYLOAD_LEN,
            None => MIN_PAYLOAD_LEN,
        });
        payload.extend_from_slice(&endpoint.ip.octets());
        payload.extend_from_slice(&endpoint.port.to_le_bytes());
        if let Some(crypt) = self.crypt {
            payload.push(crypt.connect_options.as_byte());
            payload.extend_from_slice(crypt.user_hash.as_bytes());
        }
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::PeerCallback.as_u8(),
            payload,
        )
    }
}

/// Decoded body of `OP_CALLBACKREQUESTED_IPV6` (`0x26`, server→client, TCP) —
/// the IPv6 counterpart of [`PeerCallback`] (ADR-0087 §4.5).
///
/// ```text
/// uint8[16]  requester's public IPv6, network order
/// uint16     requester's TCP port, LITTLE-endian
/// ```
///
/// Minimum payload eighteen bytes. There is no crypt extension: `0x35`'s
/// `>= 23`-byte form has no counterpart here in any implementation or in the
/// spec, so trailing bytes are ignored rather than decoded into a shape no
/// oracle has produced — the dial-back to a v6 requester is plaintext until
/// something on the wire says otherwise.
///
/// Any sixteen bytes decode. The address gate is not the codec's: core judges
/// the requester of either opcode by the Reserved Range check with the server
/// as its Informant (ADR-0085), which only the session knows.
///
/// **Evidence: `single-oracle`, and un-captured.** Only eNode-go is known to
/// emit this opcode; the other server implementing the dialect never mentions
/// it, so a firewalled IPv6 peer on that server may have no callback path at
/// all. Building the eighteen-byte consume anyway costs nothing and is what
/// keeps an IPv6-only rmule able to take the one server's callback — the
/// evidence table is the honest form of the gate, not a build-time one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerCallbackIpv6 {
    /// Where to dial the peer that asked for the callback.
    pub peer: Ipv6Endpoint,
}

impl PeerCallbackIpv6 {
    /// The smallest body this opcode can carry: sixteen address bytes plus the
    /// two-byte port.
    const MIN_PAYLOAD_LEN: usize = Ipv6Endpoint::ADDR_WIRE_LEN + 2;

    /// A callback naming the IPv6 requester to dial back.
    #[must_use]
    pub const fn new(peer: Ipv6Endpoint) -> Self {
        Self { peer }
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::PeerCallbackIpv6.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_CALLBACKREQUESTED_IPV6",
            });
        }
        let payload = packet.payload();
        if payload.len() < Self::MIN_PAYLOAD_LEN {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_CALLBACKREQUESTED_IPV6 payload shorter than 18 bytes",
            });
        }
        let address: [u8; Ipv6Endpoint::ADDR_WIRE_LEN] = payload[..Ipv6Endpoint::ADDR_WIRE_LEN]
            .try_into()
            .expect("validated 16-byte address");
        let port = u16::from_le_bytes([
            payload[Ipv6Endpoint::ADDR_WIRE_LEN],
            payload[Ipv6Endpoint::ADDR_WIRE_LEN + 1],
        ]);
        Ok(Self {
            peer: Ipv6Endpoint::from_addr_bytes(address, port),
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(Self::MIN_PAYLOAD_LEN);
        payload.extend_from_slice(&self.peer.addr_bytes());
        payload.extend_from_slice(&self.peer.port.to_le_bytes());
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::PeerCallbackIpv6.as_u8(),
            payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::{CryptStance, OutboundCrypt};

    /// Our own stance for these tests: supports and requests obfuscation
    /// (matching the "someone has to ask" half of `PeerCrypt::outbound`), so
    /// the assertions exercise the peer's support bit as the deciding factor.
    const OURS: CryptStance = CryptStance::new(true, true, false);

    fn peer() -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4662)
    }

    #[test]
    fn base_form_round_trips_with_no_crypt_provenance() {
        let cb = PeerCallback::new(peer());
        let packet = cb.encode_packet();
        assert_eq!(packet.opcode(), 0x35);
        // 6-byte body: IP (LE-agnostic octets) + TCP port little-endian.
        assert_eq!(packet.payload(), &[198, 51, 100, 7, 0x36, 0x12]);
        assert_eq!(PeerCallback::decode_packet(&packet).unwrap(), cb);
        // No extension ⇒ unknown crypt stance ⇒ never an obfuscated dial-back.
        assert_eq!(cb.peer_crypt(), PeerCrypt::unknown());
        assert_eq!(cb.peer_crypt().outbound(OURS), OutboundCrypt::Plaintext);
    }

    #[test]
    fn crypt_extension_is_consumed_and_gates_the_obfuscation_dial_hash() {
        // The `>= 23`-byte form: base 6 + connect-options 0x01 (supports crypt)
        // + a 16-byte user hash. The provenance rides through decode, and the
        // supported-crypt bit unlocks the obfuscated dial-back key under
        // `PeerCrypt::outbound` (ADR-0049) — the rule now decides, not a bare
        // support-bit check.
        let hash = UserHash::from_bytes([0xC7; UserHash::BYTE_LEN]);
        let cb = PeerCallback::with_crypt(
            peer(),
            PeerCallbackCrypt {
                connect_options: SourceCryptOptions::from_byte(0x01),
                user_hash: hash,
            },
        );
        let packet = cb.encode_packet();
        assert_eq!(packet.payload().len(), 23);
        assert_eq!(&packet.payload()[..6], &[198, 51, 100, 7, 0x36, 0x12]);
        assert_eq!(packet.payload()[6], 0x01);
        assert_eq!(&packet.payload()[7..23], &[0xC7; 16]);
        assert_eq!(PeerCallback::decode_packet(&packet).unwrap(), cb);
        assert_eq!(
            cb.peer_crypt().outbound(OURS),
            OutboundCrypt::Obfuscated { toward: hash }
        );
    }

    #[test]
    fn a_non_crypt_extension_carries_the_hash_but_yields_no_dial_key() {
        // Extension present but crypt-support bit clear (0x00): the requester
        // gave a hash yet does not support obfuscation, so the dial-back stays
        // plaintext — `PeerCrypt::outbound`'s support gate, never a bogus key.
        let cb = PeerCallback::with_crypt(
            peer(),
            PeerCallbackCrypt {
                connect_options: SourceCryptOptions::from_byte(0x00),
                user_hash: UserHash::from_bytes([0x09; UserHash::BYTE_LEN]),
            },
        );
        assert_eq!(
            PeerCallback::decode_packet(&cb.encode_packet()).unwrap(),
            cb
        );
        assert_eq!(cb.peer_crypt().outbound(OURS), OutboundCrypt::Plaintext);
    }

    #[test]
    fn a_size_between_the_base_and_crypt_forms_stays_base() {
        // aMule reads exactly its fields: a 10-byte body is the base callback
        // with 4 trailing bytes ignored, not a malformed crypt extension.
        let mut payload = vec![198, 51, 100, 7, 0x36, 0x12];
        payload.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]);
        let packet = Packet::new(PacketProtocol::Edonkey, 0x35, payload);
        let decoded = PeerCallback::decode_packet(&packet).unwrap();
        assert_eq!(decoded, PeerCallback::new(peer()));
        assert_eq!(decoded.crypt, None);
    }

    #[test]
    fn rejects_a_too_short_body_and_the_wrong_opcode() {
        let short = Packet::new(PacketProtocol::Edonkey, 0x35, vec![1, 2, 3]);
        assert!(PeerCallback::decode_packet(&short).is_err());
        let wrong = Packet::new(PacketProtocol::Edonkey, 0x1C, vec![1, 2, 3, 4, 5, 6]);
        assert!(PeerCallback::decode_packet(&wrong).is_err());
    }

    /// ADR-0087 §4.5's layout: sixteen network-order address bytes then the
    /// **little-endian** port, eighteen bytes minimum. The port's endianness is
    /// the one thing a reader can get wrong silently, so it is asserted
    /// against a value whose two bytes differ.
    ///
    /// Evidence: **`single-oracle` (eNode-go) and un-captured** — these are the
    /// spec's bytes, not a capture's.
    #[test]
    fn the_ipv6_callback_is_sixteen_address_bytes_then_a_little_endian_port() {
        let address: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
        let callback = PeerCallbackIpv6::new(Ipv6Endpoint::new(address, 4662));
        let packet = callback.encode_packet();
        assert_eq!(packet.opcode(), 0x26);
        assert_eq!(packet.payload().len(), 18);
        assert_eq!(&packet.payload()[..16], &address.octets());
        assert_eq!(&packet.payload()[16..], &[0x36, 0x12]);
        assert_eq!(PeerCallbackIpv6::decode_packet(&packet).unwrap(), callback);
    }

    #[test]
    fn an_ipv6_callback_ignores_a_tail_and_refuses_a_short_body() {
        let address: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
        let mut payload = address.octets().to_vec();
        payload.extend_from_slice(&4662u16.to_le_bytes());
        // No crypt extension is defined for `0x26`, so a tail is read as
        // nothing rather than guessed into a shape no oracle has produced.
        payload.extend_from_slice(&[0x01, 0x02, 0x03]);
        let decoded =
            PeerCallbackIpv6::decode_packet(&Packet::new(PacketProtocol::Edonkey, 0x26, payload))
                .unwrap();
        assert_eq!(decoded.peer, Ipv6Endpoint::new(address, 4662));

        let short = Packet::new(PacketProtocol::Edonkey, 0x26, vec![0; 17]);
        assert!(PeerCallbackIpv6::decode_packet(&short).is_err());
        // `0x35`'s bytes are not this opcode's, even at a legal length.
        let wrong = Packet::new(PacketProtocol::Edonkey, 0x35, vec![0; 18]);
        assert!(PeerCallbackIpv6::decode_packet(&wrong).is_err());
    }
}
