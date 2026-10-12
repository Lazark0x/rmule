//! Secure User Identification client-to-client packets (ADR-0041).
//!
//! `OP_SECIDENTSTATE 0x87`, `OP_PUBLICKEY 0x85`, `OP_SIGNATURE 0x86` under
//! `OP_EMULEPROT`, pinned from aMule `BaseClient.cpp` / `ClientCredits.*` @
//! `377ec8d9` and the eMule spec §4.2 (`docs/reference/notes/secure-ident.md`).
//! These are the wire codecs only; the challenge/response state machine and the
//! signing-input assembly live in `session.rs`, and the RSA crypto in
//! `rmule_primitives::secure_ident`. The public key and signature bodies are
//! carried opaquely here, exactly like AICH `recovery_data`.

use rmule_primitives::{Packet, WireReader, WireTruncated};
use thiserror::Error;

use crate::opcode::PeerOpcode;

/// Why a Secure User Identification packet could not be read.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SuiDecodeError {
    /// The state announcement was not its fixed five bytes.
    #[error("OP_SECIDENTSTATE payload is {actual} bytes, not the exact {expected} expected")]
    WrongStateLen {
        /// The size an announcement is.
        expected: usize,
        /// The size that arrived.
        actual: usize,
    },
    /// The state byte names no state this crate knows.
    #[error("OP_SECIDENTSTATE has unknown state byte 0x{value:02X}")]
    UnknownState {
        /// The byte that arrived.
        value: u8,
    },
    /// A length-prefixed body carried no prefix at all.
    #[error("{opcode} payload is empty, missing its length prefix")]
    MissingLengthPrefix {
        /// Which packet, for the message.
        opcode: &'static str,
    },
    /// The declared body length and the bytes present disagree.
    #[error("{opcode} declares {declared} body bytes but carries {actual}")]
    LengthMismatch {
        /// Which packet, for the message.
        opcode: &'static str,
        /// The length declared.
        declared: usize,
        /// The bytes that followed it.
        actual: usize,
    },
}

/// V2 `byIPUsed` kinds, pinned from aMule `ClientCredits.h`. The
/// kind names whose address the signer folded into the signature: a Low-ID
/// signer has no usable public address and signs the *remote* client's IP
/// (`CRYPT_CIP_REMOTECLIENT`); a High-ID signer signs its *own* Client ID
/// (`CRYPT_CIP_LOCALCLIENT`); `CRYPT_CIP_NONECLIENT` signs the placeholder 0.
pub const CRYPT_CIP_REMOTECLIENT: u8 = 10;
/// The signer is High-ID and folded its own Client ID into the signature.
pub const CRYPT_CIP_LOCALCLIENT: u8 = 20;
/// Neither applies: the placeholder 0 was signed.
pub const CRYPT_CIP_NONECLIENT: u8 = 30;

/// What the sender of `OP_SECIDENTSTATE` needs from the recipient. Pinned from
/// aMule `BaseClient.cpp::SendSecIdentStatePacket`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecIdentState {
    /// `IS_UNAVAILABLE 0` — nothing needed right now.
    Unavailable,
    /// `IS_SIGNATURENEEDED 1` — the sender already holds the recipient's public
    /// key and needs only a fresh signature.
    SignatureNeeded,
    /// `IS_KEYANDSIGNEEDED 2` — the sender needs both the public key and a
    /// signature.
    KeyAndSignNeeded,
}

impl SecIdentState {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Unavailable => 0,
            Self::SignatureNeeded => 1,
            Self::KeyAndSignNeeded => 2,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unavailable),
            1 => Some(Self::SignatureNeeded),
            2 => Some(Self::KeyAndSignNeeded),
            _ => None,
        }
    }
}

/// `OP_SECIDENTSTATE 0x87` — `[state:u8][challenge:u32-le]`. Announces what the
/// sender needs and carries a fresh challenge the recipient must fold into the
/// bytes it signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecIdentStatePacket {
    /// What the sender needs next.
    pub state: SecIdentState,
    /// A fresh challenge the recipient must fold into the bytes it signs, which is what stops a captured signature being replayed.
    pub challenge: u32,
}

impl SecIdentStatePacket {
    const WIRE_LEN: usize = 5;

    /// Read the announcement, whose size is fixed.
    pub fn decode_packet(packet: &Packet) -> Result<Self, SuiDecodeError> {
        let payload = packet.payload();
        if payload.len() != Self::WIRE_LEN {
            return Err(SuiDecodeError::WrongStateLen {
                expected: Self::WIRE_LEN,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        let short = |truncated: WireTruncated| SuiDecodeError::WrongStateLen {
            expected: Self::WIRE_LEN,
            actual: truncated.available,
        };
        let raw = reader.read_u8("state").map_err(short)?;
        let state =
            SecIdentState::from_u8(raw).ok_or(SuiDecodeError::UnknownState { value: raw })?;
        let challenge = reader.read_u32_le("challenge").map_err(short)?;
        Ok(Self { state, challenge })
    }

    #[must_use]
    /// Frame the announcement.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(Self::WIRE_LEN);
        payload.push(self.state.as_u8());
        payload.extend_from_slice(&self.challenge.to_le_bytes());
        Packet::new(
            PeerOpcode::SecIdentState.protocol(),
            PeerOpcode::SecIdentState.as_u8(),
            payload,
        )
    }
}

/// `OP_PUBLICKEY 0x85` — `[len:u8][der_public_key:len]`. The DER bytes are
/// carried opaquely; `rmule_primitives::SecureIdentPublicKey::from_der` parses
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyPacket {
    /// The key, DER-encoded and carried opaquely; parsing it belongs to the verifier.
    pub der: Vec<u8>,
}

impl PublicKeyPacket {
    /// Read the key off its length prefix.
    pub fn decode_packet(packet: &Packet) -> Result<Self, SuiDecodeError> {
        Ok(Self {
            der: decode_length_prefixed(packet.payload(), "OP_PUBLICKEY")?,
        })
    }

    #[must_use]
    /// Frame the key.
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PeerOpcode::PublicKey.protocol(),
            PeerOpcode::PublicKey.as_u8(),
            encode_length_prefixed(&self.der),
        )
    }
}

/// `OP_SIGNATURE 0x86` — `[len:u8][signature:len]` (V1), with V2 appending the
/// `byIPUsed` kind byte: `[len:u8][signature:len][ip_kind:u8]` (pinned from aMule
/// `SendSignaturePacket`). `ip_kind` is carried as the raw
/// wire byte — the session interprets the known `CRYPT_CIP_*` values and fails
/// verification (non-terminally) on an unknown one, so a future kind never
/// closes the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignaturePacket {
    /// The signature bytes.
    pub signature: Vec<u8>,
    /// `None` for a V1 signature; `Some(byIPUsed)` for V2.
    pub ip_kind: Option<u8>,
}

impl SignaturePacket {
    /// Read a signature, taking a trailing byte as the V2 `byIPUsed` kind.
    pub fn decode_packet(packet: &Packet) -> Result<Self, SuiDecodeError> {
        let mut reader = WireReader::new(packet.payload());
        let len = usize::from(reader.read_u8("signature length").map_err(|_| {
            SuiDecodeError::MissingLengthPrefix {
                opcode: "OP_SIGNATURE",
            }
        })?);
        let body_len = reader.remaining();
        let mismatch = || SuiDecodeError::LengthMismatch {
            opcode: "OP_SIGNATURE",
            declared: len,
            actual: body_len,
        };
        let signature = reader
            .take(len, "signature")
            .map_err(|_| mismatch())?
            .to_vec();
        // V1 carries exactly `len` signature bytes; V2 exactly one more — the
        // trailing `byIPUsed` kind. Anything else is malformed.
        let ip_kind = match reader.remaining() {
            0 => None,
            1 => Some(reader.read_u8("ip kind").map_err(|_| mismatch())?),
            _ => return Err(mismatch()),
        };
        Ok(Self { signature, ip_kind })
    }

    #[must_use]
    /// Frame the signature, appending the kind byte when this is a V2 one.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = encode_length_prefixed(&self.signature);
        if let Some(kind) = self.ip_kind {
            payload.push(kind);
        }
        Packet::new(
            PeerOpcode::Signature.protocol(),
            PeerOpcode::Signature.as_u8(),
            payload,
        )
    }
}

fn decode_length_prefixed(payload: &[u8], opcode: &'static str) -> Result<Vec<u8>, SuiDecodeError> {
    let mut reader = WireReader::new(payload);
    let len = usize::from(
        reader
            .read_u8("length prefix")
            .map_err(|_| SuiDecodeError::MissingLengthPrefix { opcode })?,
    );
    let actual = reader.remaining();
    if len != actual {
        return Err(SuiDecodeError::LengthMismatch {
            opcode,
            declared: len,
            actual,
        });
    }
    Ok(reader.remaining_bytes().to_vec())
}

fn encode_length_prefixed(body: &[u8]) -> Vec<u8> {
    // eMule's length prefix is a single byte: a public key fits MAXPUBKEYSIZE
    // (80) and a signature is one RSA block, so our own bodies always fit u8.
    let len = u8::try_from(body.len()).expect("SUI body fits a u8 length prefix");
    let mut payload = Vec::with_capacity(1 + body.len());
    payload.push(len);
    payload.extend_from_slice(body);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secident_state_round_trips_every_state() {
        for state in [
            SecIdentState::Unavailable,
            SecIdentState::SignatureNeeded,
            SecIdentState::KeyAndSignNeeded,
        ] {
            let packet = SecIdentStatePacket {
                state,
                challenge: 0xDEAD_BEEF,
            };
            let wire = packet.encode_packet();
            assert_eq!(wire.payload().len(), SecIdentStatePacket::WIRE_LEN);
            assert_eq!(SecIdentStatePacket::decode_packet(&wire).unwrap(), packet);
        }
    }

    #[test]
    fn secident_state_challenge_is_little_endian() {
        let packet = SecIdentStatePacket {
            state: SecIdentState::KeyAndSignNeeded,
            challenge: 0x0403_0201,
        };
        // [state=2][01 02 03 04] — challenge is LE per aMule WriteUInt32.
        assert_eq!(
            packet.encode_packet().payload(),
            &[2, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn secident_state_rejects_unknown_state_and_wrong_len() {
        let unknown = Packet::new(
            PeerOpcode::SecIdentState.protocol(),
            PeerOpcode::SecIdentState.as_u8(),
            vec![9, 0, 0, 0, 0],
        );
        assert!(matches!(
            SecIdentStatePacket::decode_packet(&unknown),
            Err(SuiDecodeError::UnknownState { value: 9 })
        ));

        let short = Packet::new(
            PeerOpcode::SecIdentState.protocol(),
            PeerOpcode::SecIdentState.as_u8(),
            vec![0, 0, 0],
        );
        assert!(matches!(
            SecIdentStatePacket::decode_packet(&short),
            Err(SuiDecodeError::WrongStateLen { .. })
        ));
    }

    #[test]
    fn public_key_round_trips_opaque_der() {
        let packet = PublicKeyPacket {
            der: vec![0x30, 0x59, 0xAB, 0xCD], // a stand-in DER blob
        };
        let decoded = PublicKeyPacket::decode_packet(&packet.encode_packet()).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn signature_round_trips_opaque_bytes() {
        let packet = SignaturePacket {
            signature: vec![0x11; 48], // a 384-bit RSA signature is 48 bytes
            ip_kind: None,
        };
        let decoded = SignaturePacket::decode_packet(&packet.encode_packet()).unwrap();
        assert_eq!(decoded, packet);
    }

    /// V2: `OP_SIGNATURE` carries a trailing `byIPUsed` kind byte
    /// after the length-prefixed signature — `[len][signature:len][ip_kind]`,
    /// pinned from aMule `SendSignaturePacket`.
    #[test]
    fn v2_signature_round_trips_its_ip_kind_trailer() {
        let packet = SignaturePacket {
            signature: vec![0x22; 48],
            ip_kind: Some(20), // CRYPT_CIP_LOCALCLIENT
        };
        let wire = packet.encode_packet();
        assert_eq!(wire.payload().len(), 1 + 48 + 1);
        assert_eq!(wire.payload()[49], 20, "kind byte trails the signature");
        assert_eq!(SignaturePacket::decode_packet(&wire).unwrap(), packet);
    }

    #[test]
    fn v2_signature_fixture_decodes_signature_then_kind() {
        // [len=3][AA BB CC][kind=10 CRYPT_CIP_REMOTECLIENT]
        let wire = Packet::new(
            PeerOpcode::Signature.protocol(),
            PeerOpcode::Signature.as_u8(),
            vec![3, 0xAA, 0xBB, 0xCC, 10],
        );
        assert_eq!(
            SignaturePacket::decode_packet(&wire).unwrap(),
            SignaturePacket {
                signature: vec![0xAA, 0xBB, 0xCC],
                ip_kind: Some(10),
            }
        );
    }

    #[test]
    fn signature_rejects_more_than_one_trailing_byte() {
        // Two bytes after the declared signature: neither V1 nor V2 shaped.
        let wire = Packet::new(
            PeerOpcode::Signature.protocol(),
            PeerOpcode::Signature.as_u8(),
            vec![2, 0xAA, 0xBB, 10, 10],
        );
        assert!(matches!(
            SignaturePacket::decode_packet(&wire),
            Err(SuiDecodeError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn length_prefixed_bodies_reject_a_mismatched_prefix() {
        // Declared length 9, but only 2 body bytes follow.
        let corrupt = Packet::new(
            PeerOpcode::PublicKey.protocol(),
            PeerOpcode::PublicKey.as_u8(),
            vec![9, 0xAA, 0xBB],
        );
        assert!(matches!(
            PublicKeyPacket::decode_packet(&corrupt),
            Err(SuiDecodeError::LengthMismatch {
                declared: 9,
                actual: 2,
                ..
            })
        ));

        let empty = Packet::new(
            PeerOpcode::Signature.protocol(),
            PeerOpcode::Signature.as_u8(),
            Vec::new(),
        );
        assert!(matches!(
            SignaturePacket::decode_packet(&empty),
            Err(SuiDecodeError::MissingLengthPrefix { .. })
        ));
    }
}
