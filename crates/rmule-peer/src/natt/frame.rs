//! The `0xB2` frame codec: `[0xB2][frame type][payload]`, five types, no
//! opcode and no length prefix.
//!
//! eMuleAI's own comment on the receive switch is the contract — *"Note: here
//! we dont have opcodes, just \[uint8 - Prot\]\[n bytes - data\]"* — and the
//! minimum length is two. An unknown frame type is **ignored**, never answered:
//! the type space is the dialect's only extension point and a stranger's byte
//! must not become a reply.

use rmule_primitives::{UserHash, WireReader, WireTruncated};
use thiserror::Error;

use super::caps::CapsFrame;

/// `OP_UDPRESERVEDPROT2` (`0xB2`) — the protocol byte the whole NAT-T
/// transport rides, reserved (and passed through unparsed) by every
/// eMule-family client since 2007.
pub const NATT_PROTOCOL: u8 = 0xB2;

/// The one-byte frame-type namespace behind [`NATT_PROTOCOL`]. Five of 256
/// values are used; an unrecognised one is dropped, not answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NattFrameType {
    /// `0x00` — a raw BEP-29 uTP packet.
    Utp,
    /// `0x01` — a raw QUIC datagram.
    Quic,
    /// `0x02` — a **CAPS** capability probe.
    Caps,
    /// `0x03` — a **CAPS-ACK**, the answer to a probe. Never itself answered.
    CapsAck,
    /// `0xFF` — the **KEY** frame: the sender's own user hash, so the
    /// recipient can obfuscate its side of the transport.
    Key,
}

impl NattFrameType {
    /// The wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Utp => 0x00,
            Self::Quic => 0x01,
            Self::Caps => 0x02,
            Self::CapsAck => 0x03,
            Self::Key => 0xFF,
        }
    }

    /// Read a frame-type byte, or `None` for one this dialect does not define.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Utp),
            0x01 => Some(Self::Quic),
            0x02 => Some(Self::Caps),
            0x03 => Some(Self::CapsAck),
            0xFF => Some(Self::Key),
            _ => None,
        }
    }
}

/// Classify a datagram that already carries the `0xB2` protocol byte, without
/// decoding its payload — the demux front's first cut, cheap enough to run on
/// every datagram before anything is copied.
#[must_use]
pub fn natt_frame_type(datagram: &[u8]) -> Option<NattFrameType> {
    match datagram {
        [NATT_PROTOCOL, frame_type, ..] => NattFrameType::from_byte(*frame_type),
        _ => None,
    }
}

/// One decoded `0xB2` frame. The transport payloads borrow the datagram rather
/// than copying it: a uTP or QUIC frame is handed straight to its engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NattFrame<'a> {
    /// A BEP-29 uTP packet, the `0xB2 0x00` prefix stripped.
    Utp(&'a [u8]),
    /// A QUIC datagram, the `0xB2 0x01` prefix stripped.
    Quic(&'a [u8]),
    /// A capability probe. Answered with exactly one [`NattFrame::CapsAck`].
    Caps(CapsFrame),
    /// A capability answer. Never answered — that would be a probe loop.
    CapsAck(CapsFrame),
    /// The sender's own user hash, keying obfuscation toward it.
    Key(UserHash),
}

/// Why a `0xB2` datagram could not be read as a frame.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum NattFrameDecodeError {
    /// Fewer than the two bytes `[protocol][frame type]` an envelope is.
    #[error("NAT-T datagram is {actual} bytes, shorter than the 2-byte envelope")]
    TooShort {
        /// Bytes present.
        actual: usize,
    },

    /// The leading byte was not `0xB2`, so this is not a NAT-T datagram at all.
    #[error("NAT-T datagram protocol byte is 0x{actual:02X}, not 0xB2")]
    WrongProtocol {
        /// The byte that arrived.
        actual: u8,
    },

    /// A frame type the dialect does not define. The caller drops it; eMuleAI
    /// logs "unknown NAT-T frame type" and does the same.
    #[error("unknown NAT-T frame type 0x{actual:02X}")]
    UnknownFrameType {
        /// The byte that arrived.
        actual: u8,
    },

    /// A KEY frame whose body is shorter than the sixteen bytes a user hash
    /// is — eMuleAI's "Key packet too short". A longer body is read by its
    /// first sixteen bytes, as eMuleAI reads it.
    #[error("NAT-T KEY body is {actual} bytes, short of the 16 a user hash is")]
    KeyBodyWidth {
        /// Bytes present after the envelope.
        actual: usize,
    },

    /// A CAPS or CAPS-ACK body that did not decode.
    #[error("NAT-T CAPS body: {0}")]
    Caps(#[from] super::caps::CapsDecodeError),
}

impl<'a> NattFrame<'a> {
    /// Read one datagram received under the `0xB2` protocol byte.
    ///
    /// # Errors
    /// [`NattFrameDecodeError`] — every variant is a *drop*, never a reply:
    /// the dialect has no failure frame (its own maintainers call that a gap),
    /// so a malformed NAT-T datagram is silence by design, not by omission.
    pub fn decode(datagram: &'a [u8]) -> Result<Self, NattFrameDecodeError> {
        let too_short = |truncated: WireTruncated| NattFrameDecodeError::TooShort {
            actual: truncated.available,
        };
        let mut reader = WireReader::new(datagram);
        let protocol = reader.read_u8("protocol").map_err(too_short)?;
        if protocol != NATT_PROTOCOL {
            return Err(NattFrameDecodeError::WrongProtocol { actual: protocol });
        }
        let frame_type = reader.read_u8("frame type").map_err(too_short)?;
        let body = reader.remaining_bytes();
        match NattFrameType::from_byte(frame_type) {
            Some(NattFrameType::Utp) => Ok(Self::Utp(body)),
            Some(NattFrameType::Quic) => Ok(Self::Quic(body)),
            Some(NattFrameType::Caps) => Ok(Self::Caps(CapsFrame::decode(body)?)),
            Some(NattFrameType::CapsAck) => Ok(Self::CapsAck(CapsFrame::decode(body)?)),
            // eMuleAI refuses only a short body and reads the hash from the
            // front of a longer one (`ClientUDPSocket.cpp:1002-1003`).
            Some(NattFrameType::Key) => {
                let bytes: [u8; UserHash::BYTE_LEN] = body
                    .get(..UserHash::BYTE_LEN)
                    .and_then(|prefix| prefix.try_into().ok())
                    .ok_or(NattFrameDecodeError::KeyBodyWidth { actual: body.len() })?;
                Ok(Self::Key(UserHash::from_bytes(bytes)))
            }
            None => Err(NattFrameDecodeError::UnknownFrameType { actual: frame_type }),
        }
    }

    /// This frame's type byte.
    #[must_use]
    pub const fn frame_type(&self) -> NattFrameType {
        match self {
            Self::Utp(_) => NattFrameType::Utp,
            Self::Quic(_) => NattFrameType::Quic,
            Self::Caps(_) => NattFrameType::Caps,
            Self::CapsAck(_) => NattFrameType::CapsAck,
            Self::Key(_) => NattFrameType::Key,
        }
    }

    /// The datagram this frame goes out as, envelope included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut datagram = vec![NATT_PROTOCOL, self.frame_type().as_byte()];
        match self {
            Self::Utp(payload) | Self::Quic(payload) => datagram.extend_from_slice(payload),
            Self::Caps(caps) | Self::CapsAck(caps) => datagram.extend_from_slice(&caps.encode()),
            Self::Key(hash) => datagram.extend_from_slice(hash.as_bytes()),
        }
        datagram
    }
}

/// Frame one transport payload for the wire without building a borrow — the
/// send-side shape the uTP and QUIC engines use, where the payload is already
/// an owned buffer the engine just produced.
#[must_use]
pub fn frame_transport(frame_type: NattFrameType, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(2 + payload.len());
    datagram.push(NATT_PROTOCOL);
    datagram.push(frame_type.as_byte());
    datagram.extend_from_slice(payload);
    datagram
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::natt::caps::NattConnectOptions;

    fn hash(fill: u8) -> UserHash {
        UserHash::from_bytes([fill; UserHash::BYTE_LEN])
    }

    /// The envelope is two bytes and the payload is untouched — no length
    /// prefix, no opcode, the uTP packet handed to the engine byte for byte.
    #[test]
    fn a_utp_frame_is_the_two_byte_envelope_and_the_raw_bep29_packet() {
        // `0x41` = (ST_SYN << 4) | version 1 — the first byte of a uTP SYN.
        let packet = [0x41u8, 0x00, 0x12, 0x34, 0xDE, 0xAD];
        let datagram = frame_transport(NattFrameType::Utp, &packet);
        assert_eq!(datagram[..2], [0xB2, 0x00]);
        assert_eq!(&datagram[2..], &packet);
        assert_eq!(NattFrame::decode(&datagram), Ok(NattFrame::Utp(&packet)));
    }

    /// A QUIC long header (`0x80` bit set) rides `0x01`, likewise unmodified:
    /// eMuleAI hands ngtcp2's output through with no transformation at all.
    #[test]
    fn a_quic_frame_is_the_envelope_and_the_raw_datagram() {
        let packet = [0xC0u8, 0x00, 0x00, 0x00, 0x01, 0x08];
        let datagram = frame_transport(NattFrameType::Quic, &packet);
        assert_eq!(datagram[..2], [0xB2, 0x01]);
        assert_eq!(NattFrame::decode(&datagram), Ok(NattFrame::Quic(&packet)));
    }

    /// The KEY frame is the sender's own sixteen-byte user hash and nothing
    /// else — the whole key-distribution mechanism of the dialect.
    #[test]
    fn the_key_frame_is_exactly_the_senders_user_hash() {
        let datagram = NattFrame::Key(hash(0x5A)).encode();
        assert_eq!(datagram.len(), 2 + UserHash::BYTE_LEN);
        assert_eq!(datagram[..2], [0xB2, 0xFF]);
        assert_eq!(NattFrame::decode(&datagram), Ok(NattFrame::Key(hash(0x5A))));
    }

    /// A short body is eMuleAI's "Key packet too short"; a longer one is read
    /// by its first sixteen bytes, as eMuleAI reads it, so a later eMuleAI that
    /// extends the frame still teaches us its hash.
    #[test]
    fn a_short_key_frame_is_refused_and_a_long_one_is_read_by_its_prefix() {
        for body_len in [0usize, 15] {
            let mut datagram = vec![0xB2, 0xFF];
            datagram.extend(std::iter::repeat_n(0xAAu8, body_len));
            assert_eq!(
                NattFrame::decode(&datagram),
                Err(NattFrameDecodeError::KeyBodyWidth { actual: body_len })
            );
        }
        let mut datagram = NattFrame::Key(hash(0x5A)).encode();
        datagram.push(0x01);
        assert_eq!(NattFrame::decode(&datagram), Ok(NattFrame::Key(hash(0x5A))));
    }

    /// Two bytes is the floor: one byte carries no frame type, so there is no
    /// frame to classify.
    #[test]
    fn a_datagram_shorter_than_the_envelope_is_not_a_frame() {
        assert_eq!(
            NattFrame::decode(&[]),
            Err(NattFrameDecodeError::TooShort { actual: 0 })
        );
        assert_eq!(
            NattFrame::decode(&[0xB2]),
            Err(NattFrameDecodeError::TooShort { actual: 1 })
        );
        assert_eq!(natt_frame_type(&[0xB2]), None);
    }

    /// An undefined frame type is dropped rather than answered. The dialect's
    /// type space is its only extension point, so tomorrow's `0x04` must not
    /// draw a reply from today's rmule.
    #[test]
    fn an_undefined_frame_type_is_dropped() {
        for byte in [0x04u8, 0x10, 0x7F, 0xFE] {
            assert_eq!(NattFrameType::from_byte(byte), None);
            assert_eq!(
                NattFrame::decode(&[0xB2, byte, 0x00]),
                Err(NattFrameDecodeError::UnknownFrameType { actual: byte })
            );
        }
    }

    /// A datagram on another protocol byte is not this decoder's — the
    /// classification error is explicit so a mis-wired demux is a typed
    /// failure rather than a silently mangled uTP packet.
    #[test]
    fn another_protocol_byte_is_refused_rather_than_reinterpreted() {
        assert_eq!(
            NattFrame::decode(&[0xC5, 0xA1]),
            Err(NattFrameDecodeError::WrongProtocol { actual: 0xC5 })
        );
        assert_eq!(natt_frame_type(&[0xC5, 0x00]), None);
    }

    /// CAPS and CAPS-ACK share one body and differ only in the type byte —
    /// which is exactly how a receiver knows not to answer the second.
    #[test]
    fn caps_and_caps_ack_share_a_body_and_differ_only_in_the_type_byte() {
        let body = CapsFrame {
            connect_options: NattConnectOptions::from_byte(0x81),
            sender: hash(0x11),
            expected_recipient: hash(0x22),
            file_hash: rmule_primitives::FileHash::from_bytes([0x33; 16]),
        };
        let probe = NattFrame::Caps(body).encode();
        let answer = NattFrame::CapsAck(body).encode();
        assert_eq!(probe[1], 0x02);
        assert_eq!(answer[1], 0x03);
        assert_eq!(probe[2..], answer[2..]);
        assert_eq!(NattFrame::decode(&probe), Ok(NattFrame::Caps(body)));
        assert_eq!(NattFrame::decode(&answer), Ok(NattFrame::CapsAck(body)));
    }
}
