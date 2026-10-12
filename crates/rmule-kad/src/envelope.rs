//! Kad UDP datagram envelope codec.
//!
//! The eMule Kad UDP envelope is byte 0 protocol, byte 1 opcode, and the
//! remaining bytes are the opcode-specific payload. It is deliberately not the
//! eD2k TCP/server frame (`rmule_primitives::Packet`), which carries a
//! four-byte length field between protocol and opcode.

/// Kad UDP protocol byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadProtocol {
    /// Plain Kad, protocol byte `0xE4`.
    Plain,
    /// Packed (zlib-compressed payload) Kad, protocol byte `0xE5`.
    Packed,
}

impl KadProtocol {
    const PLAIN_BYTE: u8 = 0xE4;
    const PACKED_BYTE: u8 = 0xE5;

    /// The Kad protocol a datagram's leading byte declares, or `None` when it
    /// declares none — how a shared UDP socket's demux tells Kad from the
    /// other protocols on it.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            Self::PLAIN_BYTE => Some(Self::Plain),
            Self::PACKED_BYTE => Some(Self::Packed),
            _ => None,
        }
    }

    /// The protocol's leading byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Plain => Self::PLAIN_BYTE,
            Self::Packed => Self::PACKED_BYTE,
        }
    }
}

/// A decoded plain Kad UDP envelope.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KadEnvelope {
    protocol: KadProtocol,
    opcode: u8,
    payload: Vec<u8>,
}

impl KadEnvelope {
    /// Build a plain (`0xE4`) Kad envelope for outbound encoding.
    ///
    /// Packed (`0xE5`) envelopes are intentionally not constructible: outbound
    /// packing needs a zlib policy and compatibility trade-off that is not
    /// decided yet.
    #[must_use]
    pub const fn plain(opcode: u8, payload: Vec<u8>) -> Self {
        Self {
            protocol: KadProtocol::Plain,
            opcode,
            payload,
        }
    }

    /// Which Kad framing the datagram arrived in.
    #[must_use]
    pub const fn protocol(&self) -> KadProtocol {
        self.protocol
    }

    /// The opcode byte, uninterpreted.
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        self.opcode
    }

    /// The payload, already inflated for a packed datagram — so a reader
    /// never has to know which framing carried it.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Serialize a plain Kad envelope as protocol byte, opcode, then payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.payload.len());
        bytes.push(self.protocol.byte());
        bytes.push(self.opcode);
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

/// A successfully recognized Kad datagram.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KadDecoded {
    /// A plain `0xE4` envelope ready for opcode dispatch.
    Plain(KadEnvelope),
    /// A packed `0xE5` datagram, already inflated to its logical plain packet.
    ///
    /// The carried envelope reports [`KadProtocol::Plain`]: aMule's receive
    /// path inflates the payload and restores the logical protocol byte to
    /// `0xE4` before dispatch, so the packed transport is invisible past this
    /// point. The variant records only that the transport was packed.
    Packed(KadEnvelope),
}

/// Upper bound for an inflated packed-Kad payload, in bytes.
///
/// aMule sizes its receive-side inflation buffer as `packetLen * 10 + 300`,
/// which scales with attacker-controlled input. rmule instead uses this fixed
/// cap: a packed datagram is a compressed form of a plain datagram, and a plain
/// Kad datagram can never exceed one UDP payload (< 64 KiB), so any stream
/// inflating past this bound cannot be a legitimate packet. The trade-off is
/// documented in `docs/reference/notes/kad-packet-framing.md`.
pub const MAX_INFLATED_KAD_PAYLOAD: usize = 64 * 1024;

/// Reasons a Kad datagram is malformed and cannot be recognized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadEnvelopeDecodeError {
    /// Fewer than the two bytes (protocol + opcode) a Kad datagram requires.
    Truncated {
        /// How many bytes actually arrived.
        len: usize,
    },
    /// First byte is neither plain `0xE4` nor packed `0xE5` Kad.
    UnsupportedProtocol(u8),
    /// A packed `0xE5` payload is not one exact, well-formed zlib stream:
    /// empty, corrupt, truncated, or followed by trailing bytes.
    PackedPayloadInflate,
    /// A packed `0xE5` payload inflates beyond [`MAX_INFLATED_KAD_PAYLOAD`].
    PackedPayloadTooLarge {
        /// The inflation ceiling the stream exceeded.
        cap: usize,
    },
}

/// Decode exactly one Kad UDP datagram from `bytes`.
///
/// Plain `0xE4` datagrams become [`KadDecoded::Plain`]. Packed `0xE5` datagrams
/// have their payload inflated (bounded by [`MAX_INFLATED_KAD_PAYLOAD`]) and
/// become [`KadDecoded::Packed`] carrying the logical plain envelope.
/// Truncation, unsupported protocol bytes, and malformed or oversized packed
/// payloads are the [`Err`] outcomes.
pub fn decode_exact(bytes: &[u8]) -> Result<KadDecoded, KadEnvelopeDecodeError> {
    let [protocol, opcode, payload @ ..] = bytes else {
        return Err(KadEnvelopeDecodeError::Truncated { len: bytes.len() });
    };

    match KadProtocol::from_byte(*protocol) {
        Some(KadProtocol::Plain) => Ok(KadDecoded::Plain(KadEnvelope::plain(
            *opcode,
            payload.to_vec(),
        ))),
        Some(KadProtocol::Packed) => {
            let inflated = inflate_bounded(payload, MAX_INFLATED_KAD_PAYLOAD)?;
            Ok(KadDecoded::Packed(KadEnvelope::plain(*opcode, inflated)))
        }
        None => Err(KadEnvelopeDecodeError::UnsupportedProtocol(*protocol)),
    }
}

/// Inflate one exact zlib stream into at most `cap` bytes.
///
/// The output buffer is sized `cap + 1` so "inflates to exactly `cap`"
/// (stream ends, fits) and "wants more than `cap`" (fills the sentinel byte)
/// are distinguishable in a single decompress call.
fn inflate_bounded(input: &[u8], cap: usize) -> Result<Vec<u8>, KadEnvelopeDecodeError> {
    use flate2::{Decompress, FlushDecompress, Status};

    let mut decompress = Decompress::new(true);
    let mut out = vec![0u8; cap + 1];
    match decompress.decompress(input, &mut out, FlushDecompress::Finish) {
        Ok(Status::StreamEnd) => {
            let produced = usize::try_from(decompress.total_out())
                .map_err(|_| KadEnvelopeDecodeError::PackedPayloadTooLarge { cap })?;
            if produced > cap {
                return Err(KadEnvelopeDecodeError::PackedPayloadTooLarge { cap });
            }
            let consumed = usize::try_from(decompress.total_in())
                .map_err(|_| KadEnvelopeDecodeError::PackedPayloadInflate)?;
            if consumed < input.len() {
                // Trailing bytes after the stream: not one exact zlib stream.
                return Err(KadEnvelopeDecodeError::PackedPayloadInflate);
            }
            out.truncate(produced);
            Ok(out)
        }
        // The stream did not end: either it wants more output than the cap
        // allows, or the input ran out / made no progress (truncated stream).
        Ok(Status::Ok | Status::BufError) => {
            if decompress.total_out() > cap as u64 {
                Err(KadEnvelopeDecodeError::PackedPayloadTooLarge { cap })
            } else {
                Err(KadEnvelopeDecodeError::PackedPayloadInflate)
            }
        }
        Err(_) => Err(KadEnvelopeDecodeError::PackedPayloadInflate),
    }
}
