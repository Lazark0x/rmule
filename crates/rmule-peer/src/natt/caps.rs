//! The **CAPS** / **CAPS-ACK** body (`0xB2 0x02` / `0x03`) and the
//! connect-options byte it carries.
//!
//! CAPS is the second negotiation stage: the hello's `CT_MOD_MISCOPTIONS`
//! bits say what a peer's *build* can do, and a CAPS exchange says what this
//! *endpoint* will do right now — which is the answer that matters when a peer
//! ships QUIC code but has no QUIC runtime.
//!
//! The body is a fixed 54 bytes. Anything else is dropped: there is no length
//! field and no extension mechanism, so a "shorter is fine" reader would parse
//! whatever followed a truncated frame as a file hash.

use rmule_primitives::{FileHash, UserHash, WireReader, WireTruncated};
use thiserror::Error;

/// The CAPS body's leading magic as it appears on the wire: ASCII `EAQC`.
/// eMuleAI stores it as the `u32` `0x43514145` and writes it little-endian, so
/// the four wire bytes read as text — which is what a capture shows and what
/// this constant therefore is.
pub const CAPS_MAGIC: [u8; 4] = *b"EAQC";

/// The only CAPS body version the dialect defines. A frame carrying any other
/// value is dropped, not negotiated down — eMuleAI rejects it outright.
pub const CAPS_VERSION: u8 = 1;

/// The fixed CAPS / CAPS-ACK body width: magic 4, version 1, connect options
/// 1, sender hash 16, expected-recipient hash 16, file hash 16.
pub const CAPS_FRAME_LEN: usize = 4 + 1 + 1 + 16 + 16 + 16;

/// Which reliable transport a NAT-T tunnel raises over the punched path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NattTransport {
    /// BEP-29 uTP under `0xB2 0x00` — the floor every eMuleAI build speaks.
    Utp,
    /// QUIC under `0xB2 0x01` — preferred when both sides have a runtime.
    Quic,
}

/// The eD2k **connect-options byte** (`byCryptOptions`) read for its NAT-T
/// bits.
///
/// One byte, one namespace: the crypt ladder and the NAT-T transports share
/// it, which is the correction amule#1177 settled after the opposite was
/// published. The crypt bits are [`SourceCryptOptions`]'s and are read there;
/// this view adds only the two transport bits, and deliberately does **not**
/// live on that type.
///
/// Bit 7 is why. In a *source-exchange* record the same bit position means
/// "the source's user hash follows", not "NAT-T uTP" — aMule had to thread an
/// explicit `treat_bit7_as_nat_t` context parameter through five call sites to
/// keep the two apart. A CAPS frame is an unambiguous NAT-T surface, so the
/// reading is safe *here* and nowhere else; keeping it on a separate type is
/// how that stays true.
///
/// [`SourceCryptOptions`]: rmule_primitives::SourceCryptOptions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NattConnectOptions(u8);

/// `CONNECT_OPT_NATT_ENDPOINT_HINT` — a *request* ("buddy, answer me with the
/// target's live endpoint"), carried on the rendezvous path, never a
/// capability.
const OPT_ENDPOINT_HINT: u8 = 0x20;
/// `CONNECT_OPT_NAT_TRAVERSAL_QUIC`.
const OPT_QUIC: u8 = 0x40;
/// `CONNECT_OPT_NAT_TRAVERSAL_UTP`.
const OPT_UTP: u8 = 0x80;

impl NattConnectOptions {
    /// Wrap the byte as it arrived; every bit is preserved, including the
    /// crypt ladder's and the one value the dialect leaves unallocated
    /// (`0x10`).
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        Self(byte)
    }

    /// The byte, unchanged.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Bit 7 (`0x80`): the endpoint speaks uTP NAT-T.
    #[must_use]
    pub const fn supports_utp(self) -> bool {
        self.0 & OPT_UTP != 0
    }

    /// Bit 6 (`0x40`): the endpoint speaks QUIC NAT-T.
    #[must_use]
    pub const fn supports_quic(self) -> bool {
        self.0 & OPT_QUIC != 0
    }

    /// Bit 5 (`0x20`): the sender is asking a buddy for the target's live
    /// endpoint. rmule sets it in exactly one place — the embedded
    /// rendezvous emit form — because its *value* matches across the two trees that
    /// speak this dialect while its *meaning* does not.
    #[must_use]
    pub const fn requests_endpoint_hint(self) -> bool {
        self.0 & OPT_ENDPOINT_HINT != 0
    }

    /// Set bit 5 — done in exactly one place, the embedded rendezvous emit
    /// form, where eMuleAI sets it and where it is a request to the buddy.
    #[must_use]
    pub(super) const fn with_endpoint_hint_request(self) -> Self {
        Self(self.0 | OPT_ENDPOINT_HINT)
    }

    /// Set or clear the QUIC bit — the one mutation the CAPS send path needs,
    /// because a blacklisted endpoint must be told "no QUIC" for *this*
    /// exchange without the local capability changing.
    #[must_use]
    pub const fn with_quic(self, on: bool) -> Self {
        Self(if on {
            self.0 | OPT_QUIC
        } else {
            self.0 & !OPT_QUIC
        })
    }

    /// Fold rmule's crypt stance and NAT-T transports into the one byte the
    /// dialect carries. `quic` is the *effective* answer for this endpoint,
    /// not the build's capability: ADR-0091 keeps bit 4 of
    /// `CT_MOD_MISCOPTIONS` dark until a live QUIC handshake is proven, and
    /// this byte follows the same discipline.
    #[must_use]
    pub const fn advertise(crypt: u8, utp: bool, quic: bool) -> Self {
        let mut byte = crypt & 0x07;
        if utp {
            byte |= OPT_UTP;
        }
        if quic {
            byte |= OPT_QUIC;
        }
        Self(byte)
    }

    /// The transport this byte prefers, QUIC first, or `None` when it claims
    /// neither. `quic_allowed` is the caller's veto — a blacklisted endpoint
    /// or a build with no QUIC runtime — applied here so the preference order
    /// lives in exactly one place.
    #[must_use]
    pub const fn preferred_transport(self, quic_allowed: bool) -> Option<NattTransport> {
        if quic_allowed && self.supports_quic() {
            Some(NattTransport::Quic)
        } else if self.supports_utp() {
            Some(NattTransport::Utp)
        } else {
            None
        }
    }
}

/// A decoded CAPS or CAPS-ACK body. The two frames share this shape exactly;
/// which one arrived is the envelope's frame-type byte, and it decides only
/// whether an answer is owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapsFrame {
    /// The sender's connect-options byte, `0x40` already cleared if QUIC is
    /// blacklisted for the recipient's endpoint.
    pub connect_options: NattConnectOptions,
    /// The sender's own user hash.
    pub sender: UserHash,
    /// The user hash the sender expects the recipient to hold, or all-zero
    /// when it does not know one.
    pub expected_recipient: UserHash,
    /// The file this exchange is about (request file, else upload file, else
    /// all-zero).
    pub file_hash: FileHash,
}

/// Why a CAPS body could not be read.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CapsDecodeError {
    /// Short of the fixed 54 bytes. There is no length field, so a short body
    /// cannot be parsed as far as it goes without inventing field boundaries.
    #[error("CAPS body is {actual} bytes, short of the fixed {CAPS_FRAME_LEN}")]
    BodyWidth {
        /// Bytes present.
        actual: usize,
    },

    /// The leading four bytes were not `EAQC`.
    #[error("CAPS magic is 0x{}, not EAQC", super::hex_digits(.actual))]
    UnknownMagic {
        /// The four bytes that arrived.
        actual: [u8; 4],
    },

    /// A body version the dialect does not define.
    #[error("CAPS version is {actual}, not {CAPS_VERSION}")]
    UnsupportedVersion {
        /// The version byte that arrived.
        actual: u8,
    },
}

impl CapsFrame {
    /// Read a CAPS or CAPS-ACK body (the `0xB2` envelope already stripped).
    ///
    /// # Errors
    /// [`CapsDecodeError`] on the wrong width, magic or version — each a drop.
    pub fn decode(body: &[u8]) -> Result<Self, CapsDecodeError> {
        // eMuleAI checks only the floor (`ClientUDPSocket.cpp:690`): a longer
        // body is read by its fixed prefix.
        if body.len() < CAPS_FRAME_LEN {
            return Err(CapsDecodeError::BodyWidth { actual: body.len() });
        }
        let mut reader = WireReader::new(body);
        let width = |truncated: WireTruncated| CapsDecodeError::BodyWidth {
            actual: truncated.available,
        };
        let magic = reader.read_array::<4>("caps magic").map_err(width)?;
        if magic != CAPS_MAGIC {
            return Err(CapsDecodeError::UnknownMagic { actual: magic });
        }
        let version = reader.read_u8("caps version").map_err(width)?;
        if version != CAPS_VERSION {
            return Err(CapsDecodeError::UnsupportedVersion { actual: version });
        }
        Ok(Self {
            connect_options: NattConnectOptions::from_byte(
                reader.read_u8("connect options").map_err(width)?,
            ),
            sender: UserHash::from_bytes(reader.read_array("caps sender").map_err(width)?),
            expected_recipient: UserHash::from_bytes(
                reader.read_array("caps recipient").map_err(width)?,
            ),
            file_hash: FileHash::from_bytes(reader.read_array("caps file hash").map_err(width)?),
        })
    }

    /// The 54-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; CAPS_FRAME_LEN] {
        let mut body = [0u8; CAPS_FRAME_LEN];
        body[0..4].copy_from_slice(&CAPS_MAGIC);
        body[4] = CAPS_VERSION;
        body[5] = self.connect_options.as_byte();
        body[6..22].copy_from_slice(self.sender.as_bytes());
        body[22..38].copy_from_slice(self.expected_recipient.as_bytes());
        body[38..54].copy_from_slice(self.file_hash.as_bytes());
        body
    }

    /// Whether this frame claims to be addressed to `ours`.
    ///
    /// An all-zero expectation means "I do not know who you are" and is
    /// accepted — that is the ordinary first contact. A *non-null* expectation
    /// naming somebody else is refused: it is a frame meant for another node,
    /// and answering it would confirm an identity to whoever misrouted it.
    #[must_use]
    pub fn addressed_to(&self, ours: &UserHash) -> bool {
        is_null_hash(&self.expected_recipient) || &self.expected_recipient == ours
    }
}

/// Whether a user hash is the all-zero "unknown" sentinel. The dialect detects
/// absence by value, never by a presence flag, so this test is the presence
/// check on every hash slot it carries.
#[must_use]
pub fn is_null_hash(hash: &UserHash) -> bool {
    hash.as_bytes().iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(fill: u8) -> UserHash {
        UserHash::from_bytes([fill; UserHash::BYTE_LEN])
    }

    fn a_frame() -> CapsFrame {
        CapsFrame {
            connect_options: NattConnectOptions::from_byte(0x83),
            sender: hash(0xA1),
            expected_recipient: hash(0xB2),
            file_hash: FileHash::from_bytes([0xC3; 16]),
        }
    }

    /// The pinned layout, byte for byte: `EAQC`, version 1, the options byte,
    /// then three hashes in sender / expected-recipient / file order.
    #[test]
    fn the_caps_body_is_the_pinned_54_byte_layout() {
        let body = a_frame().encode();
        assert_eq!(body.len(), 54);
        assert_eq!(&body[0..4], b"EAQC");
        assert_eq!(body[4], 1);
        assert_eq!(body[5], 0x83);
        assert_eq!(&body[6..22], &[0xA1; 16]);
        assert_eq!(&body[22..38], &[0xB2; 16]);
        assert_eq!(&body[38..54], &[0xC3; 16]);
        assert_eq!(CapsFrame::decode(&body), Ok(a_frame()));
    }

    /// No length field means no partial parse: a body one byte short is not a
    /// CAPS frame with a missing tail, it is bytes whose field boundaries are
    /// unknown. A longer one is eMuleAI's to extend, and its fixed prefix is
    /// read as eMuleAI reads it.
    #[test]
    fn a_short_body_is_dropped_and_a_long_one_is_read_by_its_prefix() {
        let full = a_frame().encode();
        for len in [0usize, 53] {
            let mut body = full.to_vec();
            body.resize(len, 0);
            assert_eq!(
                CapsFrame::decode(&body),
                Err(CapsDecodeError::BodyWidth { actual: len })
            );
        }
        let mut longer = full.to_vec();
        longer.extend([0xEE; 4]);
        assert_eq!(CapsFrame::decode(&longer), Ok(a_frame()));
    }

    /// Magic and version are both hard gates — eMuleAI rejects either
    /// mismatch, and a version-tolerant reader would parse a future layout
    /// with today's offsets.
    #[test]
    fn the_magic_and_the_version_are_both_refused_when_they_differ() {
        let mut body = a_frame().encode();
        body[0] = b'X';
        assert_eq!(
            CapsFrame::decode(&body),
            Err(CapsDecodeError::UnknownMagic {
                actual: [b'X', b'A', b'Q', b'C']
            })
        );
        let mut body = a_frame().encode();
        body[4] = 2;
        assert_eq!(
            CapsFrame::decode(&body),
            Err(CapsDecodeError::UnsupportedVersion { actual: 2 })
        );
    }

    /// An all-zero expectation is first contact and is accepted; a non-null
    /// one naming somebody else is a frame for another node.
    #[test]
    fn a_null_expected_recipient_is_first_contact_and_a_wrong_one_is_not_ours() {
        let ours = hash(0x77);
        let mut frame = a_frame();
        assert!(!frame.addressed_to(&ours));
        frame.expected_recipient = ours;
        assert!(frame.addressed_to(&ours));
        frame.expected_recipient = UserHash::from_bytes([0; 16]);
        assert!(frame.addressed_to(&ours));
    }

    /// QUIC is preferred when both sides have it; uTP is the floor; the
    /// caller's veto (a blacklisted endpoint) demotes rather than disqualifies.
    #[test]
    fn quic_is_preferred_utp_is_the_floor_and_the_veto_only_demotes() {
        let both = NattConnectOptions::advertise(0x01, true, true);
        assert_eq!(both.as_byte(), 0xC1);
        assert_eq!(both.preferred_transport(true), Some(NattTransport::Quic));
        assert_eq!(both.preferred_transport(false), Some(NattTransport::Utp));

        let utp_only = NattConnectOptions::advertise(0, true, false);
        assert_eq!(utp_only.preferred_transport(true), Some(NattTransport::Utp));

        let neither = NattConnectOptions::advertise(0x07, false, false);
        assert_eq!(neither.preferred_transport(true), None);
        assert_eq!(neither.as_byte(), 0x07);
    }

    /// Clearing the QUIC bit for one endpoint must not touch the crypt ladder
    /// sharing the byte — the whole hazard of a one-byte namespace.
    #[test]
    fn clearing_quic_for_one_endpoint_leaves_the_crypt_ladder_alone() {
        let options = NattConnectOptions::advertise(0x03, true, true);
        assert_eq!(options.with_quic(false).as_byte(), 0x83);
        assert_eq!(options.with_quic(true).as_byte(), 0xC3);
        assert!(!options.with_quic(false).supports_quic());
        assert!(options.with_quic(false).supports_utp());
    }
}
