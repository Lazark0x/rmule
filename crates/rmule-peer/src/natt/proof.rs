//! The QUIC **application proof** — the first 37 bytes on the NAT-T QUIC
//! stream, before any eD2k byte.
//!
//! QUIC's own handshake proves nothing here: the dialect uses self-signed
//! certificates with **no** verification, so TLS says only "somebody
//! completed a handshake". The proof is what ties the connection to a user
//! hash, and eMuleAI delivers no application data and flushes no write until
//! it has been accepted.
//!
//! uTP has no counterpart and needs none: the eD2k hello inside the tunnel is
//! the identification, and a uTP stream carries no credential of its own.

use std::fmt;

use rmule_primitives::UserHash;
use thiserror::Error;

use super::caps::is_null_hash;

/// The proof's leading magic: ASCII `EAQN1`.
pub const QUIC_PROOF_MAGIC: [u8; 5] = *b"EAQN1";

/// `EMULEAI_QUIC_NATT_PROOF_LEN` — magic 5, sender hash 16, expected peer
/// hash 16.
pub const QUIC_PROOF_LEN: usize = 5 + 16 + 16;

/// The 37-byte proof, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicProof {
    /// The sender's own user hash.
    pub sender: UserHash,
    /// The user hash the sender expects us to hold, all-zero when unknown.
    pub expected_recipient: UserHash,
}

/// Why a proof's bytes could not be read at all (as distinct from being read
/// and refused — that is [`QuicProofVerdict`]).
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum QuicProofError {
    /// Not exactly 37 bytes. The proof is fixed-width and is the *first*
    /// thing on the stream, so a short read is "not yet complete" to the
    /// caller and a long one is a framing error.
    #[error("QUIC proof is {actual} bytes, not the fixed {QUIC_PROOF_LEN}")]
    WrongSize {
        /// Bytes offered.
        actual: usize,
    },

    /// The leading five bytes were not `EAQN1`.
    #[error("QUIC proof magic is 0x{}, not EAQN1", super::hex_digits(.actual))]
    WrongMagic {
        /// The five bytes that arrived.
        actual: [u8; 5],
    },
}

/// What a decoded proof means for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicProofVerdict {
    /// Accept, and adopt `sender` as the peer's user hash — either it is the
    /// hash we already held, or we held none.
    Accept(UserHash),

    /// Accept, but the sender's hash **differs** from the one we held for this
    /// peer. Only reachable when the endpoint proved direct NAT-T caps, which
    /// is a CAPS frame this endpoint itself answered; the refreshed hash is
    /// adopted and the change is worth a warning.
    AcceptRefreshed {
        /// The hash we held before.
        previous: UserHash,
        /// The hash the proof carries, now adopted.
        refreshed: UserHash,
    },

    /// Refuse: the proof names a recipient that is not us.
    NotAddressedToUs,

    /// Refuse: the sender's hash contradicts the one we hold for this peer and
    /// nothing entitles it to change.
    ContradictsKnownPeer {
        /// The hash we held.
        known: UserHash,
        /// The hash the proof claimed.
        claimed: UserHash,
    },
}

impl fmt::Display for QuicProofVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept(sender) => write!(f, "accepted from user hash {}", sender.to_hex_upper()),
            Self::AcceptRefreshed {
                previous,
                refreshed,
            } => write!(
                f,
                "accepted, user hash refreshed from {} to {}",
                previous.to_hex_upper(),
                refreshed.to_hex_upper()
            ),
            Self::NotAddressedToUs => f.write_str("not addressed to this endpoint"),
            Self::ContradictsKnownPeer { known, claimed } => write!(
                f,
                "claims user hash {} where {} is held",
                claimed.to_hex_upper(),
                known.to_hex_upper()
            ),
        }
    }
}

impl QuicProof {
    /// Read the proof.
    ///
    /// # Errors
    /// [`QuicProofError`] when the width or the magic is wrong.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuicProofError> {
        let bytes: &[u8; QUIC_PROOF_LEN] =
            bytes.try_into().map_err(|_| QuicProofError::WrongSize {
                actual: bytes.len(),
            })?;
        let magic: [u8; 5] = bytes[0..5].try_into().expect("five bytes of a fixed proof");
        if magic != QUIC_PROOF_MAGIC {
            return Err(QuicProofError::WrongMagic { actual: magic });
        }
        Ok(Self {
            sender: UserHash::from_bytes(bytes[5..21].try_into().expect("16 of a fixed proof")),
            expected_recipient: UserHash::from_bytes(
                bytes[21..37].try_into().expect("16 of a fixed proof"),
            ),
        })
    }

    /// The 37 bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; QUIC_PROOF_LEN] {
        let mut bytes = [0u8; QUIC_PROOF_LEN];
        bytes[0..5].copy_from_slice(&QUIC_PROOF_MAGIC);
        bytes[5..21].copy_from_slice(self.sender.as_bytes());
        bytes[21..37].copy_from_slice(self.expected_recipient.as_bytes());
        bytes
    }

    /// Judge this proof against what we are and what we already believed about
    /// the peer.
    ///
    /// `known_peer` is the hash we hold for this endpoint, if any;
    /// `endpoint_has_direct_caps` is whether this endpoint answered a CAPS
    /// frame — the one thing that lets a contradicting hash be adopted rather
    /// than refused.
    ///
    /// A **null** expected recipient is accepted. That is the decision
    /// eMuleAI's own author flagged as made without evidence, and rmule keeps
    /// it: a first contact genuinely cannot name us, and refusing it would
    /// make QUIC unreachable to anyone who has not already met us. It costs
    /// nothing an unverified self-signed certificate had not already given
    /// away — what the proof still buys is that the *sender* names itself, and
    /// a contradiction is caught.
    #[must_use]
    pub fn judge(
        &self,
        ours: &UserHash,
        known_peer: Option<UserHash>,
        endpoint_has_direct_caps: bool,
    ) -> QuicProofVerdict {
        if !is_null_hash(&self.expected_recipient) && &self.expected_recipient != ours {
            return QuicProofVerdict::NotAddressedToUs;
        }
        match known_peer {
            Some(known) if known != self.sender => {
                if endpoint_has_direct_caps {
                    QuicProofVerdict::AcceptRefreshed {
                        previous: known,
                        refreshed: self.sender,
                    }
                } else {
                    QuicProofVerdict::ContradictsKnownPeer {
                        known,
                        claimed: self.sender,
                    }
                }
            }
            _ => QuicProofVerdict::Accept(self.sender),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(fill: u8) -> UserHash {
        UserHash::from_bytes([fill; UserHash::BYTE_LEN])
    }

    /// The pinned 37-byte layout: `EAQN1`, sender, expected recipient.
    #[test]
    fn the_proof_is_the_pinned_37_byte_layout() {
        let proof = QuicProof {
            sender: hash(0x0F),
            expected_recipient: hash(0xF0),
        };
        let bytes = proof.encode();
        assert_eq!(bytes.len(), 37);
        assert_eq!(&bytes[0..5], b"EAQN1");
        assert_eq!(&bytes[5..21], &[0x0F; 16]);
        assert_eq!(&bytes[21..37], &[0xF0; 16]);
        assert_eq!(QuicProof::decode(&bytes), Ok(proof));
    }

    /// Wrong width and wrong magic are both refused before any hash is read.
    #[test]
    fn a_proof_of_the_wrong_width_or_magic_is_not_read() {
        assert_eq!(
            QuicProof::decode(&[0u8; 36]),
            Err(QuicProofError::WrongSize { actual: 36 })
        );
        let mut bytes = [0u8; QUIC_PROOF_LEN];
        bytes[0..5].copy_from_slice(b"EAQN2");
        assert_eq!(
            QuicProof::decode(&bytes),
            Err(QuicProofError::WrongMagic { actual: *b"EAQN2" })
        );
    }

    /// A proof naming somebody else is refused before the sender is even
    /// considered — it is a stream meant for another node.
    #[test]
    fn a_proof_addressed_to_somebody_else_is_refused() {
        let proof = QuicProof {
            sender: hash(1),
            expected_recipient: hash(2),
        };
        assert_eq!(
            proof.judge(&hash(3), None, false),
            QuicProofVerdict::NotAddressedToUs
        );
        assert_eq!(
            proof.judge(&hash(2), None, false),
            QuicProofVerdict::Accept(hash(1))
        );
    }

    /// A null expectation is first contact and is accepted — documented above
    /// as a deliberate inheritance, not an oversight.
    #[test]
    fn a_null_expected_recipient_is_first_contact() {
        let proof = QuicProof {
            sender: hash(1),
            expected_recipient: UserHash::from_bytes([0; 16]),
        };
        assert_eq!(
            proof.judge(&hash(9), None, false),
            QuicProofVerdict::Accept(hash(1))
        );
    }

    /// A sender hash contradicting what we hold is refused — unless this
    /// endpoint answered a CAPS frame, the one fact that makes a hash change
    /// something the endpoint proved rather than something it asserted.
    #[test]
    fn a_contradicting_sender_hash_needs_proven_caps_to_refresh() {
        let proof = QuicProof {
            sender: hash(0xAA),
            expected_recipient: hash(0x01),
        };
        assert_eq!(
            proof.judge(&hash(0x01), Some(hash(0xBB)), false),
            QuicProofVerdict::ContradictsKnownPeer {
                known: hash(0xBB),
                claimed: hash(0xAA),
            }
        );
        assert_eq!(
            proof.judge(&hash(0x01), Some(hash(0xBB)), true),
            QuicProofVerdict::AcceptRefreshed {
                previous: hash(0xBB),
                refreshed: hash(0xAA),
            }
        );
        assert_eq!(
            proof.judge(&hash(0x01), Some(hash(0xAA)), false),
            QuicProofVerdict::Accept(hash(0xAA))
        );
    }
}
