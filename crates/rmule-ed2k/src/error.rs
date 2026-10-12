//! One error vocabulary for the crate: every decode and encode failure a
//! server codec can raise, plus the crate-wide [`Result`] alias.
//!
//! A malformed frame is data, not a panic — it resolves to a typed reason the
//! session diagnoses, skips or closes on.

use thiserror::Error;

use crate::search_request::MAX_EXPRESSION_DEPTH;

/// `Result` with [`Ed2kError`] already filled in.
pub type Result<T> = std::result::Result<T, Ed2kError>;

/// Why a server codec could not read or write a packet.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Ed2kError {
    /// A codec was handed a packet whose opcode is not the one it decodes.
    #[error("unsupported eD2k opcode: 0x{opcode:02X}")]
    UnsupportedOpcode {
        /// The opcode that arrived.
        opcode: u8,
    },

    /// A login packet did not hold the fields a login must carry.
    #[error("invalid eD2k login packet: {reason}")]
    InvalidLogin {
        /// Which login expectation was broken.
        reason: &'static str,
    },

    /// A packet's body did not match its opcode's layout — wrong protocol
    /// byte, wrong opcode, a truncated field, or a body where none belongs.
    #[error("invalid eD2k packet payload (opcode 0x{opcode:02X}): {reason}")]
    InvalidPayload {
        /// The opcode being decoded.
        opcode: u8,
        /// Which layout expectation the body broke.
        reason: &'static str,
    },

    /// A search expression nests deeper than
    /// [`MAX_EXPRESSION_DEPTH`].
    #[error("OP_SEARCHREQUEST expression nests deeper than {MAX_EXPRESSION_DEPTH} levels")]
    SearchExpressionTooDeep,

    /// A shared primitive — a hash, a tag, a frame — failed to decode.
    #[error("primitive decode error: {source}")]
    Primitive {
        /// The underlying failure.
        #[from]
        source: rmule_primitives::PrimitiveError,
    },
}
