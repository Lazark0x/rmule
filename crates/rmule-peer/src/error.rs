//! One error vocabulary for the crate: the fault every plain leg's decoder
//! raises, the hello's and the source answers' own reasons, and the umbrella
//! decoder's error that carries them.
//!
//! Decode errors are data, not panics — a hostile peer's malformed frame
//! resolves to a typed reason the session can diagnose, skip or close on. The
//! legs a session treats differently keep their own type, and a leg that merely
//! refuses a frame raises a [`WireFault`].

use std::net::Ipv6Addr;

use rmule_primitives::{PrimitiveError, WireTruncated, WrongFrame};
use thiserror::Error;

use crate::file::PartBitmapDecodeError;
pub use crate::parts::PartsEncodeError;
pub use crate::peer_udp::ReaskDecodeError;
pub use crate::source_exchange::{AnswerSources2DecodeError, AnswerSourcesDecodeError};

/// Why a body is not the packet its opcode names. Every leg without a reason
/// of its own raises this; which leg it was is the frame's own opcode.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WireFault {
    /// The frame is some other packet's.
    #[error(transparent)]
    WrongFrame(#[from] WrongFrame),

    /// The payload ended inside a field the shape requires.
    #[error("payload truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the shape requires at that point.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },

    /// A fixed-size shape arrived at another size, the empty-body packets
    /// included, where anything at all is wrong.
    #[error("payload wrong size: expected {expected} bytes, had {actual}")]
    WrongSize {
        /// The size the shape requires.
        expected: usize,
        /// The size that arrived.
        actual: usize,
    },

    /// A length or count the frame declares disagrees with the bytes it carries.
    #[error("declared {declared}, but the frame carries {actual} bytes")]
    LengthMismatch {
        /// What the frame declared.
        declared: usize,
        /// Bytes that followed the declaration.
        actual: usize,
    },

    /// Bytes remain after the shape ends: the frame was not the packet it
    /// claimed to be, rather than that packet with extras.
    #[error("payload has trailing bytes after its shape ends")]
    TrailingBytes,

    /// A declared count cannot be held by this platform's `usize`, rejected
    /// before it sizes any allocation.
    #[error("declared count {count} overflows usize multiplication")]
    CountOverflow {
        /// The count the frame declared.
        count: usize,
    },

    /// A block's range runs backwards, so it names no bytes.
    #[error("part range end {end} before start {start}")]
    EndBeforeStart {
        /// The declared start.
        start: u64,
        /// The declared end.
        end: u64,
    },

    /// A bundle claimed a file size above eD2k's 256 GiB ceiling.
    #[error("file size {size} exceeds the eD2k maximum")]
    FileSizeOutOfRange {
        /// The size the bundle claimed.
        size: u64,
    },

    /// `OP_SECIDENTSTATE`'s state byte names no state this crate knows.
    #[error("unknown secure-identification state byte 0x{value:02X}")]
    UnknownState {
        /// The byte that arrived.
        value: u8,
    },

    /// Sixteen well-formed bytes naming an address a scope-less tag cannot
    /// identify (`IsUsableTagIdentity`): a link-local peer would be two
    /// identities, so the announcement is refused rather than adopted.
    #[error("{address} is not a usable tag identity")]
    UnusableAddress {
        /// The address the announcement carried.
        address: Ipv6Addr,
    },

    /// The part bitmap inside the frame did not decode.
    #[error("part bitmap: {0}")]
    Bitmap(#[from] PartBitmapDecodeError),

    /// A tag inside the frame did not decode.
    #[error("tag decode failed: {source}")]
    Tag {
        #[from]
        /// The primitive decoder's reason.
        source: PrimitiveError,
    },
}

impl From<WireTruncated> for WireFault {
    fn from(truncated: WireTruncated) -> Self {
        Self::Truncated {
            needed: truncated.needed,
            actual: truncated.available,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
/// Why a peer hello (`OP_HELLO` or `OP_HELLOANSWER`) could not be read.
/// Both directions share one shape, so they share one error.
pub enum PeerHelloDecodeError {
    /// The frame is some other packet's.
    #[error(transparent)]
    WrongFrame(#[from] WrongFrame),

    /// The payload ended inside a field the hello shape requires.
    #[error("peer hello payload truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the shape requires at that point.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },

    /// The leading hash-size byte was not the User Hash length, so the
    /// frame is not the hello it claims to be.
    #[error("peer hello hash-size prefix expected {expected}, got {actual}")]
    InvalidHashSize {
        /// The length a hello declares.
        expected: u8,
        /// The length this frame declared.
        actual: u8,
    },

    /// The declared tag count cannot be held by this platform's `usize` —
    /// rejected before any allocation follows from it.
    #[error("peer hello declared tag count {count} exceeds platform usize")]
    TagCountOverflow {
        /// The count the frame declared.
        count: u32,
    },

    /// The hello counts more tags than it carries: the `written` tags end
    /// exactly at the connected server (and the optional four-byte trailer),
    /// so a reader that trusts the count takes that endpoint for a tag. Both
    /// references refuse the frame; so does rmule, by this name (ADR-0050).
    #[error("peer hello declares {declared} tags and carries {written}")]
    TagCountShort {
        /// The tag count the frame declared.
        declared: u32,
        /// The tags it carried.
        written: u32,
        /// The `CT_NAME` among them, as the peer wrote it.
        name: Option<rmule_primitives::Ed2kText>,
        /// The `CT_MOD_VERSION` among them, as the peer wrote it.
        client_mod: Option<rmule_primitives::Ed2kText>,
    },

    #[error("peer hello tag decode failed: {source}")]
    /// A tag inside the hello did not decode.
    Tag {
        #[from]
        /// The primitive decoder's reason.
        source: PrimitiveError,
    },
}

impl From<WireTruncated> for PeerHelloDecodeError {
    fn from(truncated: WireTruncated) -> Self {
        Self::Truncated {
            needed: truncated.needed,
            actual: truncated.available,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
/// Why a peer frame could not be read. The legs a session treats differently
/// from a malformed frame have a variant each, so a caller can tell them apart
/// without matching on strings; every other leg is a [`Self::Frame`].
pub enum PeerPacketDecodeError {
    #[error("OP_HELLO decode failed: {source}")]
    /// An `OP_HELLO` body.
    Hello {
        #[source]
        /// The hello decoder's reason.
        source: PeerHelloDecodeError,
    },

    #[error("OP_HELLOANSWER decode failed: {source}")]
    /// An `OP_HELLOANSWER` body.
    HelloAnswer {
        #[source]
        /// The hello decoder's reason.
        source: PeerHelloDecodeError,
    },

    #[error("source-exchange packet decode failed: {source}")]
    /// An `OP_ANSWERSOURCES` (`0x82`).
    SourceExchange {
        #[source]
        /// The source-exchange decoder's reason.
        source: AnswerSourcesDecodeError,
    },

    #[error("OP_ANSWERSOURCES2 decode failed: {source}")]
    /// An `OP_ANSWERSOURCES2` (`0x84`).
    SourceExchange2 {
        #[source]
        /// The SX2 decoder's reason.
        source: AnswerSources2DecodeError,
    },

    #[error("peer frame decode failed: {source}")]
    /// Any other leg's frame.
    Frame {
        #[from]
        /// The leg's reason.
        source: WireFault,
    },
}
