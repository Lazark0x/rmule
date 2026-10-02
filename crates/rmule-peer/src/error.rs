//! One error vocabulary for the crate: every leg's decode error re-exported
//! through here, plus the frame-level failures the umbrella decoder raises.
//!
//! Decode errors are data, not panics — a hostile peer's malformed frame
//! resolves to a typed reason the session can diagnose, skip or close on.

use std::net::Ipv6Addr;

use rmule_primitives::PrimitiveError;
use thiserror::Error;

pub use crate::aich::AichDecodeError;
pub use crate::file_request::FileRequestDecodeError;
pub use crate::hash_set::HashSetDecodeError;
pub use crate::human_layer::HumanLayerDecodeError;
pub use crate::multipacket::MultiPacketDecodeError;
pub use crate::parts::{PartsDecodeError, PartsEncodeError};
pub use crate::reask::ReaskDecodeError;
pub use crate::secure_ident::SuiDecodeError;
pub use crate::slot::SlotDecodeError;
pub use crate::source_exchange::{
    AnswerSources2DecodeError, AnswerSourcesDecodeError, RequestSources2DecodeError,
    RequestSourcesDecodeError,
};

/// Why an `OP_CHANGE_CLIENT_IP` (`0xAC`) could not be read (ADR-0087).
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PeerIpv6DecodeError {
    /// The payload was not exactly the sixteen address bytes the opcode
    /// carries — there is no tag wrapper to disambiguate a short read.
    #[error("OP_CHANGE_CLIENT_IP payload is {actual} bytes, not the {expected} an IPv6 address is")]
    WrongSize {
        /// What the shape requires.
        expected: usize,
        /// What arrived.
        actual: usize,
    },

    /// Sixteen well-formed bytes naming an address a scope-less tag cannot
    /// identify (`IsUsableTagIdentity`) — a link-local peer would be two
    /// identities, so the announcement is refused rather than adopted.
    #[error("OP_CHANGE_CLIENT_IP names {address}, which is not a usable tag identity")]
    UnusableAddress {
        /// The address the announcement carried.
        address: Ipv6Addr,
    },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
/// Why a peer hello (`OP_HELLO` or `OP_HELLOANSWER`) could not be read.
/// Both directions share one shape, so they share one error.
pub enum PeerHelloDecodeError {
    #[error("unsupported packet protocol for peer hello")]
    /// The frame arrived under a protocol byte no hello uses.
    UnsupportedProtocol,

    /// A hello decoder was handed a frame carrying some other opcode.
    #[error("wrong opcode for peer hello variant: 0x{opcode:02X}")]
    WrongOpcode {
        /// The opcode that arrived.
        opcode: u8,
    },

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

#[derive(Clone, Debug, Error, PartialEq, Eq)]
/// Why an `OP_EMULEINFO` / `OP_EMULEINFOANSWER` could not be read.
pub enum EmuleInfoDecodeError {
    #[error("unsupported packet protocol for OP_EMULEINFO")]
    /// The frame arrived under a protocol byte other than eMule's.
    UnsupportedProtocol,

    /// The decoder was handed a frame carrying some other opcode.
    #[error("wrong opcode for OP_EMULEINFO: 0x{opcode:02X}")]
    WrongOpcode {
        /// The opcode that arrived.
        opcode: u8,
    },

    /// The payload ended inside the six-byte header.
    #[error("OP_EMULEINFO payload truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the header requires.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },

    #[error("OP_EMULEINFO tag decode failed: {source}")]
    /// A tag inside the block did not decode.
    Tag {
        #[from]
        /// The primitive decoder's reason.
        source: PrimitiveError,
    },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
/// Why a peer frame could not be read. One variant per leg, each naming
/// the decoder that refused it, so a caller can tell a malformed hello
/// from a malformed part request without matching on strings.
pub enum PeerPacketDecodeError {
    #[error("OP_HELLO decode failed: {source}")]
    /// An `OP_HELLO` body.
    Hello {
        #[source]
        /// The hello decoder's reason.
        source: PeerHelloDecodeError,
    },

    #[error("OP_EMULEINFO decode failed: {source}")]
    /// An `OP_EMULEINFO` or `OP_EMULEINFOANSWER` body.
    EmuleInfo {
        #[source]
        /// The emule-info decoder's reason.
        source: EmuleInfoDecodeError,
    },

    #[error("OP_HELLOANSWER decode failed: {source}")]
    /// An `OP_HELLOANSWER` body.
    HelloAnswer {
        #[source]
        /// The hello decoder's reason.
        source: PeerHelloDecodeError,
    },

    #[error("file-request packet decode failed: {source}")]
    /// A file-request leg frame (name, status, or the id-set packets).
    FileRequest {
        #[source]
        /// The file-request decoder's reason.
        source: FileRequestDecodeError,
    },

    #[error("hash-set packet decode failed: {source}")]
    /// A part-hash set request or answer.
    HashSet {
        #[source]
        /// The hash-set decoder's reason.
        source: HashSetDecodeError,
    },

    #[error("slot-queue packet decode failed: {source}")]
    /// A slot or queue-rank frame.
    Slot {
        #[source]
        /// The slot decoder's reason.
        source: SlotDecodeError,
    },

    #[error("part packet decode failed: {source}")]
    /// A part request or a part block.
    Parts {
        #[source]
        /// The parts decoder's reason.
        source: PartsDecodeError,
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

    #[error("OP_REQUESTSOURCES decode failed: {source}")]
    /// An `OP_REQUESTSOURCES` (`0x81`).
    SourceExchangeRequest {
        #[source]
        /// The request decoder's reason.
        source: RequestSourcesDecodeError,
    },

    #[error("OP_REQUESTSOURCES2 decode failed: {source}")]
    /// An `OP_REQUESTSOURCES2` (`0x83`).
    SourceExchangeRequest2 {
        #[source]
        /// The SX2 request decoder's reason.
        source: RequestSources2DecodeError,
    },

    #[error("AICH packet decode failed: {source}")]
    /// An AICH request or answer.
    Aich {
        #[source]
        /// The AICH decoder's reason.
        source: AichDecodeError,
    },

    #[error("secure-identification packet decode failed: {source}")]
    /// A Secure User Identification frame.
    Sui {
        #[source]
        /// The identification decoder's reason.
        source: SuiDecodeError,
    },

    #[error("multipacket packet decode failed: {source}")]
    /// An `OP_MULTIPACKET` bundle or its answer.
    MultiPacket {
        #[source]
        /// The bundle walker's reason.
        source: MultiPacketDecodeError,
    },

    #[error("human-layer packet decode failed: {source}")]
    /// A chat, comment or browse frame (ADR-0068).
    HumanLayer {
        #[source]
        /// The human-layer decoder's reason.
        source: HumanLayerDecodeError,
    },

    #[error("IPv6 dialect packet decode failed: {source}")]
    /// An `OP_CHANGE_CLIENT_IP` (ADR-0087).
    Ipv6 {
        #[source]
        /// The IPv6 decoder's reason.
        source: PeerIpv6DecodeError,
    },
}
