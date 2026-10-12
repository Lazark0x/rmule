//! The one error type every primitive decode and parse returns, and the
//! crate-wide `Result` alias built on it.

use thiserror::Error;

/// `Result` with [`PrimitiveError`] already filled in — what every fallible
/// function in this crate returns.
pub type Result<T> = std::result::Result<T, PrimitiveError>;

/// Why a value could not be built from the bytes or text it was read from.
///
/// One flat vocabulary for the whole crate: a caller matching on a decode
/// failure never has to know which module produced it. Every variant means the
/// input was rejected whole — no partial value is ever handed back — so a
/// protocol crate can turn any of these into "keep the bytes, drop the frame"
/// without inspecting further (ADR-0018).
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PrimitiveError {
    /// A hash was built from a slice of the wrong width. Hash widths are fixed
    /// per kind (16 bytes for an eD2k file hash or user hash, 20 for a SHA-1
    /// AICH hash), so this is a framing error, not a content error.
    #[error("invalid hash length: expected {expected} bytes, got {actual} bytes")]
    InvalidHashLength {
        /// The width this hash kind requires.
        expected: usize,
        /// The width the caller supplied.
        actual: usize,
    },

    /// A hash's *text* form was not readable — a hex string of the wrong
    /// length or with a non-hex digit, or an AICH base32 string that does not
    /// decode.
    #[error("invalid {kind} hash encoding")]
    InvalidHashEncoding {
        /// Which hash kind was being parsed, for the message ("ed2k",
        /// "aich", …).
        kind: &'static str,
    },

    /// A part hash set did not carry the number of part hashes the file's size
    /// implies. The count is derivable from the size alone, so a mismatch
    /// means the set belongs to a different file — accepting it would corrupt
    /// every later part verification.
    #[error(
        "invalid part hash set count for {file_size} byte file: expected {expected}, got {actual}"
    )]
    InvalidPartHashSetCount {
        /// The file size the count was derived from.
        file_size: u64,
        /// How many part hashes that size requires.
        expected: usize,
        /// How many the set actually carried.
        actual: usize,
    },

    /// No part-hash count can be derived from this file size: the count
    /// overflows on the way out. Only reachable near `u64::MAX`, so in
    /// practice it means a size field that was never a real file's.
    #[error("file is too large: {file_size} bytes")]
    FileTooLarge {
        /// The rejected size.
        file_size: u64,
    },

    /// A link or a search row named a file larger than eD2k addresses
    /// ([`MAX_ED2K_FILE_SIZE`](crate::MAX_ED2K_FILE_SIZE), 256 GiB): refused
    /// where it is decoded, as aMule refuses it.
    #[error("file size {file_size} is above the eD2k limit")]
    FileSizeAboveLimit {
        /// The size the link or row named.
        file_size: u64,
    },

    /// A link or a search row named a file of zero bytes: no part to fetch.
    /// Refused where it is decoded, as aMule refuses the link and drops the
    /// row.
    #[error("file size is zero")]
    FileSizeZero,

    /// An `ed2k://` link was malformed: a missing scheme or delimiter,
    /// surrounding whitespace, an empty or absent field, or a server link
    /// without both host and port.
    #[error("invalid link: {reason}")]
    InvalidLink {
        /// Which structural expectation the link text broke.
        reason: &'static str,
    },

    /// The link's kind segment names something this crate does not model
    /// (only `file`, `server` and `serverlist` links are).
    #[error("unsupported ED2K link kind")]
    UnsupportedLinkKind,

    /// The link carried the same optional field twice, which leaves no
    /// non-arbitrary reading of which one wins.
    #[error("duplicate ED2K link field: {field}")]
    DuplicateLinkField {
        /// The field name that repeated.
        field: &'static str,
    },

    /// A `host:port` server endpoint could not be read: no `:port` at all, an
    /// empty host, or a port that is not a non-zero `u16`. Port `0` is
    /// rejected rather than normalised — it is never a dialable server.
    #[error("invalid server endpoint: {reason}")]
    InvalidServerEndpoint {
        /// Which part of the endpoint text was unreadable.
        reason: &'static str,
    },

    /// A peer endpoint's text form could not be read: not the strict
    /// `a.b.c.d:port` or `[addr]:port` spelling, or a port that is not a `u16`.
    #[error("invalid peer endpoint: {reason}")]
    InvalidPeerEndpoint {
        /// Which part of the endpoint text was unreadable.
        reason: &'static str,
    },

    /// A frame ended before its declared length. The caller holds a partial
    /// read and should wait for more bytes rather than treat the frame as
    /// broken — this is the one variant that is routinely *not* fatal.
    #[error("truncated packet: needed {needed} bytes, got {actual} bytes")]
    TruncatedPacket {
        /// How many bytes the header said the frame occupies.
        needed: usize,
        /// How many were available.
        actual: usize,
    },

    /// A frame header declared a length of zero, or one past the 16 MiB frame
    /// ceiling. The ceiling exists so a hostile length cannot make a reader
    /// allocate unboundedly before a single payload byte arrives.
    #[error("invalid packet length: {length}")]
    InvalidPacketLength {
        /// The declared payload length, in bytes.
        length: u32,
    },

    /// The frame's first byte is not one of the three eD2k protocol markers
    /// (eDonkey `0xE3`, eMule `0xC5`, packed `0xD4`). Kad's own markers never
    /// reach here — Kad datagrams carry a different envelope.
    #[error("unsupported packet protocol byte: 0x{protocol:02X}")]
    UnsupportedProtocolByte {
        /// The unrecognised marker byte.
        protocol: u8,
    },

    /// An exact decode found bytes past the end of the value. Only the
    /// "decode this buffer and nothing else" entry points raise it; the
    /// streaming decoders hand the remainder back instead.
    #[error("trailing packet bytes: {trailing}")]
    TrailingPacketBytes {
        /// How many bytes were left over.
        trailing: usize,
    },

    /// A tag ended before its declared name or value did.
    #[error("truncated tag: needed {needed} bytes, got {actual} bytes")]
    TruncatedTag {
        /// How many bytes the tag's header implies.
        needed: usize,
        /// How many were available.
        actual: usize,
    },

    /// A tag was structurally wrong in a way truncation does not explain: a
    /// name past the 65535-byte length prefix, a length that overflows, or
    /// bytes left over after an exact decode.
    #[error("invalid tag: {reason}")]
    InvalidTag {
        /// Which tag expectation was broken.
        reason: &'static str,
    },

    /// The tag's type byte names an encoding this crate does not model.
    /// Unlike an unknown *opcode*, an unknown tag type cannot be kept
    /// verbatim: without the type there is no way to know where the value
    /// ends, so the whole tag list is unreadable from here on.
    #[error("unsupported tag type: 0x{tag_type:02X}")]
    UnsupportedTagType {
        /// The unrecognised tag type byte.
        tag_type: u8,
    },

    /// A search expression could not be built — a blank phrase, which would
    /// ask a server to match everything, among others.
    #[error("invalid search query: {fault}")]
    InvalidSearchQuery {
        /// Which query rule was broken.
        fault: crate::search::QueryFault,
    },

    /// A search result row was unreadable: it carried no name, and a result
    /// with nothing to display is not worth handing a caller.
    #[error("invalid search result: {reason}")]
    InvalidSearchResult {
        /// Which result-row expectation was broken.
        reason: &'static str,
    },

    /// A Secure User Identification key pair could not be generated. The
    /// identity is unusable, not merely unverified: without a key pair this
    /// client cannot answer a challenge at all.
    #[error("secure-identification key generation failed")]
    KeyGenerationFailed,

    /// A peer's Secure User Identification public key was not a readable SPKI
    /// blob, so no signature from that peer can be checked.
    #[error("invalid secure-identification public key")]
    InvalidPublicKey,

    /// Our own stored private key could not be read back — a persisted
    /// identity that no longer loads.
    #[error("invalid secure-identification private key")]
    InvalidPrivateKey,
}

impl From<crate::WireTruncated> for PrimitiveError {
    fn from(truncated: crate::WireTruncated) -> Self {
        Self::TruncatedTag {
            needed: truncated.needed,
            actual: truncated.available,
        }
    }
}
