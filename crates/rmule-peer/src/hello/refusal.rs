//! A hello rmule refuses, named by its shape: the one refusal with a cause a
//! reader can prove from the bytes is a frame that **counts more tags than it
//! carries**. The tags it did write end exactly where the connected server
//! begins, and the reader, trusting the count, reads that endpoint as the
//! next tag's header. Both references refuse such a frame (ADR-0050); rmule
//! refuses it too, and says so rather than calling it malformed.

use rmule_primitives::{Ed2kText, Ipv4Endpoint, PrimitiveError, Tag, WireReader};

use super::{TRAILER_LEN, hello_text};
use crate::error::PeerHelloDecodeError;
use crate::hello_tag::{CT_MOD_VERSION, CT_NAME};

/// Why rmule refused a peer's hello, as a code a consumer matches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HelloRefusalCode {
    /// The hello counted `declared` tags and carried `written`: the tags it
    /// wrote end exactly at the connected server (and the optional four-byte
    /// trailer).
    TagCountShort {
        /// The tag count the frame declared.
        declared: u32,
        /// The tags it actually carried.
        written: u32,
    },
}

/// A refused hello: the code, and what the peer said about itself in the
/// tags it did write — as text the peer supplied, never checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloRefusal {
    /// Why it was refused.
    pub code: HelloRefusalCode,
    /// The `CT_NAME` the peer wrote before the frame went wrong, if any.
    pub name: Option<Ed2kText>,
    /// The `CT_MOD_VERSION` the peer wrote before the frame went wrong, if any.
    pub client_mod: Option<Ed2kText>,
}

impl HelloRefusal {
    /// The refusal a decode error names, if it is one rmule refuses by name.
    #[must_use]
    pub fn from_decode_error(error: &PeerHelloDecodeError) -> Option<Self> {
        match error {
            PeerHelloDecodeError::TagCountShort {
                declared,
                written,
                name,
                client_mod,
            } => Some(Self {
                code: HelloRefusalCode::TagCountShort {
                    declared: *declared,
                    written: *written,
                },
                name: name.clone(),
                client_mod: client_mod.clone(),
            }),
            _ => None,
        }
    }
}

/// Name a hello whose tag block failed to read, when its shape proves the
/// count was short.
///
/// `block` is the payload from the first tag to the end of the frame. The
/// block is walked tag by tag as the reader walks it; after each whole tag
/// (and before the first) the bytes left are compared with what follows the
/// tags — the six-byte connected server, or that plus the four-byte trailer.
/// The last such point below `declared` is the count the frame really
/// carried. No such point means the frame is broken some other way, and the
/// caller keeps the error it had.
pub(super) fn classify_short_count(block: &[u8], declared: u32) -> Option<PeerHelloDecodeError> {
    let tail_fits = |cursor: usize| {
        block.len().checked_sub(cursor).is_some_and(|left| {
            left == Ipv4Endpoint::WIRE_LEN || left == Ipv4Endpoint::WIRE_LEN + TRAILER_LEN
        })
    };
    let mut tags = Vec::new();
    let mut reader = WireReader::new(block);
    let mut short: Option<(u32, usize)> = tail_fits(0).then_some((0, 0));
    for written in 1..declared {
        let rest = reader.remaining_bytes();
        match Tag::decode_prefix(rest) {
            Ok((tag, used)) => {
                tags.push(tag);
                reader.advance_clamped(used);
            }
            Err(PrimitiveError::UnsupportedTagType { .. } | PrimitiveError::InvalidTag { .. }) => {
                reader.advance_clamped(Tag::skip_prefix(rest).ok()?);
            }
            Err(_) => break,
        }
        if tail_fits(reader.position()) {
            short = Some((written, tags.len()));
        }
    }
    let (written, kept) = short?;
    let tags = &tags[..kept];
    Some(PeerHelloDecodeError::TagCountShort {
        declared,
        written,
        name: hello_text(tags, CT_NAME).cloned(),
        client_mod: hello_text(tags, CT_MOD_VERSION).cloned(),
    })
}
