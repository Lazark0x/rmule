//! The Kad **notes** layer (`0x35`/`0x45`): graceful via **Empty-Storer
//! Parity** (ADR-0063). rmule implements no notes store — no comments/ratings
//! feature — but must behave exactly like an aMule storer whose notes index
//! is permanently empty and permanently refusing: classify each inbound
//! request through aMule's own gate order, count it, and never touch the
//! wire. `node.rs` routes `0x35`/`0x45` here the same way it routes `0x33`/
//! `0x43` to `keyword_store` — before `Kad2Message::decode`, out of
//! [`crate::opcode::Kad2Opcode`] — so the notes arms sit beside the keyword
//! dispatch without disturbing it.
//!
//! ## Provenance
//!
//! Read directly from the pinned aMule source the ADR cites (commit
//! `4e8f2b3c3f90cda23765730546b04c684a92e4f5`):
//!
//! - **`0x35` search** (`Process2SearchNotesRequest`,
//!   [KademliaUDPListener.cpp#L1250](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1250)):
//!   no gates at all — it parses `<target16><filesize8>` and always attempts
//!   `SendValidNoteResult`, which replies only inside an index hit
//!   ([Indexed.cpp#L869](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Indexed.cpp#L869)).
//!   rmule's index is always empty, so every search is an unconditional
//!   empty (wire-silent) answer.
//! - **`0x45` publish** (`Process2PublishNotesRequest`,
//!   [KademliaUDPListener.cpp#L1273](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1273)):
//!   silent return while UDP-firewalled
//!   ([#L1276](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1276));
//!   silent drop outside `SEARCHTOLERANCE` unless LAN
//!   ([#L1287](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1287));
//!   the `0x4B` ack is sent only when `AddNotes` succeeds
//!   ([#L1329](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1329))
//!   — a permanently-empty, permanently-refusing index never sends one.
//!   `<key16><sourceID16><tagcnt1><tags>`; the tag list is walked tolerantly
//!   (first-occurrence-wins, unknown tags skipped, aMule's own parse
//!   [#L1300](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1300))
//!   purely to find the payload's true end — every tag is then discarded,
//!   never stored (Empty-Storer Parity builds no notes state).
//!
//! See ADR-0063 and the **Empty-Storer Parity** term in `CONTEXT.md`.

use std::net::Ipv4Addr;

use rmule_primitives::{Tag, WireReader, WireTruncated};

use crate::net::{PUBLISH_TOLERANCE, distance_top_word, is_lan_ip};
use crate::wire_fields::KadWireFields;
use crate::{KadEnvelope, KadId};

// `0x35`/`0x45` are deliberately not added to `opcode::Kad2Opcode`: like
// `0x33`/`0x43`, they route to their own codec (this module) before the
// node-maintenance `Kad2Message` decode. Restated privately here (not
// imported from `mod opcode`) for the same reason `keyword_store` restates
// its own pair — keeping this module's wire surface independent of the
// entry-point dispatch machinery.
const KADEMLIA2_SEARCH_NOTES_REQ: u8 = 0x35;
const KADEMLIA2_PUBLISH_NOTES_REQ: u8 = 0x45;

/// Why a well-formed `0x45` notes publish was refused — Empty-Storer Parity
/// (ADR-0063): rmule builds no notes state, so a request that clears these
/// gates is refused unconditionally at the terminal one, indistinguishable
/// from an aMule storer whose notes index is always full or refusing. Every
/// branch is wire-silent — no `0x4B` is ever sent for a notes publish. The
/// gate order mirrors aMule's own check order (see the module provenance).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotesPublishRefusal {
    /// This node is UDP-firewalled (ADR-0058 verdict) — aMule's early return
    /// before a single payload byte past the header is inspected.
    Firewalled,
    /// The key is outside `SEARCHTOLERANCE` from a non-LAN sender (LAN-exempt,
    /// like the keyword/source publish tolerance gates).
    Tolerance,
    /// The gates passed and the payload parsed — refused at the terminal
    /// gate: rmule's notes index is permanently empty and permanently
    /// refusing (Empty-Storer Parity).
    Capacity,
}

/// Classify a well-formed `0x45` notes publish through aMule's own gate order
/// (ADR-0063 Empty-Storer Parity). `key` is the publish's target ID (the
/// [`decode_publish_notes_req`] header field); `from` is the *observed*
/// datagram sender, never a claimed identity — matching the source/keyword
/// tolerance gates. Every outcome is a silent refusal; this only picks which
/// one, for observability.
#[must_use]
pub fn classify_publish(
    own_id: KadId,
    own_udp_firewalled: bool,
    from: Ipv4Addr,
    key: KadId,
) -> NotesPublishRefusal {
    if own_udp_firewalled {
        return NotesPublishRefusal::Firewalled;
    }
    if !is_lan_ip(from) && distance_top_word(own_id, key) > PUBLISH_TOLERANCE {
        return NotesPublishRefusal::Tolerance;
    }
    NotesPublishRefusal::Capacity
}

// ---------------------------------------------------------------------------
// Wire codec
// ---------------------------------------------------------------------------

/// Why a notes-layer datagram could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotesDecodeError {
    /// The envelope opcode is not `KADEMLIA2_SEARCH_NOTES_REQ` (`0x35`).
    NotASearchNotesReq {
        /// The opcode that arrived instead.
        opcode: u8,
    },
    /// The envelope opcode is not `KADEMLIA2_PUBLISH_NOTES_REQ` (`0x45`).
    NotAPublishNotesReq {
        /// The opcode that arrived instead.
        opcode: u8,
    },
    /// The payload does not parse as the documented layout. Carries a static
    /// reason for diagnostics; never panics.
    Malformed {
        /// Which layout expectation the payload broke.
        reason: &'static str,
    },
}

/// Decode a `KADEMLIA2_SEARCH_NOTES_REQ` (`0x35`) payload: `[target ID
/// (16)][file size (8 LE)]` — 24 bytes, no tags, no gates at all
/// (`Process2SearchNotesRequest`). rmule holds no notes to filter by size;
/// both fields are returned for decode fidelity, but the caller
/// (Empty-Storer Parity) never inspects `file_size` — every well-formed
/// search is an unconditional empty answer.
pub fn decode_search_notes_req(envelope: &KadEnvelope) -> Result<(KadId, u64), NotesDecodeError> {
    if envelope.opcode() != KADEMLIA2_SEARCH_NOTES_REQ {
        return Err(NotesDecodeError::NotASearchNotesReq {
            opcode: envelope.opcode(),
        });
    }
    let mut reader = WireReader::new(envelope.payload());
    let target = reader.read_kad_id("notes search target")?;
    let file_size = reader.read_u64_le("notes search file size")?;
    if !reader.is_exhausted() {
        return Err(NotesDecodeError::Malformed {
            reason: "trailing bytes after the notes search payload",
        });
    }
    Ok((target, file_size))
}

/// Decode a `KADEMLIA2_PUBLISH_NOTES_REQ` (`0x45`) payload: `[key (16)]
/// [source ID (16)][tag count (1)][tags]` (`Process2PublishNotesRequest`).
/// The tag list is walked tolerantly (aMule's own first-occurrence-wins,
/// unknown-tags-skipped parse) purely to locate the payload's true end — a
/// truncated or malformed tag mid-list still fails the decode, matching
/// aMule's own parser — but every tag's *value* is discarded: Empty-Storer
/// Parity builds no notes state, so only the key survives (needed for the
/// tolerance-distance classification in [`classify_publish`]).
pub fn decode_publish_notes_req(envelope: &KadEnvelope) -> Result<KadId, NotesDecodeError> {
    if envelope.opcode() != KADEMLIA2_PUBLISH_NOTES_REQ {
        return Err(NotesDecodeError::NotAPublishNotesReq {
            opcode: envelope.opcode(),
        });
    }
    let mut reader = WireReader::new(envelope.payload());
    let key = reader.read_kad_id("notes publish key")?;
    reader.take(KadId::BYTE_LEN, "notes publish source ID")?;
    let tag_count = reader.read_u8("notes publish tag count")?;
    for _ in 0..tag_count {
        let (_, consumed) = Tag::decode_prefix(reader.remaining_bytes()).map_err(|_| {
            NotesDecodeError::Malformed {
                reason: "notes publish tag is truncated or malformed",
            }
        })?;
        reader.advance_clamped(consumed);
    }
    if !reader.is_exhausted() {
        return Err(NotesDecodeError::Malformed {
            reason: "trailing bytes after the notes publish tag list",
        });
    }
    Ok(key)
}

impl From<WireTruncated> for NotesDecodeError {
    fn from(truncated: WireTruncated) -> Self {
        NotesDecodeError::Malformed {
            reason: truncated.field,
        }
    }
}
