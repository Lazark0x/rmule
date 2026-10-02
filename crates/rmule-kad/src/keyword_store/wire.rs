//! The `0x43`/`0x33`/`0x3B` keyword codecs: decoding a publish or search
//! request off the wire, encoding a result set back, and the bounds-checked
//! [`Cursor`] every decode reads through. Tag layouts are aMule's, cited in
//! the parent's provenance section.

use rmule_primitives::{Ed2kText, Tag, TagName, TagValue};

use crate::search_tree::SearchTree;
use crate::{KadEnvelope, KadId};

use super::entry::KeywordPublishFile;
use super::query::{UnknownSearchOperator, validate_operators};
use super::result::KeywordResultRow;
use super::{
    KADEMLIA2_PUBLISH_KEY_REQ, KADEMLIA2_SEARCH_KEY_REQ, KADEMLIA2_SEARCH_RES,
    KEYWORD_PUBLISH_BATCH_CAP, KEYWORD_RESULT_ROWS_PER_DATAGRAM, TAG_FILENAME, TAG_FILESIZE,
};

/// Why a keyword-store datagram could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeywordDecodeError {
    /// The envelope opcode is not `KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`).
    NotAPublishKeyReq {
        /// The opcode that arrived instead.
        opcode: u8,
    },
    /// The envelope opcode is not `KADEMLIA2_SEARCH_KEY_REQ` (`0x33`).
    NotASearchKeyReq {
        /// The opcode that arrived instead.
        opcode: u8,
    },
    /// The envelope opcode is not `KADEMLIA2_SEARCH_RES` (`0x3B`) — the
    /// requester's keyword-result decode was handed the wrong opcode.
    NotASearchKeyRes {
        /// The opcode that arrived instead.
        opcode: u8,
    },
    /// The payload does not parse as the documented layout. Carries a static
    /// reason for diagnostics; never panics.
    Malformed {
        /// Which layout expectation the payload broke.
        reason: &'static str,
    },
    /// The batch declares more files than [`KEYWORD_PUBLISH_BATCH_CAP`); the
    /// whole packet is rejected rather than partially processed (see the
    /// constant's doc comment for the divergence rationale).
    TooManyFiles {
        /// The file count the header claimed — more than a legitimate batch
        /// carries, so the payload is refused before any row is read.
        declared: u16,
    },
    /// A restrictive search's tree decoded structurally (the codec accepts
    /// any operator byte) but used a numeric-relation operator outside
    /// aMule's known map; the whole request is invalid, matching aMule's
    /// parse-time rejection.
    InvalidSearchExpression(UnknownSearchOperator),
}

/// Decode a `KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`) payload: `[keyword ID
/// (16)][file count (2 LE)]` then that many `[file ID (16)][tag count
/// (1)][tags]` rows (`Process2PublishKeyRequest`).
pub fn decode_publish_key_req(
    envelope: &KadEnvelope,
) -> Result<(KadId, Vec<KeywordPublishFile>), KeywordDecodeError> {
    if envelope.opcode() != KADEMLIA2_PUBLISH_KEY_REQ {
        return Err(KeywordDecodeError::NotAPublishKeyReq {
            opcode: envelope.opcode(),
        });
    }
    let mut cursor = Cursor::new(envelope.payload());
    let keyword = cursor.read_kad_id("published keyword ID")?;
    let declared = cursor.read_u16_le("published file count")?;
    if usize::from(declared) > KEYWORD_PUBLISH_BATCH_CAP {
        return Err(KeywordDecodeError::TooManyFiles { declared });
    }
    let mut files = Vec::with_capacity(usize::from(declared));
    for _ in 0..declared {
        files.push(decode_publish_file(&mut cursor)?);
    }
    if !cursor.is_exhausted() {
        return Err(KeywordDecodeError::Malformed {
            reason: "trailing bytes after the declared file count",
        });
    }
    Ok((keyword, files))
}

fn decode_publish_file(cursor: &mut Cursor<'_>) -> Result<KeywordPublishFile, KeywordDecodeError> {
    let file_id = cursor.read_kad_id("published file ID")?;
    let tag_count = cursor.read_u8("publish tag count")?;
    let mut filename = None;
    let mut size = None;
    let mut tags = Vec::new();
    for _ in 0..tag_count {
        let (tag, consumed) =
            Tag::decode_prefix(cursor.remaining()).map_err(|_| KeywordDecodeError::Malformed {
                reason: "publish tag is truncated or malformed",
            })?;
        cursor.advance(consumed);
        // FILENAME/FILESIZE are dropped from the verbatim list on every
        // occurrence; only the first populates the typed field (aMule:
        // `if (entry->GetCommonFileName().IsEmpty()) { SetFileName(...); }
        // delete tag;` — the `delete` runs regardless of the `if`).
        match tag.name().id() {
            Some(TAG_FILENAME) => {
                if filename.is_none() {
                    filename = string_tag_value(tag.value());
                }
            }
            Some(TAG_FILESIZE) => {
                if size.is_none() {
                    size = file_size_tag_value(tag.value());
                }
            }
            _ => tags.push(tag),
        }
    }
    Ok(KeywordPublishFile {
        file_id,
        filename,
        size,
        tags,
    })
}

pub(super) fn string_tag_value(value: &TagValue) -> Option<String> {
    match value {
        TagValue::String(text) => Some(text.to_display_string()),
        TagValue::U8(_)
        | TagValue::U16(_)
        | TagValue::U32(_)
        | TagValue::U64(_)
        | TagValue::Hash(_) => None,
    }
}

/// A 32-bit integer tag at any width — `TAG_SOURCES`, `TAG_PUBLISHINFO`. A
/// `UINT64` body is unrecognized, same as a string or hash.
pub(super) fn numeric_tag_scalar(value: &TagValue) -> Option<u32> {
    match *value {
        TagValue::U32(word) => Some(word),
        TagValue::U16(short) => Some(u32::from(short)),
        TagValue::U8(byte) => Some(u32::from(byte)),
        TagValue::U64(_) | TagValue::String(_) | TagValue::Hash(_) => None,
    }
}

/// `TAG_FILESIZE` at any integer width, `UINT64` included: aMule's keyword
/// publisher writes it with `CTagVarInt` (`Search.cpp:1714`) and eMuleAI's
/// with a `uint64` `CKadTagUInt` (`Search.cpp:1650`), both widened past
/// 4 GiB, and both storers and searchers read it back with `GetInt()` into a
/// `uint64` (aMule `KademliaUDPListener.cpp:1242-1248`, `Search.cpp:1381-1388`;
/// eMuleAI `KademliaUDPListener.cpp:1225-1230`, `Search.cpp:1341-1345`).
/// Either family drops a keyword result without a size (aMule
/// `Search.cpp:1456`, eMuleAI `Search.cpp:1403`), so a size read here as
/// absent would lose the file for them too.
pub(super) fn file_size_tag_value(value: &TagValue) -> Option<u64> {
    match *value {
        TagValue::U64(size) => Some(size),
        TagValue::U32(word) => Some(u64::from(word)),
        TagValue::U16(short) => Some(u64::from(short)),
        TagValue::U8(byte) => Some(u64::from(byte)),
        TagValue::String(_) | TagValue::Hash(_) => None,
    }
}

/// Decode a `KADEMLIA2_SEARCH_KEY_REQ` (`0x33`) payload: `[keyword ID
/// (16)][start position (2 LE, top bit = restrictive flag, low 15 bits =
/// offset)]`, then a search-expression tree iff the restrictive flag is set
/// (`Process2SearchKeyRequest`). A restrictive tree using an unknown numeric
/// operator fails the whole decode (mirrors aMule's parse-time
/// `CreateSearchExpressionTree` rejection).
pub fn decode_search_key_req(
    envelope: &KadEnvelope,
) -> Result<(KadId, u16, Option<SearchTree>), KeywordDecodeError> {
    if envelope.opcode() != KADEMLIA2_SEARCH_KEY_REQ {
        return Err(KeywordDecodeError::NotASearchKeyReq {
            opcode: envelope.opcode(),
        });
    }
    let mut cursor = Cursor::new(envelope.payload());
    let keyword = cursor.read_kad_id("search keyword ID")?;
    let raw_start = cursor.read_u16_le("start position")?;
    let restrictive = raw_start & 0x8000 != 0;
    let start_position = raw_start & 0x7FFF;

    if !restrictive {
        if !cursor.is_exhausted() {
            return Err(KeywordDecodeError::Malformed {
                reason: "trailing bytes after a non-restrictive search",
            });
        }
        return Ok((keyword, start_position, None));
    }

    // `SearchTree::decode` itself requires exact exhaustion of the bytes it
    // is given (rejects trailing bytes), so no separate check is needed here.
    let tree =
        SearchTree::decode(cursor.remaining()).map_err(|_| KeywordDecodeError::Malformed {
            reason: "restrictive search expression",
        })?;
    validate_operators(&tree).map_err(KeywordDecodeError::InvalidSearchExpression)?;
    Ok((keyword, start_position, Some(tree)))
}

/// Re-encode served rows into `KADEMLIA2_SEARCH_RES` (`0x3B`) envelopes, 50
/// rows per datagram (same opcode and batching as source search results;
/// `SendValidKeywordResult`). Zero rows encode to zero envelopes.
#[must_use]
pub fn encode_search_key_res(
    sender: KadId,
    keyword: KadId,
    rows: &[KeywordResultRow],
) -> Vec<KadEnvelope> {
    rows.chunks(KEYWORD_RESULT_ROWS_PER_DATAGRAM)
        .map(|batch| {
            let mut payload = Vec::with_capacity(34 + batch.len() * 32);
            payload.extend_from_slice(sender.as_bytes());
            payload.extend_from_slice(keyword.as_bytes());
            payload.extend_from_slice(
                &u16::try_from(batch.len())
                    .expect("a batch never exceeds 50 rows")
                    .to_le_bytes(),
            );
            for row in batch {
                payload.extend_from_slice(row.file_id.as_bytes());
                payload.push(
                    u8::try_from(row.tags.len()).expect("a served row never exceeds 255 tags"),
                );
                for tag in &row.tags {
                    payload.extend_from_slice(&tag.encode());
                }
            }
            KadEnvelope::plain(KADEMLIA2_SEARCH_RES, payload)
        })
        .collect()
}

/// Encode a `KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`) — the **Kad Publisher**'s
/// counterpart to [`decode_publish_key_req`]. `[keyword ID (16)][file count (2
/// LE)]` then, per file, `[file ID (16)][tag count (1)][tags]`, with FILENAME
/// and FILESIZE synthesized from the row's typed fields ahead of its verbatim
/// `tags` — the exact split `decode_publish_key_req` inverts. The caller batches
/// at most [`KEYWORD_PUBLISH_BATCH_CAP`] files per packet (the walk's own emit
/// cap); a longer slice panics rather than emit a packet a compliant storer
/// rejects outright.
#[must_use]
pub fn encode_publish_key_req(keyword: KadId, files: &[KeywordPublishFile]) -> KadEnvelope {
    assert!(
        files.len() <= KEYWORD_PUBLISH_BATCH_CAP,
        "a publish-key batch never exceeds the emit-side 50-file cap"
    );
    let mut payload = Vec::with_capacity(18 + files.len() * 34);
    payload.extend_from_slice(keyword.as_bytes());
    payload.extend_from_slice(
        &u16::try_from(files.len())
            .expect("a batch never exceeds the 50-file cap")
            .to_le_bytes(),
    );
    for file in files {
        payload.extend_from_slice(file.file_id.as_bytes());
        let synthesized = usize::from(file.filename.is_some()) + usize::from(file.size.is_some());
        payload.push(
            u8::try_from(synthesized + file.tags.len())
                .expect("a publish row never exceeds 255 tags"),
        );
        if let Some(name) = &file.filename {
            payload.extend_from_slice(
                &Tag::new(
                    TagName::length_prefixed_id(TAG_FILENAME),
                    TagValue::String(Ed2kText::from_utf8(name.clone())),
                )
                .encode(),
            );
        }
        if let Some(size) = file.size {
            // FILESIZE rides aMule's integer-tag compaction on the *publisher*
            // emit (`CTagVarInt`, `Search.cpp:1714`), the same writer that
            // narrows SOURCES: the captured aMule `0x43` carries `65536` as a
            // four-byte `0x03` tag because it exceeds `u16`, a smaller file
            // narrows further, and a file past 4 GiB widens to `UINT64`.
            // (The storer's *serve* re-emits a fixed `U32` below 4 GiB — a
            // separate leg.)
            payload.extend_from_slice(
                &Tag::new(
                    TagName::length_prefixed_id(TAG_FILESIZE),
                    TagValue::compact_uint64(size),
                )
                .encode(),
            );
        }
        for tag in &file.tags {
            payload.extend_from_slice(&tag.encode());
        }
    }
    KadEnvelope::plain(KADEMLIA2_PUBLISH_KEY_REQ, payload)
}

/// Encode a `KADEMLIA2_SEARCH_KEY_REQ` (`0x33`) — the **Kad Requester**'s
/// counterpart to [`decode_search_key_req`]. `[keyword ID (16)][start position
/// (2 LE)]`, the top bit set and the tree appended iff `tree` is `Some`. The v1
/// requester always passes `start_position = 0` and `tree = None` (aMule's
/// unfiltered emit — plain lead keyword, no restrictive flag); the tree seam
/// exists for filtered search.
#[must_use]
pub fn encode_search_key_req(
    keyword: KadId,
    start_position: u16,
    tree: Option<&SearchTree>,
) -> KadEnvelope {
    let mut payload = Vec::with_capacity(18);
    payload.extend_from_slice(keyword.as_bytes());
    let raw_start = (start_position & 0x7FFF) | if tree.is_some() { 0x8000 } else { 0 };
    payload.extend_from_slice(&raw_start.to_le_bytes());
    if let Some(tree) = tree {
        payload.extend_from_slice(&tree.encode());
    }
    KadEnvelope::plain(KADEMLIA2_SEARCH_KEY_REQ, payload)
}

/// Decode a `KADEMLIA2_SEARCH_RES` (`0x3B`) answering a keyword target into its
/// **Kad Keyword Result Row**s — the **Kad Requester**'s counterpart to
/// [`encode_search_key_res`]. `[sender ID (16)][keyword ID (16)][row count (2
/// LE)]` then, per row, `[file ID (16)][tag count (1)][tags]`; every tag is kept
/// verbatim (FILENAME, FILESIZE, and `TAG_PUBLISHINFO` included — the requester
/// surfaces the dual form). The sender and keyword header identities are
/// validated and skipped: the node already matched the envelope's target to the
/// active search before calling this (sibling of `decode_source_result`).
pub fn decode_search_key_res(
    envelope: &KadEnvelope,
) -> Result<Vec<KeywordResultRow>, KeywordDecodeError> {
    if envelope.opcode() != KADEMLIA2_SEARCH_RES {
        return Err(KeywordDecodeError::NotASearchKeyRes {
            opcode: envelope.opcode(),
        });
    }
    let mut cursor = Cursor::new(envelope.payload());
    cursor.take(KadId::BYTE_LEN, "keyword result sender ID")?;
    cursor.take(KadId::BYTE_LEN, "keyword result keyword ID")?;
    let count = cursor.read_u16_le("keyword result count")?;
    // Bound the row pre-allocation to what the remaining bytes could actually
    // hold: the smallest possible row is a 16-byte file ID plus a one-byte
    // (zero) tag count, so a tiny malformed datagram declaring a huge count
    // cannot force a multi-megabyte reservation. Loop correctness is unchanged
    // — a genuine short count still fails the per-row reads below.
    const MIN_ROW_BYTES: usize = KadId::BYTE_LEN + 1;
    let capacity = usize::from(count).min(cursor.remaining().len() / MIN_ROW_BYTES);
    let mut rows = Vec::with_capacity(capacity);
    for _ in 0..count {
        let file_id = cursor.read_kad_id("keyword result file ID")?;
        let tag_count = cursor.read_u8("keyword result tag count")?;
        let mut tags = Vec::with_capacity(usize::from(tag_count));
        for _ in 0..tag_count {
            let (tag, consumed) = Tag::decode_prefix(cursor.remaining()).map_err(|_| {
                KeywordDecodeError::Malformed {
                    reason: "keyword result tag is truncated or malformed",
                }
            })?;
            cursor.advance(consumed);
            tags.push(tag);
        }
        rows.push(KeywordResultRow { file_id, tags });
    }
    if !cursor.is_exhausted() {
        return Err(KeywordDecodeError::Malformed {
            reason: "trailing bytes after the declared keyword result count",
        });
    }
    Ok(rows)
}

/// A forward-only byte reader whose errors carry the static field name — the
/// per-module idiom (`messages`, `source_result`, `search_tree`).
pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], KeywordDecodeError> {
        let end = self
            .position
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(KeywordDecodeError::Malformed { reason: field })?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, KeywordDecodeError> {
        Ok(self.take(1, field)?[0])
    }

    fn read_u16_le(&mut self, field: &'static str) -> Result<u16, KeywordDecodeError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_kad_id(&mut self, field: &'static str) -> Result<KadId, KeywordDecodeError> {
        let bytes = self.take(KadId::BYTE_LEN, field)?;
        let mut id = [0u8; KadId::BYTE_LEN];
        id.copy_from_slice(bytes);
        Ok(KadId::from_bytes(id))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn advance(&mut self, len: usize) {
        self.position = (self.position + len).min(self.bytes.len());
    }

    const fn is_exhausted(&self) -> bool {
        self.position >= self.bytes.len()
    }
}
