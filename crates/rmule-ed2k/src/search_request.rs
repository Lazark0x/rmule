//! `OP_SEARCHREQUEST` (`0x16`) — the search-expression tree aMule builds in
//! `CSearchList::CreateSearchData` and writes through `CSearchExprTarget`
//! (`SearchList.cpp:156-257`, `:665-836`).
//!
//! ## Grammar
//!
//! Each node is a one-byte kind, pre-order:
//!
//! | kind | form | writer |
//! |---|---|---|
//! | `0x00` | boolean: operator byte (`00` AND / `01` OR / `02` NOT), then two operands | `WriteBooleanAND` |
//! | `0x01` | bare phrase: `len16 utf8` | `WriteMetaDataSearchParam(value)` |
//! | `0x02` | string + meta tag: `len16 utf8`, `01 00`, tag id | `WriteMetaDataSearchParam(tag, value)` |
//! | `0x03` | u32 relation: `value32`, operator, `01 00`, tag id | `WriteMetaDataSearchParam(tag, op, value)` |
//! | `0x08` | u64 relation: `value64`, operator, `01 00`, tag id | same, large-value branch |
//!
//! rmule emits `0x00`(AND only), `0x01`, `0x02`, `0x03` and `0x08`. OR and NOT
//! belong to aMule's *parsed* query grammar (`yyparse` over the typed string),
//! which rmule does not offer ([`KeywordQuery::new`] refuses them), so the tree
//! it builds is always the all-AND shape.
//!
//! ## One term per word
//!
//! Each word of the phrase ([`KeywordQuery::terms`]) is its own `0x01` term.
//! eMule and aMule lex the phrase into the same AND-ed words and then join them
//! back into one space-separated term when only ANDs remain (aMule
//! `SearchList.cpp:143-157`); rmule keeps them apart, because ed2k-server looks
//! a term up whole in a word index and a term with a space in it matches
//! nothing, while Lugdunum parses AND-ed `0x01` terms in every eMule query that
//! holds `OR` or `NOT` (`docs/protocol/search-request.md`).
//!
//! ## Term order and the AND interleave
//!
//! Terms go out in aMule's order — the words, `FT_FILETYPE`, min `FT_FILESIZE`,
//! max `FT_FILESIZE`, `FT_SOURCES`, `FT_FILEFORMAT` (`SearchList.cpp:1614-1680`)
//! — with the AND marker written *before every term but the last* rather than
//! as a prefix tree. That is not an accident of implementation: it is the shape
//! "lugdunummaster requested … supposed to take less load on servers"
//! (`SearchList.cpp:728-737`), i.e. `AND "a" AND min=1 max=2`, not
//! `AND AND "a" min=1 max=2`.

use rmule_primitives::{Ed2kFileClass, Ed2kText, KeywordQuery, Packet, PacketProtocol};

use crate::{Ed2kError, Opcode, Result};

const EXPR_BOOL: u8 = 0x00;
const EXPR_PHRASE: u8 = 0x01;
const EXPR_STRING_FILTER: u8 = 0x02;
const EXPR_INTEGER_FILTER: u8 = 0x03;
/// `0x08` — the 64-bit sibling of [`EXPR_INTEGER_FILTER`], written only for a
/// value past `u32::MAX` toward a server that advertised large-file support
/// (`CSearchExprTarget::WriteMetaDataSearchParam`, `SearchList.cpp:215-232`).
const EXPR_INTEGER64_FILTER: u8 = 0x08;
const BOOL_AND: u8 = 0x00;
/// `ed2k_search_compare` (`Constants.h:94-101`). rmule uses only the two
/// "dserver" operators aMule's dialog can produce; `EQUAL`, `GREATER_EQUAL`,
/// `LESS_EQUAL` and `NOTEQUAL` exist on the wire but are eserver-16.45+ and
/// unreachable from any aMule control.
const INTEGER_GREATER: u8 = 0x01;
const INTEGER_LESS: u8 = 0x02;

const FT_FILESIZE: u8 = 0x02;
const FT_FILETYPE: u8 = 0x03;
const FT_FILEFORMAT: u8 = 0x04;
const FT_SOURCES: u8 = 0x15;

/// A search ready for the wire: the operator's [`KeywordQuery`] plus the one
/// fact about the *addressee* that changes the bytes — whether it accepts
/// 64-bit numeric terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchRequest {
    query: KeywordQuery,
    /// `SRV_TCPFLG_LARGEFILES` on the server this request is addressed to
    /// (aMule's `supports64bit`, `SearchList.cpp:340`). False — the
    /// [`SearchRequest::from_query`] default — clamps any size bound past
    /// `u32::MAX` to `0xFFFFFFFF` instead of widening the term, exactly as
    /// aMule does toward a server that never advertised large files.
    large_files: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SearchTerm {
    Word(Ed2kText),
    StringFilter {
        tag_id: u8,
        value: Ed2kText,
    },
    /// A numeric relation. `wide` records which node kind carries it — `0x08`
    /// when set, `0x03` otherwise — so a decoded tree re-encodes to the bytes
    /// it came from.
    IntegerFilter {
        tag_id: u8,
        operator: u8,
        value: u64,
        wide: bool,
    },
}

impl SearchRequest {
    /// A request for a server whose large-file support is unknown or absent:
    /// size bounds past `u32::MAX` clamp. This is the byte-for-byte behaviour
    /// every caller had before 64-bit terms existed.
    #[must_use]
    pub const fn from_query(query: KeywordQuery) -> Self {
        Self {
            query,
            large_files: false,
        }
    }

    /// Address this request to a server that did (or did not) advertise
    /// `SRV_TCPFLG_LARGEFILES` in its `OP_IDCHANGE`.
    #[must_use]
    pub const fn with_large_file_support(mut self, large_files: bool) -> Self {
        self.large_files = large_files;
        self
    }

    /// aMule's `packetUsing64bit` out-parameter (`SearchList.cpp:341`): does
    /// the encoded packet actually carry a `0x08` term?
    ///
    /// It is *not* "the query names a big size" — a big size toward a server
    /// without large-file support clamps, and the resulting packet is plain
    /// 32-bit. The global-UDP sweep gates its per-server skip on this, so a
    /// clamped packet is sent everywhere rather than withheld from servers that
    /// could have answered it (`OnGlobalSearchTimer`, `SearchList.cpp`).
    #[must_use]
    pub fn uses_64bit(&self) -> bool {
        self.large_files
            && [self.query.min_size(), self.query.max_size()]
                .into_iter()
                .flatten()
                .any(|size| size > u64::from(u32::MAX))
    }

    #[must_use]
    /// The query this request encodes.
    pub const fn query(&self) -> &KeywordQuery {
        &self.query
    }

    /// One `FT_FILESIZE` bound, widened or clamped per the addressee's
    /// large-file support (`SearchList.cpp:215-232`): a value past `u32::MAX`
    /// rides a `0x08` node when the server can take it, and is pinned to
    /// `0xFFFFFFFF` in a `0x03` node when it cannot. A bound that fits in 32
    /// bits is always a `0x03` node, whatever the server supports.
    fn size_term(&self, operator: u8, value: u64) -> SearchTerm {
        let large = value > u64::from(u32::MAX);
        SearchTerm::IntegerFilter {
            tag_id: FT_FILESIZE,
            operator,
            value: if large && !self.large_files {
                u64::from(u32::MAX)
            } else {
                value
            },
            wide: large && self.large_files,
        }
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::SearchRequest.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_SEARCHREQUEST",
            });
        }

        let mut cursor = Cursor::new(packet.payload());
        let terms = parse_expression(&mut cursor)?;
        if cursor.remaining() != 0 {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "trailing OP_SEARCHREQUEST bytes",
            });
        }
        query_from_terms(terms)
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut terms: Vec<SearchTerm> = self
            .query
            .terms()
            .into_iter()
            .map(SearchTerm::Word)
            .collect();
        if let Some(file_type) = self.query.file_type() {
            terms.push(SearchTerm::StringFilter {
                tag_id: FT_FILETYPE,
                // ASCII by construction — aMule writes this one term with
                // `WriteMetaDataSearchParamASCII` ("Type is always ascii
                // string", `SearchList.cpp:750`) while every other string in
                // the tree is UTF-8.
                value: Ed2kText::from_utf8(file_type.search_term()),
            });
        }
        if let Some(min_size) = self.query.min_size() {
            terms.push(self.size_term(INTEGER_GREATER, min_size));
        }
        if let Some(max_size) = self.query.max_size() {
            terms.push(self.size_term(INTEGER_LESS, max_size));
        }
        if let Some(min_availability) = self.query.min_availability() {
            terms.push(SearchTerm::IntegerFilter {
                tag_id: FT_SOURCES,
                operator: INTEGER_GREATER,
                value: u64::from(min_availability),
                wide: false,
            });
        }
        if let Some(extension) = self.query.extension() {
            terms.push(SearchTerm::StringFilter {
                tag_id: FT_FILEFORMAT,
                value: extension.clone(),
            });
        }

        let mut payload = Vec::new();
        write_expression(&mut payload, &terms);
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::SearchRequest.as_u8(),
            payload,
        )
    }
}

/// An `OP_SEARCHREQUEST` whose tree is one bare string term (`0x01`, `len16`,
/// the bytes) — the shape eMule and aMule give a phrase with no constraints.
pub(crate) fn phrase_only_packet(phrase: Ed2kText) -> Packet {
    let mut payload = Vec::new();
    write_term(&mut payload, &SearchTerm::Word(phrase));
    Packet::new(
        PacketProtocol::Edonkey,
        Opcode::SearchRequest.as_u8(),
        payload,
    )
}

fn file_type_from_wire_label(value: &Ed2kText) -> Result<Ed2kFileClass> {
    value
        .try_as_str()
        .ok()
        .and_then(Ed2kFileClass::from_type_tag)
        .ok_or(Ed2kError::InvalidPayload {
            opcode: Opcode::SearchRequest.as_u8(),
            reason: "unsupported OP_SEARCHREQUEST file type",
        })
}

fn write_expression(payload: &mut Vec<u8>, terms: &[SearchTerm]) {
    if let Some((first, rest)) = terms.split_first() {
        if !rest.is_empty() {
            payload.push(EXPR_BOOL);
            payload.push(BOOL_AND);
        }
        write_term(payload, first);
        if !rest.is_empty() {
            write_expression(payload, rest);
        }
    }
}

fn write_term(payload: &mut Vec<u8>, term: &SearchTerm) {
    match term {
        SearchTerm::Word(value) => {
            payload.push(EXPR_PHRASE);
            write_len_prefixed_text(payload, value);
        }
        SearchTerm::StringFilter { tag_id, value } => {
            payload.push(EXPR_STRING_FILTER);
            write_len_prefixed_text(payload, value);
            payload.extend_from_slice(&1_u16.to_le_bytes());
            payload.push(*tag_id);
        }
        SearchTerm::IntegerFilter {
            tag_id,
            operator,
            value,
            wide,
        } => {
            if *wide {
                payload.push(EXPR_INTEGER64_FILTER);
                payload.extend_from_slice(&value.to_le_bytes());
            } else {
                // A narrow term's value is `u32`-bounded by construction —
                // `size_term` clamps and `FT_SOURCES` is a `u32` — so the
                // saturation below is unreachable, not a silent truncation.
                payload.push(EXPR_INTEGER_FILTER);
                payload.extend_from_slice(&u32::try_from(*value).unwrap_or(u32::MAX).to_le_bytes());
            }
            payload.push(*operator);
            payload.extend_from_slice(&1_u16.to_le_bytes());
            payload.push(*tag_id);
        }
    }
}

fn write_len_prefixed_text(payload: &mut Vec<u8>, value: &Ed2kText) {
    let len = u16::try_from(value.as_bytes().len()).expect("search text exceeds u16");
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(value.as_bytes());
}

fn parse_expression(cursor: &mut Cursor<'_>) -> Result<Vec<SearchTerm>> {
    let kind = cursor.read_u8()?;
    match kind {
        EXPR_BOOL => {
            let op = cursor.read_u8()?;
            if op != BOOL_AND {
                return Err(Ed2kError::InvalidPayload {
                    opcode: Opcode::SearchRequest.as_u8(),
                    reason: "unsupported OP_SEARCHREQUEST boolean operator",
                });
            }
            let mut left = parse_expression(cursor)?;
            left.extend(parse_expression(cursor)?);
            Ok(left)
        }
        EXPR_PHRASE => Ok(vec![SearchTerm::Word(cursor.read_text()?)]),
        EXPR_STRING_FILTER => {
            let value = cursor.read_text()?;
            let tag_id = cursor.read_one_byte_tag_id()?;
            Ok(vec![SearchTerm::StringFilter { tag_id, value }])
        }
        EXPR_INTEGER_FILTER | EXPR_INTEGER64_FILTER => {
            let wide = kind == EXPR_INTEGER64_FILTER;
            let value = if wide {
                cursor.read_u64()?
            } else {
                u64::from(cursor.read_u32()?)
            };
            let operator = cursor.read_u8()?;
            let tag_id = cursor.read_one_byte_tag_id()?;
            Ok(vec![SearchTerm::IntegerFilter {
                tag_id,
                operator,
                value,
                wide,
            }])
        }
        _ => Err(Ed2kError::InvalidPayload {
            opcode: Opcode::SearchRequest.as_u8(),
            reason: "unsupported OP_SEARCHREQUEST expression kind",
        }),
    }
}

fn query_from_terms(terms: Vec<SearchTerm>) -> Result<SearchRequest> {
    let mut words: Vec<Ed2kText> = Vec::new();
    let mut file_type = None;
    let mut min_size = None;
    let mut max_size = None;
    let mut min_availability = None;
    let mut extension = None;
    // A `0x08` term can only have been written by a counterparty that knew the
    // addressee takes 64-bit values, so seeing one *is* the large-file fact —
    // and carrying it back onto the request is what lets a decoded tree
    // re-encode to the bytes it arrived as.
    let mut large_files = false;

    for term in terms {
        if let SearchTerm::IntegerFilter { wide: true, .. } = term {
            large_files = true;
        }
        match term {
            SearchTerm::Word(value) => words.push(value),
            SearchTerm::StringFilter { tag_id, value } if tag_id == FT_FILETYPE => {
                file_type = Some(file_type_from_wire_label(&value)?);
            }
            SearchTerm::StringFilter { tag_id, value } if tag_id == FT_FILEFORMAT => {
                extension = Some(value);
            }
            SearchTerm::IntegerFilter {
                tag_id,
                operator,
                value,
                ..
            } if tag_id == FT_FILESIZE && operator == INTEGER_GREATER => {
                min_size = Some(value);
            }
            SearchTerm::IntegerFilter {
                tag_id,
                operator,
                value,
                ..
            } if tag_id == FT_FILESIZE && operator == INTEGER_LESS => {
                max_size = Some(value);
            }
            SearchTerm::IntegerFilter {
                tag_id,
                operator,
                value,
                ..
            } if tag_id == FT_SOURCES && operator == INTEGER_GREATER => {
                min_availability =
                    Some(u32::try_from(value).map_err(|_| Ed2kError::InvalidPayload {
                        opcode: Opcode::SearchRequest.as_u8(),
                        reason: "OP_SEARCHREQUEST source count exceeds u32",
                    })?);
            }
            _ => {
                return Err(Ed2kError::InvalidPayload {
                    opcode: Opcode::SearchRequest.as_u8(),
                    reason: "unsupported OP_SEARCHREQUEST first-slice term",
                });
            }
        }
    }

    if words.is_empty() {
        return Err(Ed2kError::InvalidPayload {
            opcode: Opcode::SearchRequest.as_u8(),
            reason: "OP_SEARCHREQUEST missing phrase",
        });
    }
    // The words rejoin as the phrase the lexer would split back into them.
    let phrase = words
        .iter()
        .map(Ed2kText::as_bytes)
        .collect::<Vec<_>>()
        .join(&b' ');
    let mut query = KeywordQuery::new(Ed2kText::from_bytes(phrase))?;
    if let Some(value) = file_type {
        query = query.with_file_type(value);
    }
    if let Some(value) = min_size {
        query = query.with_min_size(value);
    }
    if let Some(value) = max_size {
        query = query.with_max_size(value);
    }
    if let Some(value) = min_availability {
        query = query.with_min_availability(value);
    }
    if let Some(value) = extension {
        query = query.with_extension(value);
    }

    Ok(SearchRequest { query, large_files })
}

struct Cursor<'a> {
    payload: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(payload: &'a [u8]) -> Self {
        Self { payload, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.payload.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes(bytes.try_into().expect("2-byte slice")))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("4-byte slice")))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("8-byte slice")))
    }

    fn read_text(&mut self) -> Result<Ed2kText> {
        let len = usize::from(self.read_u16()?);
        Ok(Ed2kText::from_bytes(self.take(len)?.to_vec()))
    }

    fn read_one_byte_tag_id(&mut self) -> Result<u8> {
        let len = self.read_u16()?;
        if len != 1 {
            return Err(Ed2kError::InvalidPayload {
                opcode: Opcode::SearchRequest.as_u8(),
                reason: "OP_SEARCHREQUEST metadata tag id must be one byte",
            });
        }
        self.read_u8()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(Ed2kError::InvalidPayload {
            opcode: Opcode::SearchRequest.as_u8(),
            reason: "OP_SEARCHREQUEST length overflow",
        })?;
        if end > self.payload.len() {
            return Err(Ed2kError::InvalidPayload {
                opcode: Opcode::SearchRequest.as_u8(),
                reason: "truncated OP_SEARCHREQUEST payload",
            });
        }
        let slice = &self.payload[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}
