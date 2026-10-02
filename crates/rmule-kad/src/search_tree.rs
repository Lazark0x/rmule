//! The Kad keyword **search-expression tree codec** (ADR-0062).
//!
//! Symmetric — encode + decode both — because golden vectors, mesh-sim
//! adversarial storers, and filtered-search captures all need the encoder even
//! though rmule's v1 node emits only a plain keyword (no tree). The storer
//! (ADR-0062 breakdown 2) parses and evaluates full trees; no tree-emitting
//! search API calls it yet, so the encode seam exists unused.
//!
//! ## Grammar
//!
//! A node is one byte, pre-order and recursive
//! (`CreateSearchExpressionTree`, KademliaUDPListener.cpp#L780):
//!
//! - `0x00` boolean — an operator byte (`0x00` AND / `0x01` OR / `0x02` NOT)
//!   then **two** operands; aMule treats all three as binary, NOT included.
//! - `0x01` string term — a `u16`-length UTF-8 string.
//! - `0x02` meta-tag term — a string value qualified by a meta-tag name.
//! - `0x03` / `0x08` numeric relation — a `u32` / `u64` value, an operator
//!   byte, and a meta-tag name.
//!
//! Recursion is capped at depth [`MAX_TREE_DEPTH`] (#L784); an unknown node
//! byte or boolean operator kills the parse, and trailing bytes are rejected.
//!
//! ## Provenance
//!
//! Node bytes, boolean operators, the string form, the depth cap, and the
//! rejection rules are ADR-0062-pinned. The field layout *within* the meta-tag
//! and numeric terms — value/operator/name order, and the numeric
//! operator→relation map (#L873) — is the surface capture recipe 4 (aMule
//! searches with a restrictive tree → rmule serves) pins. Pending that, the
//! numeric operator byte and the meta-tag name are preserved **verbatim**
//! rather than mapped, so the codec is byte-faithful regardless of the eventual
//! semantic map, and round-trip is guaranteed.

/// Maximum search-expression recursion depth (KademliaUDPListener.cpp#L784):
/// a tree nested deeper is rejected on decode.
pub const MAX_TREE_DEPTH: usize = 24;

const NODE_BOOL: u8 = 0x00;
const NODE_STRING: u8 = 0x01;
const NODE_META: u8 = 0x02;
const NODE_U32: u8 = 0x03;
const NODE_U64: u8 = 0x08;

const OP_AND: u8 = 0x00;
const OP_OR: u8 = 0x01;
const OP_NOT: u8 = 0x02;

/// The boolean combinator of a `0x00` node. All three are binary (NOT carries
/// two operands, matching aMule).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BoolOp {
    /// Both operands must match.
    And,
    /// Either operand may match.
    Or,
    /// The left operand must match and the right must not — aMule's NOT is
    /// binary, not a negation of one operand.
    Not,
}

impl BoolOp {
    const fn as_byte(self) -> u8 {
        match self {
            Self::And => OP_AND,
            Self::Or => OP_OR,
            Self::Not => OP_NOT,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            OP_AND => Some(Self::And),
            OP_OR => Some(Self::Or),
            OP_NOT => Some(Self::Not),
            _ => None,
        }
    }
}

/// One node of a Kad keyword search expression.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SearchTree {
    /// `0x00`: a boolean combinator over two operands.
    Bool {
        /// Which combinator joins the operands.
        op: BoolOp,
        /// The left operand.
        left: Box<SearchTree>,
        /// The right operand.
        right: Box<SearchTree>,
    },
    /// `0x01`: a plain keyword string term. Byte-preserved; the storer
    /// lowercases and re-tokenizes it at evaluation time (not modelled here).
    Term(String),
    /// `0x02`: a string value qualified by a meta-tag name. `tag` is the
    /// length-prefixed name preserved verbatim (special single-byte tag IDs
    /// are not text).
    MetaTerm {
        /// The string the tag must carry.
        value: String,
        /// The tag name, length-prefixed and byte-preserved — single-byte tag
        /// IDs are not text and must not be re-encoded as such.
        tag: Vec<u8>,
    },
    /// `0x03`: a `u32` numeric relation. `op` is the relation operator byte,
    /// preserved verbatim (its semantic map is capture-pending, recipe 4).
    U32Relation {
        /// The value compared against.
        value: u32,
        /// The relation operator byte, preserved verbatim — its meaning is
        /// capture-pending, so it is carried rather than interpreted.
        op: u8,
        /// The tag name, byte-preserved.
        tag: Vec<u8>,
    },
    /// `0x08`: a `u64` numeric relation.
    U64Relation {
        /// The value compared against.
        value: u64,
        /// The relation operator byte, preserved verbatim.
        op: u8,
        /// The tag name, byte-preserved.
        tag: Vec<u8>,
    },
}

/// Why a byte string could not be decoded into a [`SearchTree`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SearchTreeDecodeError {
    /// A node byte outside the known grammar (`0x00`/`0x01`/`0x02`/`0x03`/`0x08`).
    UnknownNode(u8),
    /// A boolean operator byte outside AND/OR/NOT.
    UnknownBoolOp(u8),
    /// The tree nests deeper than [`MAX_TREE_DEPTH`].
    TooDeep,
    /// A field ran past the end of the input; carries the field name.
    Truncated(&'static str),
    /// A string term's bytes are not valid UTF-8.
    InvalidUtf8,
    /// Well-formed tree, but bytes remain after it.
    TrailingBytes,
}

impl SearchTree {
    /// Decode one complete search-expression tree; rejects trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SearchTreeDecodeError> {
        let mut cursor = Cursor::new(bytes);
        let tree = decode_node(&mut cursor, 0)?;
        if !cursor.is_exhausted() {
            return Err(SearchTreeDecodeError::TrailingBytes);
        }
        Ok(tree)
    }

    /// Serialize into the pre-order wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Bool { op, left, right } => {
                out.push(NODE_BOOL);
                out.push(op.as_byte());
                left.encode_into(out);
                right.encode_into(out);
            }
            Self::Term(value) => {
                out.push(NODE_STRING);
                push_string(out, value);
            }
            Self::MetaTerm { value, tag } => {
                out.push(NODE_META);
                push_string(out, value);
                push_name(out, tag);
            }
            Self::U32Relation { value, op, tag } => {
                out.push(NODE_U32);
                out.extend_from_slice(&value.to_le_bytes());
                out.push(*op);
                push_name(out, tag);
            }
            Self::U64Relation { value, op, tag } => {
                out.push(NODE_U64);
                out.extend_from_slice(&value.to_le_bytes());
                out.push(*op);
                push_name(out, tag);
            }
        }
    }
}

fn decode_node(cursor: &mut Cursor<'_>, depth: usize) -> Result<SearchTree, SearchTreeDecodeError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SearchTreeDecodeError::TooDeep);
    }
    let node = cursor.read_u8("node byte")?;
    match node {
        NODE_BOOL => {
            let op_byte = cursor.read_u8("boolean operator")?;
            let op =
                BoolOp::from_byte(op_byte).ok_or(SearchTreeDecodeError::UnknownBoolOp(op_byte))?;
            let left = Box::new(decode_node(cursor, depth + 1)?);
            let right = Box::new(decode_node(cursor, depth + 1)?);
            Ok(SearchTree::Bool { op, left, right })
        }
        NODE_STRING => Ok(SearchTree::Term(read_string(cursor)?)),
        NODE_META => Ok(SearchTree::MetaTerm {
            value: read_string(cursor)?,
            tag: read_name(cursor)?,
        }),
        NODE_U32 => Ok(SearchTree::U32Relation {
            value: cursor.read_u32_le("u32 relation value")?,
            op: cursor.read_u8("u32 relation operator")?,
            tag: read_name(cursor)?,
        }),
        NODE_U64 => Ok(SearchTree::U64Relation {
            value: cursor.read_u64_le("u64 relation value")?,
            op: cursor.read_u8("u64 relation operator")?,
            tag: read_name(cursor)?,
        }),
        other => Err(SearchTreeDecodeError::UnknownNode(other)),
    }
}

fn read_string(cursor: &mut Cursor<'_>) -> Result<String, SearchTreeDecodeError> {
    let len = usize::from(cursor.read_u16_le("string term length")?);
    let bytes = cursor.take(len, "string term bytes")?;
    String::from_utf8(bytes.to_vec()).map_err(|_| SearchTreeDecodeError::InvalidUtf8)
}

fn read_name(cursor: &mut Cursor<'_>) -> Result<Vec<u8>, SearchTreeDecodeError> {
    let len = usize::from(cursor.read_u16_le("meta-tag name length")?);
    Ok(cursor.take(len, "meta-tag name bytes")?.to_vec())
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    // Clamp to the single-`u16` wire length field: a term past 65535 bytes
    // cannot be expressed, so truncate rather than panic. Length and bytes come
    // from one slice, so they can never desync (the encoder is mesh/test-only;
    // decode-sourced terms are already u16-bounded).
    let bytes = &value.as_bytes()[..value.len().min(u16::MAX as usize)];
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn push_name(out: &mut Vec<u8>, name: &[u8]) {
    let bytes = &name[..name.len().min(u16::MAX as usize)];
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// A forward-only byte reader whose errors carry the static field name — the
/// per-module idiom (`messages`, `source_result`).
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], SearchTreeDecodeError> {
        let end = self
            .position
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(SearchTreeDecodeError::Truncated(field))?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, SearchTreeDecodeError> {
        Ok(self.take(1, field)?[0])
    }

    fn read_u16_le(&mut self, field: &'static str) -> Result<u16, SearchTreeDecodeError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32_le(&mut self, field: &'static str) -> Result<u32, SearchTreeDecodeError> {
        let bytes = self.take(4, field)?;
        let mut word = [0u8; 4];
        word.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(word))
    }

    fn read_u64_le(&mut self, field: &'static str) -> Result<u64, SearchTreeDecodeError> {
        let bytes = self.take(8, field)?;
        let mut word = [0u8; 8];
        word.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(word))
    }

    const fn is_exhausted(&self) -> bool {
        self.position >= self.bytes.len()
    }
}
