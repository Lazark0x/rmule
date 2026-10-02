//! Matching a decoded search expression against an indexed entry: the boolean
//! tree walk, the string, meta and numeric term tests, and the relation
//! operators a `0x33` may carry. An unknown operator is rejected before any
//! matching runs — a query rmule cannot evaluate is never half-answered.

use rmule_primitives::{TagName, TagValue};

use crate::search_tree::{BoolOp, SearchTree};

use super::entry::KeywordEntry;
use super::{TAG_FILEFORMAT, TAG_FILESIZE};

/// A numeric-relation node used an operator byte outside aMule's known
/// `=`/`>`/`<`/`>=`/`<=`/`<>` map (`0x00..=0x05`). aMule fails the **whole**
/// search expression's parse for this
/// (`CreateSearchExpressionTree`'s bounds check on `mmop`) — the tree is
/// never evaluated against any entry, not even branches that don't contain
/// the bad operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownSearchOperator(pub u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelationOp {
    Eq,
    Gt,
    Lt,
    Ge,
    Le,
    Ne,
}

impl RelationOp {
    /// aMule's numeric search-relation operator map
    /// (`CreateSearchExpressionTree`'s `_aOps` table, `KademliaUDPListener.cpp`,
    /// pinned commit `4e8f2b3c3f90cda23765730546b04c684a92e4f5`): `mmop`
    /// `0x00..=0x05` map to `=`, `>`, `<`, `>=`, `<=`, `<>` in that order.
    /// The wire preserves the byte verbatim; any other value is [`None`].
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Eq),
            0x01 => Some(Self::Gt),
            0x02 => Some(Self::Lt),
            0x03 => Some(Self::Ge),
            0x04 => Some(Self::Le),
            0x05 => Some(Self::Ne),
            _ => None,
        }
    }

    /// `stored <relation> query` — the entry's value is the left operand
    /// (aMule: `GetIntTagValue(...) >= searchTerm->tag->GetInt()`).
    const fn compare(self, stored: u64, query: u64) -> bool {
        match self {
            Self::Eq => stored == query,
            Self::Gt => stored > query,
            Self::Lt => stored < query,
            Self::Ge => stored >= query,
            Self::Le => stored <= query,
            Self::Ne => stored != query,
        }
    }
}

/// Walk the whole tree checking every numeric-relation operator byte, without
/// short-circuiting — mirrors aMule validating the entire expression at parse
/// time, before evaluating it against any entry.
pub(super) fn validate_operators(tree: &SearchTree) -> Result<(), UnknownSearchOperator> {
    match tree {
        SearchTree::Bool { left, right, .. } => {
            validate_operators(left)?;
            validate_operators(right)?;
            Ok(())
        }
        SearchTree::Term(_) | SearchTree::MetaTerm { .. } => Ok(()),
        SearchTree::U32Relation { op, .. } | SearchTree::U64Relation { op, .. } => {
            RelationOp::from_byte(*op)
                .map(|_| ())
                .ok_or(UnknownSearchOperator(*op))
        }
    }
}

/// Match a validated tree against a stored entry (`CKeyEntry::
/// SearchTermsMatch`). Only safe to call after [`validate_operators`]
/// succeeded; an unrecognized operator falls back to "no match" rather than
/// panicking.
pub(super) fn matches_tree(entry: &KeywordEntry, tree: &SearchTree) -> bool {
    match tree {
        SearchTree::Bool {
            op: BoolOp::And,
            left,
            right,
        } => matches_tree(entry, left) && matches_tree(entry, right),
        SearchTree::Bool {
            op: BoolOp::Or,
            left,
            right,
        } => matches_tree(entry, left) || matches_tree(entry, right),
        // aMule's NOT is binary, not unary: `left && !right`.
        SearchTree::Bool {
            op: BoolOp::Not,
            left,
            right,
        } => matches_tree(entry, left) && !matches_tree(entry, right),
        SearchTree::Term(text) => matches_string_term(entry, text),
        SearchTree::MetaTerm { value, tag } => matches_meta_term(entry, value, tag),
        SearchTree::U32Relation { value, op, tag } => {
            matches_numeric(entry, u64::from(*value), *op, tag)
        }
        SearchTree::U64Relation { value, op, tag } => matches_numeric(entry, *value, *op, tag),
    }
}

/// `SearchTermsMatch`'s `String` branch: every token of the (lowercased,
/// re-tokenized) search string must occur as a substring of the entry's
/// common filename — aMule's own comment notes this is a substring search,
/// not a tokenized-word match, chosen for speed over the filename side.
fn matches_string_term(entry: &KeywordEntry, text: &str) -> bool {
    let tokens = crate::keyword::search_keywords(text);
    if tokens.is_empty() {
        return false;
    }
    let filename_lower = entry.common_filename().to_lowercase();
    tokens
        .iter()
        .all(|token| filename_lower.contains(token.as_str()))
}

/// `SearchTermsMatch`'s `MetaTag` branch: a string-valued tag match, always
/// case-insensitive. `TAG_FILEFORMAT` (`0x04`) is special-cased to the
/// filename's own extension rather than a stored tag (aMule: the format
/// "is already part of the filename and thus does not need to get published
/// nor stored explicitly").
fn matches_meta_term(entry: &KeywordEntry, value: &str, tag: &[u8]) -> bool {
    let value_lower = value.to_lowercase();
    if tag == [TAG_FILEFORMAT] {
        return entry
            .common_filename()
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.to_lowercase() == value_lower);
    }
    entry.tags.iter().any(|stored| {
        tag_name_matches(stored.name(), tag)
            && matches!(
                stored.value(),
                TagValue::String(text) if text.to_display_string().to_lowercase() == value_lower
            )
    })
}

/// `SearchTermsMatch`'s numeric branches (`OpEqual`/`OpGreater`/…): resolve
/// the operator, then the comparison target — `TAG_FILESIZE` (`0x02`) always
/// resolves to the entry's typed size (aMule's `GetIntTagValue`'s virtual-tag
/// fallback, which for a stored entry always fires since FILESIZE is never
/// left in the verbatim list); anything else scans the verbatim tags by name.
fn matches_numeric(entry: &KeywordEntry, value: u64, op: u8, tag: &[u8]) -> bool {
    let Some(relation) = RelationOp::from_byte(op) else {
        return false;
    };
    let Some(stored) = numeric_tag_value(entry, tag) else {
        return false;
    };
    relation.compare(stored, value)
}

fn numeric_tag_value(entry: &KeywordEntry, tag: &[u8]) -> Option<u64> {
    if tag == [TAG_FILESIZE] {
        return Some(entry.size);
    }
    entry.tags.iter().find_map(|stored| {
        if !tag_name_matches(stored.name(), tag) {
            return None;
        }
        match stored.value() {
            TagValue::U8(byte) => Some(u64::from(*byte)),
            TagValue::U16(short) => Some(u64::from(*short)),
            TagValue::U32(word) => Some(u64::from(*word)),
            TagValue::U64(word) => Some(*word),
            TagValue::String(_) | TagValue::Hash(_) => None,
        }
    })
}

/// A search-tree tag name is the wire's length-prefixed name bytes
/// (`search_tree::SearchTree`'s `tag: Vec<u8>`, preserved verbatim by the codec):
/// a single byte is a compact tag ID, matching `TagName::id()`; anything else
/// is a UTF-8 text name, matching `TagName::text_value()`.
fn tag_name_matches(name: &TagName, wire_tag: &[u8]) -> bool {
    if let [id] = wire_tag {
        name.id() == Some(*id)
    } else {
        std::str::from_utf8(wire_tag).is_ok_and(|text| name.text_value() == Some(text))
    }
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------
