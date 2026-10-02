//! Search-expression **tree codec** grammar KATs (ADR-0062, breakdown 1).
//!
//! The codec is symmetric (encode + decode) even though the v1 node emits only
//! plain keyword: golden vectors, mesh-sim adversarial storers, and
//! filtered-search captures all need the encoder.
//!
//! ## Provenance
//!
//! The node bytes (`0x00` boolean / `0x01` string / `0x02` meta-tag / `0x03`
//! u32 / `0x08` u64), the boolean operators (`0x00` AND / `0x01` OR / `0x02`
//! NOT, **all binary**), the `u16`-length UTF-8 string form, the depth-24 cap,
//! and unknown-node/operator rejection are ADR-0062-pinned (aMule
//! `KademliaUDPListener` line cites). The exact field layout *within* the
//! meta-tag and numeric terms (value/operator/name order, the operator→relation
//! map) is the surface capture recipe 4 (aMule searches with a restrictive tree
//! → rmule serves) pins; here it is exercised for round-trip consistency, with
//! the operator byte and meta-tag name preserved verbatim rather than mapped.

use rmule_kad::search_tree::{BoolOp, MAX_TREE_DEPTH, SearchTree, SearchTreeDecodeError};

fn term(text: &str) -> SearchTree {
    SearchTree::Term(text.to_owned())
}

#[test]
fn round_trips_a_string_term() {
    let tree = term("hello");
    // `[0x01][len u16 LE][utf8]`
    let bytes = vec![0x01, 0x05, 0x00, b'h', b'e', b'l', b'l', b'o'];
    assert_eq!(tree.encode(), bytes);
    assert_eq!(SearchTree::decode(&bytes), Ok(tree));
}

#[test]
fn round_trips_boolean_nodes_all_binary_including_not() {
    // `[0x00][op][left][right]` — every boolean node, NOT included, is binary.
    for (op, op_byte) in [(BoolOp::And, 0x00), (BoolOp::Or, 0x01), (BoolOp::Not, 0x02)] {
        let tree = SearchTree::Bool {
            op,
            left: Box::new(term("foo")),
            right: Box::new(term("bar")),
        };
        let bytes = vec![
            0x00, op_byte, // boolean node + operator
            0x01, 0x03, 0x00, b'f', b'o', b'o', // left string term
            0x01, 0x03, 0x00, b'b', b'a', b'r', // right string term
        ];
        assert_eq!(tree.encode(), bytes, "op {op:?}");
        assert_eq!(SearchTree::decode(&bytes), Ok(tree), "op {op:?}");
    }
}

#[test]
fn round_trips_meta_and_numeric_terms() {
    // Meta-tag string term: `[0x02][value str][name str]`, name preserved
    // verbatim (special single-byte tag IDs are not text).
    let meta = SearchTree::MetaTerm {
        value: "movie".to_owned(),
        tag: vec![0x01],
    };
    let meta_bytes = vec![
        0x02, 0x05, 0x00, b'm', b'o', b'v', b'i', b'e', // value
        0x01, 0x00, 0x01, // tag name (len 1, byte 0x01)
    ];
    assert_eq!(meta.encode(), meta_bytes);
    assert_eq!(SearchTree::decode(&meta_bytes), Ok(meta));

    // u32 relation: `[0x03][value u32 LE][op][name str]`, operator preserved.
    let u32rel = SearchTree::U32Relation {
        value: 1000,
        op: 0x00,
        tag: vec![0x02],
    };
    let u32_bytes = vec![
        0x03, 0xE8, 0x03, 0x00, 0x00, // value 1000
        0x00, // operator byte (preserved verbatim)
        0x01, 0x00, 0x02, // tag name
    ];
    assert_eq!(u32rel.encode(), u32_bytes);
    assert_eq!(SearchTree::decode(&u32_bytes), Ok(u32rel));

    // u64 relation: `[0x08][value u64 LE][op][name str]`.
    let u64rel = SearchTree::U64Relation {
        value: 5_000_000_000,
        op: 0x01,
        tag: vec![0x02],
    };
    let u64_bytes = vec![
        0x08, 0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, // value 5_000_000_000
        0x01, // operator byte
        0x01, 0x00, 0x02, // tag name
    ];
    assert_eq!(u64rel.encode(), u64_bytes);
    assert_eq!(SearchTree::decode(&u64_bytes), Ok(u64rel));
}

#[test]
fn round_trips_a_nested_expression() {
    // (foo AND (bar OR baz))
    let tree = SearchTree::Bool {
        op: BoolOp::And,
        left: Box::new(term("foo")),
        right: Box::new(SearchTree::Bool {
            op: BoolOp::Or,
            left: Box::new(term("bar")),
            right: Box::new(term("baz")),
        }),
    };
    assert_eq!(SearchTree::decode(&tree.encode()), Ok(tree));
}

#[test]
fn rejects_an_unknown_node_byte() {
    assert_eq!(
        SearchTree::decode(&[0x05, 0x00]),
        Err(SearchTreeDecodeError::UnknownNode(0x05))
    );
    assert_eq!(
        SearchTree::decode(&[0xFF]),
        Err(SearchTreeDecodeError::UnknownNode(0xFF))
    );
}

#[test]
fn rejects_an_unknown_boolean_operator() {
    // Boolean node with operator byte 0x07 — outside AND/OR/NOT.
    assert_eq!(
        SearchTree::decode(&[0x00, 0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00]),
        Err(SearchTreeDecodeError::UnknownBoolOp(0x07))
    );
}

#[test]
fn rejects_trailing_bytes_after_the_tree() {
    let mut bytes = term("foo").encode();
    bytes.push(0xEE);
    assert_eq!(
        SearchTree::decode(&bytes),
        Err(SearchTreeDecodeError::TrailingBytes)
    );
}

#[test]
fn rejects_truncated_input() {
    // A string term promising five bytes but carrying three.
    assert_eq!(
        SearchTree::decode(&[0x01, 0x05, 0x00, b'f', b'o', b'o']),
        Err(SearchTreeDecodeError::Truncated("string term bytes"))
    );
    // A boolean node missing its right operand.
    assert!(matches!(
        SearchTree::decode(&[0x00, 0x00, 0x01, 0x03, 0x00, b'f', b'o', b'o']),
        Err(SearchTreeDecodeError::Truncated(_))
    ));
}

#[test]
fn rejects_invalid_utf8_in_a_string_term() {
    // 0xFF 0xFE is not valid UTF-8.
    assert_eq!(
        SearchTree::decode(&[0x01, 0x02, 0x00, 0xFF, 0xFE]),
        Err(SearchTreeDecodeError::InvalidUtf8)
    );
}

/// A left-nested boolean chain whose decode recursion reaches depth `n`.
fn nest(n: usize) -> SearchTree {
    let mut tree = term("aaa");
    for _ in 0..n {
        tree = SearchTree::Bool {
            op: BoolOp::And,
            left: Box::new(tree),
            right: Box::new(term("bbb")),
        };
    }
    tree
}

#[test]
fn enforces_the_depth_cap() {
    // A tree at the cap round-trips; one level deeper is rejected on decode.
    let at_cap = nest(MAX_TREE_DEPTH - 1);
    assert_eq!(SearchTree::decode(&at_cap.encode()), Ok(at_cap.clone()));

    let too_deep = nest(MAX_TREE_DEPTH);
    assert_eq!(
        SearchTree::decode(&too_deep.encode()),
        Err(SearchTreeDecodeError::TooDeep)
    );
}
