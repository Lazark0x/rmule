//! `OP_QUERY_MORE_RESULT` (0x21): ask the connected server for the next page
//! of the last search this link sent. Empty body — the opcode is the whole
//! request, and it names no search: the server keeps one search's remaining
//! rows per connection, replaced by every search request (ed2k-server
//! `connection.rs:68,435,519-540`), and eMule sends it only for its one
//! current search (`SearchResultsWnd.cpp:1273-1289`).

use rmule_primitives::empty_body_codec;

use crate::{Ed2kError, Opcode};

empty_body_codec! {
    /// `OP_QUERY_MORE_RESULT` (0x21): the next page of the link's last search.
    /// The opcode is the whole request.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    QueryMoreResults, Ed2kError, Opcode::QueryMoreResult.as_u8(), "OP_QUERY_MORE_RESULT"
}
