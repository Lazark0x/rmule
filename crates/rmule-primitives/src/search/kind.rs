//! The kinds of search query: words, or a file (ADR-0037, the Related-Files
//! Search). The kind is a closed type so every consumer that only
//! understands words — the Kad keyword walk, the Global Search Sweep — takes
//! a [`KeywordQuery`] and cannot be handed a file by mistake.

use crate::{Ed2kText, FileHash};

use super::KeywordQuery;

/// One search as the operator asked for it. Core routes by this kind, never by
/// reading a prefix out of text: a phrase that happens to start with
/// `related:` is still a [`Self::Keywords`] search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchQuery {
    /// A phrase plus optional constraints, asked of the connected server, the
    /// Global Search Sweep and Kad.
    Keywords(KeywordQuery),
    /// A **Related-Files Search**: which files the connected server's users
    /// hold beside this one. Connected server, over TCP, only.
    RelatedFiles(RelatedFilesQuery),
}

/// The subject of a **Related-Files Search**: one file, by hash, and the name
/// the operator knows it by.
///
/// Only the hash reaches the wire. The name is for the front-end's query line
/// (`related to: <name>`); it never leaves rmule, so a search for a file does
/// not tell the server what the operator calls it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelatedFilesQuery {
    file_hash: FileHash,
    file_name: Ed2kText,
}

impl RelatedFilesQuery {
    /// A related-files query for the file with this hash, displayed as
    /// `file_name`.
    #[must_use]
    pub const fn new(file_hash: FileHash, file_name: Ed2kText) -> Self {
        Self {
            file_hash,
            file_name,
        }
    }

    /// The hash the server is asked about.
    #[must_use]
    pub const fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// The name for display. Never sent.
    #[must_use]
    pub const fn file_name(&self) -> &Ed2kText {
        &self.file_name
    }
}

impl From<KeywordQuery> for SearchQuery {
    fn from(query: KeywordQuery) -> Self {
        Self::Keywords(query)
    }
}

impl From<RelatedFilesQuery> for SearchQuery {
    fn from(query: RelatedFilesQuery) -> Self {
        Self::RelatedFiles(query)
    }
}
