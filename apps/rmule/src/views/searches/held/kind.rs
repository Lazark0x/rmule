//! **What a held search is**: the three things an entry can stand for, so no
//! caller asks which of several optional fields is set.

use rmule_core::RelatedSearchRefusal;
use rmule_primitives::FileHash;

/// The kind of a held search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::views::searches) enum HeldKind {
    /// A keyword search, sent through core, or one core reported that this
    /// view did not send.
    Keywords,
    /// A **Related-Files Search** about `file`.
    Related {
        file: FileHash,
        /// Why core refused it before it started, read from
        /// [`UiState::refused_searches`](crate::state::UiState::refused_searches)
        /// by the entry's id.
        refused: Option<RelatedSearchRefusal>,
    },
    /// Never sent, because no core was there to send it through: `why`, in
    /// the words the entry shows. `related` is the file when the search that
    /// was asked for was a Related-Files Search.
    NotSent {
        why: String,
        related: Option<FileHash>,
    },
}

impl HeldKind {
    /// The file a Related-Files Search asks about, sent or not.
    pub(in crate::views::searches) const fn related_file(&self) -> Option<FileHash> {
        match self {
            Self::Related { file, .. } => Some(*file),
            Self::NotSent { related, .. } => *related,
            Self::Keywords => None,
        }
    }

    /// Why core refused the search before it started, once it has.
    pub(in crate::views::searches) const fn refused(&self) -> Option<RelatedSearchRefusal> {
        match self {
            Self::Related { refused, .. } => *refused,
            Self::Keywords | Self::NotSent { .. } => None,
        }
    }

    /// Why the search was never sent, if it was not.
    pub(in crate::views::searches) fn not_sent(&self) -> Option<&str> {
        match self {
            Self::NotSent { why, .. } => Some(why),
            Self::Keywords | Self::Related { .. } => None,
        }
    }

    /// Nothing runs for this entry: core refused it, or it was never sent.
    pub(in crate::views::searches) const fn never_started(&self) -> bool {
        matches!(
            self,
            Self::Related {
                refused: Some(_),
                ..
            } | Self::NotSent { .. }
        )
    }
}
