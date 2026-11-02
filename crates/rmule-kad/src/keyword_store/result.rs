//! What a keyword search hands back: one [`KeywordResultRow`] per indexed file
//! with its aggregated tags, and the [`KadKeywordResult`] a requester folds
//! into its search stream.

use rmule_primitives::{Tag, TagValue};

use crate::KadId;

use super::KadAichRootReport;
use super::wire::{file_size_tag_value, numeric_tag_scalar};
use super::{
    KADEMLIA_VERSION9_50A, TAG_FILENAME, TAG_FILESIZE, TAG_FILETYPE, TAG_PUBLISHINFO, TAG_SOURCES,
};

/// One served keyword-search row, ready for wire encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeywordResultRow {
    /// The file's Kad ID.
    pub file_id: KadId,
    /// Its tags in wire order, ready to encode as sent.
    pub tags: Vec<Tag>,
    /// The AICH roots of its `TAG_KADAICHHASHRESULT`, written after the tags;
    /// empty when the storer wrote none. Kept beside the tags because the tag
    /// model has no `BSOB` (ADR-0053).
    pub aich_roots: Vec<KadAichRootReport>,
}

/// The typed projection of a **Kad Keyword Result Row** the **Kad Requester**
/// surfaces into the one search stream (ADR-0062's "typed" half of the dual
/// form). Core merges these by [`file_id`](Self::file_id) and ranks on the
/// popularity/publisher/trust word packed into [`publish_info`](Self::publish_info).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KadKeywordResult {
    /// The file's Kad ID — the key rows from different storers merge on.
    pub file_id: KadId,
    /// `TAG_FILENAME` — the storer's popularity-winning name.
    pub filename: Option<String>,
    /// `TAG_FILESIZE`, `UINT64` past 4 GiB.
    pub size: Option<u64>,
    /// `TAG_FILETYPE` — the publisher's classification, absent when the file
    /// does not classify.
    pub file_type: Option<String>,
    /// `TAG_SOURCES` — the complete-sources count.
    pub complete_sources: Option<u32>,
    /// `TAG_PUBLISHINFO` = `(names<<24)|(publishers<<16)|(trust*100)`.
    pub publish_info: Option<u32>,
    /// The AICH roots the storer says the file's publishers reported, each
    /// with how many did — kept from a storer at Kad v9 or later only, as eMule
    /// keeps them (ADR-0038).
    pub aich_roots: Vec<KadAichRootReport>,
}

impl KadKeywordResult {
    /// How many publishers the storer tracks for the file: the middle byte
    /// of `TAG_PUBLISHINFO`, the count a root's popularity is a share of.
    #[must_use]
    pub fn publishers(&self) -> Option<u8> {
        self.publish_info.map(|word| word.to_be_bytes()[1])
    }
}

impl KeywordResultRow {
    /// Project the served tags into the typed search-stream surface, reading
    /// FILENAME/FILESIZE/FILETYPE/SOURCES/`TAG_PUBLISHINFO`, and the AICH
    /// roots when the answering storer is at `storer_kad_version` 9 or later
    /// (eMule 0.70b `Search.cpp:1127-1146`); the verbatim `tags` stay for any
    /// caller that needs the untyped rest.
    #[must_use]
    pub fn project(&self, storer_kad_version: u8) -> KadKeywordResult {
        let mut result = KadKeywordResult {
            file_id: self.file_id,
            filename: None,
            size: None,
            file_type: None,
            complete_sources: None,
            publish_info: None,
            aich_roots: if storer_kad_version >= KADEMLIA_VERSION9_50A {
                self.aich_roots.clone()
            } else {
                Vec::new()
            },
        };
        for tag in &self.tags {
            let Some(id) = tag.name().id() else {
                continue;
            };
            match id {
                TAG_FILENAME => {
                    if let TagValue::String(text) = tag.value() {
                        result.filename = Some(text.to_display_string());
                    }
                }
                TAG_FILESIZE => result.size = file_size_tag_value(tag.value()),
                TAG_FILETYPE => {
                    if let TagValue::String(text) = tag.value() {
                        result.file_type = Some(text.to_display_string());
                    }
                }
                TAG_SOURCES => result.complete_sources = numeric_tag_scalar(tag.value()),
                TAG_PUBLISHINFO => result.publish_info = numeric_tag_scalar(tag.value()),
                _ => {}
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Search-expression tree evaluation
// ---------------------------------------------------------------------------
