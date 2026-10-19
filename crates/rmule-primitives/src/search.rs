//! Search as the protocol models it: the query a client sends, the result rows
//! it gets back keyed by file hash, where each row came from (a server or Kad),
//! and how rows for one file from several origins fold into a single result.

use crate::{
    AichRootHash, Ed2kFileClass, Ed2kFileLink, Ed2kText, FileHash, PeerSource, PrimitiveError,
    Result, Tag,
};

mod kind;
mod satisfaction;
mod terms;

pub use kind::{RelatedFilesQuery, SearchQuery};
pub use terms::QueryFault;

/// A keyword search as the operator stated it (the [`SearchQuery::Keywords`]
/// kind): the phrase plus aMule's five optional
/// constraints (`CSearchList::CSearchParams`, `SearchList.h:57-70`, filled from
/// the extended-search half of `CSearchDlg::StartNewSearch`,
/// `SearchDlg.cpp:455-494`).
///
/// The constraints are **optional in the wire sense**: an absent one contributes
/// no term to the request's expression tree, so a bare phrase encodes exactly as
/// it did before constraints existed. aMule reads "absent" off a zero — its
/// spin controls cannot express "no bound" any other way — while rmule says it
/// in the type.
///
/// Deliberately *not* here: `FT_COMPLETE_SOURCES`, media bitrate, and media
/// length. aMule's dialog has no controls for them and the code that would send
/// them sits inside `#if 0` (`SearchList.cpp:783-803`); emitting them would be
/// divergence, not parity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeywordQuery {
    phrase: Ed2kText,
    file_type: Option<Ed2kFileClass>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    min_availability: Option<u32>,
    extension: Option<Ed2kText>,
}

/// What identifies one file across every result row that mentions it: its hash
/// *and* its size.
///
/// The pair is the key, not the hash alone, because a hash collision across
/// sizes would otherwise fold two different files into one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SearchResultKey {
    file_hash: FileHash,
    file_size: u64,
}

/// Which discovery surface reported a result row. It is not cosmetic: it
/// decides how two reports of the same file combine (see
/// [`SearchResult::merge_aliases_from`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SearchResultOrigin {
    /// An eD2k server answer (TCP `OP_SEARCHRESULT`, UDP `OP_GLOBSEARCHRES`).
    /// Each server counts only the sources *it* knows.
    #[default]
    Ed2kServer,
    /// A Kad keyword answer. Every storer reports the same globally published
    /// count for the file.
    Kad,
}

/// One file as the network reported it, with every alias and source folded in.
///
/// A row is never a single answer: the same file comes back from several
/// servers and storers under different names, and those reports merge here
/// (see [`Self::merge_aliases_from`]) rather than in each front-end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResult {
    file_hash: FileHash,
    file_size: u64,
    names: Vec<Ed2kText>,
    sources: Vec<PeerSource>,
    file_type: Option<Ed2kText>,
    file_format: Option<Ed2kText>,
    reported_availability: Option<u32>,
    /// `FT_COMPLETE_SOURCES` — how many of the reported sources hold the whole
    /// file (aMule `m_completeSourceCount`, `SearchFile.cpp:82`).
    complete_sources: Option<u32>,
    origin: SearchResultOrigin,
    extra_tags: Vec<Tag>,
    /// The qualified AICH root a Kad keyword answer carried for this file
    /// (ADR-0038): the first one a report of it carried.
    kad_aich_root: Option<AichRootHash>,
}

impl KeywordQuery {
    /// A query from its phrase, with no constraints attached.
    ///
    /// # Errors
    /// [`PrimitiveError::InvalidSearchQuery`] if the phrase holds no word —
    /// that would ask a server to match everything — or cannot be sent as
    /// AND-ed words: an unterminated quote, `OR` or `NOT`, or more than eleven
    /// words ([`KeywordQuery::terms`]).
    pub fn new(phrase: Ed2kText) -> Result<Self> {
        terms::lex(phrase.as_bytes())
            .map_err(|fault| PrimitiveError::InvalidSearchQuery { fault })?;

        Ok(Self {
            phrase,
            file_type: None,
            min_size: None,
            max_size: None,
            min_availability: None,
            extension: None,
        })
    }

    /// The words the phrase sends, in order: each is one AND-ed `0x01` term of
    /// the search tree (`docs/protocol/search-request.md`). Whitespace and
    /// parentheses separate words, a double-quoted run is one word with its
    /// quotes, and an explicit `AND` is the join itself.
    #[must_use]
    pub fn terms(&self) -> Vec<Ed2kText> {
        terms::lex(self.phrase.as_bytes())
            .expect("a KeywordQuery's phrase lexed when it was made")
            .into_iter()
            .map(Ed2kText::from_bytes)
            .collect()
    }

    /// The search phrase, never blank.
    #[must_use]
    pub const fn phrase(&self) -> &Ed2kText {
        &self.phrase
    }

    /// The `FT_FILETYPE` constraint, as one of the seven classes aMule's type
    /// dropdown offers (`SearchDlg.cpp:479-487`). What reaches the wire is
    /// [`Ed2kFileClass::search_term`], so Archive and CD-image both go out as
    /// `"Pro"` — aMule folds them the same way, in `CreateSearchData`
    /// (`SearchList.cpp:676-684`), because the network has no term for either.
    #[must_use]
    pub const fn file_type(&self) -> Option<Ed2kFileClass> {
        self.file_type
    }

    /// The smallest file size that satisfies the query, when bounded.
    #[must_use]
    pub const fn min_size(&self) -> Option<u64> {
        self.min_size
    }

    /// The largest file size that satisfies the query, when bounded.
    #[must_use]
    pub const fn max_size(&self) -> Option<u64> {
        self.max_size
    }

    /// The smallest reported source count that satisfies the query, when
    /// bounded.
    #[must_use]
    pub const fn min_availability(&self) -> Option<u32> {
        self.min_availability
    }

    /// The required file extension, when the operator named one.
    #[must_use]
    pub const fn extension(&self) -> Option<&Ed2kText> {
        self.extension.as_ref()
    }

    /// Constrain to one file class.
    #[must_use]
    pub const fn with_file_type(mut self, file_type: Ed2kFileClass) -> Self {
        self.file_type = Some(file_type);
        self
    }

    /// Constrain to files of at least `min_size` bytes. Zero is no bound: aMule
    /// and eMule write a size term only for a non-zero value
    /// (`SearchList.cpp:1546-1550`).
    #[must_use]
    pub const fn with_min_size(mut self, min_size: u64) -> Self {
        self.min_size = if min_size == 0 { None } else { Some(min_size) };
        self
    }

    /// Constrain to files of at most `max_size` bytes. Zero is no bound, as for
    /// the minimum.
    #[must_use]
    pub const fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_size = if max_size == 0 { None } else { Some(max_size) };
        self
    }

    /// Constrain to files with at least `min_availability` reported sources.
    /// Zero is no floor.
    #[must_use]
    pub const fn with_min_availability(mut self, min_availability: u32) -> Self {
        self.min_availability = if min_availability == 0 {
            None
        } else {
            Some(min_availability)
        };
        self
    }

    /// Constrain to one file extension, with or without its leading dot: the
    /// dot is dropped, as eMule drops it (`SearchParamsWnd.cpp:945`), since
    /// `FT_FILEFORMAT` values are bare (`mp3`). An extension that is only dots
    /// is no constraint.
    #[must_use]
    pub fn with_extension(mut self, extension: Ed2kText) -> Self {
        let bare = extension
            .as_bytes()
            .iter()
            .position(|&byte| byte != b'.')
            .map(|start| Ed2kText::from_bytes(extension.as_bytes()[start..].to_vec()));
        self.extension = bare;
        self
    }
}

impl SearchResultKey {
    /// The key for a file of this hash and size.
    #[must_use]
    pub const fn new(file_hash: FileHash, file_size: u64) -> Self {
        Self {
            file_hash,
            file_size,
        }
    }

    /// The file's hash.
    #[must_use]
    pub const fn file_hash(self) -> FileHash {
        self.file_hash
    }

    /// The file's size in bytes.
    #[must_use]
    pub const fn file_size(self) -> u64 {
        self.file_size
    }
}

impl SearchResult {
    /// A row from what every answer carries: the file's identity, the names it
    /// was offered under, and the sources reported for it.
    ///
    /// # Errors
    /// [`PrimitiveError::InvalidSearchResult`] if `names` is empty — a row
    /// with nothing to display is not worth handing a caller — and
    /// [`PrimitiveError::FileSizeAboveLimit`] for a file larger than eD2k
    /// addresses, and [`PrimitiveError::FileSizeZero`] for a file of zero
    /// bytes, which aMule drops from every answer (`SearchList.cpp:561-569`).
    pub fn new(
        file_hash: FileHash,
        file_size: u64,
        names: Vec<Ed2kText>,
        sources: Vec<PeerSource>,
    ) -> Result<Self> {
        if file_size > crate::MAX_ED2K_FILE_SIZE {
            return Err(PrimitiveError::FileSizeAboveLimit { file_size });
        }
        if file_size == 0 {
            return Err(PrimitiveError::FileSizeZero);
        }
        if names.is_empty() {
            return Err(PrimitiveError::InvalidSearchResult {
                reason: "search result requires at least one name",
            });
        }

        Ok(Self {
            file_hash,
            file_size,
            names,
            sources,
            file_type: None,
            file_format: None,
            reported_availability: None,
            complete_sources: None,
            origin: SearchResultOrigin::Ed2kServer,
            extra_tags: Vec::new(),
            kad_aich_root: None,
        })
    }

    /// The file's hash.
    #[must_use]
    pub const fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// The file's size in bytes.
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Every name this file was offered under, first report first.
    #[must_use]
    pub fn names(&self) -> &[Ed2kText] {
        &self.names
    }

    /// The name to show: the first one reported. Always present — a row
    /// cannot be built without one.
    #[must_use]
    pub fn primary_name(&self) -> &Ed2kText {
        &self.names[0]
    }

    /// The sources reported for this file, deduplicated across answers.
    #[must_use]
    pub fn sources(&self) -> &[PeerSource] {
        &self.sources
    }

    /// The `FT_FILETYPE` tag's text, when an answer carried one. Usually
    /// absent — see [`Self::file_class`] for what to display instead.
    #[must_use]
    pub const fn file_type(&self) -> Option<&Ed2kText> {
        self.file_type.as_ref()
    }

    /// The `FT_FILEFORMAT` tag's text (an extension), when an answer carried
    /// one.
    #[must_use]
    pub const fn file_format(&self) -> Option<&Ed2kText> {
        self.file_format.as_ref()
    }

    /// How many sources the answering surfaces claimed, folded by
    /// [`Self::merge_aliases_from`]'s rule. A claim, not a measurement.
    #[must_use]
    pub const fn reported_availability(&self) -> Option<u32> {
        self.reported_availability
    }

    /// How many of the reported sources hold the whole file.
    #[must_use]
    pub const fn complete_sources(&self) -> Option<u32> {
        self.complete_sources
    }

    /// Which surface reported this row — and, once rows have merged, which
    /// rule its counts fold by.
    #[must_use]
    pub const fn origin(&self) -> SearchResultOrigin {
        self.origin
    }

    /// The row's file class for a *Type* column: the primary name's extension,
    /// falling back to the `FT_FILETYPE` tag for a name that does not classify.
    ///
    /// aMule derives its Type column from the **name alone**
    /// (`SearchListCtrl.cpp:238` → `GetFiletypeByName`) and prints "Any" when
    /// that fails. The name deserves to go first for a reason beyond parity:
    /// it is the *finer* signal. The wire term can only say one of five things
    /// (`GetED2KFileTypeSearchTerm` folds archives and CD-images into `"Pro"`),
    /// so trusting a tag over an extension would demote `distro.iso` from
    /// CD-image to program.
    ///
    /// The tag still earns its place as the fallback, because it is the only
    /// signal an extension-less name has — and it is genuinely rare: eserver
    /// never emits `FT_FILETYPE` (an audit of its search answers found none, and
    /// the captured Lugdunum answer in `rmule-ed2k`'s `search_packets` carries
    /// four tags, none of them the type), and aMule omits it for files it cannot
    /// classify (a capture against aMule corrected ADR-0062 here). Absence is
    /// the norm; the extension is the workhorse.
    #[must_use]
    pub fn file_class(&self) -> Option<Ed2kFileClass> {
        Ed2kFileClass::from_name_bytes(self.primary_name().as_bytes()).or_else(|| {
            self.file_type
                .as_ref()
                .and_then(|tag| tag.try_as_str().ok())
                .and_then(Ed2kFileClass::from_type_tag)
        })
    }

    /// Every tag the answer carried that this crate does not type, kept so a
    /// later rmule can read it without a re-capture (ADR-0018).
    #[must_use]
    pub fn extra_tags(&self) -> &[Tag] {
        &self.extra_tags
    }

    /// This row's identity, for grouping reports of the same file.
    #[must_use]
    pub const fn key(&self) -> SearchResultKey {
        SearchResultKey::new(self.file_hash, self.file_size)
    }

    /// Attach the `FT_FILETYPE` tag's text.
    #[must_use]
    pub fn with_file_type(mut self, file_type: Ed2kText) -> Self {
        self.file_type = Some(file_type);
        self
    }

    /// Attach the `FT_FILEFORMAT` tag's text.
    #[must_use]
    pub fn with_file_format(mut self, file_format: Ed2kText) -> Self {
        self.file_format = Some(file_format);
        self
    }

    /// Attach the reported source count.
    #[must_use]
    pub const fn with_reported_availability(mut self, availability: u32) -> Self {
        self.reported_availability = Some(availability);
        self
    }

    /// Attach the complete-source count.
    #[must_use]
    pub const fn with_complete_sources(mut self, complete_sources: u32) -> Self {
        self.complete_sources = Some(complete_sources);
        self
    }

    /// Mark which surface reported this row; new rows assume an eD2k server.
    #[must_use]
    pub const fn with_origin(mut self, origin: SearchResultOrigin) -> Self {
        self.origin = origin;
        self
    }

    /// Attach the AICH root a Kad keyword answer qualified for this file
    /// (ADR-0038). Which roots qualify is the caller's rule, not this row's.
    #[must_use]
    pub const fn with_kad_aich_root(mut self, root: AichRootHash) -> Self {
        self.kad_aich_root = Some(root);
        self
    }

    /// The qualified AICH root a Kad keyword answer carried for this file, the
    /// root a download started from this row trusts until its peers contest it
    /// (ADR-0038). Never part of [`Self::to_file_link`]: a link's `h=` ranks
    /// above it.
    #[must_use]
    pub const fn kad_aich_root(&self) -> Option<AichRootHash> {
        self.kad_aich_root
    }

    /// Attach the untyped tags an answer carried.
    #[must_use]
    pub fn with_extra_tags(mut self, extra_tags: Vec<Tag>) -> Self {
        self.extra_tags = extra_tags;
        self
    }

    /// Fold another report of the same file into this row: union the names,
    /// sources and untyped tags, take the first non-empty typed tag and Kad
    /// AICH root, and combine the counts by origin (sum across servers, max
    /// once Kad is involved — see `merge_counts`).
    ///
    /// A report of a *different* file is ignored rather than rejected, so a
    /// caller grouping rows cannot corrupt one by mis-grouping.
    pub fn merge_aliases_from(&mut self, other: &Self) {
        if self.key() != other.key() {
            return;
        }
        debug_assert_eq!(self.key(), other.key());

        for name in &other.names {
            if !self.names.contains(name) {
                self.names.push(name.clone());
            }
        }

        for source in &other.sources {
            if !self.sources.contains(source) {
                self.sources.push(*source);
            }
        }

        if self.file_type.is_none() {
            self.file_type.clone_from(&other.file_type);
        }
        if self.file_format.is_none() {
            self.file_format.clone_from(&other.file_format);
        }
        if self.kad_aich_root.is_none() {
            self.kad_aich_root = other.kad_aich_root;
        }
        self.reported_availability = merge_counts(
            self.origin,
            other.origin,
            self.reported_availability,
            other.reported_availability,
        );
        self.complete_sources = merge_counts(
            self.origin,
            other.origin,
            self.complete_sources,
            other.complete_sources,
        );
        // A row that started as one surface's and absorbed the other's is
        // mixed; keep the Kad marker so a third report also folds by `max`
        // rather than adding a global count onto a per-server one.
        if other.origin == SearchResultOrigin::Kad {
            self.origin = SearchResultOrigin::Kad;
        }
        for tag in &other.extra_tags {
            if !self.extra_tags.contains(tag) {
                self.extra_tags.push(tag.clone());
            }
        }
    }

    /// The `ed2k://` link for this row, built from its primary name, hash and
    /// size. No part hash set or AICH root — a search answer carries neither,
    /// so the link resolves but does not verify. No IPv6 source hint either: a
    /// search row names its sources by count, never by address.
    #[must_use]
    pub fn to_file_link(&self) -> Ed2kFileLink {
        Ed2kFileLink {
            name: self.primary_name().clone(),
            size: self.file_size,
            file_hash: self.file_hash,
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        }
    }
}

/// Combine two reports of the same file's source count, aMule's
/// `CSearchFile::MergeResults` rule (`SearchFile.cpp:141-150`, restated for
/// grouped rows at `:255-263`): **sum** across eD2k servers, because each
/// server counts only the peers logged in to it, and **max** as soon as Kad is
/// involved, because every storer republishes the same global count.
///
/// aMule never has to mix the two — a search there is either a server search
/// or a Kad search. rmule merges both producers into one result set
/// (ADR-0051/ADR-0062), so a mixed pair takes the safe side of aMule's rule:
/// `max`, which cannot inflate a count by adding a global figure onto a
/// per-server one.
fn merge_counts(
    left_origin: SearchResultOrigin,
    right_origin: SearchResultOrigin,
    left: Option<u32>,
    right: Option<u32>,
) -> Option<u32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(
            if left_origin == SearchResultOrigin::Ed2kServer
                && right_origin == SearchResultOrigin::Ed2kServer
            {
                left.saturating_add(right)
            } else {
                left.max(right)
            },
        ),
        (value, None) | (None, value) => value,
    }
}
