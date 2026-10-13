//! What a download leaves behind between sessions: its [`DownloadLifecycle`],
//! the [`DownloadPaths`] its bytes live at, the [`DownloadMetadata`] a front end
//! shows (and where that metadata came from), and the [`VerifiedPartRecord`]s
//! that let a restart resume instead of re-fetching. The vocabulary only — the
//! stores that persist it live in [`storage`](crate::storage) and `store`.

use std::path::{Path, PathBuf};

use rmule_primitives::{Ed2kFileClass, Ed2kFileLink, Ed2kText, FileHash, PartHash, ServerEndpoint};
use serde::{Deserialize, Serialize};

use crate::{DownloadFailure, DownloadId, VerificationAuthority};

/// The state a download row is in. `Completed` and `Cancelled` are terminal —
/// nothing leaves them — and every other state may go to `Cancelled` or
/// `Failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadLifecycle {
    /// Accepted and stored, but no run has started yet.
    Queued,
    /// The operator wants it running: a run is on the wire, or core starts
    /// one at attach. Quit and a crash leave it as it is (ADR-0094).
    Active,
    /// Stopped by the caller, with its verified parts kept for a resume.
    Paused,
    /// A run ended without the file. Resumable — a retry may find new sources.
    Failed,
    /// Every part verified and the file finalized. Terminal.
    Completed,
    /// Abandoned by the caller. Terminal.
    Cancelled,
}

impl DownloadLifecycle {
    #[must_use]
    pub(crate) fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (Self::Cancelled | Self::Completed, _) => false,
            (current, next) if current == next => true,
            (current, Self::Cancelled | Self::Failed)
                if !matches!(current, Self::Completed | Self::Cancelled) =>
            {
                true
            }
            (Self::Queued, Self::Active | Self::Paused) => true,
            (Self::Active, Self::Paused | Self::Completed) => true,
            (Self::Paused, Self::Active) => true,
            (Self::Failed, Self::Active | Self::Paused) => true,
            _ => false,
        }
    }
}

/// The two paths one download writes: the partial file it fills, and the
/// destination it is moved to once every part verifies. Held together so no
/// caller can pair a `.part` with the wrong destination. Chosen once, when
/// the download is placed, and kept on its row: the part file in the Temp
/// Directory (ADR-0115), or beside its final path for an older row or a core
/// given no Temp Directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadPaths {
    final_path: PathBuf,
    part_path: PathBuf,
}

impl DownloadPaths {
    /// The pair a placement chose: the destination and the partial file, in
    /// whatever directories each lies in.
    #[must_use]
    pub const fn new(final_path: PathBuf, part_path: PathBuf) -> Self {
        Self {
            final_path,
            part_path,
        }
    }

    /// Derive the pair from the destination: the partial file is the same path
    /// with `.part` appended, in the same directory: the shape of a row
    /// placed before the Temp Directory, and of a placement on a core given
    /// none.
    #[must_use]
    pub fn from_final_path(final_path: PathBuf) -> Self {
        let mut part_path = final_path.clone().into_os_string();
        part_path.push(".part");

        Self {
            final_path,
            part_path: PathBuf::from(part_path),
        }
    }

    /// Where the finished file lands. Nothing is written here until every part
    /// has verified.
    #[must_use]
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// Where partial data accumulates while the download runs.
    #[must_use]
    pub fn part_path(&self) -> &Path {
        &self.part_path
    }
}

/// Where core learned a download's [`DownloadMetadata`] (ADR-0078).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadMetadataOrigin {
    /// Recorded at creation from the `Ed2kFileLink` the `StartDownload`
    /// caller supplied. A pasted link and a search result the caller rendered
    /// into a link arrive as the same value, so core reports the one fact it
    /// can stand behind — the link — rather than a caller-claimed UI origin.
    Link,
    /// Re-parsed from the row's own canonical link rather than recorded at
    /// creation: the same bytes the link was written from, recovered by a
    /// reader that found no stored name.
    RecoveredLink,
    /// No name is known — a row whose canonical link did not parse, or a
    /// record synthesized without one. `size` is still exact.
    Unknown,
}

/// The file facts core holds for one download: the name to show a human and
/// the exact byte size, plus where they came from (ADR-0078). Recorded at
/// creation, persisted with the download row, and replayed on recovery — so a
/// front-end never has to re-derive a name from the canonical link or
/// approximate a size from the part count.
///
/// `name` keeps the wire's bytes (ADR-0019): real ED2K names are routinely
/// Windows-1252 or mojibake, so the rendering side projects them with
/// [`Ed2kText::to_display_string`] instead of core guessing an encoding. An
/// empty name means core never learned one — see [`DownloadMetadataOrigin`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadMetadata {
    /// The file's name as the wire spelled it — raw bytes, not a `String`.
    /// Empty when core never learned one.
    pub name: Ed2kText,
    /// Exact size in bytes, as the ED2K link declared it.
    pub size: u64,
    /// Where the two facts above came from, which is how much they can be
    /// trusted.
    pub origin: DownloadMetadataOrigin,
}

impl DownloadMetadata {
    /// The creation-time reading: both facts straight off the caller's link.
    #[must_use]
    pub fn from_link(file: &Ed2kFileLink) -> Self {
        Self {
            name: file.name.clone(),
            size: file.size,
            origin: DownloadMetadataOrigin::Link,
        }
    }

    /// An exact size with no name — for a record created without a link.
    #[must_use]
    pub fn unnamed(size: u64) -> Self {
        Self {
            name: Ed2kText::from_bytes(Vec::new()),
            size,
            origin: DownloadMetadataOrigin::Unknown,
        }
    }

    /// The name's eD2k File Class, read from its bytes; `None` for an empty
    /// or unclassifiable name.
    #[must_use]
    pub fn file_class(&self) -> Option<Ed2kFileClass> {
        Ed2kFileClass::from_name_bytes(self.name.as_bytes())
    }

    /// Whether the download is in the **Streaming Priority** set — video,
    /// audio or archive — which the scheduler serves head and tail first and
    /// through a sequential window (ADR-0112). aMule's preview priority is
    /// video and archive behind its `PreviewPrio` preference
    /// (`PartFile.cpp:1941-1945`); rmule adds audio, with no switch, so every
    /// Previewable download is fetched head first. A CD image is not an
    /// archive (`OtherFunctions.cpp:125-138`).
    #[must_use]
    pub fn is_streaming_priority(&self) -> bool {
        matches!(
            self.file_class(),
            Some(Ed2kFileClass::Video | Ed2kFileClass::Audio | Ed2kFileClass::Archive)
        )
    }

    /// Whether the download is **Previewable** — video or audio, aMule's
    /// preview gate (`PartFile.cpp:3795-3797`): a player can open its file
    /// while it runs (ADR-0114). A front end reads this, never re-derives it.
    #[must_use]
    pub fn is_previewable(&self) -> bool {
        matches!(
            self.file_class(),
            Some(Ed2kFileClass::Video | Ed2kFileClass::Audio)
        )
    }
}

/// One part that passed its hash check and is on disk. The store keeps these
/// so a restart resumes instead of re-fetching, and re-checks the bytes against
/// them before trusting the partial file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedPartRecord {
    /// The zero-based part index within the file.
    pub part_index: u32,
    /// The part's first byte offset in the file.
    pub offset: u64,
    /// Its length in bytes — the standard part size except for the file's last
    /// part, which is short.
    pub len: u64,
    /// The hash the bytes matched.
    pub part_hash: PartHash,
}

/// One download as the store holds it. Every field is set at creation except
/// the lifecycle and the verification authority, which the run updates; the
/// getters are the only way in, so a caller cannot desynchronize the pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableDownloadRecord {
    id: DownloadId,
    file_hash: FileHash,
    metadata: DownloadMetadata,
    canonical_link: String,
    source_hint: Option<ServerEndpoint>,
    paths: DownloadPaths,
    lifecycle: DownloadLifecycle,
    verification_authority: Option<VerificationAuthority>,
    failure: Option<DownloadFailure>,
}

impl DurableDownloadRecord {
    pub(crate) fn new(input: DurableDownloadRecordInput) -> Self {
        Self {
            id: input.id,
            file_hash: input.file_hash,
            metadata: input.metadata,
            canonical_link: input.canonical_link,
            source_hint: input.source_hint,
            paths: input.paths,
            lifecycle: input.lifecycle,
            verification_authority: input.verification_authority,
            failure: input.failure,
        }
    }

    /// The download's stable id, reused across restarts.
    #[must_use]
    pub const fn id(&self) -> DownloadId {
        self.id
    }

    /// The file's ED2K content identity.
    #[must_use]
    pub const fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// The file's exact size in bytes, as its link declared it.
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.metadata.size
    }

    /// The stored name + exact size and their origin (ADR-0078).
    #[must_use]
    pub const fn metadata(&self) -> &DownloadMetadata {
        &self.metadata
    }

    /// The `ed2k://` link the download was created from, stored verbatim. It is
    /// what a resume re-parses to recover the file's part hashes and AICH root.
    #[must_use]
    pub fn canonical_link(&self) -> &str {
        &self.canonical_link
    }

    /// The server the download's link was found on, kept as a source hint;
    /// `None` for a download started with no server connected or
    /// configured — a Kad-only start. Nothing dials it: a run's
    /// sources come from the operator's session and Kad.
    #[must_use]
    pub const fn source_hint(&self) -> Option<&ServerEndpoint> {
        self.source_hint.as_ref()
    }

    /// Where the partial and finished files live.
    #[must_use]
    pub const fn paths(&self) -> &DownloadPaths {
        &self.paths
    }

    /// Where the download's bytes lie now (ADR-0114): the finished file of a
    /// `Completed` download, the `.part` of any other. A completed row's
    /// `.part` slot may have been released to a newer row and is then not a
    /// path, so it is never read for one.
    #[must_use]
    pub fn file_path(&self) -> &Path {
        match self.lifecycle {
            DownloadLifecycle::Completed => self.paths.final_path(),
            _ => self.paths.part_path(),
        }
    }

    /// The row's current state, read straight from the store: what the
    /// operator last wanted of the download, which a restart does not rewrite
    /// (ADR-0094).
    #[must_use]
    pub const fn lifecycle(&self) -> DownloadLifecycle {
        self.lifecycle
    }

    /// What the run's verified parts were checked against, or `None` before any
    /// hash set was settled. It is recorded so a resume cannot silently verify
    /// under a weaker authority than the parts already on disk.
    #[must_use]
    pub const fn verification_authority(&self) -> Option<VerificationAuthority> {
        self.verification_authority
    }

    /// Why the last run failed, kept with the `Failed` lifecycle so a restart
    /// still knows it (ADR-0094, "Failed"); `None` for any other lifecycle.
    #[must_use]
    pub const fn failure(&self) -> Option<&DownloadFailure> {
        self.failure.as_ref()
    }
}

pub(crate) struct DurableDownloadRecordInput {
    pub id: DownloadId,
    pub file_hash: FileHash,
    pub metadata: DownloadMetadata,
    pub canonical_link: String,
    pub source_hint: Option<ServerEndpoint>,
    pub paths: DownloadPaths,
    pub lifecycle: DownloadLifecycle,
    pub verification_authority: Option<VerificationAuthority>,
    pub failure: Option<DownloadFailure>,
}

#[cfg(test)]
mod tests {
    use rmule_primitives::Ed2kText;

    use super::{DownloadMetadata, DownloadMetadataOrigin};

    fn named(name: &[u8]) -> DownloadMetadata {
        DownloadMetadata {
            name: Ed2kText::from_bytes(name.to_vec()),
            size: 1,
            origin: DownloadMetadataOrigin::Link,
        }
    }

    /// The two sets the scheduler and the Preview control read: video and
    /// audio are both, an archive is Streaming Priority only, a CD image and
    /// everything else neither; a name that is not UTF-8 keeps its class.
    #[test]
    fn previewable_and_streaming_priority_follow_the_name() {
        let cases: [(&[u8], bool, bool); 8] = [
            (b"film.MKV", true, true),
            (b"song.mp3", true, true),
            (b"pack.rar", false, true),
            (b"disc.iso", false, false),
            (b"notes.txt", false, false),
            (b"README", false, false),
            (b".avi", false, false),
            (b"Cr\xe9dits.avi", true, true),
        ];
        for (name, previewable, priority) in cases {
            let metadata = named(name);
            assert_eq!(metadata.is_previewable(), previewable, "{name:?}");
            assert_eq!(metadata.is_streaming_priority(), priority, "{name:?}");
        }
        let unnamed = DownloadMetadata::unnamed(1);
        assert!(!unnamed.is_previewable());
        assert!(!unnamed.is_streaming_priority());
    }
}
