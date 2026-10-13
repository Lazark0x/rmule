//! The download store seam. [`DownloadRepository`] is what the core asks for a
//! download's durable state; the Durable Store repository
//! ([`DurableDownloadRepository`](crate::DurableDownloadRepository)) is the one
//! implementation of it — a test opens the same repository on the engine's
//! in-memory backend rather than a twin (ADR-0083). Hash authority is resolved
//! on write ([`ResolvedAuthority`]), so a record can never claim a stronger
//! guarantee than the link it came from.

use std::future::Future;

use rmule_primitives::{Ed2kFileLink, Ed2kLink, PartHash, ServerEndpoint};

use crate::content::Revalidation;
use crate::file_history::Ed2kIdentity;
use crate::{
    CoreError, DownloadId, DownloadLifecycle, DownloadPaths, DurableDownloadRecord,
    VerifiedPartRecord,
};

/// The effective per-part hash authority for a download, resolved behind the
/// seam by [`DownloadRepository::hash_authority`]. Precedence is link >
/// provisional > none: `Link` carries the ordered part hashes reconstructed
/// from the persisted canonical **ED2K Link**'s `p=` set (which wins — a
/// link-authority download's provisional child rows stay empty by design),
/// `Provisional` the peer-supplied hashes recorded in the child rows, and
/// `FileHashOnly` means neither exists (the file verifies whole-hash only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedAuthority {
    /// The link's own `p=` set, in part order. Authoritative: a part that
    /// matches one of these is final.
    Link(Vec<PartHash>),
    /// Peer-supplied hashes, in part order. A matching part is only
    /// provisionally good until the finished file's own hash agrees.
    Provisional(Vec<PartHash>),
    /// No part hashes at all, so nothing can be checked before the whole file
    /// is assembled.
    FileHashOnly,
}

/// The precedence rule behind [`DownloadRepository::hash_authority`], shared by
/// both adapters so it resolves identically: the canonical link's `p=` set
/// wins, else the recorded provisional hashes, else file-hash-only.
pub(crate) fn resolve_hash_authority(
    canonical_link: &str,
    provisional: &[PartHash],
) -> ResolvedAuthority {
    if let Ok(Ed2kLink::File(file)) = Ed2kLink::parse(canonical_link)
        && let Some(set) = file.part_hash_set
    {
        return ResolvedAuthority::Link(set.hashes().to_vec());
    }
    if provisional.is_empty() {
        ResolvedAuthority::FileHashOnly
    } else {
        ResolvedAuthority::Provisional(provisional.to_vec())
    }
}

/// The download storage boundary (ADR-0083): persistence is wholly the
/// repository's business. Callers hand verified bytes across the seam and ask
/// for resume-time revalidation; where the rows live (a
/// `rmule.redb` file or the engine's in-memory backend) and that the bytes go
/// to content files composed via [`ContentFileStore`](crate::ContentFileStore)
/// are not observable. The
/// repository received the download's [`DownloadPaths`] at
/// [`create_download`](Self::create_download) and keeps them.
///
/// The persistence methods are async — part writes are ~9.28 MB, so they stay
/// on async I/O — spelled as `impl Future + Send` (the `async fn` desugar with
/// an explicit `Send` bound) so the spawned generic runner can hold them
/// across `.await`. Usage is generic-only; the trait is not dyn-compatible.
/// Every method is `&self` and the trait is `Sync` (ADR-0083): core shares one
/// `Arc<R>` between the actor and every runner with no lock around it.
pub trait DownloadRepository: Send + Sync + 'static {
    /// Mint a row for a new download and hand back the record, including the id
    /// it was given. Refuses a `file` whose identity or `paths` another row
    /// already holds, so two downloads never race for one output file.
    fn create_download(
        &self,
        file: &Ed2kFileLink,
        source_hint: Option<&ServerEndpoint>,
        paths: &DownloadPaths,
    ) -> Result<DurableDownloadRecord, CoreError>;

    /// Read one row back. [`CoreError::UnknownDownload`] when there is none.
    fn load_download(&self, id: DownloadId) -> Result<DurableDownloadRecord, CoreError>;

    /// Every row a caller could still resume — the queued, paused and failed
    /// ones. Completed and cancelled rows never appear.
    fn list_resumable(&self) -> Result<Vec<DurableDownloadRecord>, CoreError>;

    /// The identity — file hash and size — of every download the operator
    /// cancelled before it completed, oldest first (ADR-0100: the
    /// **Cancelled** mark). A file cancelled twice appears twice.
    fn list_cancelled(&self) -> Result<Vec<Ed2kIdentity>, CoreError>;

    /// Move a row's lifecycle. Rejects a transition the state machine forbids
    /// with [`CoreError::InvalidLifecycleTransition`] rather than forcing it.
    fn set_lifecycle(&self, id: DownloadId, state: DownloadLifecycle) -> Result<(), CoreError>;

    /// The parts already hash-checked and on disk, so a resume knows what not
    /// to fetch. Ordered by part index.
    fn verified_parts(&self, id: DownloadId) -> Result<Vec<VerifiedPartRecord>, CoreError>;

    /// Record a peer-supplied part hash set for the download, and drop in the
    /// same write every verified part whose recorded hash the set disproves —
    /// returned, to be fetched again. Only one set may be in force — a
    /// second, different set is [`CoreError::ProvisionalAuthorityConflict`].
    fn record_provisional_part_hashes(
        &self,
        id: DownloadId,
        hashes: &[PartHash],
    ) -> Result<Vec<VerifiedPartRecord>, CoreError>;

    /// The recorded peer-supplied hashes in part order, or empty when none were
    /// recorded. Prefer [`hash_authority`](Self::hash_authority), which applies
    /// the link-wins precedence.
    fn provisional_part_hashes(&self, id: DownloadId) -> Result<Vec<PartHash>, CoreError>;

    /// Resolve the *effective* per-part hash authority for a download —
    /// link > provisional > none — so a caller asks one question instead of
    /// reaching into which hashes the storage happens to hold. Link hashes are
    /// reconstructed from the persisted canonical ED2K link; provisional ones
    /// come from the child rows. See [`ResolvedAuthority`].
    fn hash_authority(&self, id: DownloadId) -> Result<ResolvedAuthority, CoreError>;

    /// Every row that still holds its file's place (`Queued`, `Active`,
    /// `Paused`, `Failed`), as the last process left it — read once at attach,
    /// which starts the running ones again (ADR-0094). Writes nothing.
    fn live_downloads(&self) -> Result<Vec<DurableDownloadRecord>, CoreError>;

    /// Resume-time revalidation: re-hash the stored content against the
    /// durable verified-part records (ADR-0094, "Damaged parts"). A part that
    /// no longer holds has its record dropped before this returns, so the
    /// verified set read next is the one to resume from; the part file is
    /// condemned only when nothing recorded can be trusted.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] or [`CoreError::Repository`] when the
    /// store could not be read or written — not a fault of the part file.
    fn revalidate(
        &self,
        id: DownloadId,
    ) -> impl Future<Output = Result<Revalidation, CoreError>> + Send;
}
