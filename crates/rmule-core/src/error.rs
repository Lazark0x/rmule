//! The two failure vocabularies of the core. [`CoreError`] is an ask the core
//! refuses or a store that would not answer — the caller's problem, reported
//! synchronously. [`DownloadFailure`] is why a running download stopped, which
//! rides an event to the front end long after the ask returned.

/// The OS's error number as an error text carries it: ` (os error 13)`, or
/// nothing when the OS gave none.
struct OsCode(Option<i32>);

impl std::fmt::Display for OsCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(code) => write!(f, " (os error {code})"),
            None => Ok(()),
        }
    }
}

/// An ask core refused, or a store that would not answer. Returned
/// synchronously from the call that made the ask, so it never reaches the event
/// stream.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoreError {
    /// The store already holds a row with this download id.
    #[error("download already exists")]
    DownloadAlreadyExists,
    /// Another download of the same file is already active or resumable. eD2k
    /// identity is the file hash plus its size, so two rows for it would race
    /// for the same parts and the same output path.
    #[error("duplicate active or resumable download identity")]
    DuplicateDownloadIdentity,
    /// No row exists for the named download id — it was never created, or it
    /// was cancelled.
    #[error("unknown download")]
    UnknownDownload,
    /// The requested output path is already claimed by another row or already
    /// exists on disk. Refused up front rather than overwriting.
    #[error("download path conflicts with existing durable state or filesystem path")]
    PathConflict,
    /// The move is not one [`DownloadLifecycle`](crate::DownloadLifecycle)
    /// allows — completed and cancelled are terminal, so nothing leaves them.
    #[error("invalid download lifecycle transition")]
    InvalidLifecycleTransition,
    /// A verified-part record's range falls outside the file's declared size,
    /// so either the record or the size is wrong and neither can be trusted.
    #[error("verified part is outside the declared file size")]
    PartOutOfBounds,
    /// The store itself failed (I/O, a SQL error, a poisoned lock). The string
    /// is the backend's own message and is for a log, not for matching on.
    #[error("download repository error: {0}")]
    Repository(String),
    /// A second provisional part hash set was offered for a download that
    /// already has one. Only one provisional authority can be in force, since
    /// two would disagree about what a verified part means.
    #[error("provisional verification authority already exists")]
    ProvisionalAuthorityConflict,
    /// The Kad node could not start — typically the UDP bind. The session keeps
    /// running without Kad; the string is the underlying reason.
    #[error("kad runtime unavailable: {0}")]
    KadUnavailable(String),
    /// The serve activity's inbound listener did not bind — the port is held,
    /// or the address is not this host's. `ErrorKind` is the smallest portable
    /// summary (the `CloseReason::Io` shape); the whole `io::Error` is in the
    /// adapter's log line. Nothing started, so the serve adapter is intact and
    /// a retry is a real retry.
    #[error("serve listener bind failed: {0}")]
    ListenerBind(std::io::ErrorKind),
    /// The core actor is gone, so nothing can be asked of it any more. Every
    /// later send fails the same way.
    #[error("core service stopped")]
    ServiceStopped,
}

/// Why a running download stopped. Delivered on the event stream long after the
/// command that started the run returned, so it is a fact about the run rather
/// than a rejected ask. [`Cancelled`](Self::Cancelled) and
/// [`Paused`](Self::Paused) are caller-initiated and not faults.
///
/// A failed download's row keeps its reason (ADR-0094, "Failed"), encoded by
/// declaration order: a variant is added at the end, or the download row's
/// record version moves with it.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DownloadFailure {
    /// The candidate pool is empty and nothing can refill it: no reachable
    /// High-ID source, no callback-able Low-ID source, and no discovery channel
    /// armed. With discovery armed the download waits instead.
    #[error("no usable sources")]
    NoUsableSources,
    /// A peer offered a part hash set that contradicts the link's own. The
    /// link's set is authoritative, so the run stops rather than verify against
    /// hashes that cannot both be right.
    #[error("peer hash set disagrees with link part hash set")]
    HashSetMismatch,
    /// A `CancelDownload` stopped the run. Not a fault; the row is gone.
    #[error("download cancelled")]
    Cancelled,
    /// A `PauseDownload` stopped the run. Not a fault; the verified parts and
    /// the row survive for a resume.
    #[error("download paused")]
    Paused,
    /// The server session ended before the source lookup answered, so the run
    /// never learned a single candidate.
    #[error("server disconnected before sources arrived")]
    ServerDisconnected,
    /// The download's server is in the IP filter table, so rmule never dialed
    /// it.
    #[error("server IP is filtered; not connecting")]
    ServerFiltered,
    /// `source_lookup_timeout` elapsed with no `OP_FOUNDSOURCES`. Bounds a
    /// sourceless file so it terminates instead of parking forever.
    #[error("source lookup timed out before the server answered")]
    SourceLookupTimedOut,
    /// The last usable worker's connection ended with parts still missing and
    /// no candidate left to backfill from.
    #[error("peer disconnected before download completed")]
    PeerDisconnected,
    /// A part's bytes did not match its hash and no other source could supply
    /// it. The peer that served the bad bytes is retired first; this is the
    /// failure only when retrying runs out of sources.
    #[error("part verification failed")]
    PartVerificationFailed,
    /// The part file could not back the verified-part records at all, so the
    /// download cannot resume from it. The fault names which check failed and
    /// on what. A part that merely stopped hashing is not this: it is dropped
    /// and fetched again (ADR-0094, "Damaged parts").
    #[error("stored download content does not match its verified-part records: {0}")]
    StorageIntegrityFailed(StorageIntegrityFault),
    /// Every part verified and the whole file hashed, but a file already
    /// stood at the final path, and rmule never overwrites one. No longer
    /// produced — a taken name now takes the next free one (ADR-0115) — and
    /// still read from a row that holds it.
    #[error("a file already stands at the download's final path")]
    FinalPathTaken,
    /// Every part verified and the whole file hashed, but the part file could
    /// not be moved onto its final path. The OS's error number, when it gave
    /// one, is kept as data. The verified parts are kept.
    #[error("the finished file could not be moved to its final path{}", OsCode(*.os_code))]
    CompletedFileNotMoved {
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// The Durable Store could not read or write this download's record, so
    /// the run could not keep what it earned or learn what it holds.
    #[error("the download's store record could not be read or written")]
    StoreFailed,
    /// Every part verified and the whole file hashed, the destination lies on
    /// another volume, and the Completion Copy onto it failed — a full disk,
    /// an I/O error (ADR-0115). The partial copy is deleted, the part file
    /// and every verified part are kept.
    #[error("the finished file could not be copied to its final path{}", OsCode(*.os_code))]
    CompletionCopyFailed {
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
}

/// Why [`DownloadRepository::finalize`](crate::DownloadRepository::finalize)
/// did not promote a download: each cause is its own, since only a file that
/// does not hash is a matter for the parts.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum FinalizeError {
    /// The assembled file does not hash to the file's hash.
    #[error("the assembled file does not hash to the file's hash")]
    Mismatch,
    /// A file already stands at the final path.
    #[error("a file already stands at the final path")]
    FinalPathTaken,
    /// The part file could not be read whole.
    #[error("the part file could not be read{}", OsCode(*.os_code))]
    Unreadable {
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// The rename onto the final path failed.
    #[error("the part file could not be moved to its final path{}", OsCode(*.os_code))]
    NotMoved {
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// The store failed around the rename.
    #[error(transparent)]
    Store(#[from] CoreError),
}

/// Which resume-time check condemned a download's part file (ADR-0094,
/// "Damaged parts"). Carried on [`DownloadFailure::StorageIntegrityFailed`]
/// and kept with it in the store, so the operator reads what was expected and
/// what was found rather than a bare code.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StorageIntegrityFault {
    /// Verified parts are recorded but the part file the row names is not on
    /// disk: nothing recorded can be trusted.
    #[error("the part file is missing")]
    PartFileMissing,
    /// The part file exists but could not be opened or read. The OS's error
    /// number, when it gave one, is kept as data — a front end words it;
    /// the OS's message is for the Run Log.
    #[error("the part file could not be read{}", OsCode(*.os_code))]
    PartFileUnreadable {
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// Every recorded part failed its check: nothing on disk can be trusted.
    /// `first` is the lowest part that failed.
    #[error("none of the {recorded} verified parts still holds; {first}")]
    NoPartHolds {
        /// How many verified parts the store recorded.
        recorded: u32,
        /// The first of them that failed, and how.
        first: PartFault,
    },
}

/// How one recorded verified part failed its resume-time check. The part is
/// dropped from the verified set and fetched again; only when every part
/// fails does the download fail ([`StorageIntegrityFault::NoPartHolds`]).
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PartFault {
    /// The part file ends before the part does.
    #[error("part {part_index} ends at byte {expected_end} but the part file holds {found_len}")]
    Short {
        /// The part's zero-based index.
        part_index: u32,
        /// Where the part's last byte ends, per its record.
        expected_end: u64,
        /// The part file's length on disk.
        found_len: u64,
    },
    /// The part's bytes hash to something other than the hash it was verified
    /// against.
    #[error(
        "part {part_index} hashes to {}, its record says {}",
        .found.to_hex_upper(),
        .expected.to_hex_upper()
    )]
    HashMismatch {
        /// The part's zero-based index.
        part_index: u32,
        /// The hash recorded when the part verified.
        expected: rmule_primitives::PartHash,
        /// The hash of the bytes on disk now.
        found: rmule_primitives::PartHash,
    },
}

impl PartFault {
    /// The part this fault is about.
    #[must_use]
    pub const fn part_index(&self) -> u32 {
        match self {
            Self::Short { part_index, .. } | Self::HashMismatch { part_index, .. } => *part_index,
        }
    }
}
