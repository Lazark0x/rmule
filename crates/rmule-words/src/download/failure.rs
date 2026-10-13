//! Why a download failed, as the operator reads it: the failure's clause,
//! which check condemned a part file and how a checked part failed on disk,
//! the note a failure sets, and the row whose reason was never kept.

use rmule_core::{DownloadFailure, PartFault, StorageIntegrityFault};

use super::super::Sentence;
use super::super::units::short_hex;

/// Why a failed row has no reason to give (ADR-0094): it failed before rmule
/// kept why — store version 5 or earlier, or the version-6 bare
/// storage-integrity code — and its next Restart finds the fault again.
pub const FAILURE_NOT_RECORDED: &str =
    "not recorded: it failed before rmule kept the reason; Restart finds it again";

/// Why a download failed, as a clause that completes "It failed because …".
#[must_use]
pub fn download_failure_words(reason: &DownloadFailure) -> String {
    let code: &str = match reason {
        DownloadFailure::NoUsableSources => {
            "no source could be reached and nothing was looking for more"
        }
        DownloadFailure::HashSetMismatch => "a source's part hashes contradicted the link's own",
        DownloadFailure::Cancelled => "it was cancelled",
        DownloadFailure::Paused => "it was paused",
        DownloadFailure::ServerDisconnected => "the server disconnected before it named any source",
        DownloadFailure::ServerFiltered => "the server's address is in your IP filter",
        DownloadFailure::SourceLookupTimedOut => "the server never answered the ask for sources",
        DownloadFailure::PeerDisconnected => {
            "the last source disconnected with parts still missing"
        }
        DownloadFailure::PartVerificationFailed => {
            "a part kept failing its check and no other source had it"
        }
        DownloadFailure::StorageIntegrityFailed(fault) => {
            return format!(
                "the file on disk no longer backs the parts already checked: {}",
                integrity_fault_words(fault)
            );
        }
        DownloadFailure::FinalPathTaken => {
            "a file already stands where the finished file goes; every checked part is kept, so move that file away and Restart"
        }
        DownloadFailure::CompletedFileNotMoved { os_code } => {
            return format!(
                "the finished file could not be moved to where it goes{}; every checked part is kept, so Restart once the folder takes it",
                os_clause(*os_code)
            );
        }
        DownloadFailure::StoreFailed => {
            "rmule's store could not read or write this download's record"
        }
        DownloadFailure::CompletionCopyFailed { os_code } => {
            return format!(
                "the finished file could not be copied to the disk where it goes{}; every checked part is kept, so Restart once that disk takes it",
                os_clause(*os_code)
            );
        }
    };
    code.to_string()
}

/// What the system said when it refused, as a parenthesised clause after
/// the refusal's sentence; nothing when it gave no code.
fn os_clause(os_code: Option<i32>) -> String {
    os_code.map_or_else(String::new, |code| {
        format!(
            " ({})",
            super::super::os::refusal_words(
                std::io::Error::from_raw_os_error(code).kind(),
                Some(code)
            )
        )
    })
}

/// Which check condemned a download's part file, and what it found.
#[must_use]
pub fn integrity_fault_words(fault: &StorageIntegrityFault) -> String {
    match fault {
        StorageIntegrityFault::PartFileMissing => "its part file is missing".to_string(),
        StorageIntegrityFault::PartFileUnreadable { os_code } => {
            format!("its part file could not be read{}", os_clause(*os_code))
        }
        StorageIntegrityFault::NoPartHolds { recorded, first } => format!(
            "none of its {recorded} checked parts still matches ({})",
            part_fault_words(first)
        ),
    }
}

/// How one checked part failed on disk.
#[must_use]
pub fn part_fault_words(fault: &PartFault) -> String {
    match fault {
        PartFault::Short {
            part_index,
            expected_end,
            found_len,
        } => format!(
            "part {part_index} should end at byte {expected_end}, the part file holds {found_len}"
        ),
        PartFault::HashMismatch {
            part_index,
            expected,
            found,
        } => format!(
            "part {part_index} hashes to {}, it was checked as {}",
            short_hex(found.as_bytes()),
            short_hex(expected.as_bytes())
        ),
    }
}

/// A download failed — or, when it was already Failed, its Restart failed
/// again, which the row itself cannot show.
#[must_use]
pub fn failed(name: &str, reason: &DownloadFailure, again: bool) -> Sentence {
    let words = download_failure_words(reason);
    Sentence::owned(if again {
        format!("{name}: restart failed again: {words}")
    } else {
        format!("{name} failed: {words}")
    })
}

/// The store could not record a failure just told.
#[must_use]
pub fn failure_not_recorded(name: &str) -> Sentence {
    Sentence::owned(format!(
        "{name}: rmule's store could not record that it failed — the next start shows it as it was before"
    ))
}
