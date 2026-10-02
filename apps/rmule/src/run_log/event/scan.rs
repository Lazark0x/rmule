//! The Run Log's record of each Shared Directory List and scan event. Every path is
//! a full-level field.

use rmule_core::ScanEvent;

use crate::run_log::codes;
use crate::run_log::record::Record;

pub(super) fn record(event: &ScanEvent) -> Record {
    use ScanEvent as S;
    match event {
        S::ConsentRequested {
            dir,
            offer,
            adding,
            replaces,
        } => Record::new("scan.consent_requested")
            .path("dir", dir)
            .count("files", offer.files)
            .count("bytes", offer.bytes)
            .count("unread", offer.unread)
            .flag("adding", *adding)
            .count("replaces", replaces.len()),
        S::DirectoryAdded { dir, replaced } => Record::new("shared_directory.added")
            .path("dir", dir)
            .count("replaced", replaced.len()),
        S::DirectoryRefused { dir, reason } => codes::directory_refusal(
            Record::new("shared_directory.refused").path("dir", dir),
            reason,
        ),
        S::DirectoryRemoved { dir, files } => Record::new("shared_directory.removed")
            .path("dir", dir)
            .count("files", *files),
        S::DirectoryMissing { dir, .. } => Record::new("shared_directory.missing").path("dir", dir),
        S::DirectoryReturned { dir } => Record::new("shared_directory.returned").path("dir", dir),
        S::Finished { dir, summary } => Record::new("scan.finished")
            .path("dir", dir)
            .count("trusted", summary.trusted)
            .count("hashed", summary.hashed)
            .count("carried", summary.carried)
            .count("dropped", summary.dropped)
            .count("skipped", summary.skipped)
            .count("unreadable", summary.unreadable),
        S::Declined { dir } => Record::new("scan.declined").path("dir", dir),
        S::WatchUnavailable { dir, reason } => codes::watch_fault(
            Record::new("scan.watch_unavailable").path("dir", dir),
            *reason,
        ),
        S::WatchInterrupted { dir, reason } => codes::watch_fault(
            Record::new("scan.watch_interrupted").path("dir", dir),
            *reason,
        ),
        S::WatchRestored { dir } => Record::new("scan.watch_restored").path("dir", dir),
        S::PathUnwatched { dir, path, reason } => codes::watch_fault(
            Record::new("scan.path_unwatched")
                .path("dir", dir)
                .path("path", path),
            *reason,
        ),
        S::LeftoverParts { dir, paths } => Record::new("scan.leftover_parts")
            .path("dir", dir)
            .count("count", paths.len()),
        S::FileNotHashed {
            dir,
            path,
            kind,
            os_code,
        } => Record::new("scan.file_not_hashed")
            .path("dir", dir)
            .path("path", path)
            .os_error(*kind, *os_code),
        S::Unlistable { dir } => Record::new("scan.unlistable").path("dir", dir),
    }
}
