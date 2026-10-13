//! The stored encoding of a download row: its part path and the live enums it
//! embeds, pinned byte for byte.

use rmule_primitives::{Ed2kFileLink, Ed2kText, FileHash};

use super::DownloadRow;
use crate::DownloadPaths;

fn row() -> DownloadRow {
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("a.bin"),
        size: 10,
        file_hash: FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let paths = DownloadPaths::new("/dl/a.bin".into(), "/dl/a.bin.part".into());
    DownloadRow::new(&file, None, &paths)
}

/// Every byte of the version-5 row: the record's postcard encoding the store
/// wrote before the part path became a typed state.
const HELD_ROW: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10a386564326b3a2f2f7c66696c657c612e62696e7c31307c41314131413141314131413141314131413141314131413141314131413141317c2f00092f646c2f612e62696e0e2f646c2f612e62696e2e70617274000005612e62696e0000";
const RELEASED_ROW: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10a386564326b3a2f2f7c66696c657c612e62696e7c31307c41314131413141314131413141314131413141314131413141314131413141317c2f00092f646c2f612e62696e0b0072656c65617365643a37000005612e62696e0000";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A held part path and a released one encode to the bytes version 9 has
/// always written: the path's text, and the stand-in `"\0released:{key}"`.
#[test]
fn a_part_path_encodes_to_the_bytes_version_nine_writes() {
    let held = row();
    assert_eq!(hex(&postcard::to_allocvec(&held).unwrap()), HELD_ROW);
    let mut released = row();
    released.release_part_path(7);
    let bytes = postcard::to_allocvec(&released).unwrap();
    assert_eq!(hex(&bytes), RELEASED_ROW);
    assert_eq!(
        postcard::from_bytes::<DownloadRow>(&bytes).unwrap(),
        released
    );
    assert_eq!(released.part_path.held_path(), None);
}

/// The live lifecycle and failure are encoded by position on today's row:
/// every variant a store already holds keeps its byte, and the completion
/// move's `Completing` and `CompletionCopyFailed` take the next ones, so every
/// row on disk decodes as it was written (ADR-0115).
#[test]
fn the_completion_variants_are_appended_after_every_byte_a_store_holds() {
    use crate::{DownloadFailure, DownloadLifecycle};

    let lifecycles = [
        (DownloadLifecycle::Queued, 0),
        (DownloadLifecycle::Active, 1),
        (DownloadLifecycle::Paused, 2),
        (DownloadLifecycle::Failed, 3),
        (DownloadLifecycle::Completed, 4),
        (DownloadLifecycle::Cancelled, 5),
        (DownloadLifecycle::Completing, 6),
    ];
    for (lifecycle, byte) in lifecycles {
        assert_eq!(postcard::to_allocvec(&lifecycle).unwrap(), [byte]);
        assert_eq!(
            postcard::from_bytes::<DownloadLifecycle>(&[byte]).unwrap(),
            lifecycle
        );
    }
    let failures: [(DownloadFailure, &[u8]); 5] = [
        (DownloadFailure::PartVerificationFailed, &[8]),
        (DownloadFailure::FinalPathTaken, &[10]),
        (
            DownloadFailure::CompletedFileNotMoved { os_code: Some(18) },
            &[11, 1, 36],
        ),
        (DownloadFailure::StoreFailed, &[12]),
        (
            DownloadFailure::CompletionCopyFailed { os_code: Some(28) },
            &[13, 1, 56],
        ),
    ];
    for (failure, encoded) in failures {
        assert_eq!(postcard::to_allocvec(&failure).unwrap(), encoded);
        assert_eq!(
            postcard::from_bytes::<DownloadFailure>(encoded).unwrap(),
            failure
        );
    }
}
