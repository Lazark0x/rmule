//! eD2k's file size ceiling, 256 GiB (aMule `MAX_FILE_SIZE`): a link or a
//! search row naming a larger file is refused where it is decoded, by that
//! cause, so nothing downstream sizes a part map from it. A file of zero
//! bytes is refused the same way: it has no part to fetch.

use rmule_primitives::{
    Ed2kLink, Ed2kText, FileHash, MAX_ED2K_FILE_SIZE, PrimitiveError, SearchResult,
};

const HASH: &str = "0123456789ABCDEF0123456789ABCDEF";

fn link_of(size: u64) -> rmule_primitives::Result<Ed2kLink> {
    Ed2kLink::parse(&format!("ed2k://|file|big.bin|{size}|{HASH}|/"))
}

#[test]
fn a_file_link_above_the_ceiling_is_refused_by_that_cause() {
    assert!(
        link_of(MAX_ED2K_FILE_SIZE).is_ok(),
        "the ceiling itself is a file"
    );
    for size in [MAX_ED2K_FILE_SIZE + 1, u64::MAX] {
        assert_eq!(
            link_of(size).unwrap_err(),
            PrimitiveError::FileSizeAboveLimit { file_size: size }
        );
    }
}

#[test]
fn a_search_row_above_the_ceiling_is_refused_by_that_cause() {
    let row = |size| {
        SearchResult::new(
            FileHash::from_bytes([0x5B; 16]),
            size,
            vec![Ed2kText::from_utf8("big.bin")],
            Vec::new(),
        )
    };
    assert!(row(MAX_ED2K_FILE_SIZE).is_ok());
    assert_eq!(
        row(u64::MAX).unwrap_err(),
        PrimitiveError::FileSizeAboveLimit {
            file_size: u64::MAX
        }
    );
}

/// aMule drops a search row of zero bytes before it reaches the list
/// (`SearchList.cpp:561-569`, `AddToList`): no part, nothing to fetch.
#[test]
fn a_search_row_of_zero_bytes_is_refused_by_that_cause() {
    let row = |size| {
        SearchResult::new(
            FileHash::from_bytes([0x5B; 16]),
            size,
            vec![Ed2kText::from_utf8("empty.bin")],
            Vec::new(),
        )
    };
    assert!(row(1).is_ok(), "one byte is a file");
    assert_eq!(row(0).unwrap_err(), PrimitiveError::FileSizeZero);
}

/// aMule refuses a link of zero bytes as it refuses one above the ceiling
/// (`ED2KLink.cpp:179`, one condition for both): no part, nothing to fetch.
#[test]
fn a_file_link_of_zero_bytes_is_refused_by_that_cause() {
    assert!(link_of(1).is_ok(), "one byte is a file");
    assert_eq!(link_of(0).unwrap_err(), PrimitiveError::FileSizeZero);
}
