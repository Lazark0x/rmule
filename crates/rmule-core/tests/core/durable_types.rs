//! The derivation the durable download types own: the `.part` sibling a final
//! output path implies.
use std::path::PathBuf;

use rmule_core::DownloadPaths;

#[test]
fn derives_sibling_part_path_from_final_output_path() {
    let paths = DownloadPaths::from_final_path(PathBuf::from("/tmp/example.bin"));

    assert_eq!(paths.final_path(), PathBuf::from("/tmp/example.bin"));
    assert_eq!(paths.part_path(), PathBuf::from("/tmp/example.bin.part"));
}
