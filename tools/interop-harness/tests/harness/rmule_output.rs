//! What rmule reports about its own download, parsed from its stdout: the
//! summary is stimulus context, so the parser must refuse an incomplete run.

use rmule_interop_harness::rmule::parse_download_output;

#[test]
fn parser_requires_completion_and_part_verification() {
    let output = "\
download server_login_accepted id=1 client_id=16777343
download.sources_found id=1 total=1 usable_high_id=1
download.peer_selected id=1 peer=127.0.0.1:4662
download.part_verified id=1 part_index=0
download.completed id=1
download finalized id=1 path=/tmp/output.bin
";

    let summary = parse_download_output(output).unwrap();

    assert!(summary.completed);
    assert!(summary.part_verified);
    assert_eq!(summary.usable_high_id, Some(1));
}

#[test]
fn parser_allows_missing_part_verification_when_download_completed() {
    let output = "\
download.sources_found id=1 total=1 usable_high_id=1
download.completed id=1
";

    let summary = parse_download_output(output).unwrap();

    assert!(summary.completed);
    assert!(!summary.part_verified);
    assert_eq!(summary.usable_high_id, Some(1));
}

#[test]
fn parser_rejects_missing_completion() {
    let output = "\
download.sources_found id=1 total=1 usable_high_id=1
download.part_verified id=1 part_index=0
";

    let error = parse_download_output(output).unwrap_err();

    assert!(
        error.to_string().contains("download.completed"),
        "{error:?}"
    );
}
