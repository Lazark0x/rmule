//! CLI coverage for `rmule-tools ed2k search`: flag surface, and a hermetic
//! end-to-end run against the testkit `FakeEd2kServer`'s search seam
//! (Correctness Tier, ADR-0040).

use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use rmule_primitives::{ClientId, Ed2kText, FileHash, PeerSource, SearchResult};
use rmule_testkit::FakeEd2kServer;

#[tokio::test(flavor = "current_thread")]
async fn search_cli_completes_against_loopback_server() {
    let server = FakeEd2kServer::start_scripted().await;
    let result = SearchResult::new(
        FileHash::from_bytes([0xAA; FileHash::BYTE_LEN]),
        2048,
        vec![Ed2kText::from_utf8("ubuntu.iso")],
        vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4662)],
    )
    .unwrap();
    server.set_search_results(vec![result]).await;

    let server_arg = server.local_addr().to_string();
    let out = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("rmule-tools")
            .unwrap()
            .args([
                "ed2k",
                "search",
                "--server",
                &server_arg,
                "--query",
                "ubuntu",
                "--quiet-timeout-secs",
                "1",
            ])
            .timeout(Duration::from_secs(15))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}\nstdout: {stdout}");
    assert!(stdout.contains("search_started id=1"), "{stdout}");
    // The scripted answer carries no `FT_SOURCES`/`FT_COMPLETE_SOURCES`, so
    // both counts print as `-` rather than as a fabricated zero; the type is
    // classified from the name (`.iso` → CD-image), since no server sends
    // `FT_FILETYPE`.
    assert!(
        stdout.contains(
            "0: file_hash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA size=2048 primary_name=ubuntu.iso \
             source_count=1 availability=- complete=- type=Iso",
        ),
        "{stdout}"
    );
    assert!(stdout.contains("search_completed id=1 total=1"), "{stdout}");

    assert_eq!(
        server.search_phrases().await,
        vec!["ubuntu".to_owned()],
        "the CLI sent exactly the queried phrase"
    );
}

/// The type flag offers all seven of aMule's dropdown classes
/// (`SearchDlg.cpp:479-487`).
#[test]
fn the_type_flag_offers_every_amule_search_class() {
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "search", "--help"]);
    cmd.assert().success().stdout(predicate::str::contains(
        "audio, video, image, document, program, archive, cd-image",
    ));
}

/// Every constraint the CLI accepts survives the expression tree: the server
/// decodes the request back into the query that was asked for. An `iso`
/// extension with a `cd-image` type also pins the fold — the class rides the
/// wire as `"Pro"`, so the server can only report `Program` back.
#[tokio::test(flavor = "current_thread")]
async fn the_constraint_flags_arrive_as_a_decodable_expression_tree() {
    let server = FakeEd2kServer::start_scripted().await;
    let server_arg = server.local_addr().to_string();
    let out = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("rmule-tools")
            .unwrap()
            .args([
                "ed2k",
                "search",
                "--server",
                &server_arg,
                "--query",
                "ubuntu",
                "--type",
                "cd-image",
                "--min-size",
                "1024",
                "--max-size",
                "4096",
                "--min-availability",
                "7",
                "--extension",
                "iso",
                "--quiet-timeout-secs",
                "1",
            ])
            .timeout(Duration::from_secs(15))
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let queries = server.search_queries().await;
    assert_eq!(queries.len(), 1);
    let query = &queries[0];
    assert_eq!(query.phrase().to_display_string(), "ubuntu");
    assert_eq!(
        query.file_type(),
        Some(rmule_primitives::Ed2kFileClass::Program),
        "\"Iso\" has no wire term of its own; aMule sends CD-images as \"Pro\""
    );
    assert_eq!(query.min_size(), Some(1024));
    assert_eq!(query.max_size(), Some(4096));
    assert_eq!(query.min_availability(), Some(7));
    assert_eq!(
        query
            .extension()
            .map(Ed2kText::to_display_string)
            .as_deref(),
        Some("iso")
    );
}
