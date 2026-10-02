//! Hermetic CLI coverage for `rmule-tools ed2k download start` and `resume`
//! (ADR-0040): the real binary runs via assert_cmd while the
//! testkit counterparties — `FakeEd2kServer` in scripted mode plus a real
//! serving core (start) or a `FakePeer` (resume) — live in the test process.
//! Ordinary `cargo test`, no containers, localhost only — this is where the
//! end-to-end transfer that `download_cli.rs` cannot reach is asserted.

use rmule_core::DownloadRepository;
use std::time::Duration;

use assert_cmd::Command;
use rmule_core::{
    ContentFileStore, DownloadPaths, DurableDownloadRepository, VerifiedPartRecord,
    open_durable_store,
};
use rmule_primitives::{Ed2kFileLink, Ed2kText, FileHashSummary};
use rmule_testkit::{FakeEd2kServer, FakePeer, PeerScript, ServingCore};

fn file_link_arg(name: &str, bytes: &[u8]) -> String {
    let summary = FileHashSummary::digest_bytes(bytes);
    format!(
        "ed2k://|file|{name}|{}|{}|/",
        bytes.len(),
        summary.file_hash().to_hex_upper()
    )
}

#[tokio::test(flavor = "current_thread")]
async fn download_start_completes_hermetically_from_a_real_serving_core() {
    let bytes = vec![0x5C_u8; 4096];
    let link = file_link_arg("hermetic-start.bin", &bytes);

    let server = FakeEd2kServer::start_scripted().await;
    let serving = ServingCore::spawn(0x66, "hermetic-start.bin", &bytes).await;
    server.set_sources(vec![serving.source()]).await;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("hermetic-start.bin");
    let server_arg = server.local_addr().to_string();

    let data_dir_arg = dir.path().to_str().unwrap().to_owned();
    let out_arg = out.to_str().unwrap().to_owned();
    let cmd_out = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("rmule-tools")
            .unwrap()
            .args([
                "ed2k",
                "download",
                "start",
                "--data-dir",
                &data_dir_arg,
                "--server",
                &server_arg,
                "--file",
                &link,
                "--out",
                &out_arg,
            ])
            // A hang guard, not a latency budget: the child links and drives a whole
            // core, and a loaded runner serialises that against every other binary.
            .timeout(Duration::from_secs(120))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&cmd_out.stdout);
    let stderr = String::from_utf8_lossy(&cmd_out.stderr);
    assert!(
        cmd_out.status.success(),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("download finalized id=1"),
        "stdout missing finalize line:\n{stdout}"
    );
    assert_eq!(
        std::fs::read(&out).unwrap(),
        bytes,
        "output byte-for-byte identical to the served file"
    );
    drop(serving);
}

/// Two `--file` links run as two downloads in one core, each written to its
/// own `--out`, and the run ends once both are whole.
#[tokio::test(flavor = "current_thread")]
async fn download_start_runs_two_downloads_in_one_core() {
    let first = vec![0x3A_u8; 4096];
    let second: Vec<u8> = (0..5000u32).map(|index| (index % 253) as u8).collect();
    let server = FakeEd2kServer::start_scripted().await;
    let serving_first = ServingCore::spawn(0x67, "two-first.bin", &first).await;
    let serving_second = ServingCore::spawn(0x68, "two-second.bin", &second).await;
    server
        .set_sources(vec![serving_first.source(), serving_second.source()])
        .await;

    let dir = tempfile::tempdir().unwrap();
    let outs = [dir.path().join("first.bin"), dir.path().join("second.bin")];
    let args: Vec<String> = [
        "ed2k",
        "download",
        "start",
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--server",
        &server.local_addr().to_string(),
        "--file",
        &file_link_arg("two-first.bin", &first),
        "--out",
        outs[0].to_str().unwrap(),
        "--file",
        &file_link_arg("two-second.bin", &second),
        "--out",
        outs[1].to_str().unwrap(),
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect();
    let cmd_out = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("rmule-tools")
            .unwrap()
            .args(&args)
            .timeout(Duration::from_secs(120))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&cmd_out.stdout);
    let stderr = String::from_utf8_lossy(&cmd_out.stderr);
    assert!(
        cmd_out.status.success(),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    assert_eq!(stdout.matches("download finalized").count(), 2, "{stdout}");
    assert_eq!(std::fs::read(&outs[0]).unwrap(), first);
    assert_eq!(std::fs::read(&outs[1]).unwrap(), second);
    drop((serving_first, serving_second));
}

#[tokio::test(flavor = "current_thread")]
async fn download_resume_completes_hermetically_from_verified_parts() {
    // A two-part file with part 0 already verified on disk: resume must plan
    // only part 1, fetch it from the peer, and finalize byte-for-byte.
    let part_size = rmule_primitives::ED2K_PART_SIZE as usize;
    let mut bytes = vec![0xA5_u8; part_size];
    bytes.extend_from_slice(b"resume-tail");
    let summary = FileHashSummary::digest_bytes(&bytes);
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("hermetic-resume.bin"),
        size: bytes.len() as u64,
        file_hash: summary.file_hash(),
        part_hash_set: summary.part_hash_set().cloned(),
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let hashes = file.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let first = bytes[..part_size].to_vec();

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    let peer_task = peer.spawn(PeerScript {
        file_name: "hermetic-resume.bin".into(),
        hash_set: rmule_testkit::HashSetPolicy::Parts(hashes.clone()),
        ..PeerScript::serving(file.file_hash, bytes.clone())
    });

    // Seed the durable state the CLI resumes from: the download record (bound
    // to the fake server) plus part 0 verified in the repository and written
    // into the part file.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("hermetic-resume.bin");
    let paths = DownloadPaths::from_final_path(out.clone());
    let server_ep = server.endpoint();
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let record = repo
        .create_download(&file, Some(&server_ep), &paths)
        .unwrap();
    repo.record_verified_part(
        record.id(),
        VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: first.len() as u64,
            part_hash: hashes[0],
        },
    )
    .unwrap();
    ContentFileStore::write_verified_part(&paths, 0, &first)
        .await
        .unwrap();
    let download_id = record.id().as_u64();
    // One process owns the store file (ADR-0083): hand the lock back before
    // the binary under test opens the same directory.
    drop(repo);

    let data_dir_arg = dir.path().to_str().unwrap().to_owned();
    let id_arg = download_id.to_string();
    let cmd_out = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("rmule-tools")
            .unwrap()
            .args([
                "ed2k",
                "download",
                "resume",
                "--data-dir",
                &data_dir_arg,
                "--download-id",
                &id_arg,
            ])
            .timeout(Duration::from_secs(120))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&cmd_out.stdout);
    let stderr = String::from_utf8_lossy(&cmd_out.stderr);
    assert!(
        cmd_out.status.success(),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    assert_eq!(
        std::fs::read(&out).unwrap(),
        bytes,
        "resumed output byte-for-byte identical"
    );
    assert!(
        !paths.part_path().exists(),
        "part file removed after finalize"
    );
    peer_task.abort();
}
