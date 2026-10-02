//! The **Run Dir** layout and the **Synthetic File**: what a flow stages before
//! any container starts, and the hash-command seam that turns it into a link.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use rmule_interop_harness::artifacts::{
    Ed2kHashCommand, RunLayout, write_synthetic_ed2k_link, write_synthetic_file,
};

#[test]
fn run_layout_creates_expected_artifact_paths() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let layout = RunLayout::create(temp.path())?;

    assert_eq!(layout.synthetic_dir(), temp.path().join("synthetic"));
    assert_eq!(
        layout.synthetic_shared_file(),
        temp.path().join("synthetic/shared.bin")
    );
    assert_eq!(
        layout.synthetic_ed2k_file(),
        temp.path().join("synthetic/shared.ed2k.txt")
    );
    assert_eq!(layout.rmule_dir(), temp.path().join("rmule"));
    assert_eq!(
        layout.rmule_output_file(),
        temp.path().join("rmule/output.bin")
    );
    assert_eq!(layout.amule_dir(), temp.path().join("amule"));
    assert_eq!(
        layout.amule_output_file(),
        temp.path().join("amule/shared.bin")
    );
    assert_eq!(layout.server_logs_dir(), temp.path().join("logs/server"));
    assert_eq!(layout.amule_logs_dir(), temp.path().join("logs/amule"));
    assert_eq!(
        layout.amule_diagnostics_stdout_log(),
        temp.path().join("logs/amule/diagnostics.stdout.log")
    );
    assert_eq!(
        layout.amule_diagnostics_stderr_log(),
        temp.path().join("logs/amule/diagnostics.stderr.log")
    );
    assert_eq!(layout.rmule_logs_dir(), temp.path().join("logs/rmule"));

    assert!(layout.synthetic_dir().is_dir());
    assert!(layout.rmule_dir().is_dir());
    assert!(layout.amule_dir().is_dir());
    assert!(layout.server_logs_dir().is_dir());
    assert!(layout.amule_logs_dir().is_dir());
    assert!(layout.rmule_logs_dir().is_dir());

    Ok(())
}

#[test]
fn run_layout_creates_kad_capture_paths() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let layout = RunLayout::create(temp.path())?;

    assert_eq!(layout.kad_dir(), temp.path().join("kad"));
    assert_eq!(layout.kad_capture_dir(), temp.path().join("capture/kad"));
    assert_eq!(
        layout.kad_pcap_file(),
        temp.path().join("capture/kad/kad.pcap")
    );
    assert_eq!(layout.kad_nodes_file(), temp.path().join("kad/nodes.toml"));
    assert_eq!(
        layout.kad_endpoint_map_file(),
        temp.path().join("kad/endpoints.toml")
    );
    assert_eq!(
        layout.kad_candidate_summary_file(),
        temp.path().join("kad/candidate-summary.toml")
    );
    assert_eq!(
        layout.kad_node_logs_dir("requester"),
        temp.path().join("logs/kad/requester")
    );
    assert_eq!(
        layout.kad_node_stdout_log("requester"),
        temp.path().join("logs/kad/requester/stdout.log")
    );
    assert_eq!(
        layout.kad_node_stderr_log("publisher"),
        temp.path().join("logs/kad/publisher/stderr.log")
    );

    assert!(layout.kad_dir().is_dir());
    assert!(layout.kad_capture_dir().is_dir());
    assert!(temp.path().join("logs/kad").is_dir());

    Ok(())
}

#[test]
fn synthetic_file_uses_deterministic_byte_pattern() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let layout = RunLayout::create(temp.path())?;

    write_synthetic_file(&layout, 1025)?;

    let bytes = fs::read(layout.synthetic_shared_file())?;
    assert_eq!(bytes.len(), 1025);
    for (index, byte) in bytes.iter().enumerate() {
        assert_eq!(*byte, (index % 251) as u8);
    }

    Ok(())
}

#[test]
fn ed2k_link_generation_uses_hash_command_and_writes_artifact() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let layout = RunLayout::create(temp.path())?;
    write_synthetic_file(&layout, 16)?;

    let fake_hash = temp.path().join("fake-hash");
    let mut script = fs::File::create(&fake_hash)?;
    writeln!(script, "#!/bin/sh")?;
    writeln!(
        script,
        "printf '%s\\n' \"$1\" > \"{}\"",
        temp.path().join("seen-arg").display()
    )?;
    writeln!(
        script,
        "printf '%s\\n' 'canonical_link: ed2k://|file|shared.bin|16|abcd|/'"
    )?;
    drop(script);
    let mut permissions = fs::metadata(&fake_hash)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_hash, permissions)?;

    let command = Ed2kHashCommand::new(&fake_hash);
    let link = write_synthetic_ed2k_link(&layout, &command)?;

    assert_eq!(link, "ed2k://|file|shared.bin|16|abcd|/");
    assert_eq!(
        fs::read_to_string(layout.synthetic_ed2k_file())?,
        "ed2k://|file|shared.bin|16|abcd|/\n"
    );
    assert_eq!(
        fs::read_to_string(temp.path().join("seen-arg"))?,
        format!("{}\n", layout.synthetic_shared_file().display())
    );

    Ok(())
}
