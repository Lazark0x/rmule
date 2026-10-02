//! The one thing every leg needs: an `rmule-cli` invocation pinned to a
//! throwaway data directory, so no leg touches the real one.

use assert_cmd::Command;

/// `rmule-cli --data-dir <data_dir>`, ready for the subcommand under test.
pub fn cli(data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("rmule-cli").unwrap();
    cmd.arg("--data-dir").arg(data_dir);
    cmd
}
