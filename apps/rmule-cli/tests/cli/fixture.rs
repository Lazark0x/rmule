//! What the legs share: an `rmule-cli` invocation pinned to a throwaway data
//! directory, so no leg touches the real one, and the settings that keep a
//! leg's core off the host's ports and router.

use assert_cmd::Command;
use rmule_core::port_mapping::PortMappingMode;
use rmule_core::{CoreSettingsHandle, Setting, open_durable_store};

/// `rmule-cli --data-dir <data_dir>`, ready for the subcommand under test.
pub fn cli(data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("rmule-cli").unwrap();
    cmd.arg("--data-dir").arg(data_dir);
    cmd
}

/// Store Core Settings in `data_dir` under which a core the CLI builds binds
/// only ports the OS just found free, and asks no router for a mapping. The
/// store closes again before the CLI opens it: the engine's lock admits one
/// opener.
pub fn off_the_host(data_dir: &std::path::Path) {
    let settings = CoreSettingsHandle::open(open_durable_store(data_dir).unwrap());
    rmule_testkit::scratch_ports(&settings);
    settings
        .set(Setting::PortMapping(PortMappingMode::Off))
        .unwrap();
}
