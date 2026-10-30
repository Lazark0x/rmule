//! The one switch of a fast-clock debug run: `AMULE_CLOCK_SCALE=<n>`, in
//! `--amule-env` or the harness's own environment, puts aMule, ed2k-server and
//! rmule on one sped-up clock. Such a run never fills a row.
//!
//! aMule and ed2k-server run from their derived images, whose wrappers read the
//! switch. rmule takes libfaketime from a mounted library, on its own run
//! command only: a container that runs cargo stays on the real clock, because
//! a faked clock would break the build's mtimes. Lugdunum stays real.

use std::path::PathBuf;
use std::sync::OnceLock;

/// The variable the wrappers read.
pub(crate) const SWITCH: &str = "AMULE_CLOCK_SCALE";
/// Where a run's rmule finds the library inside its container.
const LIBRARY_MOUNT: &str = "/fastclock/libfaketimeMT.so.1";
/// The bookworm build of the library, beside the workspace's other caches.
const LIBRARY: &str = ".scratch/fastclock/libfaketimeMT.so.1";

static SCALE: OnceLock<u64> = OnceLock::new();

/// The run's clock scale; 1 is real speed.
pub fn scale() -> u64 {
    *SCALE.get_or_init(|| {
        let assignment = format!("{SWITCH}=");
        std::env::args()
            .find_map(|arg| arg.strip_prefix(&assignment)?.parse().ok())
            .or_else(|| std::env::var(SWITCH).ok()?.parse().ok())
            .unwrap_or(1)
    })
}

/// How long `app_secs` of an app's clock takes on the wall, never nothing.
pub fn wall_secs(app_secs: u64) -> u64 {
    (app_secs / scale()).max(1)
}

/// The fast-clock image of a stock counterparty.
pub(crate) fn counterparty_image(image: &str) -> Option<&'static str> {
    match image {
        "rmule/interop-amule:local" | "rmule/interop-amule-debug:local" => {
            Some("rmule/interop-amule-fastclock:local")
        }
        "rmule/interop-ed2ksrv:local" => Some("rmule/interop-ed2ksrv-fastclock:local"),
        _ => None,
    }
}

/// The library's host path and its mount.
pub(crate) fn library_volume() -> (PathBuf, &'static str) {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    (workspace.join(LIBRARY), LIBRARY_MOUNT)
}

/// The environment of an rmule on the fast clock.
pub(crate) fn rmule_env() -> [(&'static str, String); 4] {
    [
        ("LD_PRELOAD", LIBRARY_MOUNT.to_owned()),
        ("FAKETIME", format!("+0 x{}", scale())),
        ("FAKETIME_NO_CACHE", "1".to_owned()),
        ("DONT_FAKE_MONOTONIC", "0".to_owned()),
    ]
}
