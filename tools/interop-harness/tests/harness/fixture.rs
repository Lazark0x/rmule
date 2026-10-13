//! Shared builders and assertions for every leg: the harness invocation a leg
//! starts from, the ports and roots it is pointed at, the stub ED2K hash
//! command, the `run_dir=` readback, the seeded Kad identity the capture family
//! expects, and the ordering assertion the argv logs are read with.

use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;

/// The default flow's invocation against a fake runtime.
pub(crate) fn base_command(docker: &Path, hash_command: &Path, run_root: &Path) -> Command {
    base_command_for(
        "amule-serves-rmule-downloads",
        docker,
        hash_command,
        run_root,
    )
}

/// `flow` invoked against a fake runtime with a one-second budget.
pub(crate) fn base_command_for(
    flow: &str,
    docker: &Path,
    hash_command: &Path,
    run_root: &Path,
) -> Command {
    let mut command = Command::cargo_bin("rmule-interop-harness").unwrap();
    command.args([
        flow,
        "--container-runtime",
        docker.to_str().unwrap(),
        "--ed2k-hash-command",
        hash_command.to_str().unwrap(),
        "--run-root",
        run_root.to_str().unwrap(),
        "--timeout",
        "1",
    ]);
    command
}

pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The band [`unused_local_port`] draws numbers from: below every kernel's
/// ephemeral range (Linux starts at 32768, macOS at 49152) and clear of
/// `rmule-core`'s own `PORT_BAND` (20 000..30 000) in case both
/// suites' binaries ever run at once on one host — so a number this fixture
/// reserves is invisible to a stray `:0` bind anywhere else.
const PORT_BAND: std::ops::Range<u16> = 10_000..20_000;
// Linux's ephemeral range starts at 32768; the band must end below it.
const _: () = assert!(PORT_BAND.end <= 32_768);

/// A port reserved by [`unused_local_port`], held open until dropped. Two
/// calls in this binary can never be handed the same number the way two
/// independent `:0` bind-then-drops could be — a kernel
/// ephemeral pick can be reused by anyone the instant it is freed, but each
/// reservation here draws its own number off one shared, never-repeating
/// cursor ([`next_band_port`]), so a sibling call has nothing to collide on.
///
/// The hold cannot itself reach the *real* bind these numbers are reserved
/// for: every call site hands the number to a docker container or an
/// `rmule-interop-harness` child process, both across a process boundary
/// this socket cannot follow, and — for a leg that wants the port to answer
/// nothing at all (`fake_docker::cleanup`'s readiness-timeout case) — must
/// not follow anyway, since a held-but-unaccepted listener still completes a
/// TCP handshake and would falsify "closed". So every call site drops the
/// reservation right before spawning that child: the drop closes the
/// setup-time gap this process controls, and the band's own uniqueness —
/// not the hold's duration — is what defeats the sibling-reuse race a plain
/// bind-then-drop could lose.
/// Where a process's cursor starts in [`PORT_BAND`].
fn band_start(pid: u32) -> u16 {
    let width = u32::from(PORT_BAND.end - PORT_BAND.start);
    PORT_BAND.start + u16::try_from(pid.wrapping_mul(2_654_435_761) % width).unwrap_or(0)
}

pub(crate) struct ReservedPort {
    port: u16,
    _held: TcpListener,
}

impl ReservedPort {
    pub(crate) const fn port(&self) -> u16 {
        self.port
    }
}

/// The next number off this binary's cursor through [`PORT_BAND`] — never
/// the same one twice until the band wraps. The cursor starts at a point
/// scattered by the process id, so two test binaries running at once do not
/// walk the same sequence.
fn next_band_port() -> u16 {
    static CURSOR: std::sync::LazyLock<std::sync::Mutex<u16>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(band_start(std::process::id())));
    let mut cursor = CURSOR.lock().expect("port cursor is never poisoned");
    let candidate = *cursor;
    *cursor = if candidate + 1 >= PORT_BAND.end {
        PORT_BAND.start
    } else {
        candidate + 1
    };
    candidate
}

/// Reserve a loopback port for a flow's host-published server/peer port,
/// held until the caller drops it (see [`ReservedPort`]) — replacing the
/// plain `:0` bind-then-drop that let a freed number be reclaimed before
/// this call's own, later use of it.
pub(crate) fn unused_local_port() -> ReservedPort {
    loop {
        let port = next_band_port();
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            return ReservedPort {
                port,
                _held: listener,
            };
        }
    }
}

/// The retained run dir a flow printed as `run_dir=`, made absolute.
pub(crate) fn run_dir_from(stdout: &[u8]) -> PathBuf {
    let stdout = String::from_utf8_lossy(stdout);
    let run_dir = stdout
        .lines()
        .find_map(|line| line.strip_prefix("run_dir="))
        .expect("flow prints a run_dir= line");
    let path = PathBuf::from(run_dir);
    if path.is_absolute() {
        path
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
    }
}

/// A stub ED2K hash command printing a `fakehash` link of `size` bytes — the
/// placeholder the eD2k legs assert on (it is not hex, so no Kad ID can be
/// derived from it; see `fake_kad_hash_command`).
pub(crate) fn fake_hash_command(dir: &Path, size: u64) -> PathBuf {
    let path = dir.join("fake-hash");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(
        script,
        "printf '%s\\n' 'canonical_link: ed2k://|file|shared.bin|{size}|fakehash|/'"
    )
    .unwrap();
    drop(script);
    make_executable(&path);
    path
}

pub(crate) fn make_executable(path: &Path) {
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

/// The synthetic file's ED2K hash used by `fake_kad_hash_command`, matching the
/// `kad_seed` unit-test vector.
pub(crate) const KAD_FILE_HASH_HEX: &str = "8E302DB5B806A25C9385FC23F21062D2";

/// The storer's expected seeded Kad ID: the file hash with each 32-bit word
/// byte-swapped (the proven on-wire `0x34` target), per
/// `kad_seed::storer_kad_id_for_file_hash`.
pub(crate) fn expected_storer_kad_id() -> [u8; 16] {
    [
        0xB5, 0x2D, 0x30, 0x8E, 0x5C, 0xA2, 0x06, 0xB8, 0x23, 0xFC, 0x85, 0x93, 0xD2, 0x62, 0x10,
        0xF2,
    ]
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Extract the value of an `-e KEY=VALUE` argument from a logged docker run line.
pub(crate) fn env_value(run_line: &str, key: &str) -> String {
    let needle = format!("-e {key}=");
    let start = run_line
        .find(&needle)
        .unwrap_or_else(|| panic!("missing `{needle}` in:\n{run_line}"))
        + needle.len();
    run_line[start..]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned()
}

/// Drive the Kad capture flow against the fake docker, with the settle window
/// and search schedule zeroed so the fake-docker test stays fast (real timing is only for live
/// runs). Asserts success.
pub(crate) fn run_fake_kad_capture(
    docker: &Path,
    hash_command: &Path,
    run_root: &Path,
    extra: &[&str],
) {
    let mut command = Command::cargo_bin("rmule-interop-harness").unwrap();
    command
        .env("RMULE_KAD_SETTLE_WINDOW_SECS", "0")
        .env("RMULE_KAD_SEARCH_CANCEL_GAP_SECS", "0")
        .env("RMULE_KAD_SEARCH_RETRY_INTERVAL_SECS", "0")
        .args([
            "kad-source-lookup-capture",
            "--skip-build",
            "--container-runtime",
            docker.to_str().unwrap(),
            "--ed2k-hash-command",
            hash_command.to_str().unwrap(),
            "--run-root",
            run_root.to_str().unwrap(),
            "--timeout",
            "5",
        ])
        .args(extra);
    command.assert().success();
}

pub(crate) fn deterministic_bytes(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index % 251) as u8).collect()
}

pub(crate) fn run_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    dirs.sort();
    dirs
}

pub(crate) fn assert_ordered(haystack: &str, needles: &[String]) {
    let mut offset = 0;
    for needle in needles {
        let position = haystack[offset..]
            .find(needle.as_str())
            .unwrap_or_else(|| panic!("missing `{needle}` in fake docker log:\n{haystack}"));
        offset += position + needle.len();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::unused_local_port;

    /// A freed reservation is never handed to a later caller —
    /// the defect a plain `:0` bind-then-drop had, where the very next
    /// probe (a sibling test's `unused_local_port()`, or its own real bind
    /// later) was fair game to reclaim the number this call just gave up.
    /// Each draw is dropped immediately, exactly as every real call site
    /// does once it has copied the number out.
    #[test]
    fn a_freed_reservation_is_never_handed_to_the_next_caller() {
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let port = unused_local_port().port();
            assert!(seen.insert(port), "port {port} handed out twice in one run");
        }
    }
}

/// The band sits below every kernel's ephemeral range, so a stray `:0` bind
/// cannot be handed a reserved number, and two processes start their cursors
/// apart instead of walking one sequence.
#[test]
fn the_port_band_is_below_the_ephemeral_ranges_and_scattered_per_process() {
    for pid in [1, 2, 4242, 99_999, u32::MAX] {
        assert!(PORT_BAND.contains(&band_start(pid)), "pid {pid}");
    }
    assert_ne!(band_start(4242), band_start(4243));
}
