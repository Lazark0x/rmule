//! Losing the terminal (ADR-0118): the built binary on a real pty whose
//! master closes, as a closed window or a dropped ssh leaves it. The pty is
//! nobody's controlling terminal here, so no SIGHUP helps: the run has only
//! the hang-up itself to hear. It must end by itself, by the usual Quit, and
//! neither crash on a stderr that is gone nor spin on a reader that is.
//!
//! A plain start is not offline: on an empty list it fetches `server.met` and
//! pings what it got, and it maps ports on the router. So the store is seeded
//! with both off, and the Run Log has to show neither happened.

use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use rmule_core::port_mapping::PortMappingMode;
use rmule_core::{CoreSettingsHandle, Setting, open_durable_store};
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use tempfile::TempDir;

/// Past the probe's two seconds and the quit's own run.
const ENDS_WITHIN: Duration = Duration::from_secs(20);
/// What the run writes once it holds the screen.
const ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049h";

fn pty() -> (OwnedFd, File) {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("a pty");
    // A run that inherited the master would hold its own terminal open.
    fcntl_setfd(&master, FdFlags::CLOEXEC).expect("close on exec");
    grantpt(&master).expect("granted");
    unlockpt(&master).expect("unlocked");
    let name = ptsname(&master, Vec::new()).expect("its name");
    let path = std::path::PathBuf::from(name.to_string_lossy().into_owned());
    let terminal = File::options()
        .read(true)
        .write(true)
        .open(path)
        .expect("the terminal end");
    (master, terminal)
}

/// A data directory whose run touches no network, closed again before the
/// run opens it.
fn offline_data_dir(home: &Path) {
    let data = home.join("data");
    std::fs::create_dir_all(&data).expect("the data directory");
    let settings = CoreSettingsHandle::open(open_durable_store(&data).expect("the store"));
    rmule_testkit::scratch_ports(&settings);
    for setting in [
        Setting::AutoFetchServerMet(false),
        Setting::PortMapping(PortMappingMode::Off),
    ] {
        settings.set(setting).expect("the setting");
    }
}

fn assert_stayed_offline(home: &Path) {
    let log = std::fs::read_to_string(home.join("data").join("rmule.log")).expect("the Run Log");
    for reached_out in ["server_list.update_started", "status=probing"] {
        assert!(!log.contains(reached_out), "the run logged {reached_out}");
    }
}

fn run_on(terminal: &File, stderr: Stdio, home: &Path) -> Child {
    let stream = || Stdio::from(terminal.try_clone().expect("a stream"));
    Command::new(env!("CARGO_BIN_EXE_rmule"))
        .env_remove("XDG_DATA_HOME")
        .env("HOME", home)
        .env("RMULE_DATA", home.join("data"))
        .stdin(stream())
        .stdout(stream())
        .stderr(stderr)
        .spawn()
        .expect("the rmule binary is built")
}

/// Read until the run holds the screen, then close the master.
fn close_once_up(master: OwnedFd) {
    let mut master = File::from(master);
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 4096];
    while !seen
        .windows(ALTERNATE_SCREEN.len())
        .any(|window| window == ALTERNATE_SCREEN)
    {
        let read = master.read(&mut chunk).expect("the run's first frames");
        assert_ne!(read, 0, "the run ended before it took the screen");
        seen.extend_from_slice(&chunk[..read]);
    }
}

fn assert_ends_by_itself(mut child: Child) {
    let id = child.id();
    let (ended, wait) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = ended.send(child.wait());
    });
    let status = wait.recv_timeout(ENDS_WITHIN).unwrap_or_else(|_| {
        let _ = Command::new("kill").arg("-9").arg(id.to_string()).status();
        panic!("the run did not end after its terminal closed");
    });
    assert!(
        status.expect("waited").success(),
        "a closed window is no fault"
    );
}

/// One test for both, so no second pty is being opened while this one's
/// run forks.
#[test]
fn a_closed_terminal_ends_the_run_whatever_stderr_is() {
    for stderr_on_the_terminal in [true, false] {
        let home = TempDir::new().expect("a scratch home");
        offline_data_dir(home.path());
        let (master, terminal) = pty();
        let stderr = if stderr_on_the_terminal {
            Stdio::from(terminal.try_clone().expect("stderr"))
        } else {
            Stdio::from(File::create(home.path().join("stderr")).expect("a redirect"))
        };
        let child = run_on(&terminal, stderr, home.path());
        drop(terminal);

        close_once_up(master);

        assert_ends_by_itself(child);
        assert_stayed_offline(home.path());
    }
}
