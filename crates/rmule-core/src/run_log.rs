//! The **Run Log** (ADR-0075): the one place a run's records land, and the
//! vocabulary they are written in.
//!
//! It is a file in the data directory (`rmule.log`), appended to across runs
//! so a defect met in an ordinary session has left its evidence behind. It is
//! bounded: a write that would take the file past its cap first moves it
//! aside as the single predecessor (`rmule.log.1`), replacing the one before,
//! so the pair never holds more than twice the cap. `RMULE_LOG` is the filter
//! (`tracing-subscriber`'s `EnvFilter` syntax); absent or unparsable, the
//! level is `info`.
//!
//! What it holds is decided by type. A line is a [`Record`], an event code and
//! typed fields, and each field's [`Kind`] names the [`Level`] that admits it:
//! lean (the default) holds reachability evidence and codes, full adds peer
//! addresses, file names, paths and hashes. Every core event projects into a
//! record through its own `record()` ([`CoreEvent::record`]), an exhaustive
//! match beside the reason code tables in `codes`, and so does a value Core
//! Settings refused ([`SettingRefusal::record`]); nothing is written from
//! `Debug` output. The lines other code emits through `tracing` are free-form
//! and reach the file at the full level alone.
//!
//! A front end writes the records of the events it receives. Core writes the
//! **Reachability Trail** itself (`trail`): its own levels — addresses, port
//! mappings, the server and its health, Kad verdicts and the own buddy's
//! state, the NAT-T own mapping — each written as its owner moves it.
//!
//! A log that stops being writable is told once, on the receiver
//! [`RunLog::install`] hands back, as a [`RunLogFailure`]: a failed rotation
//! leaves the log growing past its cap rather than ending it, and a failed
//! write is dropped by the `tracing` layer without a word of its own.
//!
//! [`CoreEvent::record`]: crate::CoreEvent::record
//! [`SettingRefusal::record`]: crate::SettingRefusal::record

pub(crate) mod codes;
mod event;
mod level;
mod record;
mod setting;
mod sink;
#[cfg(test)]
mod tests;
pub(crate) mod trail;

pub use level::{Level, LevelHandle};
pub use record::{Address, Kind, Number, Record};
pub use sink::RunLog;

/// The log's name inside the data directory.
pub const FILE_NAME: &str = "rmule.log";
/// The name the log is moved aside under when it reaches its cap.
pub const PREDECESSOR_NAME: &str = "rmule.log.1";
/// The environment variable holding the filter.
pub const FILTER_VAR: &str = "RMULE_LOG";
/// The key the *Full run log* preference is stored under: a front end's own
/// key in the preferences table, which core never reads (ADR-0069), shared by
/// every front end that writes the Run Log. Stable: renaming it would orphan
/// an installed value.
pub const PREFERENCE_KEY: &str = "run_log_full";
/// The size past which the log is moved aside.
pub const CAP_BYTES: u64 = 16 * 1024 * 1024;
/// The `tracing` target of a record, and of nothing else: the lean level
/// admits this target alone.
const RECORD_TARGET: &str = "run_log";

/// Why a run has no log, as a code a front end words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunLogFailure {
    /// No data directory to put it in.
    NoDataDir,
    /// The OS refused to open the file: its error kind, and its number when
    /// it gave one.
    Open {
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// A `tracing` subscriber was already installed.
    AlreadyInstalled,
    /// The file stopped taking writes.
    Write {
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// The file could not be moved aside at its cap; it keeps growing.
    Rotate {
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
}

/// Write `record` at `level`.
pub fn write(record: &Record, level: Level) {
    tracing::info!(target: RECORD_TARGET, "{}", record.render(level));
}

/// The record that opens a run in the log, so two runs' lines tell apart and
/// the log names the build that wrote them. A build fact the build could not
/// capture (empty) is the word `unknown`.
#[must_use]
pub fn run_start(
    version: &'static str,
    commit: &'static str,
    committed: &'static str,
    dirty: bool,
) -> Record {
    let fact = |value: &'static str| if value.is_empty() { "unknown" } else { value };
    Record::new("run_start")
        .code("version", version)
        .code("commit", fact(commit))
        .flag("dirty", dirty)
        .code("committed", fact(committed))
}
