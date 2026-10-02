//! The **Run Log**: the one place a run's records land, since the terminal
//! itself is the alternate screen and can carry none of it.
//!
//! It is a file in the data directory (`rmule.log`), always on, appended to
//! across runs so a defect met in an ordinary session has left its evidence
//! behind. It is bounded: a write that would take the file past its cap first
//! moves it aside as the single predecessor (`rmule.log.1`), replacing the one
//! before, so the pair never holds more than twice the cap. `RMULE_LOG` is the
//! filter (`tracing-subscriber`'s `EnvFilter` syntax); absent or unparsable,
//! the level is `info`.
//!
//! What it holds is decided by type. A line is a [`Record`], an event code and
//! typed fields, and each field's kind names the [`Level`] that admits it: lean
//! (the default) holds reachability evidence and codes, full adds peer
//! addresses, file names, paths and hashes. [`event::record`] projects every
//! core event, [`ReachTrail`] every change of a reachability level and
//! [`ServerHealthTrail`] every edge of the server list's health, into
//! records; nothing is written from `Debug` output. The lines other code emits
//! through `tracing` are free-form and reach the file at the full level alone.
//!
//! A log that stops being writable is told once, on the channel it was opened
//! with, as a [`RunLogFailure`]: a failed rotation leaves the log growing past
//! its cap rather than ending it, and a failed write is dropped by the
//! `tracing` layer without a word of its own.

mod codes;
pub mod event;
mod level;
mod reach;
mod record;
mod server_health;
mod sink;
#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::mpsc::Sender;

use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, FilterExt, filter_fn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub use level::{Level, LevelHandle};
pub use reach::ReachTrail;
pub use record::{Address, Kind, Number, Record};
pub use server_health::ServerHealthTrail;
pub use sink::RunLog;

/// The log's name inside the data directory.
pub const FILE_NAME: &str = "rmule.log";
/// The name the log is moved aside under when it reaches its cap.
pub const PREDECESSOR_NAME: &str = "rmule.log.1";
/// The environment variable holding the filter.
pub const FILTER_VAR: &str = "RMULE_LOG";
/// The size past which the log is moved aside.
pub const CAP_BYTES: u64 = 16 * 1024 * 1024;
/// The `tracing` target of a record, and of nothing else: the lean level
/// admits this target alone.
const RECORD_TARGET: &str = "run_log";

/// Why a run has no log, as a code the words module words.
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

/// Open the log in `data_dir` and make it the process's `tracing` subscriber,
/// at `level`; the first failure to write it goes to `tell`. The handle it
/// returns changes the level for every writer, at once.
///
/// # Errors
///
/// Why the run has no log: the file could not be opened, or a subscriber was
/// already installed.
pub fn install(
    data_dir: &Path,
    tell: Sender<RunLogFailure>,
    level: Level,
) -> Result<LevelHandle, RunLogFailure> {
    let log = RunLog::open(data_dir, CAP_BYTES, tell).map_err(|error| RunLogFailure::Open {
        kind: error.kind(),
        os_code: error.raw_os_error(),
    })?;
    let filter = EnvFilter::try_from_env(FILTER_VAR).unwrap_or_else(|_| EnvFilter::new("info"));
    let handle = LevelHandle::new(level);
    subscriber(log, filter, handle.clone())
        .try_init()
        .map_err(|_| RunLogFailure::AlreadyInstalled)?;
    Ok(handle)
}

/// The subscriber that writes `log`: everything `filter` admits at the full
/// level, and only records at lean.
fn subscriber(
    log: RunLog,
    filter: EnvFilter,
    level: LevelHandle,
) -> impl tracing::Subscriber + Send + Sync {
    let records_only =
        filter_fn(move |metadata| level.get() == Level::Full || metadata.target() == RECORD_TARGET);
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(log)
        .with_filter(filter.and(records_only));
    tracing_subscriber::registry().with(layer)
}

/// Write `record` at `level`.
pub fn write(record: &Record, level: Level) {
    tracing::info!(target: RECORD_TARGET, "{}", record.render(level));
}
