//! The file behind the Run Log: append-only, bounded, told once when it
//! stops being writable, and the `tracing` subscriber that writes it.

#[cfg(test)]
mod tests;

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};

use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, FilterExt, filter_fn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::{
    CAP_BYTES, FILE_NAME, FILTER_VAR, Level, LevelHandle, PREDECESSOR_NAME, RECORD_TARGET,
    RunLogFailure,
};

/// The open log: its file, the level in force, where the file's first
/// failure is told, and whether its records are mirrored to stderr.
#[derive(Debug)]
pub struct RunLog {
    pub(super) file: LogFile,
    pub(super) level: LevelHandle,
    failures: Receiver<RunLogFailure>,
    mirrored: bool,
}

impl RunLog {
    /// Open (creating the directory and the file as needed) the log in
    /// `data_dir` at `level`, appending to what earlier runs left.
    ///
    /// # Errors
    ///
    /// [`RunLogFailure::Open`] if the directory cannot be created or the file
    /// cannot be opened.
    pub fn open(data_dir: &Path, level: Level) -> Result<Self, RunLogFailure> {
        let (tell, failures) = mpsc::channel();
        let file =
            LogFile::open(data_dir, CAP_BYTES, tell).map_err(|error| RunLogFailure::Open {
                kind: error.kind(),
                os_code: error.raw_os_error(),
            })?;
        Ok(Self {
            file,
            level: LevelHandle::new(level),
            failures,
            mirrored: false,
        })
    }

    /// Also write to stderr everything the `RMULE_LOG` filter admits: every
    /// record as the file holds it, rendered at the level in force, and
    /// every free-form `tracing` line, at either level. The file is
    /// unchanged by this: at lean it still holds records alone.
    #[must_use]
    pub fn mirrored_to_stderr(mut self) -> Self {
        self.mirrored = true;
        self
    }

    /// The level in force, shared: setting it through any clone changes it
    /// for every writer, at once.
    #[must_use]
    pub fn level(&self) -> LevelHandle {
        self.level.clone()
    }

    /// Make the log the process's `tracing` subscriber. The receiver it
    /// returns is told the first write or rotation that fails, once.
    ///
    /// # Errors
    ///
    /// [`RunLogFailure::AlreadyInstalled`] if a subscriber was already
    /// installed.
    pub fn install(self) -> Result<Receiver<RunLogFailure>, RunLogFailure> {
        let mirror = self.mirrored.then(|| Mirror {
            writer: BoxMakeWriter::new(io::stderr),
            filter: filter_from_env(),
        });
        subscriber(self.file, filter_from_env(), self.level, mirror)
            .try_init()
            .map_err(|_| RunLogFailure::AlreadyInstalled)?;
        Ok(self.failures)
    }
}

/// The filter `RMULE_LOG` names, or `info` when it names none.
fn filter_from_env() -> EnvFilter {
    EnvFilter::try_from_env(FILTER_VAR).unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Where the events are mirrored, under a filter of its own.
pub(super) struct Mirror {
    pub(super) writer: BoxMakeWriter,
    pub(super) filter: EnvFilter,
}

/// The subscriber that writes `file`: everything `filter` admits at the full
/// level, and only records at lean; and, with a `mirror`, everything its own
/// filter admits, free-form lines included, at either level.
pub(super) fn subscriber(
    file: LogFile,
    filter: EnvFilter,
    level: LevelHandle,
    mirror: Option<Mirror>,
) -> impl tracing::Subscriber + Send + Sync {
    let records_only =
        filter_fn(move |metadata| level.get() == Level::Full || metadata.target() == RECORD_TARGET);
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(file)
        .with_filter(filter.and(records_only));
    let mirror = mirror.map(|Mirror { writer, filter }| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(writer)
            .with_filter(filter)
    });
    tracing_subscriber::registry().with(layer).with(mirror)
}

/// The bounded file, shared by every thread that writes an event.
#[derive(Clone, Debug)]
pub(super) struct LogFile {
    pub(super) sink: Arc<Mutex<Sink>>,
}

#[derive(Debug)]
pub(super) struct Sink {
    pub(super) path: PathBuf,
    predecessor: PathBuf,
    cap: u64,
    pub(super) file: File,
    written: u64,
    /// The size the file must reach before a rotation is tried again after
    /// one failed: a refusal costs once per cap of growth, not once per write.
    retry_at: u64,
    /// Where the first failure goes; `None` once it has been told.
    tell: Option<Sender<RunLogFailure>>,
}

impl LogFile {
    /// Open (creating the directory and the file as needed) the log in
    /// `data_dir`, appending to what earlier runs left, moved aside past
    /// `cap`.
    ///
    /// The first write or rotation that fails is sent on `tell`, once.
    ///
    /// # Errors
    ///
    /// If the directory cannot be created or the file cannot be opened.
    pub(super) fn open(data_dir: &Path, cap: u64, tell: Sender<RunLogFailure>) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(FILE_NAME);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            sink: Arc::new(Mutex::new(Sink {
                predecessor: data_dir.join(PREDECESSOR_NAME),
                path,
                cap,
                file,
                written,
                retry_at: 0,
                tell: Some(tell),
            })),
        })
    }
}

impl Sink {
    /// Move the log aside and start an empty one. An event larger than the
    /// cap still lands whole, in a file of its own.
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        std::fs::rename(&self.path, &self.predecessor)?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        self.retry_at = 0;
        Ok(())
    }

    /// Tell the first failure and no other.
    fn fail(
        &mut self,
        failure: impl FnOnce(io::ErrorKind, Option<i32>) -> RunLogFailure,
        error: &io::Error,
    ) {
        if let Some(tell) = self.tell.take() {
            // A gone receiver means the run is ending; nobody is left to tell.
            let _ = tell.send(failure(error.kind(), error.raw_os_error()));
        }
    }
}

impl Write for LogFile {
    fn write(&mut self, event: &[u8]) -> io::Result<usize> {
        let mut sink = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        let length = event.len() as u64;
        if sink.written > 0
            && sink.written.saturating_add(length) > sink.cap
            && sink.written >= sink.retry_at
            && let Err(error) = sink.rotate()
        {
            // The log keeps growing past its cap: an oversize file is
            // better evidence than none. The next try waits for another
            // cap's worth of growth.
            sink.retry_at = sink.written.saturating_add(sink.cap);
            sink.fail(
                |kind, os_code| RunLogFailure::Rotate { kind, os_code },
                &error,
            );
        }
        if let Err(error) = sink.file.write_all(event) {
            sink.fail(
                |kind, os_code| RunLogFailure::Write { kind, os_code },
                &error,
            );
            return Err(error);
        }
        sink.written = sink.written.saturating_add(length);
        Ok(event.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .file
            .flush()
    }
}

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
