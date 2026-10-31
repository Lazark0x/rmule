//! The file behind the Run Log: append-only, bounded, told once when it
//! stops being writable, and the `tracing` subscriber that writes it. One
//! thread owns the file behind a bounded lane, so a stalled disk delays the
//! log and never the thread that logged: past the lane's room a line is
//! counted and dropped, and the file says how many (ADR-0075).

#[cfg(test)]
mod tests;

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

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

/// How many lines wait for the disk before the next is dropped: a burst at
/// the full level fits, and a stalled disk costs a bounded amount of memory.
const LANE_ROOM: usize = 4096;

/// How long leaving waits for what is queued: past this the disk is the fault,
/// and a run that is ending does not wait on it.
const DRAIN_WAIT: Duration = Duration::from_secs(2);

/// The installed log, for [`drain`].
static INSTALLED: OnceLock<LogFile> = OnceLock::new();

/// Wait for what the installed log has queued to reach the file, for as long
/// as a stalled disk is worth. What a run says last is what a defect's reader
/// wants, so every front end leaves through this.
pub fn drain() {
    if let Some(log) = INSTALLED.get() {
        log.drain();
    }
}

/// [`drain`] at the end of a scope, however it ends.
#[derive(Debug)]
pub struct DrainAtExit;

impl Drop for DrainAtExit {
    fn drop(&mut self) {
        drain();
    }
}

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
        let _ = INSTALLED.set(self.file.clone());
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

/// One entry of the lane to the thread that owns the file.
#[derive(Debug)]
enum Entry {
    /// One formatted event.
    Event(Vec<u8>),
    /// Everything before this is in the file.
    Drained(Sender<()>),
}

/// The caller's end of the log: every thread that writes an event holds a
/// clone, and none of them ever touches the file.
#[derive(Clone, Debug)]
pub(super) struct LogFile {
    lane: SyncSender<Entry>,
    /// Lines the lane had no room for, since the file last said so.
    dropped: Arc<AtomicU64>,
}

/// The bounded file, owned by the thread that writes it.
#[derive(Debug)]
pub(super) struct Sink {
    path: PathBuf,
    predecessor: PathBuf,
    cap: u64,
    file: File,
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
    /// `cap`, and start the thread that writes it.
    ///
    /// The first write or rotation that fails is sent on `tell`, once.
    ///
    /// # Errors
    ///
    /// If the directory cannot be created, the file cannot be opened or the
    /// thread cannot start.
    pub(super) fn open(data_dir: &Path, cap: u64, tell: Sender<RunLogFailure>) -> io::Result<Self> {
        let sink = Sink::open(data_dir, cap, tell)?;
        let (log, entries) = Self::with_room(LANE_ROOM);
        let dropped = Arc::clone(&log.dropped);
        std::thread::Builder::new()
            .name("rmule-run-log".into())
            .spawn(move || sink.run(&entries, &dropped))?;
        Ok(log)
    }

    /// The caller's end, and the entries it sends, with no thread yet.
    fn with_room(room: usize) -> (Self, Receiver<Entry>) {
        let (lane, entries) = mpsc::sync_channel(room);
        let dropped = Arc::default();
        (Self { lane, dropped }, entries)
    }

    /// Wait for everything queued to be in the file, at most [`DRAIN_WAIT`].
    pub(super) fn drain(&self) {
        let deadline = Instant::now() + DRAIN_WAIT;
        let (done, drained) = mpsc::channel();
        let mut entry = Entry::Drained(done);
        loop {
            match self.lane.try_send(entry) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Disconnected(_)) => return,
                Err(mpsc::TrySendError::Full(back)) => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    entry = back;
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        let _ = drained.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }
}

/// The log at `path` for appending; a new one is born readable by this user
/// alone (ADR-0083), and `make_private` repairs one an older run left.
fn private_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

impl Sink {
    fn open(data_dir: &Path, cap: u64, tell: Sender<RunLogFailure>) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        crate::data_dir::make_private(data_dir);
        let path = data_dir.join(FILE_NAME);
        let file = private_append(&path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            predecessor: data_dir.join(PREDECESSOR_NAME),
            path,
            cap,
            file,
            written,
            retry_at: 0,
            tell: Some(tell),
        })
    }

    /// Write every entry until the last caller's end is gone. What the lane
    /// had no room for is said before the line that next found room.
    fn run(mut self, entries: &Receiver<Entry>, dropped: &AtomicU64) {
        for entry in entries {
            match entry {
                Entry::Event(event) => {
                    let lost = dropped.swap(0, Ordering::Relaxed);
                    if lost > 0 {
                        let line = format!("run_log.dropped lines={lost}\n");
                        let _ = self.append(line.as_bytes());
                    }
                    // A failure is told once, by `append`; nobody is left to
                    // hand this one to.
                    let _ = self.append(&event);
                }
                Entry::Drained(done) => {
                    let _ = done.send(());
                }
            }
        }
    }

    /// Land one event, moving the log aside first when it would pass the cap.
    fn append(&mut self, event: &[u8]) -> io::Result<()> {
        let length = event.len() as u64;
        if self.written > 0
            && self.written.saturating_add(length) > self.cap
            && self.written >= self.retry_at
            && let Err(error) = self.rotate()
        {
            // The log keeps growing past its cap: an oversize file is
            // better evidence than none. The next try waits for another
            // cap's worth of growth.
            self.retry_at = self.written.saturating_add(self.cap);
            self.fail(
                |kind, os_code| RunLogFailure::Rotate { kind, os_code },
                &error,
            );
        }
        if let Err(error) = self.file.write_all(event) {
            self.fail(
                |kind, os_code| RunLogFailure::Write { kind, os_code },
                &error,
            );
            return Err(error);
        }
        self.written = self.written.saturating_add(length);
        Ok(())
    }

    /// Move the log aside and start an empty one. An event larger than the
    /// cap still lands whole, in a file of its own.
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        std::fs::rename(&self.path, &self.predecessor)?;
        self.file = private_append(&self.path)?;
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
    /// Queue one event and return at once: a line the lane has no room for
    /// is counted, never waited for.
    fn write(&mut self, event: &[u8]) -> io::Result<usize> {
        if self.lane.try_send(Entry::Event(event.to_vec())).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(event.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
