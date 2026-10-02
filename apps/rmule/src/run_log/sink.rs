//! The file behind the Run Log: append-only, bounded, told once when it
//! stops being writable.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, PoisonError};

use tracing_subscriber::fmt::MakeWriter;

use super::{FILE_NAME, PREDECESSOR_NAME, RunLogFailure};

/// The open log, shared by every thread that writes an event.
#[derive(Clone, Debug)]
pub struct RunLog {
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

impl RunLog {
    /// Open (creating the directory and the file as needed) the log in
    /// `data_dir`, appending to what earlier runs left.
    ///
    /// The first write or rotation that fails is sent on `tell`, once.
    ///
    /// # Errors
    ///
    /// If the directory cannot be created or the file cannot be opened.
    pub fn open(data_dir: &Path, cap: u64, tell: Sender<RunLogFailure>) -> io::Result<Self> {
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

impl Write for RunLog {
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

impl<'a> MakeWriter<'a> for RunLog {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
