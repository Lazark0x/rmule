//! The one [`DirectoryWatch`] over the operating system: `notify`'s
//! recommended watcher (FSEvents on macOS, inotify on Linux), recursive, not
//! following symlinks. It only translates: an event becomes the path it
//! names, an overflow becomes [`WatchSignal::Lost`], an error that names a
//! path under the directory becomes [`WatchSignal::PathFailed`] for that path,
//! and any other error becomes [`WatchSignal::Failed`], each with a reason the
//! operator can act on. What moved is decided by the scan, which examines the
//! path.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use notify::event::{AccessKind, AccessMode};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::directory_scan::{DirectoryWatch, WatchBatch, WatchFault, WatchSignal, WatchStarter};

/// The [`WatchStarter`] over the operating system: a [`NotifyDirectoryWatch`]
/// per start, and the wall clock during an outage.
pub(crate) struct NotifyWatchStarter;

impl WatchStarter for NotifyWatchStarter {
    fn start(&mut self, root: &Path) -> Result<Box<dyn DirectoryWatch>, WatchFault> {
        NotifyDirectoryWatch::start(root).map(|watch| Box::new(watch) as Box<dyn DirectoryWatch>)
    }

    fn pause(&mut self, max: Duration) {
        std::thread::sleep(max);
    }
}

/// A running watch over one directory; dropping it stops the watch.
pub(crate) struct NotifyDirectoryWatch {
    // Held for its drop, which ends the backend's stream or watches.
    _watcher: RecommendedWatcher,
    events: Receiver<notify::Result<Event>>,
    /// The directory as the scan names it.
    root: PathBuf,
    /// The same directory with every symlink resolved, which is how FSEvents
    /// names what it reports (`/var` is `/private/var` on macOS).
    resolved: PathBuf,
}

impl NotifyDirectoryWatch {
    /// Watch `root` and everything under it.
    ///
    /// # Errors
    /// Why the watch could not start.
    pub(crate) fn start(root: &Path) -> Result<Self, WatchFault> {
        let resolved = std::fs::canonicalize(root).map_err(|error| {
            tracing::warn!(dir = %root.display(), %error, "the directory to watch could not be resolved");
            WatchFault::io(&error)
        })?;
        let (tx, events) = mpsc::channel();
        let mut watcher =
            RecommendedWatcher::new(tx, Config::default().with_follow_symlinks(false))
                .map_err(describe)?;
        watcher
            .watch(&resolved, RecursiveMode::Recursive)
            .map_err(describe)?;
        Ok(Self {
            _watcher: watcher,
            events,
            root: root.to_path_buf(),
            resolved,
        })
    }

    fn translate(&self, event: notify::Result<Event>, signals: &mut Vec<WatchSignal>) {
        let event = match event {
            Ok(event) => event,
            Err(error) => return self.failed(error, signals),
        };
        if event.need_rescan() {
            return signals.push(WatchSignal::Lost);
        }
        // A read (the scan's own hashing among them) moves nothing; a close
        // after writing is kept as the hint it is.
        if matches!(event.kind, EventKind::Access(access)
            if access != AccessKind::Close(AccessMode::Write))
        {
            return;
        }
        for path in event.paths {
            signals.push(match self.place(&path) {
                Some(path) => WatchSignal::Moved(path),
                // A name the scan cannot place: look at everything.
                None => WatchSignal::Lost,
            });
        }
    }

    /// `path` as the scan names it, if it lies under the directory.
    fn place(&self, path: &Path) -> Option<PathBuf> {
        match path.strip_prefix(&self.resolved) {
            Ok(relative) => Some(self.root.join(relative)),
            Err(_) if path.starts_with(&self.root) => Some(path.to_path_buf()),
            Err(_) => None,
        }
    }

    /// An error that names paths under the directory, other than the
    /// directory itself, is about those paths: the rest stays watched. Any
    /// other error is about the watch.
    fn failed(&self, error: notify::Error, signals: &mut Vec<WatchSignal>) {
        let paths: Vec<PathBuf> = error
            .paths
            .iter()
            .filter_map(|path| self.place(path))
            .filter(|path| *path != self.root)
            .collect();
        let reason = describe(error);
        if paths.is_empty() {
            return signals.push(WatchSignal::Failed(reason));
        }
        for path in paths {
            signals.push(WatchSignal::PathFailed { path, reason });
        }
    }
}

impl DirectoryWatch for NotifyDirectoryWatch {
    fn wait(&mut self, max: Duration) -> WatchBatch {
        let mut signals = Vec::new();
        match self.events.recv_timeout(max) {
            Ok(first) => {
                self.translate(first, &mut signals);
                while let Ok(next) = self.events.try_recv() {
                    self.translate(next, &mut signals);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                signals.push(WatchSignal::Failed(WatchFault::Stopped));
            }
        }
        WatchBatch {
            now: Instant::now(),
            signals,
        }
    }
}

/// A `notify` error as the code a front end words; the library's own
/// sentence goes to the Run Log, here, and nowhere else.
pub(super) fn describe(error: notify::Error) -> WatchFault {
    tracing::warn!(%error, "the file watch reported an error");
    WatchFault::from(&error)
}

#[cfg(test)]
mod tests {
    use notify::ErrorKind;

    use super::{NotifyDirectoryWatch, WatchFault, WatchSignal};

    /// Which errors are about one path and which about the watch (ADR-0103,
    /// "A watch that fails while running is re-established").
    #[test]
    fn an_error_naming_a_path_under_the_directory_drops_only_that_path() {
        let tmp = tempfile::tempdir().unwrap();
        let watch = NotifyDirectoryWatch::start(tmp.path()).unwrap();
        let sub = watch.resolved.join("sub");
        let mut signals = Vec::new();
        watch.failed(
            notify::Error::new(ErrorKind::MaxFilesWatch).add_path(sub),
            &mut signals,
        );
        watch.failed(notify::Error::generic("stream ended"), &mut signals);
        watch.failed(
            notify::Error::path_not_found().add_path(watch.resolved.clone()),
            &mut signals,
        );
        assert_eq!(
            signals[..2],
            [
                WatchSignal::PathFailed {
                    path: tmp.path().join("sub"),
                    reason: WatchFault::Limit,
                },
                WatchSignal::Failed(WatchFault::Backend),
            ]
        );
        assert!(
            matches!(&signals[2..], [WatchSignal::Failed(_)]),
            "an error naming the directory itself is about the watch"
        );
    }
}
