//! The one [`FolderWatch`] over the operating system: `notify`'s recommended
//! watcher over a changing set of folders, each without its subfolders. The
//! Registry Check hands it the folders of the shared files outside the
//! download directory. On Linux each folder takes one inotify watch; on macOS
//! the set is one FSEvents stream. It only translates, as the directory
//! watch does: an event becomes the path it names, an overflow becomes
//! [`WatchSignal::Lost`], an error becomes [`WatchSignal::Failed`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use notify::event::{AccessKind, AccessMode};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use super::directory_watch::describe;
use crate::directory_scan::{WatchBatch, WatchFault, WatchSignal};
use crate::registry_check::FolderWatch;

/// A watch over a set of folders; dropping it stops every watch.
pub(crate) struct NotifyFolderWatch {
    /// `None` once the backend could not be created: the waits still pass
    /// time, and nothing is ever reported.
    watcher: Option<RecommendedWatcher>,
    events: Receiver<notify::Result<Event>>,
    /// Keeps `events` open while there is no watcher, so a wait waits.
    _idle: Sender<notify::Result<Event>>,
    /// Each watched folder as the check names it, by the name the backend
    /// reports it under (every symlink resolved).
    watched: BTreeMap<PathBuf, PathBuf>,
    /// Why the backend could not be created, reported at the first cover.
    unavailable: Option<WatchFault>,
}

impl NotifyFolderWatch {
    /// A watch over no folders yet.
    pub(crate) fn new() -> Self {
        let (tx, events) = mpsc::channel();
        let (watcher, unavailable) = match RecommendedWatcher::new(
            tx.clone(),
            Config::default().with_follow_symlinks(false),
        ) {
            Ok(watcher) => (Some(watcher), None),
            Err(error) => (None, Some(describe(error))),
        };
        Self {
            watcher,
            events,
            _idle: tx,
            watched: BTreeMap::new(),
            unavailable,
        }
    }

    fn translate(&self, event: notify::Result<Event>, signals: &mut Vec<WatchSignal>) {
        let event = match event {
            Ok(event) => event,
            Err(error) => return signals.push(WatchSignal::Failed(describe(error))),
        };
        if event.need_rescan() {
            return signals.push(WatchSignal::Lost);
        }
        if matches!(event.kind, EventKind::Access(access)
            if access != AccessKind::Close(AccessMode::Write))
        {
            return;
        }
        for path in event.paths {
            signals.push(
                self.named(&path)
                    .map_or(WatchSignal::Lost, WatchSignal::Moved),
            );
        }
    }

    /// `path` as the check names it: under a watched folder, by that folder's
    /// own name.
    fn named(&self, path: &Path) -> Option<PathBuf> {
        self.watched.iter().find_map(|(resolved, folder)| {
            path.strip_prefix(resolved)
                .ok()
                .map(|relative| folder.join(relative))
                .or_else(|| path.starts_with(folder).then(|| path.to_path_buf()))
        })
    }
}

impl FolderWatch for NotifyFolderWatch {
    fn wait(&mut self, max: Duration) -> WatchBatch {
        let mut signals = Vec::new();
        match self.events.recv_timeout(max) {
            Ok(first) => {
                self.translate(first, &mut signals);
                while let Ok(next) = self.events.try_recv() {
                    self.translate(next, &mut signals);
                }
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
        }
        WatchBatch {
            now: Instant::now(),
            signals,
        }
    }

    fn cover(&mut self, folders: &BTreeSet<PathBuf>) -> Result<(), WatchFault> {
        let Some(watcher) = self.watcher.as_mut() else {
            return Err(self.unavailable.unwrap_or(WatchFault::Backend));
        };
        let leaving: Vec<PathBuf> = self
            .watched
            .iter()
            .filter(|(_, folder)| !folders.contains(*folder))
            .map(|(resolved, _)| resolved.clone())
            .collect();
        for resolved in leaving {
            let _ = watcher.unwatch(&resolved);
            self.watched.remove(&resolved);
        }
        let mut refused = None;
        for folder in folders {
            if self.watched.values().any(|watched| watched == folder) {
                continue;
            }
            // A folder that is not there (an unplugged volume) is asked for
            // again at the next cover.
            let Ok(resolved) = std::fs::canonicalize(folder) else {
                continue;
            };
            match watcher.watch(&resolved, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    self.watched.insert(resolved, folder.clone());
                }
                Err(error) if matches!(&error.kind, notify::ErrorKind::PathNotFound) => {}
                Err(error) => refused = Some(describe(error)),
            }
        }
        refused.map_or(Ok(()), Err)
    }
}
