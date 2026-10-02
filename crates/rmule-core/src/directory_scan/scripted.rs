//! A directory tree held in memory, the [`DirectorySource`] the pass and the
//! watch are tested against. Files carry their bytes; every open is counted,
//! and so is every look at a single path, so a test can bound the work a
//! burst of events costs.

use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use rmule_primitives::FileHash;

use super::{DirEntry, DirectorySource, EntryKind, FileIdentity, FileStamp, Known, WatchSignal};
use crate::registry::{ShareSource, SharedFileEntry};

pub(crate) const ROOT: &str = "/dl";

pub(crate) fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

#[derive(Default)]
pub(crate) struct Scripted {
    pub(crate) dirs: HashMap<PathBuf, Vec<DirEntry>>,
    pub(crate) files: HashMap<PathBuf, (FileStamp, Vec<u8>)>,
    /// Files whose stamp reads differently after they were listed.
    pub(crate) moving: HashSet<PathBuf>,
    /// Files that are there but refuse to open.
    pub(crate) denied: HashSet<PathBuf>,
    /// Directories that refuse to be listed; what is under them can still
    /// be looked at by its path.
    pub(crate) unlistable: HashSet<PathBuf>,
    /// Directories that refuse to be listed or looked through, as a folder
    /// with no permissions does.
    pub(crate) sealed: HashSet<PathBuf>,
    /// The identity each file's filesystem gives, where it gives one.
    pub(crate) identities: HashMap<PathBuf, FileIdentity>,
    opens: AtomicUsize,
    identity_looks: AtomicUsize,
    looks: AtomicUsize,
}

impl Scripted {
    pub(crate) fn new() -> Self {
        let mut dirs = HashMap::new();
        dirs.insert(PathBuf::from(ROOT), Vec::new());
        Self {
            dirs,
            ..Self::default()
        }
    }

    /// Put `kind` at `path`, replacing whatever entry had its name.
    pub(crate) fn entry(&mut self, path: &str, kind: EntryKind) {
        let path = Path::new(path);
        let parent = path.parent().expect("under the root").to_path_buf();
        let name = OsString::from(path.file_name().expect("named"));
        if kind == EntryKind::Directory {
            self.dirs.entry(path.to_path_buf()).or_default();
        }
        let listing = self.dirs.entry(parent).or_default();
        listing.retain(|entry| entry.name != name);
        listing.push(DirEntry { name, kind });
    }

    pub(crate) fn dir(&mut self, path: &str) {
        self.entry(path, EntryKind::Directory);
    }

    /// Make the directory at `path` a symlink to one: a look reports the
    /// link, a listing and a folder question follow it.
    pub(crate) fn link(&mut self, path: &str) {
        self.dirs.entry(PathBuf::from(path)).or_default();
        self.entry(path, EntryKind::Symlink);
    }

    /// Write (or rewrite) the file at `path`.
    pub(crate) fn file(&mut self, path: &str, bytes: &[u8], modified: u64) -> FileStamp {
        let stamp = FileStamp {
            size: bytes.len() as u64,
            modified: at(modified),
        };
        self.entry(path, EntryKind::File(stamp));
        self.files
            .insert(PathBuf::from(path), (stamp, bytes.to_vec()));
        stamp
    }

    /// Give the file at `path` an identity: inode `inode` on device 1, born
    /// at second `born`.
    pub(crate) fn identify(&mut self, path: &str, inode: u64, born: u64) -> FileIdentity {
        let identity = FileIdentity {
            device: 1,
            inode,
            born: at(born),
        };
        self.identities.insert(PathBuf::from(path), identity);
        identity
    }

    /// Rename the file `from` to `to`, as `rename(2)` does on one
    /// filesystem: same bytes, same stamp, same identity.
    pub(crate) fn rename(&mut self, from: &str, to: &str) {
        let (stamp, bytes) = self.files.get(Path::new(from)).cloned().expect("a file");
        let identity = self.identities.remove(Path::new(from));
        self.remove(from);
        self.entry(to, EntryKind::File(stamp));
        self.files.insert(PathBuf::from(to), (stamp, bytes));
        if let Some(identity) = identity {
            self.identities.insert(PathBuf::from(to), identity);
        }
    }

    /// Take `path` out of the tree, and everything under it.
    pub(crate) fn remove(&mut self, path: &str) {
        let path = Path::new(path);
        if let Some(listing) = self.dirs.get_mut(path.parent().expect("under the root")) {
            listing.retain(|entry| Some(entry.name.as_os_str()) != path.file_name());
        }
        self.dirs.retain(|dir, _| !dir.starts_with(path));
        self.files.retain(|file, _| !file.starts_with(path));
        self.identities.retain(|file, _| !file.starts_with(path));
    }

    /// Whether `path` can be reached: no folder above it is sealed.
    fn through(&self, path: &Path) -> io::Result<()> {
        if path
            .ancestors()
            .skip(1)
            .any(|dir| self.sealed.contains(dir))
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }

    pub(crate) fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }

    /// How many identities were asked for.
    pub(crate) fn identity_looks(&self) -> usize {
        self.identity_looks.load(Ordering::SeqCst)
    }

    /// How many single paths were looked at (`kind`), not counting listings.
    pub(crate) fn looks(&self) -> usize {
        self.looks.load(Ordering::SeqCst)
    }
}

impl DirectorySource for Scripted {
    fn list(&self, dir: &Path) -> io::Result<Vec<DirEntry>> {
        self.through(dir)?;
        if self.unlistable.contains(dir) || self.sealed.contains(dir) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.dirs
            .get(dir)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        self.looks.fetch_add(1, Ordering::SeqCst);
        self.through(path)?;
        let parent = path.parent().ok_or(io::ErrorKind::NotFound)?;
        self.dirs
            .get(parent)
            .and_then(|listing| {
                listing
                    .iter()
                    .find(|entry| Some(entry.name.as_os_str()) == path.file_name())
            })
            .map(|entry| entry.kind)
            .or_else(|| self.dirs.contains_key(path).then_some(EntryKind::Directory))
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn is_folder(&self, path: &Path) -> io::Result<bool> {
        self.through(path)?;
        if self.dirs.contains_key(path) {
            return Ok(true);
        }
        self.kind(path).map(|_| false)
    }

    fn stamp(&self, path: &Path) -> io::Result<FileStamp> {
        self.through(path)?;
        let mut stamp = self.files.get(path).ok_or(io::ErrorKind::NotFound)?.0;
        if self.moving.contains(path) {
            stamp.modified += Duration::from_secs(1);
        }
        Ok(stamp)
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn io::Read + Send>> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        self.through(path)?;
        if self.denied.contains(path) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let (_, bytes) = self.files.get(path).ok_or(io::ErrorKind::NotFound)?;
        Ok(Box::new(io::Cursor::new(bytes.clone())))
    }

    fn identity(&self, path: &Path) -> Option<FileIdentity> {
        self.identity_looks.fetch_add(1, Ordering::SeqCst);
        self.identities.get(path).copied()
    }
}

/// The registry row a past pass left for `path`, its hash made up.
pub(crate) fn row(path: &str, stamp: FileStamp, tag: u8) -> SharedFileEntry {
    SharedFileEntry {
        file_hash: FileHash::from_bytes([tag; FileHash::BYTE_LEN]),
        file_size: stamp.size,
        path: PathBuf::from(path),
        name: String::new(),
        source: ShareSource::DownloadDirectory,
        part_hashes: Vec::new(),
        modified: Some(stamp.modified),
    }
}

/// What the scan would know with `rows` shared and no download.
pub(crate) fn known(rows: &[SharedFileEntry]) -> Known {
    Known {
        rows: rows.to_vec(),
        ..Known::default()
    }
}

/// The scripted directory, shared between the source and the watch that
/// changes it as time passes.
#[derive(Clone)]
pub(crate) struct World(Arc<Mutex<Scripted>>);

impl World {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(Scripted::new())))
    }

    pub(crate) fn with<T>(&self, change: impl FnOnce(&mut Scripted) -> T) -> T {
        change(&mut self.0.lock().unwrap())
    }

    pub(crate) fn opens(&self) -> usize {
        self.with(|dir| dir.opens())
    }

    pub(crate) fn looks(&self) -> usize {
        self.with(|dir| dir.looks())
    }
}

impl DirectorySource for World {
    fn list(&self, dir: &Path) -> io::Result<Vec<DirEntry>> {
        self.0.lock().unwrap().list(dir)
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        self.0.lock().unwrap().kind(path)
    }

    fn is_folder(&self, path: &Path) -> io::Result<bool> {
        self.0.lock().unwrap().is_folder(path)
    }

    fn stamp(&self, path: &Path) -> io::Result<FileStamp> {
        self.0.lock().unwrap().stamp(path)
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn io::Read + Send>> {
        self.0.lock().unwrap().open(path)
    }

    fn identity(&self, path: &Path) -> Option<FileIdentity> {
        self.0.lock().unwrap().identity(path)
    }
}

/// What a step reports when it changes the directory.
pub(crate) type Step<T> = Box<dyn FnOnce(&mut Scripted) -> T + Send>;

/// The OS reporting that something moved at `path`.
pub(crate) fn moved(path: &str) -> WatchSignal {
    WatchSignal::Moved(PathBuf::from(path))
}

/// The clock and the script of a scripted watch: each step changes the
/// directory at its offset and returns what the OS would report. Time passes
/// only in `wait`; at `until` the stop flag is raised, as a retire would.
pub(crate) struct Timeline<T> {
    pub(crate) world: World,
    pub(crate) start: Instant,
    pub(crate) elapsed: Arc<AtomicU64>,
    pub(crate) script: VecDeque<(Duration, Step<T>)>,
    pub(crate) until: Duration,
    pub(crate) stop: Arc<AtomicBool>,
}

impl<T> Timeline<T> {
    /// Move time on by at most `max`, stopping at the next step if it falls
    /// inside; returns the instant reached and what the step reported.
    pub(crate) fn wait(&mut self, max: Duration) -> (Instant, Option<T>) {
        let elapsed = Duration::from_millis(self.elapsed.load(Ordering::SeqCst));
        let target = elapsed + max;
        let mut reported = None;
        let now = match self.script.front() {
            Some((at, _)) if *at <= target => {
                let (at, step) = self.script.pop_front().unwrap();
                reported = Some(self.world.with(step));
                at.max(elapsed)
            }
            _ => target,
        };
        self.elapsed
            .store(u64::try_from(now.as_millis()).unwrap(), Ordering::SeqCst);
        if now >= self.until {
            self.stop.store(true, Ordering::SeqCst);
        }
        (self.start + now, reported)
    }
}
