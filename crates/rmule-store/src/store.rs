//! One durable state file — or the engine's in-memory backend — opened
//! against a schema and a version ladder. `open` runs the ladder first, then
//! creates every registered table in one write, so no read can find a table
//! missing and no table is touched under the wrong version. A write commits
//! with immediate durability, set explicitly. A store is `Send + Sync`; seams
//! share one behind an `Arc` and take `&self`. A climb keeps a copy of the file
//! it found, and a failed read or write leaves the store stopped, which it
//! says (ADR-0083).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use redb::backends::InMemoryBackend;
use redb::{Database, Durability, ReadableDatabase, RepairSession, StorageBackend};

use crate::ladder::{read_version, stamp, stamp_home};
use crate::sequence::SEQUENCES;
use crate::{Ladder, ReadTransaction, Schema, StoreError, WriteTransaction};

/// What a slow open is doing, told as it starts and as it goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opening {
    /// The last run did not close the file, and the engine checks all of it.
    Repairing {
        /// How far through, of 100.
        percent: u8,
    },
    /// The file is an older version and climbs to this build's.
    Climbing {
        /// The version found.
        from: u32,
        /// The version it climbs to.
        to: u32,
    },
}

/// Where an open tells what it is doing.
pub type OpeningWatch = Arc<dyn Fn(Opening)>;

/// One open store. Holds the engine's exclusive lock for the process's life.
#[derive(Debug)]
pub struct Store {
    db: Database,
    /// The file, when there is one.
    file: Option<PathBuf>,
    /// Whether a failed read or write latched the engine.
    stopped: AtomicBool,
}

impl Store {
    /// Open the file at `path`, creating it when absent, run `ladder`, then
    /// create every table in `schema`.
    ///
    /// # Errors
    /// [`StoreError::FutureVersion`] when the file is newer than `ladder`,
    /// [`StoreError::MissingStep`] when a rung has no step,
    /// [`StoreError::NotCopied`] when a climb could not keep its copy,
    /// [`StoreError::TableTypeMismatch`] when a schema table exists under
    /// other types, or an engine error (including another process holding
    /// the file). [`StoreError::open_refusal`] sorts them for the operator.
    pub fn open(
        path: impl AsRef<Path>,
        schema: &Schema,
        ladder: &Ladder,
    ) -> Result<Self, StoreError> {
        let quiet: OpeningWatch = Arc::new(|_| {});
        Self::open_watched(path, schema, ladder, &quiet)
    }

    /// [`Store::open`], telling `watch` what a slow open is doing.
    ///
    /// # Errors
    /// As [`Store::open`].
    pub fn open_watched(
        path: impl AsRef<Path>,
        schema: &Schema,
        ladder: &Ladder,
        watch: &OpeningWatch,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let mut store = Self::on_file(path, watch)?;
        let found = store.stamp_when_new(ladder)?;
        if let Some(found) = found.filter(|found| *found < ladder.current) {
            // The engine's lock also keeps other handles from reading on
            // Windows, so the copy is taken with the file closed.
            drop(store);
            keep_a_copy(path, found)?;
            store = Self::on_file(path, watch)?;
            watch(Opening::Climbing {
                from: found,
                to: ladder.current,
            });
        }
        store.climb_and_create(found, schema, ladder)?;
        Ok(store)
    }

    /// The engine on the file at `path`, a repair reported to `watch`.
    fn on_file(path: &Path, watch: &OpeningWatch) -> Result<Self, StoreError> {
        let told = Arc::clone(watch);
        let mut builder = Database::builder();
        builder.set_repair_callback(move |session: &mut RepairSession| {
            // The ratio is in 0..=1, so the cast keeps every value.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let percent = (session.progress() * 100.0) as u8;
            told(Opening::Repairing { percent });
        });
        Ok(Self::over(builder.create(path)?, Some(path)))
    }

    /// The same store on the engine's in-memory backend: an isolation tool
    /// for tests and front-ends — this type over another `StorageBackend`,
    /// not a second implementation of it.
    ///
    /// # Errors
    /// As [`Store::open`].
    pub fn open_in_memory(schema: &Schema, ladder: &Ladder) -> Result<Self, StoreError> {
        Self::open_backend(InMemoryBackend::new(), schema, ladder)
    }

    /// Open on a caller-supplied engine backend — what [`Store::open_in_memory`]
    /// does, and how a test reopens memory it kept hold of.
    ///
    /// # Errors
    /// As [`Store::open`].
    pub fn open_backend(
        backend: impl StorageBackend,
        schema: &Schema,
        ladder: &Ladder,
    ) -> Result<Self, StoreError> {
        let store = Self::over(Database::builder().create_with_backend(backend)?, None);
        let found = store.stamp_when_new(ladder)?;
        store.climb_and_create(found, schema, ladder)?;
        Ok(store)
    }

    fn over(db: Database, file: Option<&Path>) -> Self {
        Self {
            db,
            file: file.map(Path::to_path_buf),
            stopped: AtomicBool::new(false),
        }
    }

    /// The version the file was found at, `None` on a new one. The stamp is
    /// read on a write transaction, which creates the meta table when the
    /// file is new; a file nobody has stamped is this version by definition,
    /// and says so before anything else is written. A newer file is refused
    /// here, before anything is copied.
    fn stamp_when_new(&self, ladder: &Ladder) -> Result<Option<u32>, StoreError> {
        let found = self.write(|txn| {
            let found = read_version(txn)?;
            if found.is_none() {
                stamp(txn, ladder.current)?;
            }
            Ok::<_, StoreError>(found)
        })?;
        if let Some(found) = found.filter(|found| *found > ladder.current) {
            return Err(StoreError::FutureVersion {
                found,
                current: ladder.current,
            });
        }
        Ok(found)
    }

    fn climb_and_create(
        &self,
        found: Option<u32>,
        schema: &Schema,
        ladder: &Ladder,
    ) -> Result<(), StoreError> {
        if let Some(found) = found.filter(|found| *found < ladder.current) {
            if let Some(home) = self.file.as_deref().and_then(Path::parent) {
                self.write(|txn| stamp_home(txn, home))?;
            }
            // One transaction per rung, so a crash mid-climb resumes at the
            // rung it reached rather than replaying the ones below it.
            for from in found..ladder.current {
                let step = ladder.step_from(from)?;
                self.write(|txn| {
                    (step.run)(txn)?;
                    stamp(txn, from + 1)
                })?;
            }
        }
        self.write(|txn| {
            txn.open_table(SEQUENCES)?;
            schema.create_all(txn)
        })
    }

    /// Whether a failed read or write stopped the store. The engine then
    /// answers nothing but that failure until the file is reopened, so what
    /// a caller is told from here on is this and not its own call's fault.
    #[must_use]
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// The file this store lies in, when it has one.
    #[must_use]
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// Note whether `error` stopped the engine.
    fn noted(&self, error: StoreError) -> StoreError {
        if error.stops_the_engine() {
            self.stopped.store(true, Ordering::Relaxed);
        }
        error
    }

    /// Run `act` inside one snapshot transaction.
    ///
    /// # Errors
    /// Whatever `act` returns, or an engine error opening the transaction.
    pub fn read<R, E: From<StoreError>>(
        &self,
        act: impl FnOnce(&ReadTransaction) -> Result<R, E>,
    ) -> Result<R, E> {
        act(&self.begin_read()?)
    }

    /// Run `act` inside one write transaction, committing durably when it
    /// returns `Ok` and aborting — the engine's own drop behaviour — when it
    /// returns `Err`. Every seam writes through this, so no caller can forget
    /// either half.
    ///
    /// # Errors
    /// Whatever `act` returns, or an engine error opening or committing.
    pub fn write<R, E: From<StoreError>>(
        &self,
        act: impl FnOnce(&WriteTransaction) -> Result<R, E>,
    ) -> Result<R, E> {
        let txn = self.begin_write()?;
        let outcome = act(&txn)?;
        txn.commit()
            .map_err(|error| self.noted(StoreError::from(error)))?;
        Ok(outcome)
    }

    /// A snapshot read; any number may be live at once.
    ///
    /// # Errors
    /// An engine error.
    pub fn begin_read(&self) -> Result<ReadTransaction, StoreError> {
        self.db
            .begin_read()
            .map_err(|error| self.noted(error.into()))
    }

    /// The one live write; commits with immediate durability. Dropping it
    /// without `commit` aborts it.
    ///
    /// # Errors
    /// An engine error.
    pub fn begin_write(&self) -> Result<WriteTransaction, StoreError> {
        let mut txn = self
            .db
            .begin_write()
            .map_err(|error| self.noted(error.into()))?;
        txn.set_durability(Durability::Immediate)?;
        Ok(txn)
    }

    /// The version the file is stamped at — the ladder's `current` after a
    /// successful open.
    ///
    /// # Errors
    /// [`StoreError::Unversioned`] if the stamp is gone, or an engine error.
    pub fn version(&self) -> Result<u32, StoreError> {
        read_version(&self.begin_read()?)?.ok_or(StoreError::Unversioned)
    }
}

/// The name a climb from `found` keeps the file under: `<file>.v<found>`.
fn copy_of(path: &Path, found: u32) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".v{found}"));
    PathBuf::from(name)
}

/// Keep the file as `found` left it. Written whole under another name, so a
/// copy that stands is a whole one, and one that stands stays: a climb that
/// was stopped and comes back must not replace what it left.
fn keep_a_copy(path: &Path, found: u32) -> Result<(), StoreError> {
    let copy = copy_of(path, found);
    if copy.exists() {
        return Ok(());
    }
    let mut partial = copy.as_os_str().to_os_string();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let copied = std::fs::copy(path, &partial)
        .and_then(|_| std::fs::File::open(&partial)?.sync_all())
        .and_then(|()| std::fs::rename(&partial, &copy));
    copied.map_err(|source| StoreError::NotCopied { copy, source })
}
