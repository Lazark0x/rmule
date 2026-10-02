//! One durable state file — or the engine's in-memory backend — opened
//! against a schema and a version ladder. `open` runs the ladder first, then
//! creates every registered table in one write, so no read can find a table
//! missing and no table is touched under the wrong version. A write commits
//! with immediate durability, set explicitly, unless the caller asked for
//! [`Store::begin_write_deferred`]. A store is `Send + Sync`; seams share one
//! behind an `Arc` and take `&self`.

use std::path::Path;

use redb::backends::InMemoryBackend;
use redb::{Database, Durability, ReadableDatabase, StorageBackend};

use crate::ladder::{read_version, stamp};
use crate::sequence::SEQUENCES;
use crate::{Ladder, ReadTransaction, Schema, StoreError, WriteTransaction};

/// One open store. Holds the engine's exclusive lock for the process's life.
#[derive(Debug)]
pub struct Store {
    db: Database,
}

impl Store {
    /// Open the file at `path`, creating it when absent, run `ladder`, then
    /// create every table in `schema`.
    ///
    /// # Errors
    /// [`StoreError::FutureVersion`] when the file is newer than `ladder`,
    /// [`StoreError::MissingStep`] when a rung has no step,
    /// [`StoreError::TableTypeMismatch`] when a schema table exists under
    /// other types, or an engine error (including another process holding
    /// the file).
    pub fn open(
        path: impl AsRef<Path>,
        schema: &Schema,
        ladder: &Ladder,
    ) -> Result<Self, StoreError> {
        Self::initialise(Database::create(path)?, schema, ladder)
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
        Self::initialise(
            Database::builder().create_with_backend(backend)?,
            schema,
            ladder,
        )
    }

    fn initialise(db: Database, schema: &Schema, ladder: &Ladder) -> Result<Self, StoreError> {
        let store = Self { db };
        // The stamp is read on a write transaction, which creates the meta
        // table when the file is new; a file nobody has stamped is this
        // version by definition, and says so before anything else is written.
        let found = store.write(|txn| {
            let found = read_version(txn)?;
            if found.is_none() {
                stamp(txn, ladder.current)?;
            }
            Ok::<_, StoreError>(found)
        })?;
        if let Some(found) = found {
            if found > ladder.current {
                return Err(StoreError::FutureVersion {
                    found,
                    current: ladder.current,
                });
            }
            // One transaction per rung, so a crash mid-climb resumes at the
            // rung it reached rather than replaying the ones below it.
            for from in found..ladder.current {
                let step = ladder.step_from(from)?;
                store.write(|txn| {
                    (step.run)(txn)?;
                    stamp(txn, from + 1)
                })?;
            }
        }
        store.write(|txn| {
            txn.open_table(SEQUENCES)?;
            schema.create_all(txn)
        })?;
        Ok(store)
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
        Self::run(self.begin_write()?, act)
    }

    /// [`Store::write`] without the device flush — see
    /// [`Store::begin_write_deferred`] for what that costs and
    /// [`Store::flush`] for what settles it.
    ///
    /// # Errors
    /// As [`Store::write`].
    pub fn write_deferred<R, E: From<StoreError>>(
        &self,
        act: impl FnOnce(&WriteTransaction) -> Result<R, E>,
    ) -> Result<R, E> {
        Self::run(self.begin_write_deferred()?, act)
    }

    fn run<R, E: From<StoreError>>(
        txn: WriteTransaction,
        act: impl FnOnce(&WriteTransaction) -> Result<R, E>,
    ) -> Result<R, E> {
        let outcome = act(&txn)?;
        txn.commit().map_err(StoreError::from)?;
        Ok(outcome)
    }

    /// Make every [`write_deferred`](Self::write_deferred) commit so far
    /// durable: an empty immediate commit, which the engine settles every
    /// deferred commit before it with.
    ///
    /// # Errors
    /// An engine error.
    pub fn flush(&self) -> Result<(), StoreError> {
        self.write(|_| Ok(()))
    }

    /// A snapshot read; any number may be live at once.
    ///
    /// # Errors
    /// An engine error.
    pub fn begin_read(&self) -> Result<ReadTransaction, StoreError> {
        Ok(self.db.begin_read()?)
    }

    /// The one live write; commits with immediate durability. Dropping it
    /// without `commit` aborts it.
    ///
    /// # Errors
    /// An engine error.
    pub fn begin_write(&self) -> Result<WriteTransaction, StoreError> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::Immediate)?;
        Ok(txn)
    }

    /// A write that commits without a device flush: the writes land in the
    /// store and every later read sees them, but they reach the disk only
    /// when some transaction — this seam's or any other's — next commits
    /// through [`begin_write`](Self::begin_write). A crash before that loses
    /// them, so this is for a hot counter whose last few seconds are worth
    /// less than a flush per write, never for a fact a caller was told was
    /// durable.
    ///
    /// # Errors
    /// An engine error.
    pub fn begin_write_deferred(&self) -> Result<WriteTransaction, StoreError> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::None)?;
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
