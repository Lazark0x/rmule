//! The store-wide version and the steps that carry a file forward: each
//! [`UpgradeStep`] rewrites one version's tables into the next inside one
//! durable write and the store stamps the new version before the next step
//! runs. A file newer than the build is refused, a rung with no step is
//! refused, a fresh file is stamped at the current version. The stamp lives
//! in a meta table of the store's own.

use redb::{ReadableTable, TableDefinition};

use crate::{Readable, StoreError, WriteTransaction};

/// The table the version stamp lives in. Owned by the store, never by a
/// domain crate.
pub(crate) const META: TableDefinition<&str, u32> = TableDefinition::new("rmule.meta");

/// The meta key under which the store-wide version is stamped.
const STORE_VERSION: &str = "STORE_VERSION";

/// One rung of a [`Ladder`]: carries a store from `from` to `from + 1`.
///
/// The step opens the old tables under the old record types, rewrites them
/// into the new ones and drops the old, all on the transaction it is handed;
/// the store commits and stamps `from + 1` when it returns `Ok`.
pub struct UpgradeStep {
    /// The version the step starts from.
    pub from: u32,
    /// The rewrite. Runs inside one write transaction; an `Err` aborts it and
    /// leaves the file at `from`.
    pub run: fn(&WriteTransaction) -> Result<(), StoreError>,
}

/// The current store version and the steps that reach it from every older
/// version still supported.
pub struct Ladder {
    /// The version this build writes and expects.
    pub current: u32,
    /// The steps, one per version below `current` that a file may still be
    /// at. Order in the slice does not matter; `from` does.
    pub steps: &'static [UpgradeStep],
}

impl Ladder {
    /// A ladder topping out at `current` with the given steps.
    #[must_use]
    pub const fn new(current: u32, steps: &'static [UpgradeStep]) -> Self {
        Self { current, steps }
    }

    pub(crate) fn step_from(&self, from: u32) -> Result<&UpgradeStep, StoreError> {
        self.steps
            .iter()
            .find(|step| step.from == from)
            .ok_or(StoreError::MissingStep { from })
    }
}

/// The stamped version, or `None` on a file nothing has stamped. Opening the
/// meta table on a write transaction creates it, so the caller decides
/// whether that commit lands.
pub(crate) fn read_version(txn: &impl Readable) -> Result<Option<u32>, StoreError> {
    let meta = txn.table(META)?;
    let found = meta.get(STORE_VERSION)?.map(|guard| guard.value());
    Ok(found)
}

pub(crate) fn stamp(txn: &WriteTransaction, version: u32) -> Result<(), StoreError> {
    txn.open_table(META)?.insert(STORE_VERSION, version)?;
    Ok(())
}
