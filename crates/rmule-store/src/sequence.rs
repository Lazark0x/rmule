//! Monotonic counters, one shared table for the whole store. A seam that
//! mints its own keys declares a [`Sequence`] beside the record it keys and
//! asks it for the next value inside the transaction that writes the row —
//! so the number and the row it names land together or not at all.
//!
//! The table is the store's, created at open, so a sequence needs no schema
//! entry of its own.

use redb::{ReadableTable, TableDefinition};

use crate::{Readable, StoreError, WriteTransaction};

/// The store's counters, keyed by sequence name.
pub(crate) const SEQUENCES: TableDefinition<'static, &str, u64> =
    TableDefinition::new("rmule.sequence");

/// One named counter. Values start at 1 and only ever rise: a removed row's
/// key is never handed out again, so a key identifies the same thing for the
/// life of the file.
pub struct Sequence {
    name: &'static str,
}

impl Sequence {
    /// Declare the counter `name` — conventionally the record kind it keys.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Take the next value on `txn`.
    ///
    /// # Errors
    /// An engine error.
    pub fn next(&self, txn: &WriteTransaction) -> Result<u64, StoreError> {
        let mut counter = txn.open_table(SEQUENCES)?;
        let next = match counter.get(self.name)? {
            Some(highest) => highest.value().saturating_add(1),
            None => 1,
        };
        counter.insert(self.name, next)?;
        Ok(next)
    }

    /// The highest value handed out so far, or 0 when none has been.
    ///
    /// # Errors
    /// An engine error.
    pub fn highest(&self, txn: &impl Readable) -> Result<u64, StoreError> {
        Ok(txn
            .table(SEQUENCES)?
            .get(self.name)?
            .map_or(0, |highest| highest.value()))
    }
}
