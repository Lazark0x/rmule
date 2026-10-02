//! A record kind that belongs to another row: keyed by its parent's key and
//! its ordinal, so one parent's children are a contiguous key range in
//! ordinal order and the engine, not the caller, keeps them sorted.
//!
//! The pattern — list a parent's set, replace it wholesale, drop it when the
//! parent goes — is the same wherever it appears, so it lives here once
//! rather than being re-derived beside each parent. In particular the cascade
//! is a call, not something each seam has to remember.

use crate::{Indexed, OwnedKey, Readable, Record, StoreError, WriteTransaction};

/// The child table of parents keyed by `P`, holding record kind `T`.
pub struct Children<P, T: Record>
where
    (P, u32): OwnedKey,
{
    table: Indexed<(P, u32), T>,
}

impl<P: Copy, T: Record> Children<P, T>
where
    (P, u32): OwnedKey,
{
    /// Declare the table under `name`. Child tables carry no index: the
    /// parent key is already the first half of their own.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self {
            table: Indexed::new(name, &[]),
        }
    }

    /// The table this child kind lives in, for the store's [`Schema`](crate::Schema).
    #[must_use]
    pub const fn table(&self) -> &Indexed<(P, u32), T> {
        &self.table
    }

    /// One parent's children in ordinal order, each with its ordinal.
    ///
    /// # Errors
    /// [`StoreError::Decode`] or an engine error.
    pub fn list(&self, txn: &impl Readable, parent: P) -> Result<Vec<(u32, T)>, StoreError> {
        Ok(self
            .table
            .range(txn, Self::range(parent))?
            .into_iter()
            .map(|((_, ordinal), record)| (ordinal, record))
            .collect())
    }

    /// Store one child at `ordinal`, replacing whatever was there — what
    /// re-deriving a single child after a repair does.
    ///
    /// # Errors
    /// An engine error.
    pub fn put(
        &self,
        txn: &WriteTransaction,
        parent: P,
        ordinal: u32,
        record: &T,
    ) -> Result<(), StoreError> {
        self.table.set(txn, &(parent, ordinal), record)
    }

    /// Replace a parent's whole set, numbering the records from zero. The
    /// clear and the writes are the caller's one transaction, so a shorter
    /// set can never leave a child of the old one behind.
    ///
    /// # Errors
    /// [`StoreError::TooManyChildren`] when the set outruns an ordinal, or an
    /// engine error.
    pub fn replace(
        &self,
        txn: &WriteTransaction,
        parent: P,
        records: impl IntoIterator<Item = T>,
    ) -> Result<(), StoreError> {
        self.clear(txn, parent)?;
        for (ordinal, record) in records.into_iter().enumerate() {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| StoreError::TooManyChildren { record: T::NAME })?;
            self.table.set(txn, &(parent, ordinal), &record)?;
        }
        Ok(())
    }

    /// Drop every child of `parent` — the cascade a parent's removal owes.
    ///
    /// # Errors
    /// An engine error.
    pub fn clear(&self, txn: &WriteTransaction, parent: P) -> Result<(), StoreError> {
        self.table.remove_range(txn, Self::range(parent))
    }

    /// Every key under one parent: the whole ordinal space beneath it.
    fn range(parent: P) -> std::ops::RangeInclusive<(P, u32)> {
        (parent, 0)..=(parent, u32::MAX)
    }
}
