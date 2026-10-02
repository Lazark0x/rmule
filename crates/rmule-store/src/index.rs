//! Secondary indexes a record kind declares once, next to the record: a
//! [`UniqueIndex`] maps an index value to at most one primary key, a
//! [`MultimapIndex`] to any number. Each carries the function that derives
//! the index value from a record, and the maintenance an [`Indexed`](crate::Indexed) table
//! performs on every write lives on a sealed supertrait so no caller can add
//! or drop an entry by hand.

use redb::{Key, MultimapTableDefinition, ReadableMultimapTable, ReadableTable, TableDefinition};
use std::borrow::Borrow;

use crate::indexed::{OwnedKey, same_key};
use crate::{Readable, Record, StoreError, WriteTransaction};

/// The maintenance an `Indexed` table drives; unnameable outside the crate.
pub(crate) mod sealed {
    use crate::{StoreError, WriteTransaction};

    pub trait Maintain<K, T> {
        fn create(&self, txn: &WriteTransaction) -> Result<(), StoreError>;
        fn check_unique(
            &self,
            txn: &WriteTransaction,
            key: &K,
            record: &T,
        ) -> Result<(), StoreError>;
        fn add(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<(), StoreError>;
        fn drop_entry(&self, txn: &WriteTransaction, key: &K, record: &T)
        -> Result<(), StoreError>;
        /// Follow `key`'s entry from `old` to `new`. A record whose index
        /// value did not move — the common edit, which touches some other
        /// field — costs the comparison and nothing else.
        fn move_entry(
            &self,
            txn: &WriteTransaction,
            key: &K,
            old: &T,
            new: &T,
        ) -> Result<(), StoreError>;
    }
}

/// A secondary index on record kind `T` keyed by `K`. Implemented by
/// [`UniqueIndex`] and [`MultimapIndex`] only.
pub trait Index<K: OwnedKey, T: Record>: sealed::Maintain<K, T> + Send + Sync {
    /// The index's table name — unique across the store, like a record name.
    fn name(&self) -> &'static str;
}

/// A redb key usable as an index value: any of redb's own, owned or
/// borrowed (`&str`, `&[u8]`, `[u8; N]`, `u64`, tuples). Not a codec.
pub trait IndexKey: Key + Send + Sync + 'static {}

impl<IK> IndexKey for IK where IK: Key + Send + Sync + 'static {}

/// The function that derives an index value from a record. It may borrow
/// from the record (`&str` index keys are the common case).
pub type Extractor<IK, T> = for<'r> fn(&'r T) -> <IK as redb::Value>::SelfType<'r>;

/// Whether two records index to the same value, by the engine's own bytes.
fn indexes_alike<IK: IndexKey, T: Record>(extract: Extractor<IK, T>, left: &T, right: &T) -> bool {
    IK::as_bytes(&extract(left)).as_ref() == IK::as_bytes(&extract(right)).as_ref()
}

/// An index whose value maps to at most one primary key.
///
/// A write whose index value already maps to a *different* key fails with
/// [`StoreError::UniqueViolation`] before anything is written; a write that
/// keeps a key's own value is fine.
pub struct UniqueIndex<IK: IndexKey, K: OwnedKey, T: Record> {
    name: &'static str,
    table: TableDefinition<'static, IK, K>,
    extract: Extractor<IK, T>,
}

impl<IK: IndexKey, K: OwnedKey, T: Record> UniqueIndex<IK, K, T> {
    /// Declare the index under `name` with the function deriving its value.
    #[must_use]
    pub const fn new(name: &'static str, extract: Extractor<IK, T>) -> Self {
        Self {
            name,
            table: TableDefinition::new(name),
            extract,
        }
    }

    pub(crate) fn lookup<'a>(
        &self,
        txn: &impl Readable,
        value: impl Borrow<IK::SelfType<'a>>,
    ) -> Result<Option<K>, StoreError> {
        let table = txn.table(self.table)?;
        let found = table.get(value)?.map(|guard| guard.value());
        Ok(found)
    }
}

impl<IK: IndexKey, K: OwnedKey, T: Record> sealed::Maintain<K, T> for UniqueIndex<IK, K, T> {
    fn create(&self, txn: &WriteTransaction) -> Result<(), StoreError> {
        txn.open_table(self.table)?;
        Ok(())
    }

    fn check_unique(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<(), StoreError> {
        let table = txn.open_table(self.table)?;
        let holder = table
            .get((self.extract)(record))?
            .map(|guard| guard.value());
        match holder {
            Some(other) if !same_key(&other, key) => {
                Err(StoreError::UniqueViolation { index: self.name })
            }
            _ => Ok(()),
        }
    }

    fn add(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<(), StoreError> {
        txn.open_table(self.table)?
            .insert((self.extract)(record), key)?;
        Ok(())
    }

    fn drop_entry(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<(), StoreError> {
        let mut table = txn.open_table(self.table)?;
        let value = (self.extract)(record);
        let is_ours = table
            .get(&value)?
            .is_some_and(|guard| same_key(&guard.value(), key));
        if is_ours {
            table.remove(&value)?;
        }
        Ok(())
    }

    fn move_entry(
        &self,
        txn: &WriteTransaction,
        key: &K,
        old: &T,
        new: &T,
    ) -> Result<(), StoreError> {
        if indexes_alike(self.extract, old, new) {
            return Ok(());
        }
        self.drop_entry(txn, key, old)?;
        self.add(txn, key, new)
    }
}

impl<IK: IndexKey, K: OwnedKey, T: Record> Index<K, T> for UniqueIndex<IK, K, T> {
    fn name(&self) -> &'static str {
        self.name
    }
}

/// An index whose value maps to any number of primary keys.
pub struct MultimapIndex<IK: IndexKey, K: OwnedKey, T: Record> {
    name: &'static str,
    table: MultimapTableDefinition<'static, IK, K>,
    extract: Extractor<IK, T>,
}

impl<IK: IndexKey, K: OwnedKey, T: Record> MultimapIndex<IK, K, T> {
    /// Declare the index under `name` with the function deriving its value.
    #[must_use]
    pub const fn new(name: &'static str, extract: Extractor<IK, T>) -> Self {
        Self {
            name,
            table: MultimapTableDefinition::new(name),
            extract,
        }
    }

    pub(crate) fn lookup<'a>(
        &self,
        txn: &impl Readable,
        value: impl Borrow<IK::SelfType<'a>>,
    ) -> Result<Vec<K>, StoreError> {
        let table = txn.multimap(self.table)?;
        let mut keys = Vec::new();
        for guard in table.get(value)? {
            keys.push(guard?.value());
        }
        Ok(keys)
    }
}

impl<IK: IndexKey, K: OwnedKey, T: Record> sealed::Maintain<K, T> for MultimapIndex<IK, K, T> {
    fn create(&self, txn: &WriteTransaction) -> Result<(), StoreError> {
        txn.open_multimap_table(self.table)?;
        Ok(())
    }

    fn check_unique(&self, _: &WriteTransaction, _: &K, _: &T) -> Result<(), StoreError> {
        Ok(())
    }

    fn add(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<(), StoreError> {
        txn.open_multimap_table(self.table)?
            .insert((self.extract)(record), key)?;
        Ok(())
    }

    fn drop_entry(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<(), StoreError> {
        txn.open_multimap_table(self.table)?
            .remove((self.extract)(record), key)?;
        Ok(())
    }

    fn move_entry(
        &self,
        txn: &WriteTransaction,
        key: &K,
        old: &T,
        new: &T,
    ) -> Result<(), StoreError> {
        if indexes_alike(self.extract, old, new) {
            return Ok(());
        }
        self.drop_entry(txn, key, old)?;
        self.add(txn, key, new)
    }
}

impl<IK: IndexKey, K: OwnedKey, T: Record> Index<K, T> for MultimapIndex<IK, K, T> {
    fn name(&self) -> &'static str {
        self.name
    }
}
