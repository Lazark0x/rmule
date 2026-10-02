//! A record kind's primary table together with every index declared on it,
//! and the only path through which the kind is written: `insert`, `update`,
//! `put` and `remove` keep each index exactly in step, and every read — by
//! key, by key range, or through an index — takes either transaction kind.
//! The raw table definitions are private, so nothing outside can write past
//! the indexes.

use std::borrow::Borrow;
use std::ops::RangeBounds;

use redb::{Key, ReadableTable, ReadableTableMetadata, TableDefinition, Value};

use crate::{
    Index, IndexKey, MultimapIndex, Packed, Readable, Record, StoreError, UniqueIndex,
    WriteTransaction,
};

/// A redb key whose decoded form owns its bytes — `u64`, `[u8; N]`, tuples of
/// those, `String` — which is what an [`Indexed`] table hands back by value.
/// Not a codec: every implementation is one of redb's own.
pub trait OwnedKey: Key + for<'a> Value<SelfType<'a> = Self> + Send + Sync + 'static {}

impl<K> OwnedKey for K where K: Key + for<'a> Value<SelfType<'a> = K> + Send + Sync + 'static {}

/// Whether two keys encode to the same bytes — the engine's own equality.
pub(crate) fn same_key<K: OwnedKey>(left: &K, right: &K) -> bool {
    K::as_bytes(left).as_ref() == K::as_bytes(right).as_ref()
}

/// The primary table of record kind `T`, keyed by `K`, plus its indexes.
///
/// Declared once per record kind as a `static` or `const`, registered with
/// the store's [`Schema`](crate::Schema), then used from any transaction.
pub struct Indexed<K: OwnedKey, T: Record> {
    primary: TableDefinition<'static, K, Packed<T>>,
    indexes: &'static [&'static dyn Index<K, T>],
}

/// What a write expects to find under the key before it runs.
#[derive(Clone, Copy)]
enum Expect {
    Absent,
    Present,
    Either,
}

impl<K: OwnedKey, T: Record> Indexed<K, T> {
    /// Declare the table under `name` with its indexes. Names are unique
    /// across the store; the record's `NAME` is the natural choice.
    #[must_use]
    pub const fn new(name: &'static str, indexes: &'static [&'static dyn Index<K, T>]) -> Self {
        Self {
            primary: TableDefinition::new(name),
            indexes,
        }
    }

    /// Create the primary and every index table if missing. Run by the
    /// schema at open; refuses a primary written under another record
    /// version.
    ///
    /// # Errors
    /// [`StoreError::TableTypeMismatch`] or an engine error.
    pub fn create(&self, txn: &WriteTransaction) -> Result<(), StoreError> {
        txn.open_table(self.primary)?;
        for index in self.indexes {
            index.create(txn)?;
        }
        Ok(())
    }

    /// Whether a record is stored under `key`. Does not decode it — what a
    /// caller asking "is this row there" wants.
    ///
    /// # Errors
    /// An engine error.
    pub fn contains(&self, txn: &impl Readable, key: &K) -> Result<bool, StoreError> {
        Ok(txn.table(self.primary)?.get(key)?.is_some())
    }

    /// The record under `key`, if any.
    ///
    /// # Errors
    /// [`StoreError::Decode`] or an engine error.
    pub fn get(&self, txn: &impl Readable, key: &K) -> Result<Option<T>, StoreError> {
        let table = txn.table(self.primary)?;
        let found = table.get(key)?;
        found.map(|guard| guard.value().unpack()).transpose()
    }

    /// Every `(key, record)` whose key falls in `range`, ascending by key.
    ///
    /// # Errors
    /// [`StoreError::Decode`] or an engine error.
    pub fn range(
        &self,
        txn: &impl Readable,
        range: impl RangeBounds<K>,
    ) -> Result<Vec<(K, T)>, StoreError> {
        let table = txn.table(self.primary)?;
        let mut rows = Vec::new();
        for entry in table.range::<K>(range)? {
            let (key, value) = entry?;
            rows.push((key.value(), value.value().unpack()?));
        }
        Ok(rows)
    }

    /// Every `(key, record)`, ascending by key.
    ///
    /// # Errors
    /// As [`Indexed::range`].
    pub fn iter(&self, txn: &impl Readable) -> Result<Vec<(K, T)>, StoreError> {
        self.range(txn, ..)
    }

    /// How many records the table holds.
    ///
    /// # Errors
    /// An engine error.
    pub fn len(&self, txn: &impl Readable) -> Result<u64, StoreError> {
        Ok(txn.table(self.primary)?.len()?)
    }

    /// Whether the table holds no record.
    ///
    /// # Errors
    /// An engine error.
    pub fn is_empty(&self, txn: &impl Readable) -> Result<bool, StoreError> {
        Ok(self.len(txn)? == 0)
    }

    /// The key a unique index maps `value` to, if any.
    ///
    /// # Errors
    /// [`StoreError::UnknownIndex`] when `index` is not one of this table's;
    /// otherwise an engine error.
    pub fn by_unique<'a, IK: IndexKey>(
        &self,
        txn: &impl Readable,
        index: &UniqueIndex<IK, K, T>,
        value: impl Borrow<IK::SelfType<'a>>,
    ) -> Result<Option<K>, StoreError> {
        self.ensure_declared(index)?;
        index.lookup(txn, value)
    }

    /// Every key a multimap index maps `value` to, ascending by key.
    ///
    /// # Errors
    /// As [`Indexed::by_unique`].
    pub fn by_multi<'a, IK: IndexKey>(
        &self,
        txn: &impl Readable,
        index: &MultimapIndex<IK, K, T>,
        value: impl Borrow<IK::SelfType<'a>>,
    ) -> Result<Vec<K>, StoreError> {
        self.ensure_declared(index)?;
        index.lookup(txn, value)
    }

    /// Store a new record under `key`.
    ///
    /// # Errors
    /// [`StoreError::KeyExists`] when the key is taken,
    /// [`StoreError::UniqueViolation`] when a unique index value is; in both
    /// cases nothing was written. Any other error may leave the transaction
    /// half-written — abort it.
    pub fn insert(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<(), StoreError> {
        self.write(txn, key, Some(record), Expect::Absent)
            .map(|_| ())
    }

    /// Replace the record under `key`, returning the one replaced. Index
    /// entries whose value changed move with it.
    ///
    /// # Errors
    /// [`StoreError::KeyMissing`] when nothing is under the key,
    /// [`StoreError::UniqueViolation`] as for [`Indexed::insert`].
    pub fn update(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<T, StoreError> {
        self.write(txn, key, Some(record), Expect::Present)
            .map(|previous| previous.expect("update verified the key was present"))
    }

    /// Store the record under `key` whether or not one is there, returning
    /// the one replaced.
    ///
    /// # Errors
    /// [`StoreError::UniqueViolation`] as for [`Indexed::insert`].
    pub fn put(
        &self,
        txn: &WriteTransaction,
        key: &K,
        record: &T,
    ) -> Result<Option<T>, StoreError> {
        self.write(txn, key, Some(record), Expect::Either)
    }

    /// Store the record under `key`, replacing whatever was there, without
    /// reading it back. The cheap write: a table with no index has nothing to
    /// learn from the record it replaces, so the read and the decode are
    /// skipped.
    ///
    /// # Errors
    /// [`StoreError::UniqueViolation`] as for [`Indexed::insert`].
    pub fn set(&self, txn: &WriteTransaction, key: &K, record: &T) -> Result<(), StoreError> {
        if self.indexes.is_empty() {
            txn.open_table(self.primary)?
                .insert(key, &Packed::pack(record)?)?;
            return Ok(());
        }
        self.write(txn, key, Some(record), Expect::Either)
            .map(|_| ())
    }

    /// Remove every record whose key falls in `range`, with its index
    /// entries — one pass over the range rather than a lookup per key, which
    /// is what dropping a parent's children is.
    ///
    /// # Errors
    /// An engine error, or [`StoreError::Decode`] when an indexed table has
    /// to read a record back to drop its entries.
    pub fn remove_range(
        &self,
        txn: &WriteTransaction,
        range: impl RangeBounds<K> + Clone,
    ) -> Result<(), StoreError> {
        if self.indexes.is_empty() {
            txn.open_table(self.primary)?
                .retain_in::<K, _>(range, |_, _| false)?;
            return Ok(());
        }
        for (key, record) in self.range(txn, range)? {
            for index in self.indexes {
                index.drop_entry(txn, &key, &record)?;
            }
            txn.open_table(self.primary)?.remove(&key)?;
        }
        Ok(())
    }

    /// Remove the record under `key`, returning it, and drop its index
    /// entries.
    ///
    /// # Errors
    /// An engine error.
    pub fn remove(&self, txn: &WriteTransaction, key: &K) -> Result<Option<T>, StoreError> {
        self.write(txn, key, None, Expect::Either)
    }

    /// The one write path. Checks run before any mutation, so a refused write
    /// leaves the transaction untouched.
    fn write(
        &self,
        txn: &WriteTransaction,
        key: &K,
        new: Option<&T>,
        expect: Expect,
    ) -> Result<Option<T>, StoreError> {
        let mut primary = txn.open_table(self.primary)?;
        let previous = primary
            .get(key)?
            .map(|guard| guard.value().unpack())
            .transpose()?;
        match (expect, &previous) {
            (Expect::Absent, Some(_)) => return Err(StoreError::KeyExists { record: T::NAME }),
            (Expect::Present, None) => return Err(StoreError::KeyMissing { record: T::NAME }),
            _ => {}
        }
        if let Some(record) = new {
            for index in self.indexes {
                index.check_unique(txn, key, record)?;
            }
        }
        match (&previous, new) {
            (Some(old), Some(record)) => {
                for index in self.indexes {
                    index.move_entry(txn, key, old, record)?;
                }
            }
            (Some(old), None) => {
                for index in self.indexes {
                    index.drop_entry(txn, key, old)?;
                }
            }
            (None, Some(record)) => {
                for index in self.indexes {
                    index.add(txn, key, record)?;
                }
            }
            (None, None) => {}
        }
        match new {
            Some(record) => {
                primary.insert(key, &Packed::pack(record)?)?;
            }
            None => {
                primary.remove(key)?;
            }
        }
        Ok(previous)
    }

    fn ensure_declared(&self, index: &dyn Index<K, T>) -> Result<(), StoreError> {
        if self.indexes.iter().any(|own| own.name() == index.name()) {
            Ok(())
        } else {
            Err(StoreError::UnknownIndex {
                record: T::NAME,
                index: index.name(),
            })
        }
    }
}
