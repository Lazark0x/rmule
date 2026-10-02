//! The read side of either transaction kind. A read transaction and a write
//! transaction open tables through different engine types, so every typed
//! read on an [`Indexed`](crate::Indexed) table takes `&impl Readable` and
//! works on both — a write transaction sees its own uncommitted writes, which
//! is what a guard-then-insert needs.

use redb::{
    Key, MultimapTable, MultimapTableDefinition, ReadOnlyMultimapTable, ReadOnlyTable,
    ReadTransaction, ReadableMultimapTable, ReadableTable, Table, TableDefinition, Value,
    WriteTransaction,
};

use crate::StoreError;

mod sealed {
    pub trait Sealed {}
    impl Sealed for redb::ReadTransaction {}
    impl Sealed for redb::WriteTransaction {}
}

/// A transaction typed reads can go through: the engine's read transaction
/// or its write transaction. Implemented for exactly those two.
pub trait Readable: sealed::Sealed {
    /// The engine's table type for this transaction kind.
    type Table<'s, K: Key + 'static, V: Value + 'static>: ReadableTable<K, V>
    where
        Self: 's;
    /// The engine's multimap table type for this transaction kind.
    type Multimap<'s, K: Key + 'static, V: Key + 'static>: ReadableMultimapTable<K, V>
    where
        Self: 's;

    /// Open a table for reading.
    ///
    /// # Errors
    /// [`StoreError::TableTypeMismatch`] when the table exists under other
    /// types; an engine error when it does not exist at all.
    fn table<'s, K: Key + 'static, V: Value + 'static>(
        &'s self,
        definition: TableDefinition<'static, K, V>,
    ) -> Result<Self::Table<'s, K, V>, StoreError>;

    /// Open a multimap table for reading.
    ///
    /// # Errors
    /// As [`Readable::table`].
    fn multimap<'s, K: Key + 'static, V: Key + 'static>(
        &'s self,
        definition: MultimapTableDefinition<'static, K, V>,
    ) -> Result<Self::Multimap<'s, K, V>, StoreError>;
}

impl Readable for ReadTransaction {
    type Table<'s, K: Key + 'static, V: Value + 'static> = ReadOnlyTable<K, V>;
    type Multimap<'s, K: Key + 'static, V: Key + 'static> = ReadOnlyMultimapTable<K, V>;

    fn table<'s, K: Key + 'static, V: Value + 'static>(
        &'s self,
        definition: TableDefinition<'static, K, V>,
    ) -> Result<Self::Table<'s, K, V>, StoreError> {
        Ok(self.open_table(definition)?)
    }

    fn multimap<'s, K: Key + 'static, V: Key + 'static>(
        &'s self,
        definition: MultimapTableDefinition<'static, K, V>,
    ) -> Result<Self::Multimap<'s, K, V>, StoreError> {
        Ok(self.open_multimap_table(definition)?)
    }
}

impl Readable for WriteTransaction {
    type Table<'s, K: Key + 'static, V: Value + 'static> = Table<'s, K, V>;
    type Multimap<'s, K: Key + 'static, V: Key + 'static> = MultimapTable<'s, K, V>;

    fn table<'s, K: Key + 'static, V: Value + 'static>(
        &'s self,
        definition: TableDefinition<'static, K, V>,
    ) -> Result<Self::Table<'s, K, V>, StoreError> {
        Ok(self.open_table(definition)?)
    }

    fn multimap<'s, K: Key + 'static, V: Key + 'static>(
        &'s self,
        definition: MultimapTableDefinition<'static, K, V>,
    ) -> Result<Self::Multimap<'s, K, V>, StoreError> {
        Ok(self.open_multimap_table(definition)?)
    }
}
