//! The set of tables one store owns, assembled by the domain crates that
//! declare them and handed to the store at open: every declaration creates
//! its tables if missing and refuses them if they exist under other types.
//! Domain crates build their own piece and the owner merges the pieces, so
//! five seams register against one store without knowing each other.

use redb::{Key, TableDefinition, Value};

use crate::{Children, Indexed, OwnedKey, Record, StoreError, WriteTransaction};

type Creator = Box<dyn Fn(&WriteTransaction) -> Result<(), StoreError> + Send + Sync>;

/// The tables a store creates at open.
#[derive(Default)]
pub struct Schema {
    creators: Vec<Creator>,
}

impl Schema {
    /// An empty schema.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an indexed table: its primary and every index.
    #[must_use]
    pub fn indexed<K: OwnedKey, T: Record>(mut self, table: &'static Indexed<K, T>) -> Self {
        self.creators.push(Box::new(move |txn| table.create(txn)));
        self
    }

    /// Register a child table: the primary of a [`Children`] kind.
    #[must_use]
    pub fn children<P: Copy + Send + Sync + 'static, T: Record>(
        mut self,
        children: &'static Children<P, T>,
    ) -> Self
    where
        (P, u32): OwnedKey,
    {
        self.creators
            .push(Box::new(move |txn| children.table().create(txn)));
        self
    }

    /// Register a plain typed table — for what is not a record, such as a
    /// counter. Writes to it go through the engine's transaction directly.
    #[must_use]
    pub fn table<K, V>(mut self, definition: TableDefinition<'static, K, V>) -> Self
    where
        K: Key + Send + Sync + 'static,
        V: Value + Send + Sync + 'static,
    {
        self.creators.push(Box::new(move |txn| {
            txn.open_table(definition)?;
            Ok(())
        }));
        self
    }

    /// Fold another crate's piece into this one.
    #[must_use]
    pub fn merge(mut self, other: Schema) -> Self {
        self.creators.extend(other.creators);
        self
    }

    pub(crate) fn create_all(&self, txn: &WriteTransaction) -> Result<(), StoreError> {
        for create in &self.creators {
            create(txn)?;
        }
        Ok(())
    }
}
