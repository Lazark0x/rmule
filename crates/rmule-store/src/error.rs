//! The one error type every store operation returns: the engine's own errors
//! wrapped, the codec's encode and decode failures named with the record they
//! concern, and the invariants this layer adds — key presence, index
//! uniqueness, table-type agreement and the version ladder — each as its own
//! variant so a caller can match on what actually went wrong.

use redb::{
    CommitError, DatabaseError, SetDurabilityError, StorageError, TableError, TransactionError,
};

/// Everything a store operation can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The engine failed underneath the typed layer.
    #[error("store engine: {0}")]
    Engine(#[from] redb::Error),
    /// A table exists but was written under other key or value types — for a
    /// record table, another record version. The stored type names are the
    /// engine's; a record's reads as `rmule:{NAME}@v{VERSION}`.
    #[error("table `{table}` holds `{stored_key}` -> `{stored_value}`, not the types opened")]
    TableTypeMismatch {
        /// The table the schema tried to open.
        table: String,
        /// The key type the table was created with.
        stored_key: String,
        /// The value type the table was created with.
        stored_value: String,
    },
    /// A record could not be turned into bytes.
    #[error("record `{record}` could not be encoded: {source}")]
    Encode {
        /// The record kind's [`Record::NAME`](crate::Record::NAME).
        record: &'static str,
        /// The codec's reason.
        #[source]
        source: postcard::Error,
    },
    /// Stored bytes do not decode as the record they were opened as.
    #[error("record `{record}` could not be decoded: {source}")]
    Decode {
        /// The record kind's [`Record::NAME`](crate::Record::NAME).
        record: &'static str,
        /// The codec's reason.
        #[source]
        source: postcard::Error,
    },
    /// `insert` found the key already present.
    #[error("record `{record}`: key already present")]
    KeyExists {
        /// The record kind's [`Record::NAME`](crate::Record::NAME).
        record: &'static str,
    },
    /// `update` found no record under the key.
    #[error("record `{record}`: no record under that key")]
    KeyMissing {
        /// The record kind's [`Record::NAME`](crate::Record::NAME).
        record: &'static str,
    },
    /// A write would map a unique index value to a second primary key.
    #[error("index `{index}`: value already maps to another key")]
    UniqueViolation {
        /// The index's declared name.
        index: &'static str,
    },
    /// A parent's child set outran the ordinal that numbers it.
    #[error("record `{record}` has more children than an ordinal can number")]
    TooManyChildren {
        /// The child record kind.
        record: &'static str,
    },
    /// A lookup named an index the record kind does not declare.
    #[error("record `{record}` declares no index `{index}`")]
    UnknownIndex {
        /// The record kind's [`Record::NAME`](crate::Record::NAME).
        record: &'static str,
        /// The index name that was asked for.
        index: &'static str,
    },
    /// The file was written by a newer build than this one.
    #[error("store is version {found}, newer than this build's {current}")]
    FutureVersion {
        /// The version stamped in the file.
        found: u32,
        /// The version this build's ladder tops out at.
        current: u32,
    },
    /// The ladder has no step starting at a version the file is at.
    #[error("upgrade ladder has no step from version {from}")]
    MissingStep {
        /// The version no step starts from.
        from: u32,
    },
    /// The store carries no version stamp, which `open` always writes.
    #[error("store carries no version stamp")]
    Unversioned,
}

impl From<TableError> for StoreError {
    fn from(error: TableError) -> Self {
        match error {
            TableError::TableTypeMismatch { table, key, value } => Self::TableTypeMismatch {
                table,
                stored_key: key.name().to_owned(),
                stored_value: value.name().to_owned(),
            },
            other => Self::Engine(other.into()),
        }
    }
}

macro_rules! via_engine {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for StoreError {
                fn from(error: $error) -> Self {
                    Self::Engine(error.into())
                }
            }
        )+
    };
}

via_engine!(
    CommitError,
    DatabaseError,
    SetDurabilityError,
    StorageError,
    TransactionError,
);
