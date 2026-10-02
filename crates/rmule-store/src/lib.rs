//! The domain-free typed layer over `redb` (ADR-0083). A [`Record`] is a
//! serde type with a name and a version; a [`Packed`] column stores it
//! postcard-encoded under an engine type name that carries that version, so a
//! table written under another version is refused, not misread. An
//! [`Indexed`] table owns a record kind's primary table plus its declared
//! [`UniqueIndex`]es and [`MultimapIndex`]es and is the only write path, so an
//! index cannot rot. A [`Store`] is one file — or the engine's in-memory
//! backend — opened against a [`Schema`] and a [`Ladder`]: every registered
//! table exists once the open returns, a write commits with immediate
//! durability unless the caller asked for [`Store::begin_write_deferred`],
//! and the version ladder runs before any table is touched.
#![warn(missing_docs)]

mod children;
mod error;
mod index;
mod indexed;
mod ladder;
mod record;
mod schema;
mod sequence;
mod store;
mod txn;

pub use children::Children;
pub use error::StoreError;
pub use index::{Extractor, Index, IndexKey, MultimapIndex, UniqueIndex};
pub use indexed::{Indexed, OwnedKey};
pub use ladder::{Ladder, UpgradeStep};
pub use record::{Packed, PackedBytes, Record};
pub use schema::Schema;
pub use sequence::Sequence;
pub use store::Store;
pub use txn::Readable;

pub use redb::{
    self, MultimapTableDefinition, ReadTransaction, StorageBackend, TableDefinition,
    WriteTransaction,
};
