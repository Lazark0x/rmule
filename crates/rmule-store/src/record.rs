//! What a domain crate declares durable: the [`Record`] trait names a serde
//! type and versions its shape, and [`Packed`] is that record's stored form —
//! the `redb::Value` the engine sees, whose type name carries the name and
//! version so a table written under another version is refused at open. The
//! `Value` impl is an identity on bytes: packing and unpacking happen in
//! [`Packed::pack`] / [`PackedBytes::unpack`], where they can fail with a
//! typed error instead of inside the engine where nothing can.
//!
//! A read borrows the engine's page — [`PackedBytes`] holds a `Cow` — so
//! nothing is copied between the file and the decode.

use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;

use redb::{TypeName, Value};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::StoreError;

/// A value type a domain crate stores. `NAME` identifies the kind, `VERSION`
/// its shape; every change to the shape bumps `VERSION` and lands a ladder
/// step (ADR-0083), because the engine matches tables on both.
pub trait Record: Serialize + DeserializeOwned + 'static {
    /// The kind's stable name, unique across the store.
    const NAME: &'static str;
    /// The shape's version, bumped with every field change.
    const VERSION: u32;
}

/// A record's stored form, typed by the record: the column type redb sees —
/// `TableDefinition<K, Packed<T>>` — whose [`Value::type_name`] is
/// `rmule:{NAME}@v{VERSION}`. The bytes themselves live in [`PackedBytes`].
pub struct Packed<T: Record> {
    record: PhantomData<fn() -> T>,
}

impl<T: Record> Packed<T> {
    /// The engine type name this record version is stored under.
    #[must_use]
    pub fn tag() -> String {
        format!("rmule:{}@v{}", T::NAME, T::VERSION)
    }

    /// Encode a record for writing.
    ///
    /// # Errors
    /// [`StoreError::Encode`] when the codec cannot represent the record.
    pub fn pack(record: &T) -> Result<PackedBytes<'static, T>, StoreError> {
        postcard::to_allocvec(record)
            .map(|bytes| PackedBytes {
                bytes: Cow::Owned(bytes),
                record: PhantomData,
            })
            .map_err(|source| StoreError::Encode {
                record: T::NAME,
                source,
            })
    }
}

impl<T: Record> fmt::Debug for Packed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Packed({})", Self::tag())
    }
}

/// One record's postcard bytes: borrowed from the engine's page on a read,
/// owned on a write.
pub struct PackedBytes<'a, T: Record> {
    bytes: Cow<'a, [u8]>,
    record: PhantomData<fn() -> T>,
}

impl<T: Record> PackedBytes<'_, T> {
    /// Decode the record.
    ///
    /// # Errors
    /// [`StoreError::Decode`] when the bytes do not match the record's shape.
    pub fn unpack(&self) -> Result<T, StoreError> {
        postcard::from_bytes(&self.bytes).map_err(|source| StoreError::Decode {
            record: T::NAME,
            source,
        })
    }
}

impl<T: Record> fmt::Debug for PackedBytes<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackedBytes")
            .field("record", &T::NAME)
            .field("version", &T::VERSION)
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl<T: Record> Value for Packed<T> {
    type SelfType<'a>
        = PackedBytes<'a, T>
    where
        Self: 'a;

    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        PackedBytes {
            bytes: Cow::Borrowed(data),
            record: PhantomData,
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        &value.bytes
    }

    fn type_name() -> TypeName {
        TypeName::new(&Self::tag())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize)]
    struct Pair {
        left: u64,
        right: String,
    }

    impl Record for Pair {
        const NAME: &'static str = "pair";
        const VERSION: u32 = 3;
    }

    #[test]
    fn bytes_that_are_not_the_record_unpack_to_a_typed_error() {
        // A truncated varint-length string: valid bytes for no `Pair`.
        let stored = <Packed<Pair> as Value>::from_bytes(&[0x01, 0xFF]);
        let error = stored.unpack().unwrap_err();
        assert!(
            matches!(error, StoreError::Decode { record: "pair", .. }),
            "{error:?}"
        );
    }
}
