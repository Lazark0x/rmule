//! The one bounds-checked byte reader every wire decoder in the protocol
//! crates reads through. A read past the end of the buffer answers
//! [`WireTruncated`], which names the field being read; each decoder maps it
//! into its own error type. The reader never panics on any input.

use crate::FileHash;

/// A read ran past the end of the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("truncated {field}: needed {needed} bytes, got {available} bytes")]
pub struct WireTruncated {
    /// The field being read when the buffer ended.
    pub field: &'static str,
    /// The buffer length the read required ([`usize::MAX`] when the
    /// required end offset overflows).
    pub needed: usize,
    /// The buffer length that was available.
    pub available: usize,
}

/// A forward-only, little-endian reader over a byte slice.
#[derive(Clone, Copy, Debug)]
pub struct WireReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WireReader<'a> {
    /// A reader positioned at the start of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// How many bytes have been consumed.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// How many bytes are left.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// The bytes not yet consumed, without consuming them.
    #[must_use]
    pub fn remaining_bytes(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    /// Whether every byte has been consumed.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.position >= self.bytes.len()
    }

    /// Consume `len` bytes.
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` when fewer than `len` bytes remain.
    pub fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], WireTruncated> {
        let end = self
            .position
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(WireTruncated {
                field,
                needed: self.position.saturating_add(len),
                available: self.bytes.len(),
            })?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    /// Consume `len` bytes without returning them.
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` when fewer than `len` bytes remain.
    pub fn skip(&mut self, len: usize, field: &'static str) -> Result<(), WireTruncated> {
        self.take(len, field).map(|_| ())
    }

    /// Consume exactly `N` bytes as an array (a 16-byte hash, a Kad id).
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` when fewer than `N` bytes remain.
    pub fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], WireTruncated> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N, field)?);
        Ok(out)
    }

    /// Consume a 16-byte file hash in its wire order.
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` when fewer than 16 bytes remain.
    pub fn read_file_hash(&mut self, field: &'static str) -> Result<FileHash, WireTruncated> {
        self.read_array(field).map(FileHash::from_bytes)
    }

    /// Consume one byte.
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` at the end of the buffer.
    pub fn read_u8(&mut self, field: &'static str) -> Result<u8, WireTruncated> {
        Ok(self.read_array::<1>(field)?[0])
    }

    /// Consume a little-endian `u16`.
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` when fewer than 2 bytes remain.
    pub fn read_u16_le(&mut self, field: &'static str) -> Result<u16, WireTruncated> {
        self.read_array(field).map(u16::from_le_bytes)
    }

    /// Consume a little-endian `u32`.
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` when fewer than 4 bytes remain.
    pub fn read_u32_le(&mut self, field: &'static str) -> Result<u32, WireTruncated> {
        self.read_array(field).map(u32::from_le_bytes)
    }

    /// Consume a little-endian `u64`.
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` when fewer than 8 bytes remain.
    pub fn read_u64_le(&mut self, field: &'static str) -> Result<u64, WireTruncated> {
        self.read_array(field).map(u64::from_le_bytes)
    }

    /// Consume a `u16` length and then that many bytes.
    ///
    /// # Errors
    /// [`WireTruncated`] naming `field` when the prefix or the body is cut off.
    pub fn read_len16_bytes(&mut self, field: &'static str) -> Result<&'a [u8], WireTruncated> {
        let len = usize::from(self.read_u16_le(field)?);
        self.take(len, field)
    }

    /// Consume up to `len` bytes, stopping at the end of the buffer. For
    /// bytes a decoder has already measured and only needs to step past.
    pub fn advance_clamped(&mut self, len: usize) {
        self.position = self.position.saturating_add(len).min(self.bytes.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_tracks_position() {
        let mut reader = WireReader::new(&[1, 2, 0, 3, 0, 0, 0, 9]);
        assert_eq!(reader.read_u8("a"), Ok(1));
        assert_eq!(reader.read_u16_le("b"), Ok(2));
        assert_eq!(reader.read_u32_le("c"), Ok(3));
        assert_eq!(reader.position(), 7);
        assert_eq!(reader.remaining_bytes(), &[9]);
        assert!(!reader.is_exhausted());
        assert_eq!(reader.read_u8("d"), Ok(9));
        assert!(reader.is_exhausted());
    }

    #[test]
    fn truncation_names_the_field_and_consumes_nothing() {
        let mut reader = WireReader::new(&[1, 2, 3]);
        let err = reader.read_u32_le("size").unwrap_err();
        assert_eq!(
            err,
            WireTruncated {
                field: "size",
                needed: 4,
                available: 3
            }
        );
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn a_length_that_overflows_is_truncation() {
        let mut reader = WireReader::new(&[1]);
        reader.read_u8("a").unwrap();
        let err = reader.take(usize::MAX, "blob").unwrap_err();
        assert_eq!(err.needed, usize::MAX);
    }

    #[test]
    fn len16_bytes_checks_prefix_and_body() {
        assert_eq!(
            WireReader::new(&[2, 0, 7, 8]).read_len16_bytes("name"),
            Ok(&[7, 8][..])
        );
        assert!(
            WireReader::new(&[2, 0, 7])
                .read_len16_bytes("name")
                .is_err()
        );
        assert!(WireReader::new(&[2]).read_len16_bytes("name").is_err());
    }
}
