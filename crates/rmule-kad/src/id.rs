//! Kad identity and distance: the 128-bit node/file ID and the XOR metric the
//! whole DHT is ordered by. The byte order is the capture-proven eMule one —
//! four 32-bit words, most-significant first, each read little-endian — so
//! rmule's "closest" is aMule's.

use crate::KadEvidence;

/// A 128-bit Kad identity: a node's place in the keyspace, or a published
/// key's.
///
/// Nodes and keys share one type because the DHT treats them identically —
/// "closest" is the same question either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadId([u8; Self::BYTE_LEN]);

/// The XOR distance between two [`KadId`]s, ordered so smaller is closer.
///
/// The magnitude is assembled under the capture-proven eMule Kad byte order
/// (`word_le_msw_first`): four 32-bit words, most-significant word first, each read
/// little-endian from the 16 wire bytes. This is aMule's `CUInt128` comparison,
/// confirmed by the 2026-07-07 routing capture (ADR-0043).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KadDistance(u128);

impl KadDistance {
    /// Leading zero bits of the distance magnitude — the k-bucket index basis:
    /// more shared prefix (under the proven ordering) means a higher count.
    pub(crate) const fn leading_zeros(self) -> u32 {
        self.0.leading_zeros()
    }
}

impl KadId {
    /// The ID's width in bytes.
    pub const BYTE_LEN: usize = 16;

    /// The evidence any distance/ordering API for [`KadId`] still waits on.
    ///
    /// Empty: the Kad ID byte order (the `0x34` capture), the distance
    /// ordering, and a reproducible lookup target (the 2026-07-07 `0x29` routing
    /// capture, ADR-0043) are all proven, so [`KadId::distance`] and the
    /// nearest-contact selection APIs are live.
    pub const DISTANCE_ORDER_BLOCKED_BY: &'static [KadEvidence] = &[];

    /// Wrap 16 wire bytes as an ID. No validation exists to do — every
    /// pattern is a legal ID.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LEN]) -> Self {
        Self(bytes)
    }

    /// The ID's bytes in wire order — *not* the order its magnitude is
    /// assembled in (see [`KadDistance`]).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }

    /// These bytes with each four-byte word reversed — the one difference
    /// between the two spellings of a 128-bit ID the eMule families write as
    /// hex: aMule's `CUInt128::ToByteArray` (big-endian) and eMule 0.70b /
    /// eMuleAI's `GetData()` (the raw little-endian words, eMuleAI
    /// `srchybrid/kademlia/utils/UInt128.h:66` against `:214-220`). Self-inverse.
    /// `TAG_BUDDYHASH` is the one field where the families disagree (ADR-0061).
    #[must_use]
    pub const fn word_swapped(&self) -> Self {
        Self(rmule_primitives::kad_wire_id(self.0))
    }

    /// The comparable 128-bit magnitude of these bytes under the proven Kad byte
    /// order (`word_le_msw_first`).
    fn magnitude(bytes: &[u8; Self::BYTE_LEN]) -> u128 {
        let mut m = 0u128;
        for word in 0..4 {
            let base = word * 4;
            let value = u32::from_le_bytes([
                bytes[base],
                bytes[base + 1],
                bytes[base + 2],
                bytes[base + 3],
            ]);
            m = (m << 32) | u128::from(value);
        }
        m
    }

    /// The XOR distance from this ID to `target`. Smaller is closer, matching how
    /// aMule ranks contacts for a lookup (capture-proven, ADR-0043).
    #[must_use]
    pub fn distance(&self, target: &KadId) -> KadDistance {
        let mut xor = [0u8; Self::BYTE_LEN];
        for (out, (a, b)) in xor.iter_mut().zip(self.0.iter().zip(target.0.iter())) {
            *out = a ^ b;
        }
        KadDistance(Self::magnitude(&xor))
    }
}
