//! Canonical list of evidence gaps that block byte-order-sensitive Kad work.

/// A single piece of external evidence rmule still needs before it can safely
/// implement a byte-order-sensitive part of Kad source lookup.
///
/// This is the one canonical list. Both [`KadId`](crate::KadId) distance/bucket
/// ordering and the source-result row decoder reference the subset that blocks
/// them, so the missing-evidence story is stated once in code instead of being
/// re-spelled across tests, fixture metadata, and docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadEvidence {
    /// Exact byte order of Kad IDs in rmule fixtures.
    KadIdByteOrder,
    /// A captured or independently reproducible routing comparison that proves
    /// Kad distance ordering.
    DistanceOrdering,
    /// Captured or independently reproducible eMule/aMule behavior for at least
    /// one lookup target.
    ReproducibleLookupTarget,
    /// Exact byte order of the source IP tag in Kad source-result rows.
    SourceIpTagByteOrder,
    /// The meaning of the per-row source ID for each source type.
    SourceIdMeaning,
    /// A captured or independently handwritten High ID source-result fixture.
    HighIdSourceResultFixture,
}
