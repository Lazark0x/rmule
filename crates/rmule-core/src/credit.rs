//! The credit ring: what this session owes a peer and what a peer owes it.
//! [`credit_modifier`] is aMule's `GetScoreRatio` (the up/down ratio bounded to
//! its floor and ceiling), [`CreditStore`] is the ledger seam behind it, and
//! [`KeyBinding`] ties a peer's totals to the identity that earned them — so a
//! peer that proves the same secure identity keeps its standing across sessions.

use std::sync::Arc;

use rmule_primitives::UserHash;

use crate::CoreError;

/// One eMule MiB, the unit the volume cap is computed in.
const BYTES_PER_MIB: f64 = 1024.0 * 1024.0;

/// aMule's minimum-received floor (`GetScoreRatio`: `GetDownloadedTotal() <
/// 1000000 → 1.0`): below ~1 MB received from a peer, no credit bonus at all.
/// Decimal 1e6 exactly as in source — not 1 MiB.
const MIN_CREDITED_DOWNLOADED: u64 = 1_000_000;

/// eMule's upload-credit score ratio (`clientcredits.cpp::GetScoreRatio`).
/// `up` = bytes we served this peer; `down` = bytes the peer served us. The
/// ratio rewards peers who gave us more than we gave them; the volume cap keeps
/// a peer we have barely exchanged with from dominating the queue.
///
/// - `down < 1_000_000` (the peer has served us under ~1 MB, including
///   nothing): no credit, modifier `1.0` — the pinned received floor.
/// - `up == 0` while `down` clears the floor: ratio is `10.0` (we gave nothing
///   back), then capped by the volume term.
/// - otherwise `ratio = down * 2 / up`.
/// - volume cap `= sqrt(down_in_MiB + 2)`; the result is clamped to `[1, 10]`.
#[must_use]
pub fn credit_modifier(up: u64, down: u64) -> f64 {
    if down < MIN_CREDITED_DOWNLOADED {
        return 1.0;
    }
    let ratio = if up == 0 {
        10.0
    } else {
        (down as f64 * 2.0) / up as f64
    };
    let cap = ((down as f64 / BYTES_PER_MIB) + 2.0).sqrt();
    ratio.min(cap).clamp(1.0, 10.0)
}

/// Lifetime byte totals rmule has exchanged with one peer, keyed by `UserHash`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreditTotals {
    /// Bytes we served this peer (serve `SendBlock`).
    pub uploaded: u64,
    /// Bytes this peer served us (download `BlockReceived`).
    pub downloaded: u64,
}

/// One peer's full ring row — the persistable unit of the credit ring
/// ([`CreditStore::snapshot`]): its User Hash, lifetime totals, and bound SUI
/// public key (ADR-0041). The `clients.met` writer maps each of
/// these onto an on-disk `CreditRecord`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCredit {
    /// The peer's User Hash — the ring key.
    pub key: UserHash,
    /// Lifetime bytes exchanged with the peer.
    pub totals: CreditTotals,
    /// The peer's bound SUI public key, or `None` if it never proved one.
    pub public_key: Option<Vec<u8>>,
}

/// Outcome of binding a peer's Secure User Identification public key to its
/// credit record (ADR-0041).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyBinding {
    /// The record held no key; this key is now bound — first SUI, or an
    /// unsecured record adopting its first proof (first-secures-wins).
    Adopted,
    /// The record already held this exact key: a no-op.
    AlreadyBound,
    /// The record holds a *different* key — identity theft. The stored key is
    /// left unchanged and the claimant is denied the secured credit.
    Mismatch,
}

/// The durable, `UserHash`-keyed credit ledger (ADR-0031: a new abstraction,
/// not a widening of any download/serve store). Both halves write it — the
/// download runner records bytes received, the serve task records bytes served
/// — and the serve task reads the derived modifier to rank its queue.
pub trait CreditStore: Send + Sync + 'static {
    /// Add `bytes` we served `peer` to its uploaded total.
    fn record_upload(&self, peer: UserHash, bytes: u64) -> Result<(), CoreError>;

    /// Add `bytes` `peer` served us to its downloaded total.
    fn record_download(&self, peer: UserHash, bytes: u64) -> Result<(), CoreError>;

    /// The lifetime totals for `peer` (zeroed if rmule has never met it).
    fn totals(&self, peer: UserHash) -> Result<CreditTotals, CoreError>;

    /// The peer's current score modifier (`[1, 10]`), derived from its totals.
    fn modifier(&self, peer: UserHash) -> Result<f64, CoreError> {
        let totals = self.totals(peer)?;
        Ok(credit_modifier(totals.uploaded, totals.downloaded))
    }

    /// Bind `key` as `peer`'s Secure User Identification public key (ADR-0041).
    /// Anti-theft: a record with no key adopts it, the same key is a no-op, and
    /// a *different* key is a [`KeyBinding::Mismatch`] that leaves the stored key
    /// unchanged. Atomic per store.
    fn bind_public_key(&self, peer: UserHash, key: &[u8]) -> Result<KeyBinding, CoreError>;

    /// The peer's bound SUI public key, or `None` if it has never proven one.
    /// Lets a peer session choose `IS_SIGNATURENEEDED` vs `IS_KEYANDSIGNEEDED`.
    fn public_key(&self, peer: UserHash) -> Result<Option<Vec<u8>>, CoreError>;

    /// Make everything accrued since the last checkpoint durable.
    ///
    /// `record_upload`/`record_download` are called once per transferred
    /// block, so they do not pay a device flush each (ADR-0083); the ring is
    /// flushed here instead, on the same cadence its `clients.met` copy is
    /// written. A crash between two checkpoints loses at most that window of
    /// accrual — which is what `clients.met` alone lost before the ring was
    /// durable at all.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store will not commit.
    fn checkpoint(&self) -> Result<(), CoreError>;

    /// Snapshot every peer the ring knows — the {User Hash, totals, bound SUI
    /// key} rows the `clients.met` writer persists across runs.
    /// Order is unspecified (the credit file is a set). The dual of replaying
    /// the loaded records back through `record_upload`/`record_download`/
    /// `bind_public_key` into a fresh ring on startup.
    fn snapshot(&self) -> Result<Vec<PeerCredit>, CoreError>;
}

/// The shared, type-erased credit ledger threaded into the download runner and
/// the serve task. One `Arc` is the join point where both halves' byte
/// accounting meets; every method is `&self`, so nothing locks around it
/// (ADR-0083).
pub(crate) type SharedCreditStore = Arc<dyn CreditStore>;

#[cfg(test)]
mod tests {
    use super::credit_modifier;

    /// Pins `credit_modifier` to aMule `GetScoreRatio` (formula quoted in
    /// `docs/reference/notes/secure-ident.md`): the 1e6-byte
    /// received floor, the `down*2/up` ratio, the `sqrt(down_MiB + 2)` volume
    /// cap, and the `[1, 10]` clamp.
    #[test]
    fn credit_modifier_matches_the_pinned_get_score_ratio() {
        const MIB: u64 = 1024 * 1024;
        let cases: &[(u64, u64, f64)] = &[
            // (up, down, expected)
            (0, 0, 1.0),
            (5 * MIB, 0, 1.0),
            // The received floor is decimal 1e6, from source — under it, no
            // bonus even though the ratio and cap would both exceed 1.
            (0, 999_999, 1.0),
            (0, 1_000_000, ((1_000_000.0 / (MIB as f64)) + 2.0f64).sqrt()),
            // up == 0 → ratio 10, then the volume cap applies.
            (0, 4 * MIB, 6.0f64.sqrt()),
            // Plain ratio under the cap: down*2/up.
            (100 * MIB, 100 * MIB, 2.0),
            // Ratio above the cap → cap wins.
            (MIB, 4 * MIB, 6.0f64.sqrt()),
            // Cap above 10 → clamp to 10.
            (MIB, 200 * MIB, 10.0),
            // Ratio below 1 → clamp to 1.
            (100 * MIB, 10 * MIB, 1.0),
        ];
        for &(up, down, expected) in cases {
            let got = credit_modifier(up, down);
            assert!(
                (got - expected).abs() < 1e-9,
                "credit_modifier({up}, {down}) = {got}, expected {expected}"
            );
        }
    }
}
