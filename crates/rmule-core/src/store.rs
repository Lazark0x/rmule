//! The Durable Store's seam implementations (ADR-0083): one `rmule-store`
//! database, one record family per seam, every method `&self`. Each submodule
//! owns its record kinds, its indexes, and a `schema()`; this module is the
//! store's owner — it merges those schemas, holds the store-wide version
//! [`LADDER`], and opens the one `rmule.redb` a process runs on, so a front-end
//! asks for the store and never assembles it.

pub mod app_config;
pub mod credit;
pub mod download;
pub mod had_set;
mod home_path;
pub mod registry;
pub mod share_totals;
mod spare_copy;

use std::path::Path;
use std::sync::Arc;

/// The one open Durable Store a process runs on — `rmule-store`'s engine
/// handle, re-exported so a front-end can hold the `Arc` it hands each seam
/// without depending on the engine crate.
pub use rmule_store::Store as DurableStore;
use rmule_store::{Indexed, Ladder, OwnedKey, Readable, Record, Store, StoreError, UpgradeStep};
pub use rmule_store::{OpenRefusal, Opening, OpeningWatch, Schema};

use crate::CoreError;

/// The file name of the Durable Store inside a data directory.
pub const DURABLE_STORE_FILE: &str = "rmule.redb";

/// The store-wide version ladder (ADR-0083): the current version, the floor
/// and the steps from it. Published builds wrote versions 13 and 14, nothing
/// published wrote an older one, and the
/// operator's store holds downloads a reset would lose, so a record change
/// takes a rung (ADR-0102), and so does a new table whose absence an older
/// build would write past (ADR-0105 "The Had Set").
pub(crate) const LADDER: Ladder = Ladder::new(
    18,
    13,
    &[
        UPGRADE_FROM_V13,
        UPGRADE_FROM_V14,
        credit::UPGRADE_FROM_V15,
        download::UPGRADE_FROM_V16,
        app_config::UPGRADE_FROM_V17,
    ],
);

/// Store version 13 → 14 (ADR-0080, "Aux ports"): every managed server row
/// gains no aux-ports list. A version-13 build refuses the store: it could
/// not read the row.
pub(crate) const UPGRADE_FROM_V13: UpgradeStep = UpgradeStep {
    from: 13,
    run: app_config::grow_from_v13,
};

/// Store version 14 → 15, one rung for two seams: every download row keeps
/// its Download Name, read from the name it was placed under (ADR-0115,
/// step 2), and every managed server row's figures date the status answer
/// apart from the counts (ADR-0080). A version-14 build refuses the store:
/// it could not read either row.
pub(crate) const UPGRADE_FROM_V14: UpgradeStep = UpgradeStep {
    from: 14,
    run: |txn| {
        download::grow_from_v14(txn)?;
        app_config::grow_from_v14(txn)
    },
};

/// Every `(key, record)` of `table` that reads, ascending by key. A row that
/// will not decode costs that row and a line in the Run Log, not the table
/// (ADR-0083): what a read of a whole seam goes through. A rung does not: it
/// refuses what it cannot carry, and the copy before the climb holds it.
///
/// # Errors
/// An engine error.
pub(crate) fn readable<K, T>(
    table: &Indexed<K, T>,
    txn: &impl Readable,
) -> Result<Vec<(K, T)>, StoreError>
where
    K: OwnedKey,
    T: Record,
{
    Ok(table
        .rows(txn)?
        .into_iter()
        .filter_map(|(key, row)| {
            row.inspect_err(|error| {
                tracing::warn!(record = T::NAME, %error, "a row could not be read");
            })
            .ok()
            .map(|row| (key, row))
        })
        .collect())
}

/// Every table the durable seams own, merged for the one `Store::open`.
/// A seam whose tables are missing here would fail its first read, so this is
/// the list a test opens against too.
#[must_use]
pub(crate) fn durable_schema() -> Schema {
    credit::schema()
        .merge(download::schema())
        .merge(registry::schema())
        .merge(had_set::schema())
        .merge(share_totals::schema())
        .merge(spare_copy::schema())
        .merge(app_config::schema())
}

/// Every table store version 13 held, as it declared them: today's, with the
/// download row and the server list as they were before the aux-ports list
/// and the Download Name, and the credit row as it was before it kept when it
/// was last seen.
#[cfg(test)]
pub(crate) fn durable_schema_v13() -> Schema {
    credit::schema_v1()
        .merge(download::schema_v13())
        .merge(registry::schema())
        .merge(had_set::schema())
        .merge(share_totals::schema())
        .merge(spare_copy::schema())
        .merge(app_config::schema_v13())
}

/// Open the Durable Store at `data_dir/rmule.redb`, creating the directory
/// and the file when absent, against core's whole schema and version ladder. One
/// call per process: the engine holds an exclusive file lock, and every seam
/// wraps a clone of the returned handle.
///
/// # Errors
/// [`CoreError::StoreRefused`], as [`open_durable_store_watched`].
pub fn open_durable_store(data_dir: &Path) -> Result<Arc<Store>, CoreError> {
    open_durable_store_watched(data_dir, &(Arc::new(|_| {}) as OpeningWatch))
}

/// [`open_durable_store`], telling `watch` when a repair or a climb runs. The
/// directory and everything in it are kept private (ADR-0083), a store just
/// made included.
///
/// # Errors
/// [`CoreError::StoreRefused`] when the directory cannot be created or the
/// store refuses to open: a newer file, a damaged one, a climb that could not
/// keep its copy, another process holding the lock.
pub fn open_durable_store_watched(
    data_dir: &Path,
    watch: &OpeningWatch,
) -> Result<Arc<Store>, CoreError> {
    std::fs::create_dir_all(data_dir).map_err(|error| CoreError::StoreRefused {
        refusal: OpenRefusal::Disk {
            // The system says only that something exists there: what stands
            // in the way is a file, or the directory would have done.
            kind: match error.kind() {
                std::io::ErrorKind::AlreadyExists => std::io::ErrorKind::NotADirectory,
                kind => kind,
            },
            os_code: error.raw_os_error(),
        },
        reason: format!("create data dir {}: {error}", data_dir.display()),
    })?;
    crate::data_dir::make_private(data_dir);
    let store = Store::open_watched(
        data_dir.join(DURABLE_STORE_FILE),
        &durable_schema(),
        &LADDER,
        watch,
    )
    .map_err(|error| CoreError::StoreRefused {
        refusal: error.open_refusal(),
        reason: error.to_string(),
    })?;
    crate::data_dir::make_private(data_dir);
    Ok(Arc::new(store))
}

/// The same store on the engine's in-memory backend — the isolation tool a
/// test or an ephemeral tool opens instead of a file (ADR-0083: one
/// implementation per seam, no twin).
///
/// # Errors
/// [`CoreError::Repository`] when the store refuses to open.
pub fn open_durable_store_in_memory() -> Result<Arc<Store>, CoreError> {
    Ok(Arc::new(Store::open_in_memory(&durable_schema(), &LADDER)?))
}

/// Every store failure reaches core as one repository error: the seam's
/// callers act on "the store would not", not on which invariant it was. The
/// string is the store's own message, for a log rather than for matching on.
impl From<StoreError> for CoreError {
    fn from(error: StoreError) -> Self {
        CoreError::Repository(error.to_string())
    }
}

/// Pin a live record's bytes: postcard is positional and the engine compares
/// only the tag, so a reordered field or an inserted variant keeps the tag and
/// misreads the operator's store. A pin that moved is a rung owed, never a
/// number to update (ADR-0083).
#[cfg(test)]
pub(crate) fn assert_pinned<T: serde::Serialize>(record: &T, hex: &str) {
    let bytes = postcard::to_allocvec(record).unwrap();
    let found: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(found, hex, "this record's stored bytes moved");
}

#[cfg(test)]
mod tests;
