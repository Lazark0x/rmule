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
pub mod registry;
pub mod share_totals;
mod spare_copy;

use std::path::Path;
use std::sync::Arc;

pub use rmule_store::Schema;
/// The one open Durable Store a process runs on — `rmule-store`'s engine
/// handle, re-exported so a front-end can hold the `Arc` it hands each seam
/// without depending on the engine crate.
pub use rmule_store::Store as DurableStore;
use rmule_store::{Ladder, Store, StoreError, UpgradeStep};

use crate::CoreError;

/// The file name of the Durable Store inside a data directory.
pub const DURABLE_STORE_FILE: &str = "rmule.redb";

/// The store-wide version ladder (ADR-0083): the current version and the
/// steps up to it. No release exists yet, but the operator's own store holds
/// downloads a reset would lose, so a record change takes a rung
/// (ADR-0102 "Building the scan"), and so does a new table whose absence an
/// older build would write past (ADR-0105 "The Had Set").
pub(crate) const LADDER: Ladder = Ladder::new(
    15,
    &[
        registry::UPGRADE_FROM_V1,
        had_set::UPGRADE_FROM_V2,
        share_totals::UPGRADE_FROM_V3,
        registry::UPGRADE_FROM_V4,
        download::UPGRADE_FROM_V5,
        download::UPGRADE_FROM_V6,
        download::UPGRADE_FROM_V7,
        UPGRADE_FROM_V8,
        UPGRADE_FROM_V9,
        registry::UPGRADE_FROM_V10,
        UPGRADE_FROM_V11,
        download::UPGRADE_FROM_V12,
        UPGRADE_FROM_V13,
        UPGRADE_FROM_V14,
    ],
);

/// Store version 8 → 9, one rung for two seams: every managed
/// server row gains its figures (none yet — a row rmule kept none for reads
/// as never answered), and every download row's server becomes an optional
/// source hint, keeping the server it named. A version-8 build refuses the
/// store: it could not read either row.
pub(crate) const UPGRADE_FROM_V8: UpgradeStep = UpgradeStep {
    from: 8,
    run: |txn| {
        app_config::grow_from_v8(txn)?;
        download::grow_from_v8(txn)
    },
};

/// Store version 9 → 10 (ADR-0080, "What a server grants is durable"):
/// every managed server row gains no grants report and its figures no UDP
/// flags. A version-9 build refuses the store: it could not read the row.
pub(crate) const UPGRADE_FROM_V9: UpgradeStep = UpgradeStep {
    from: 9,
    run: app_config::grow_from_v9,
};

/// Store version 11 → 12 (ADR-0052, "a server's UDP crypt facts are
/// durable"): every managed server row gains no UDP crypt facts. A
/// version-11 build refuses the store: it could not read the row.
pub(crate) const UPGRADE_FROM_V11: UpgradeStep = UpgradeStep {
    from: 11,
    run: app_config::grow_from_v11,
};

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

/// Every table store version 12 held: today's less the download seeds, with
/// the server list as it was before the aux-ports list.
#[cfg(test)]
pub(crate) fn durable_schema_v12() -> Schema {
    credit::schema()
        .merge(download::schema_v12())
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
/// [`CoreError::Repository`] when the directory cannot be created or the
/// store refuses to open (a newer file, a missing ladder step, another process
/// holding the lock).
pub fn open_durable_store(data_dir: &Path) -> Result<Arc<Store>, CoreError> {
    std::fs::create_dir_all(data_dir).map_err(|error| {
        CoreError::Repository(format!("create data dir {}: {error}", data_dir.display()))
    })?;
    let store = Store::open(
        data_dir.join(DURABLE_STORE_FILE),
        &durable_schema(),
        &LADDER,
    )?;
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

#[cfg(test)]
mod tests;
