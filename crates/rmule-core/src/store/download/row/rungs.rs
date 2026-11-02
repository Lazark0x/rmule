//! **How an older store's download rows climb** (ADR-0083's ladder): the row
//! shape the published store versions wrote, and the rungs that grow it into
//! today's [`DownloadRow`](super::DownloadRow).
//!
//! A frozen row shape embeds only frozen enums: its bytes decode by variant
//! position, so a live enum that gains or reorders a variant must not reach
//! a shape whose bytes are already on disk. Each frozen enum converts into
//! the live one, and its encoding is pinned by test. The enums the shape
//! embeds unchanged live in `row_enums`.

use rmule_store::UpgradeStep;

use super::{DOWNLOADS, HomePath, PartPathSlot};

mod row_enums;
mod row_v5;

pub(crate) use row_v5::grow_from_v14;

/// Store version 16 → 17 (ADR-0083): a part or final path inside the Data
/// Directory becomes relative to it, so a move of that directory carries the
/// download.
/// The row's shape does not change; what its text means does, so a version-16
/// build refuses the store rather than read a relative path against its own
/// working directory.
pub(crate) const UPGRADE_FROM_V16: UpgradeStep = UpgradeStep {
    from: 16,
    run: |txn| {
        let Some(home) = rmule_store::climbing_home(txn)? else {
            return Ok(());
        };
        for (key, mut row) in DOWNLOADS.iter(txn)? {
            let before = row.clone();
            if let Some(path) = row.part_path.held_path(None) {
                row.part_path = PartPathSlot::held(&path, Some(&home));
            }
            row.final_path = HomePath::new(&row.final_path.path(None), Some(&home));
            if row != before {
                DOWNLOADS.update(txn, &key, &row)?;
            }
        }
        Ok(())
    },
};
/// Store version 18 → 19 (ADR-0117 §4): the Arrived Checkpoint's table. An
/// older build would write past it, and a part it finished would keep a row
/// that claims bytes of a part already verified, so a version-18 build refuses
/// the store.
pub(crate) const UPGRADE_FROM_V18: UpgradeStep = UpgradeStep {
    from: 18,
    run: |_| Ok(()),
};

#[cfg(test)]
mod declared_v5;
#[cfg(test)]
pub(crate) use declared_v5::{schema_v5_rows, seed_running_v5};
