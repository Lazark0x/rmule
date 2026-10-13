//! A run's side of its Served Download: the lease it writes the entry
//! through, every write checked against the entry's holder.

use rmule_primitives::{FileHash, PartHash, SourceSighting};
use tokio::sync::mpsc;

use super::{
    ASKER_INBOX, BytesAt, ExchangePool, PartFileIdentity, ServedDownloads, VerifiedRange, WholeSet,
};
use crate::VerifiedPartRecord;
use crate::download::RunNumber;

/// A run's lease on its download's entry: the only way a run writes it, and
/// good only while the actor has not taken it back.
pub(crate) struct RunLease {
    pub(super) cell: ServedDownloads,
    pub(super) file_hash: FileHash,
    pub(super) run: RunNumber,
}

impl RunLease {
    /// Open the entry's inbox: the askers the serve side hands this run from
    /// now on, in place of any inbox an earlier pass of the run opened.
    /// `None` when the run no longer holds the entry.
    pub(crate) fn take_askers(&self) -> Option<mpsc::Receiver<SourceSighting>> {
        let (askers, inbox) = mpsc::channel(ASKER_INBOX);
        let mut guard = self.cell.lock();
        let book = &mut *guard;
        book.leased(self)?.askers = Some(askers);
        book.version += 1;
        Some(inbox)
    }

    /// The source-exchange pool the run's Source Book holds now; the cell's
    /// version moves only when it differs from the one held.
    pub(crate) fn record_pool(&self, pool: ExchangePool) -> bool {
        let mut guard = self.cell.lock();
        let book = &mut *guard;
        let Some(entry) = book.leased(self) else {
            return false;
        };
        if entry.served.pool != pool {
            entry.served.pool = pool;
            book.version += 1;
        }
        true
    }

    /// Rule the Verified Range from the part hash set in force and the parts
    /// the store records: `set` becomes the entry's set when it is whole.
    pub(crate) fn record_range(&self, set: &[PartHash], records: &[VerifiedPartRecord]) -> bool {
        self.cell.write(self, |entry| {
            let served = &mut entry.served;
            if let Some(whole) = WholeSet::of(served.file_size, set) {
                served.set = Some(whole);
            }
            served.range = if entry.emptied {
                VerifiedRange::default()
            } else {
                VerifiedRange::of_records(served.set.as_ref(), records)
            };
        })
    }

    /// The file the run holds, as it read it through its handle: a range a
    /// read emptied may be ruled again from here.
    pub(crate) fn record_identity(&self, identity: PartFileIdentity) -> bool {
        self.cell.write(self, |entry| {
            entry.served.identity = Some(identity);
            entry.emptied = false;
        })
    }

    /// The finished file is in place at `path`, the destination the
    /// completion move chose (ADR-0115), `identity` the file that holds the
    /// bytes now: the entry is read from there, still under the download's
    /// name.
    pub(crate) fn bytes_in_place(
        &self,
        path: &std::path::Path,
        identity: Option<PartFileIdentity>,
    ) -> bool {
        self.cell.write(self, |entry| {
            let served = &mut entry.served;
            served.final_path = path.to_path_buf();
            served.bytes_at = BytesAt::FinalFile;
            served.identity = identity;
            entry.emptied &= identity.is_none();
        })
    }
}
