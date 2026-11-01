//! The Source Book's records, held behind the one type that can reach them
//! mutably: every way to change a record moves the **Book Generation**, so what
//! a runner republished from the book is known to stand while it reads the
//! same number. A mutable reach that changes nothing moves it too, and costs
//! one republish. The same reach names the record **touched**, so what reads
//! the records as they move reads only those: anything a record's published
//! facts read beyond the record touches it by [`Records::touch`].

use std::collections::{HashMap, HashSet};
use std::ops::Deref;

use super::record::{Record, RecordId};

/// The book's records and the generation they stand at.
#[derive(Debug, Default)]
pub(super) struct Records {
    by_id: HashMap<RecordId, Record>,
    generation: u64,
    touched: HashSet<RecordId>,
}

impl Records {
    /// How many times the records may have changed.
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    /// Every record reached since the last ask, gone ones included.
    pub(super) fn take_touched(&mut self) -> HashSet<RecordId> {
        std::mem::take(&mut self.touched)
    }

    /// What `id`'s record publishes may have moved, by a fact held elsewhere.
    pub(super) fn touch(&mut self, id: RecordId) {
        self.generation += 1;
        self.touched.insert(id);
    }

    pub(super) fn get_mut(&mut self, id: &RecordId) -> Option<&mut Record> {
        self.touch(*id);
        self.by_id.get_mut(id)
    }

    pub(super) fn insert(&mut self, id: RecordId, record: Record) {
        self.touch(id);
        self.by_id.insert(id, record);
    }

    pub(super) fn remove(&mut self, id: &RecordId) -> Option<Record> {
        self.touch(*id);
        self.by_id.remove(id)
    }
}

impl Deref for Records {
    type Target = HashMap<RecordId, Record>;

    fn deref(&self) -> &Self::Target {
        &self.by_id
    }
}
