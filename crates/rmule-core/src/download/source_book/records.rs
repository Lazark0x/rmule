//! The Source Book's records, held behind the one type that can reach them
//! mutably: every way to change a record moves the **Book Generation**, so what
//! a runner republished from the book is known to stand while it reads the
//! same number. A mutable reach that changes nothing moves it too, and costs
//! one republish.

use std::collections::HashMap;
use std::ops::Deref;

use super::record::{Record, RecordId};

/// The book's records and the generation they stand at.
#[derive(Debug, Default)]
pub(super) struct Records {
    by_id: HashMap<RecordId, Record>,
    generation: u64,
}

impl Records {
    /// How many times the records may have changed.
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn get_mut(&mut self, id: &RecordId) -> Option<&mut Record> {
        self.generation += 1;
        self.by_id.get_mut(id)
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut Record> {
        self.generation += 1;
        self.by_id.values_mut()
    }

    pub(super) fn insert(&mut self, id: RecordId, record: Record) {
        self.generation += 1;
        self.by_id.insert(id, record);
    }

    pub(super) fn remove(&mut self, id: &RecordId) -> Option<Record> {
        self.generation += 1;
        self.by_id.remove(id)
    }
}

impl Deref for Records {
    type Target = HashMap<RecordId, Record>;

    fn deref(&self) -> &Self::Target {
        &self.by_id
    }
}
