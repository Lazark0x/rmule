//! What a table derived from the rows, kept until they change.
//!
//! Every key and every wheel notch asks a table for its order, and a frame
//! asks again, so with ten thousand shared files a table rebuilt on each ask
//! spends its whole frame there. A table's lines are a function of the state's
//! revision and its own sort and filter, so one build serves them all until
//! either moves.

use std::cell::RefCell;
use std::sync::Arc;

/// The last thing built, under the key it was built for.
pub(crate) struct Memo<K, L> {
    held: RefCell<Option<(K, Arc<[L]>)>>,
}

impl<K, L> Default for Memo<K, L> {
    fn default() -> Self {
        Self {
            held: RefCell::new(None),
        }
    }
}

impl<K: PartialEq, L> Memo<K, L> {
    /// What `build` made for `key`, building it when the key has moved.
    pub(crate) fn get(&self, key: K, build: impl FnOnce() -> Vec<L>) -> Arc<[L]> {
        if let Some((held, lines)) = &*self.held.borrow()
            && *held == key
        {
            return Arc::clone(lines);
        }
        let lines: Arc<[L]> = build().into();
        *self.held.borrow_mut() = Some((key, Arc::clone(&lines)));
        lines
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn a_key_that_stands_builds_once_and_one_that_moves_builds_again() {
        let memo: Memo<u64, u8> = Memo::default();
        let builds = Cell::new(0);
        let build = || {
            builds.set(builds.get() + 1);
            vec![1, 2]
        };
        memo.get(1, build);
        memo.get(1, build);
        assert_eq!(builds.get(), 1);
        memo.get(2, build);
        assert_eq!(builds.get(), 2);
    }
}
