//! A **Revised** part of the [`UiState`](super::UiState): a value that counts
//! its writes, so what a table derived from it stands until the part it read
//! is written. Every write goes through [`DerefMut`], so no fold can change
//! the value and leave its revision behind; a mutable borrow that ends up
//! writing nothing moves it anyway, which costs one rebuild and shows nothing
//! stale.

use std::ops::{Deref, DerefMut};

/// A value and how many times it has been written.
#[derive(Clone, Debug, Default)]
pub struct Revised<T> {
    value: T,
    revision: u64,
}

impl<T> Revised<T> {
    /// Moves on every write, so an unmoved revision means an unchanged value.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl<T: PartialEq> Revised<T> {
    /// Take `value` when it differs: for a level republished whole, whose
    /// revision must move only when the level did.
    pub fn settle(&mut self, value: T) {
        if self.value != value {
            **self = value;
        }
    }
}

impl<T> From<T> for Revised<T> {
    fn from(value: T) -> Self {
        Self { value, revision: 0 }
    }
}

impl<T> Deref for Revised<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for Revised<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.revision = self.revision.wrapping_add(1);
        &mut self.value
    }
}
