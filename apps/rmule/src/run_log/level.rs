//! The two levels of the Run Log and the shared handle that holds the one in
//! force.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// How much of what a run touches the Run Log may hold. Ordered: a level
/// admits every class at or below it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Reachability evidence and event codes only.
    #[default]
    Lean,
    /// Lean, plus peer addresses, file names, paths and hashes.
    Full,
}

impl Level {
    /// The level a *Full run log* choice stands for.
    #[must_use]
    pub const fn from_full(full: bool) -> Self {
        if full { Self::Full } else { Self::Lean }
    }
}

/// The level in force, shared by every writer and by the subscriber's filter,
/// so a change is seen by the next line written. Cloning shares it.
#[derive(Clone, Debug, Default)]
pub struct LevelHandle(Arc<AtomicBool>);

impl LevelHandle {
    /// A handle holding `level`.
    #[must_use]
    pub fn new(level: Level) -> Self {
        let handle = Self::default();
        handle.set(level);
        handle
    }

    /// The level now in force.
    #[must_use]
    pub fn get(&self) -> Level {
        if self.0.load(Ordering::Relaxed) {
            Level::Full
        } else {
            Level::Lean
        }
    }

    /// Put `level` in force for every clone.
    pub fn set(&self, level: Level) {
        self.0.store(level == Level::Full, Ordering::Relaxed);
    }
}
