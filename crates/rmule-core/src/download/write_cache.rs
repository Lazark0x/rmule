//! The **Write Cache** (ADR-0117 §4): the node's bound on bytes between the
//! brain and the disk. A run takes a block's length of it as the block leaves
//! the brain and gives it back when the write ends, so however many transfers
//! run and however many parts they hold open, assembly costs at most
//! [`WRITE_CACHE_BYTES`] of heap. A run short of it holds its drain, and the
//! sockets wait behind the workers.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The cap, over every run of the node.
pub(crate) const WRITE_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// What one run may hold of the cap, so a volume that stalls costs its own
/// runs and not the node's.
pub(crate) const RUN_SHARE_BYTES: usize = WRITE_CACHE_BYTES / 4;

/// The node's cache: every run holds a clone of the one count.
#[derive(Clone, Debug)]
pub(crate) struct WriteCache {
    room: Arc<Semaphore>,
    /// The cap this cache was built with.
    cap: usize,
}

impl Default for WriteCache {
    fn default() -> Self {
        Self::of(WRITE_CACHE_BYTES)
    }
}

impl WriteCache {
    /// A cache of `bytes`.
    pub(crate) fn of(bytes: usize) -> Self {
        Self {
            room: Arc::new(Semaphore::new(bytes)),
            cap: bytes,
        }
    }

    /// The permits one take asks: a block longer than the whole count, which
    /// no peer's framing makes, takes all of it rather than wait for ever.
    fn permits(&self, len: usize) -> u32 {
        u32::try_from(len.min(self.cap)).unwrap_or(u32::MAX)
    }

    /// `len` bytes of the cache, if it has them now.
    pub(crate) fn try_take(&self, len: usize) -> Option<CachedBytes> {
        Arc::clone(&self.room)
            .try_acquire_many_owned(self.permits(len))
            .ok()
            .map(|permit| CachedBytes {
                _permit: Some(permit),
            })
    }

    /// `len` bytes of the cache, once it has them.
    pub(crate) async fn take(&self, len: usize) -> CachedBytes {
        let permits = self.permits(len);
        // The count is never closed.
        Arc::clone(&self.room)
            .acquire_many_owned(permits)
            .await
            .map_or(CachedBytes::over_the_cap(), |permit| CachedBytes {
                _permit: Some(permit),
            })
    }
}

/// A block's share of the cache, given back as it drops: when its write ends,
/// or its run does.
#[derive(Debug)]
pub(crate) struct CachedBytes {
    _permit: Option<OwnedSemaphorePermit>,
}

impl CachedBytes {
    /// A block let through over the cap: a stop never waits on the cache, so a
    /// stalled volume stands between no run and its end.
    pub(crate) const fn over_the_cap() -> Self {
        Self { _permit: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap holds across every holder and comes back as they drop.
    #[test]
    fn the_cap_holds_until_a_write_ends() {
        let cache = WriteCache::of(100);
        let first = cache.try_take(60).expect("room");
        assert!(cache.try_take(50).is_none(), "the cap holds");
        let second = cache.try_take(40).expect("what is left");
        drop(first);
        assert!(
            cache.try_take(50).is_some(),
            "a write that ended gives back"
        );
        drop(second);
    }
}
