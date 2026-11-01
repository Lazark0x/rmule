//! The **Ask Clock** (ADR-0064): when a file may next be asked, kept per hash
//! and outside any run.
//!
//! Stock's re-ask is `KADEMLIAREASKTIME × N` with `N` capped at 7, counted per
//! part file (`PartFile.cpp:1529-1532`). rmule's runs come and go on Pause,
//! Resume, a repair and a Kad stop, so a clock held by a run would forget the
//! ask on each, and the storers' per-IP count is what pays. One Core-owned
//! clock therefore holds every file's next ask:
//!
//! | Event | Clock |
//! |---|---|
//! | Pause, Resume, run restart | kept |
//! | Cancel, re-add of the hash | kept (stock's Stop clears it, `PartFile.cpp:2376`; rmule keeps the storers' side of the bargain) |
//! | Kad stop and start | kept |
//! | Process restart | lost, as stock's (`PartFile.cpp:3696`) |
//!
//! Time is the caller's, so the rule is testable without sleeping.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rmule_primitives::FileHash;
use tokio::time::Instant;

/// Stock's cap on the backoff multiplier (`PartFile.cpp:1529`).
const MOST_STEPS: u32 = 7;

/// Files remembered at once, the soonest due out: an entry that falls out
/// cost the far side nothing it was not already owed.
const MOST_FILES: usize = 4096;

#[derive(Clone, Copy, Debug)]
struct FileAsks {
    steps: u32,
    next: Instant,
}

/// Every file's next ask on one channel. A zero interval is due every sweep.
#[derive(Debug)]
pub(crate) struct AskClock {
    interval: Duration,
    files: HashMap<FileHash, FileAsks>,
}

/// The one clock a channel's discovery tasks share, across Kad restarts.
pub(crate) type SharedAskClock = Arc<Mutex<AskClock>>;

impl AskClock {
    pub(crate) fn shared(interval: Duration) -> SharedAskClock {
        Arc::new(Mutex::new(Self {
            interval,
            files: HashMap::new(),
        }))
    }

    /// Spend an ask for `file` if one is due at `now`.
    pub(crate) fn take_ask(&mut self, file: FileHash, now: Instant) -> bool {
        if self.files.get(&file).is_some_and(|asks| now < asks.next) {
            return false;
        }
        if self.interval.is_zero() {
            return true;
        }
        if self.files.len() >= MOST_FILES && !self.files.contains_key(&file) {
            let soonest = self
                .files
                .iter()
                .min_by_key(|(_, asks)| asks.next)
                .map(|(&file, _)| file);
            if let Some(soonest) = soonest {
                self.files.remove(&soonest);
            }
        }
        let asks = self.files.entry(file).or_insert(FileAsks {
            steps: 0,
            next: now,
        });
        asks.steps = (asks.steps + 1).min(MOST_STEPS);
        asks.next = now + self.interval * asks.steps;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn file(byte: u8) -> FileHash {
        FileHash::from_bytes([byte; FileHash::BYTE_LEN])
    }

    fn clock() -> AskClock {
        AskClock {
            interval: HOUR,
            files: HashMap::new(),
        }
    }

    #[test]
    fn each_ask_waits_one_more_hour_up_to_seven() {
        let mut clock = clock();
        let mut now = Instant::now();
        assert!(clock.take_ask(file(1), now), "the first ask is at once");
        for steps in 1..=9_u32 {
            let wait = HOUR * steps.min(MOST_STEPS);
            assert!(!clock.take_ask(file(1), now + wait - Duration::from_secs(1)));
            now += wait;
            assert!(clock.take_ask(file(1), now));
        }
    }

    #[test]
    fn a_zero_interval_is_due_every_time() {
        let mut clock = AskClock {
            interval: Duration::ZERO,
            files: HashMap::new(),
        };
        let now = Instant::now();
        assert!(clock.take_ask(file(1), now));
        assert!(clock.take_ask(file(1), now));
    }

    #[test]
    fn the_table_stays_bounded_and_drops_the_soonest_due() {
        let mut clock = clock();
        let t0 = Instant::now();
        let hash = |n: usize| {
            let mut bytes = [0; FileHash::BYTE_LEN];
            bytes[..8].copy_from_slice(&n.to_le_bytes());
            FileHash::from_bytes(bytes)
        };
        clock.take_ask(hash(0), t0);
        for n in 1..=MOST_FILES {
            clock.take_ask(hash(n), t0 + Duration::from_secs(1));
        }
        assert_eq!(clock.files.len(), MOST_FILES);
        assert!(!clock.files.contains_key(&hash(0)));
    }
}
