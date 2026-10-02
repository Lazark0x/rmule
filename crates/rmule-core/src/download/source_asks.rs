//! The **Source Ask Budget** (ADR-0107): how many `OP_GETSOURCES` the whole
//! **Download Set** may put on one server session, and when the next may go.
//!
//! Lookups for different files ride the session side by side; what bounds them
//! is the counterparty's flood tolerance, not a turn. aMule packs at most 15
//! asks into one TCP frame and sends the next frame no sooner than
//! `15 × (16 + 4)` s later (stock 2.3.3 `DownloadQueue.cpp:1044`, `:1127`),
//! starting over at a new server (`DownloadQueue.cpp:1010-1015`). A rolling 15 per 300 s on
//! one **Session Generation** never exceeds that envelope, and lets up to 15
//! downloads ask at once.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

/// aMule's `iMaxFilesPerTcpFrame` (stock 2.3.3 `DownloadQueue.cpp:1044`).
pub(crate) const ASKS_PER_WINDOW: usize = 15;

/// aMule's frame spacing, `iMaxFilesPerTcpFrame × (16 + 4)` seconds
/// (stock 2.3.3 `DownloadQueue.cpp:1127`).
pub(crate) const ASK_WINDOW: Duration = Duration::from_secs(300);

/// The asks sent on the current session inside the last [`ASK_WINDOW`].
#[derive(Debug, Default)]
pub(crate) struct SourceAskBudget {
    generation: u64,
    sent: VecDeque<Instant>,
}

/// The core's one budget, shared by every run of the **Download Set**. Held
/// only for an [`SourceAskBudget::admit`], never across an await.
pub(crate) type SharedSourceAskBudget = Arc<Mutex<SourceAskBudget>>;

impl SourceAskBudget {
    /// Admit one ask on session `generation` at `now`, counting it; or refuse
    /// it with the instant the window next has room. A new generation starts
    /// the count over, as a new server does in aMule.
    pub(crate) fn admit(&mut self, generation: u64, now: Instant) -> Result<(), Instant> {
        if generation != self.generation {
            self.generation = generation;
            self.sent.clear();
        }
        while self
            .sent
            .front()
            .is_some_and(|sent| now.saturating_duration_since(*sent) >= ASK_WINDOW)
        {
            self.sent.pop_front();
        }
        match self.sent.front() {
            Some(oldest) if self.sent.len() >= ASKS_PER_WINDOW => Err(*oldest + ASK_WINDOW),
            _ => {
                self.sent.push_back(now);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fifteen asks go at once; the sixteenth waits until the first leaves the
    /// window — aMule's one frame, then its spacing.
    #[test]
    fn fifteen_asks_go_at_once_and_the_sixteenth_waits_for_the_window() {
        let start = Instant::now();
        let mut budget = SourceAskBudget::default();
        for _ in 0..ASKS_PER_WINDOW {
            assert_eq!(budget.admit(1, start), Ok(()));
        }
        let later = start + Duration::from_secs(40);
        assert_eq!(budget.admit(1, later), Err(start + ASK_WINDOW));
        assert_eq!(budget.admit(1, start + ASK_WINDOW), Ok(()));
    }

    /// A new session starts the count over (aMule `ResetLocalServerRequests`).
    #[test]
    fn a_new_session_starts_the_count_over() {
        let start = Instant::now();
        let mut budget = SourceAskBudget::default();
        for _ in 0..ASKS_PER_WINDOW {
            assert_eq!(budget.admit(1, start), Ok(()));
        }
        assert!(budget.admit(1, start).is_err());
        assert_eq!(budget.admit(2, start), Ok(()));
    }
}
