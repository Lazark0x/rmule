//! The node's **Connection Budget** (ADR-0116): the pace every download's
//! **Asking** shares. The **Dial Window** lets the downloads open at most
//! `dials_per_window` roads per 5-second window, and the **Connection
//! Ceiling** lets them hold at most `max_connections` connections at once —
//! aMule's `TooManySockets` (stock 2.3.3 `ListenSocket.cpp:193-201`), whose
//! interval counter `CListenSocket::Process` turns every five seconds
//! (`amule.cpp:1230-1232`). A grant never asks it: its link is open already.
//!
//! Each run holds one [`BudgetSeat`]. The count it holds is read off its
//! **Source Book** and republished after every step, never incremented and
//! decremented by hand, and the seat's drop withdraws it. Time is an argument,
//! as everywhere in the download brain.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::service::{DownloadId, PeerConnections};

/// How long one Dial Window lasts: aMule turns its interval counter every
/// five seconds.
pub(crate) const DIAL_WINDOW: Duration = Duration::from_secs(5);

/// The budget's state: the limits, the window now open, and the count each
/// run last published.
#[derive(Debug)]
pub(crate) struct ConnectionBudget {
    dials_per_window: u32,
    max_connections: usize,
    window: Option<Window>,
    held: HashMap<DownloadId, usize>,
}

/// One Dial Window: when it opened and the roads it admitted.
#[derive(Clone, Copy, Debug)]
struct Window {
    opened_at: Instant,
    admitted: u32,
}

impl Window {
    fn turns_at(self) -> Instant {
        self.opened_at + DIAL_WINDOW
    }
}

/// The core's one budget, shared by every run of the **Download Set**. Held
/// only for one admission or publication, never across an await.
pub(crate) type SharedConnectionBudget = Arc<Mutex<ConnectionBudget>>;

impl ConnectionBudget {
    /// A budget with `limits`; a zero in either reads as one, so a configured
    /// zero starves nothing.
    pub(crate) fn new(limits: PeerConnections) -> Self {
        Self {
            dials_per_window: limits.dials_per_window.max(1),
            max_connections: limits.max_connections.max(1),
            window: None,
            held: HashMap::new(),
        }
    }

    /// The shared form of [`Self::new`].
    pub(crate) fn shared(limits: PeerConnections) -> SharedConnectionBudget {
        Arc::new(Mutex::new(Self::new(limits)))
    }

    /// The window open at `now`, a new one when the last has turned.
    fn window_at(&mut self, now: Instant) -> &mut Window {
        let window = self.window.get_or_insert(Window {
            opened_at: now,
            admitted: 0,
        });
        if now >= window.turns_at() {
            *window = Window {
                opened_at: now,
                admitted: 0,
            };
        }
        window
    }

    fn admit(
        &mut self,
        download: DownloadId,
        now: Instant,
        held: usize,
    ) -> Result<(), Option<Instant>> {
        self.held.insert(download, held);
        let total: usize = self.held.values().sum();
        let max_connections = self.max_connections;
        let dials_per_window = self.dials_per_window;
        let window = self.window_at(now);
        if window.admitted >= dials_per_window {
            return Err(Some(window.turns_at()));
        }
        if total >= max_connections {
            // A run holding connections fills again at its own next release;
            // one holding none can only wait for another run's, so it looks
            // again when the window turns.
            return Err((held == 0).then(|| window.turns_at()));
        }
        window.admitted += 1;
        // The road about to open is held from now, so a run admitted next
        // in the same window reads it before this run republishes.
        if let Some(count) = self.held.get_mut(&download) {
            *count += 1;
        }
        Ok(())
    }

    fn give_back(&mut self, download: DownloadId, now: Instant) {
        if let Some(window) = self.window.as_mut().filter(|w| now < w.turns_at()) {
            window.admitted = window.admitted.saturating_sub(1);
        }
        if let Some(count) = self.held.get_mut(&download) {
            *count = count.saturating_sub(1);
        }
    }
}

/// One run's place in the shared budget. Its drop withdraws the count the run
/// held.
#[derive(Debug)]
pub(crate) struct BudgetSeat {
    budget: SharedConnectionBudget,
    download: DownloadId,
}

impl BudgetSeat {
    /// Take `download`'s seat in `budget`, holding nothing yet.
    pub(crate) fn new(budget: SharedConnectionBudget, download: DownloadId) -> Self {
        Self { budget, download }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConnectionBudget> {
        self.budget.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Admit one road at `now` for a run holding `held` connections, or refuse
    /// it with when to look again: the Dial Window's turn when the window is
    /// spent, or when the downloads together hold the Ceiling and this run
    /// holds none of it; nothing when this run's own next release will.
    pub(crate) fn admit(&self, now: Instant, held: usize) -> Result<(), Option<Instant>> {
        self.lock().admit(self.download, now, held)
    }

    /// Give back a road admitted at `now` that the fill found nothing to open.
    pub(crate) fn give_back(&self, now: Instant) {
        self.lock().give_back(self.download, now);
    }

    /// Republish the connections the run holds now, read off its book.
    pub(crate) fn hold(&self, held: usize) {
        self.lock().held.insert(self.download, held);
    }
}

#[cfg(test)]
impl BudgetSeat {
    /// A seat alone in a budget of its own whose Dial Window never runs out
    /// and whose Ceiling is `connections`: one download's brain under test
    /// opens at most that many roads at once, as a worker cap did.
    pub(crate) fn ceiling(connections: usize) -> Self {
        let budget = ConnectionBudget::shared(PeerConnections {
            dials_per_window: u32::MAX,
            max_connections: connections,
        });
        Self::new(budget, DownloadId::from_u64(0))
    }
}

impl Drop for BudgetSeat {
    fn drop(&mut self) {
        self.lock().held.remove(&self.download);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(dials_per_window: u32, max_connections: usize) -> SharedConnectionBudget {
        ConnectionBudget::shared(PeerConnections {
            dials_per_window,
            max_connections,
        })
    }

    /// The window's roads go at once; the next waits for the window to turn,
    /// as aMule's `m_OpenSocketsInterval` refuses until `Process` zeroes it.
    #[test]
    fn a_spent_window_refuses_until_it_turns() {
        let start = Instant::now();
        let seat = BudgetSeat::new(budget(2, 100), DownloadId::from_u64(1));
        assert_eq!(seat.admit(start, 0), Ok(()));
        assert_eq!(seat.admit(start, 1), Ok(()));
        assert_eq!(seat.admit(start, 2), Err(Some(start + DIAL_WINDOW)));
        assert_eq!(seat.admit(start + DIAL_WINDOW, 2), Ok(()));
    }

    /// The Ceiling sums every run's count: a run holding nothing is refused
    /// while another holds it all, and admitted once that run's count falls.
    #[test]
    fn the_ceiling_counts_every_run_and_frees_with_a_republished_count() {
        let start = Instant::now();
        let shared = budget(100, 3);
        let busy = BudgetSeat::new(Arc::clone(&shared), DownloadId::from_u64(1));
        let idle = BudgetSeat::new(Arc::clone(&shared), DownloadId::from_u64(2));
        busy.hold(3);
        assert_eq!(idle.admit(start, 0), Err(Some(start + DIAL_WINDOW)));
        assert_eq!(busy.admit(start, 3), Err(None), "its own release fills it");
        busy.hold(2);
        assert_eq!(idle.admit(start, 0), Ok(()));
        drop(busy);
        assert_eq!(idle.admit(start, 1), Ok(()));
    }

    /// A road admitted for a fill that found nothing is no road: the window
    /// and the count both give it back.
    #[test]
    fn a_road_given_back_frees_its_token() {
        let start = Instant::now();
        let seat = BudgetSeat::new(budget(1, 100), DownloadId::from_u64(1));
        assert_eq!(seat.admit(start, 0), Ok(()));
        seat.give_back(start);
        assert_eq!(seat.admit(start, 0), Ok(()));
    }
}
