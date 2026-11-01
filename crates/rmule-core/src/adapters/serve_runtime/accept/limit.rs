//! The **Accept Limit**: how many peers the listener takes (ADR-0031). Past
//! the node's Connection Ceiling, or past 50 accepts in five seconds, an
//! inbound peer is refused before anything reads it, as aMule stops accepting
//! at `TooManySockets` (`ListenSocket.cpp:85`, `:186-196`, `Constants.h:72`).
//! Stock leaves the peer in the backlog; a close says the same a moment
//! sooner, and it dials again. Explicit time, one window; a serve restart
//! opens a new one.

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// aMule turns its accept interval every five seconds (`amule.cpp:1230-1232`).
const ACCEPT_WINDOW: Duration = Duration::from_secs(5);

/// aMule's `MAXCONPER5SEC` (`Constants.h:72`).
const MAX_ACCEPTS_PER_WINDOW: u32 = 50;

/// The window now open, shared by every road that feeds the accept channel.
#[derive(Clone, Default)]
pub(super) struct AcceptLimit(Arc<Mutex<Option<Window>>>);

#[derive(Clone, Copy)]
struct Window {
    opened_at: Instant,
    accepted: u32,
}

impl AcceptLimit {
    /// Whether a peer may join `open` links under `ceiling` at `now`, the
    /// window counting it when it may. As stock's test both limits are passed,
    /// not met.
    pub(super) fn takes(&self, now: Instant, open: usize, ceiling: usize) -> bool {
        if open > ceiling {
            return false;
        }
        let mut window = self.0.lock();
        let open_window =
            window.filter(|window| now.saturating_duration_since(window.opened_at) < ACCEPT_WINDOW);
        let accepted = open_window.map_or(0, |window| window.accepted);
        if accepted > MAX_ACCEPTS_PER_WINDOW {
            return false;
        }
        *window = Some(Window {
            opened_at: open_window.map_or(now, |window| window.opened_at),
            accepted: accepted + 1,
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_is_passed_not_met() {
        let limit = AcceptLimit::default();
        let t = Instant::now();
        assert!(limit.takes(t, 500, 500));
        assert!(!limit.takes(t, 501, 500));
    }

    #[test]
    fn a_window_takes_its_fifty_and_one_and_the_next_opens_afresh() {
        let limit = AcceptLimit::default();
        let t = Instant::now();
        for _ in 0..=MAX_ACCEPTS_PER_WINDOW {
            assert!(limit.takes(t, 0, 500));
        }
        assert!(!limit.takes(t + ACCEPT_WINDOW / 2, 0, 500));
        assert!(limit.takes(t + ACCEPT_WINDOW, 0, 500));
    }
}
