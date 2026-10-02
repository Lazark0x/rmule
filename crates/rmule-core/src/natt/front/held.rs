//! **Held Burst**s: the requester's punch burst, waiting out the ½-RTT hold a
//! believed hint measured (ADR-0091's scheduling), and the one deadline
//! the front's loop sleeps toward so each leaves on time.
//!
//! The hold is a few milliseconds to a few hundred; the front's tick is a
//! second. A burst released by the tick lands 0–1 s late — behind a stricter
//! filter than endpoint-independent, late enough that the target's own burst
//! has already hit a closed mapping — so the loop arms a timer at the earliest
//! deadline held here, inside the same `select!` and on the same task: no
//! second task, no lock.
//!
//! A hold belongs to its **Traversal Attempt**. Whatever ends the attempt — a
//! Tunnel adopted, a retirement, a run gone idle — or closes the path the
//! burst was aimed at takes the hold with it, because a release after that
//! would dial a second Tunnel toward a peer the first one already served.

use std::time::Instant;

use rmule_net::natt::NattDatagramSink;
use rmule_primitives::{Ipv4Endpoint, UserHash};

use super::NattFront;

/// A burst held for the half-round-trip the hint exchange measured.
#[derive(Clone, Copy, Debug)]
pub(super) struct HeldBurst {
    /// When it leaves.
    pub(super) at: Instant,
    /// Where it is aimed: the endpoint the buddy observed.
    pub(super) target: Ipv4Endpoint,
    /// The attempt it belongs to.
    pub(super) peer: UserHash,
}

/// Every burst waiting out its hold.
#[derive(Debug, Default)]
pub(super) struct HeldBursts {
    waiting: Vec<HeldBurst>,
}

impl HeldBursts {
    /// Hold `burst` until its deadline.
    pub(super) fn hold(&mut self, burst: HeldBurst) {
        self.waiting.push(burst);
    }

    /// The earliest deadline held — what the front's loop sleeps toward.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.waiting.iter().map(|burst| burst.at).min()
    }

    /// Take every burst whose hold has elapsed by `now`.
    fn take_due(&mut self, now: Instant) -> Vec<HeldBurst> {
        let (due, waiting) = self.waiting.iter().partition(|burst| burst.at <= now);
        self.waiting = waiting;
        due
    }

    /// Drop every hold belonging to `peer`'s attempt.
    pub(super) fn cancel_peer(&mut self, peer: &UserHash) {
        self.waiting.retain(|burst| burst.peer != *peer);
    }

    /// Drop every hold aimed at `at`, a path that just closed.
    pub(super) fn cancel_at(&mut self, at: Ipv4Endpoint) {
        self.waiting.retain(|burst| burst.target != at);
    }
}

/// Sleep until `deadline`, or forever when nothing is held — the arm the
/// front's `select!` races its inbox and its tick against.
///
/// `deadline` is on the front's clock ([`super::front_clock`]), which is
/// tokio's, so the conversion is exact and paused test time drives both.
pub(super) async fn hold_elapsed(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

impl<S: NattDatagramSink> NattFront<S> {
    /// Release every burst whose hold has elapsed: fire it, then dial the
    /// endpoint it opened.
    pub(super) async fn release_held(&mut self, now: Instant) {
        for burst in self.held.take_due(now) {
            tracing::debug!(
                target = ?burst.target,
                late = ?now.saturating_duration_since(burst.at),
                "held burst released on its deadline"
            );
            self.fire_burst(burst.target, now).await;
            self.plan_prediction(burst.peer, burst.target, now);
            self.dial(burst.peer, burst.target, now).await;
        }
    }
}
