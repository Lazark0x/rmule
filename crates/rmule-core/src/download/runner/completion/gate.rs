//! The **Completion Gate**: the one instant a completion move's finished file
//! lands in place, shared by the run and the core actor so a Pause or a
//! Cancel and that landing never cross (ADR-0115). Before the file is in
//! place the actor's stop closes the gate and the run lands nothing; once it
//! is in place the stop is refused. The run holds the gate *settling* only
//! across a rename and the look attach's recovery takes at what is on disk,
//! so a stop that meets it waits no longer than one syscall.

use tokio::sync::watch;

/// Where a run's completion move stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    /// Nothing landed; a stop may close the gate.
    Open,
    /// The run is landing the file, or finding whether a past one landed it.
    Settling,
    /// A stop closed the gate: the run lands nothing.
    Stopped,
    /// The finished file is in place: a stop is refused.
    InPlace,
}

/// One run's gate, held by its run and by the actor's ledger entry.
#[derive(Debug)]
pub(crate) struct CompletionGate(watch::Sender<Gate>);

/// What the actor's stop found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopAnswer {
    /// The gate is closed: the run lands nothing, and stops.
    Stopped,
    /// The finished file is in place: the stop is refused.
    InPlace,
}

impl CompletionGate {
    /// An open gate, for a run that starts its move from the check.
    pub(crate) fn open() -> Self {
        Self(watch::Sender::new(Gate::Open))
    }

    /// A settling gate, for a run attach found `Completing`: whether its file
    /// is in place is not known until the run has looked.
    pub(crate) fn settling() -> Self {
        Self(watch::Sender::new(Gate::Settling))
    }

    /// The actor's stop: close the gate unless the file is in place, waiting
    /// out a run that is settling.
    pub(crate) async fn stop(&self) -> StopAnswer {
        let mut seen = self.0.subscribe();
        loop {
            let mut settling = false;
            let mut answer = StopAnswer::Stopped;
            self.0.send_if_modified(|gate| match *gate {
                Gate::Open => {
                    *gate = Gate::Stopped;
                    true
                }
                Gate::Stopped => false,
                Gate::InPlace => {
                    answer = StopAnswer::InPlace;
                    false
                }
                Gate::Settling => {
                    settling = true;
                    false
                }
            });
            if !settling {
                return answer;
            }
            // The sender is ours, so the channel cannot close under us.
            let _ = seen.changed().await;
        }
    }

    /// The run is about to land its file: `false` when a stop closed the gate.
    pub(crate) fn begin(&self) -> bool {
        let mut open = false;
        self.0.send_if_modified(|gate| {
            open = matches!(*gate, Gate::Open | Gate::Settling);
            if open && *gate == Gate::Open {
                *gate = Gate::Settling;
                return true;
            }
            false
        });
        open
    }

    /// The landing ended: in place, or not (the gate opens again).
    pub(crate) fn settle(&self, in_place: bool) {
        self.0.send_if_modified(|gate| {
            if *gate != Gate::Settling {
                return false;
            }
            *gate = if in_place { Gate::InPlace } else { Gate::Open };
            true
        });
    }

    /// The file a past process landed is in place: `false` when a stop
    /// closed the gate first.
    pub(crate) fn found_in_place(&self) -> bool {
        self.begin() && {
            self.settle(true);
            true
        }
    }

    /// Open a gate the run left settling: its run ended, or let it go.
    pub(crate) fn release(&self) {
        self.settle(false);
    }
}

#[cfg(test)]
mod tests {
    use super::{CompletionGate, StopAnswer};

    #[tokio::test]
    async fn a_stop_before_the_landing_closes_the_gate_and_one_after_is_refused() {
        let gate = CompletionGate::open();
        assert_eq!(gate.stop().await, StopAnswer::Stopped);
        assert!(!gate.begin(), "a closed gate lands nothing");

        let gate = CompletionGate::open();
        assert!(gate.begin());
        gate.settle(true);
        assert_eq!(gate.stop().await, StopAnswer::InPlace);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_that_meets_a_settling_run_waits_for_its_answer() {
        let gate = std::sync::Arc::new(CompletionGate::settling());
        let stopping = tokio::spawn({
            let gate = gate.clone();
            async move { gate.stop().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !stopping.is_finished(),
            "the stop waits while the run looks"
        );
        gate.settle(false);
        assert_eq!(stopping.await.unwrap(), StopAnswer::Stopped);

        let gate = std::sync::Arc::new(CompletionGate::settling());
        let stopping = tokio::spawn({
            let gate = gate.clone();
            async move { gate.stop().await }
        });
        tokio::task::yield_now().await;
        assert!(gate.found_in_place());
        assert_eq!(stopping.await.unwrap(), StopAnswer::InPlace);
    }
}
