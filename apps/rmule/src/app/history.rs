//! Keeping the **File History** current (ADR-0100): asked for once the core is
//! attached, and again whenever an edge says it moved — a file shared or
//! unshared, a download completed or cancelled. At most one ask is ever out;
//! a change that lands meanwhile asks once more when the answer arrives, so a
//! burst of shares costs two reads, not one per share.

use rmule_core::{CoreCommand, CoreEvent, DownloadEvent, ServeEvent};

/// Whether an ask is out, and whether the history moved since it went.
#[derive(Debug, Default)]
pub(super) struct HistoryPoll {
    outstanding: bool,
    again: bool,
}

impl HistoryPoll {
    /// The ask to send for `event`, if it is one.
    pub(super) fn on_event(&mut self, event: &CoreEvent) -> Option<CoreCommand> {
        if matches!(event, CoreEvent::FileHistory { .. }) {
            self.outstanding = false;
            return if std::mem::take(&mut self.again) {
                self.ask()
            } else {
                None
            };
        }
        if !moves_history(event) {
            return None;
        }
        if self.outstanding {
            self.again = true;
            return None;
        }
        self.ask()
    }

    /// Ask now unless an ask is already out.
    pub(super) fn ask(&mut self) -> Option<CoreCommand> {
        if self.outstanding {
            return None;
        }
        self.outstanding = true;
        Some(CoreCommand::DumpFileHistory)
    }
}

fn moves_history(event: &CoreEvent) -> bool {
    matches!(
        event,
        CoreEvent::Serve(ServeEvent::FileShared { .. } | ServeEvent::FileUnshared { .. })
            | CoreEvent::Download(
                DownloadEvent::DownloadCompleted { .. } | DownloadEvent::DownloadCancelled { .. }
            )
    )
}

#[cfg(test)]
mod tests {
    use rmule_core::file_history::FileHistory;
    use rmule_primitives::FileHash;

    use super::*;

    fn shared() -> CoreEvent {
        CoreEvent::Serve(ServeEvent::FileShared {
            file_hash: FileHash::from_bytes([1; 16]),
        })
    }

    fn answer() -> CoreEvent {
        CoreEvent::FileHistory {
            history: FileHistory::default(),
        }
    }

    #[test]
    fn a_burst_of_changes_while_an_ask_is_out_costs_one_more_ask() {
        let mut poll = HistoryPoll::default();
        assert!(poll.ask().is_some(), "the first ask goes out");
        assert!(poll.on_event(&shared()).is_none());
        assert!(poll.on_event(&shared()).is_none());
        assert!(
            matches!(poll.on_event(&answer()), Some(CoreCommand::DumpFileHistory)),
            "the history moved while the ask was out"
        );
        assert!(poll.on_event(&answer()).is_none(), "nothing moved since");
        assert!(
            poll.on_event(&shared()).is_some(),
            "idle: a change asks at once"
        );
    }
}
