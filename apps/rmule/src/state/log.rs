//! The Networks log pane's ring.
//!
//! Every core event is logged — compactly, before it folds — so the pane shows
//! the session's whole traffic rather than the subset that happened to move the
//! spine; its line is the words module's ([`crate::words::event::log_line`]).
//! `at` is the injected `apply` instant, never wall time: the view renders
//! relative age against a draw-time `now`.

use std::time::Instant;

use super::UiState;
use crate::words::Sentence;

/// Ring capacity of the Networks log pane (spec §3.4): once full, the oldest
/// line drops as a new one arrives.
const LOG_CAP: usize = 200;

/// One line in the Networks log pane (spec §3.4). `at` is an
/// *injected* [`Instant`] (the `apply` tick), never wall time — the view
/// renders relative age ("12s ago") against a draw-time `now`.
#[derive(Clone, Debug)]
pub struct LogLine {
    /// The `apply` tick this line arrived on; age is a draw-time subtraction.
    pub at: Instant,
    /// The line, written once by the words modules — the view never
    /// reformats, and nothing else can make one.
    pub text: Sentence,
}

impl UiState {
    /// Append one line to the Networks log pane, evicting the oldest beyond
    /// [`LOG_CAP`]. `at` is injected time; rendering age is a draw-time concern.
    pub(super) fn push_log(&mut self, text: Sentence, at: Instant) {
        self.log.push_back(LogLine { at, text });
        while self.log.len() > LOG_CAP {
            self.log.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_core::{CoreEvent, DownloadEvent, DownloadLifecycle};

    use super::*;
    use crate::action::Action;
    use crate::fixture::{download_event, download_id, file_hash};

    #[test]
    fn the_log_ring_caps_at_two_hundred_dropping_oldest_first() {
        let mut state = UiState::default();
        let now = Instant::now();
        for part_index in 0..(LOG_CAP as u32 + 50) {
            state.apply(
                Action::Core(download_event(DownloadEvent::PartVerified {
                    download_id: download_id(1),
                    part_index,
                })),
                now,
            );
        }
        assert_eq!(state.log.len(), LOG_CAP);
        // 250 pushed, 200 kept ⇒ the first 50 evicted: front is part 50.
        assert_eq!(state.log.front().unwrap().text, "part 50 verified");
        assert_eq!(state.log.back().unwrap().text, "part 249 verified");
    }

    /// A queued/recovered download's log line names the file once metadata
    /// supplies a name; an `Unknown`-origin empty name keeps the terse
    /// nameless wording rather than printing nothing after the colon.
    #[test]
    fn queued_and_recovered_log_lines_name_the_file_when_metadata_has_one() {
        let mut state = UiState::default();
        state.apply(
            Action::Core(download_event(DownloadEvent::DownloadQueued {
                download_id: download_id(1),
                file_hash: file_hash(7),
                metadata: rmule_core::DownloadMetadata {
                    name: rmule_primitives::Ed2kText::from_utf8("bunny.mp4"),
                    size: 123_456,
                    origin: rmule_core::DownloadMetadataOrigin::Link,
                },
                file_path: crate::fixture::part_file(),
            })),
            Instant::now(),
        );
        assert_eq!(state.log.back().unwrap().text, "download queued: bunny.mp4");

        state.apply(
            Action::Core(download_event(DownloadEvent::DownloadRecovered {
                download_id: download_id(2),
                state: DownloadLifecycle::Paused,
                failure: None,
                file_hash: file_hash(7),
                metadata: rmule_core::DownloadMetadata::unnamed(999),
                file_path: crate::fixture::part_file(),
            })),
            Instant::now(),
        );
        // Unknown origin, empty name: the terse nameless wording, not a bare
        // trailing colon.
        assert_eq!(
            state.log.back().unwrap().text,
            "download recovered (paused)"
        );
    }

    /// The client-UDP bind failure's log line (ADR-0057) names the
    /// port and the OS's reason in the TUI's words — neither a Debug dump nor
    /// the standard library's own sentence.
    #[test]
    fn a_client_udp_bind_failure_names_the_port_and_the_reason() {
        let mut state = UiState::default();
        state.apply(
            Action::Core(CoreEvent::ClientUdpBindFailed {
                port: 4672,
                kind: std::io::ErrorKind::AddrInUse,
            }),
            Instant::now(),
        );
        assert_eq!(
            state.log.back().unwrap().text,
            "UDP port 4672 could not be bound (another program holds the port) — \
             Kad, reask and NAT traversal are off until restart"
        );
    }
}
