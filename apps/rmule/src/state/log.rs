//! The Networks log: every core event in a line, kept for a return after days.
//!
//! Every core event is logged — compactly, before it folds — so the pane shows
//! the session's whole traffic rather than the subset that happened to move the
//! spine; its line is the words module's ([`crate::words::event::log_line`]).
//!
//! Two rings in fixed memory: the everyday lines, and the warnings and failures,
//! which a chatty login cannot push out. They read as one, in the order they were
//! said. A line carries the wall time it was said at, stamped as it arrives:
//! `Instant` stops while a machine sleeps, so a time worked out at draw from an
//! age would move every line older than the sleep.

use std::collections::VecDeque;
use std::iter::Peekable;
use std::time::Instant;

use chrono::{DateTime, FixedOffset, TimeDelta};

use super::UiState;
use crate::words::Sentence;
use crate::words::severity::Severity;

/// The everyday ring: a login writes about 18 lines, so this holds some fifty
/// logins.
const EVERYDAY_CAP: usize = 1_000;

/// The ring of warnings and failures.
const ALARM_CAP: usize = 500;

/// The wall time a run reads before its loop says what time it is: midday UTC,
/// so a render nobody clocked is the same on every machine.
fn unclocked() -> DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339("2026-01-01T12:00:00+00:00").expect("static timestamp parses")
}

/// One line in the Networks log pane (spec §3.4).
#[derive(Clone, Debug)]
pub struct LogLine {
    /// The local time it was said at.
    pub wall: DateTime<FixedOffset>,
    /// How much it asks of the operator, from its code and never its words.
    pub severity: Severity,
    /// The line, written once by the words modules — the view never
    /// reformats, and nothing else can make one.
    pub text: Sentence,
    /// Its place among every line said, which orders the two rings as one.
    said: u64,
}

/// The log's two rings and the wall clock that stamps them.
#[derive(Debug, Default)]
pub struct Log {
    everyday: VecDeque<LogLine>,
    alarms: VecDeque<LogLine>,
    said: u64,
    /// The last wall reading and the instant it was taken at. A line between
    /// two readings adds its distance from this one.
    clock: Option<(Instant, DateTime<FixedOffset>)>,
}

impl Log {
    /// Say what time it is: the app loop's one wall reading, taken before each
    /// action lands. State stays free of clocks.
    pub fn set_wall(&mut self, at: Instant, wall: DateTime<FixedOffset>) {
        self.clock = Some((at, wall));
    }

    fn stamp(&mut self, at: Instant) -> DateTime<FixedOffset> {
        let (read_at, wall) = *self.clock.get_or_insert_with(|| (at, unclocked()));
        let since = TimeDelta::from_std(at.saturating_duration_since(read_at))
            .unwrap_or_else(|_| TimeDelta::zero());
        wall + since
    }

    fn push(&mut self, severity: Severity, text: Sentence, at: Instant) {
        let line = LogLine {
            wall: self.stamp(at),
            severity,
            text,
            said: self.said,
        };
        self.said += 1;
        let (ring, cap) = if severity == Severity::Info {
            (&mut self.everyday, EVERYDAY_CAP)
        } else {
            (&mut self.alarms, ALARM_CAP)
        };
        ring.push_back(line);
        if ring.len() > cap {
            ring.pop_front();
        }
    }

    /// Every line kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.everyday.len() + self.alarms.len()
    }

    /// Nothing has been said.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every line kept, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &LogLine> {
        Merged {
            everyday: self.everyday.iter().peekable(),
            alarms: self.alarms.iter().peekable(),
        }
    }

    /// The line said last.
    #[must_use]
    pub fn back(&self) -> Option<&LogLine> {
        match (self.everyday.back(), self.alarms.back()) {
            (Some(everyday), Some(alarm)) => Some(if alarm.said > everyday.said {
                alarm
            } else {
                everyday
            }),
            (line, None) | (None, line) => line,
        }
    }
}

/// Two rings read as one, by when each line was said.
struct Merged<'a, E: Iterator<Item = &'a LogLine>, A: Iterator<Item = &'a LogLine>> {
    everyday: Peekable<E>,
    alarms: Peekable<A>,
}

impl<'a, E: Iterator<Item = &'a LogLine>, A: Iterator<Item = &'a LogLine>> Iterator
    for Merged<'a, E, A>
{
    type Item = &'a LogLine;

    fn next(&mut self) -> Option<&'a LogLine> {
        match (self.everyday.peek(), self.alarms.peek()) {
            (Some(everyday), Some(alarm)) if alarm.said < everyday.said => self.alarms.next(),
            (Some(_), _) => self.everyday.next(),
            (None, _) => self.alarms.next(),
        }
    }
}

impl UiState {
    /// Append one line to the Networks log. `at` is injected time.
    pub(super) fn push_log(&mut self, severity: Severity, text: Sentence, at: Instant) {
        self.log.push(severity, text, at);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rmule_core::{CoreEvent, DownloadEvent, DownloadLifecycle};

    use super::*;
    use crate::action::Action;
    use crate::fixture::{download_event, download_id, file_hash};

    fn verified(part_index: u32) -> Action {
        Action::Core(download_event(DownloadEvent::PartVerified {
            download_id: download_id(1),
            part_index,
        }))
    }

    #[test]
    fn the_everyday_ring_drops_its_oldest_line_when_full() {
        let mut state = UiState::default();
        let now = Instant::now();
        for part_index in 0..(EVERYDAY_CAP as u32 + 50) {
            state.apply(verified(part_index), now);
        }
        assert_eq!(state.log.len(), EVERYDAY_CAP);
        assert_eq!(state.log.iter().next().unwrap().text, "part 50 verified");
        assert_eq!(state.log.back().unwrap().text, "part 1049 verified");
    }

    /// The case the second ring is for: a failure, then logins enough to fill
    /// the everyday ring many times over.
    #[test]
    fn a_failure_outlives_any_number_of_everyday_lines_and_keeps_its_place() {
        let mut state = UiState::default();
        let now = Instant::now();
        state.apply(verified(0), now);
        state.apply(
            Action::Core(CoreEvent::ClientUdpBindFailed {
                port: 4672,
                kind: std::io::ErrorKind::AddrInUse,
            }),
            now,
        );
        state.apply(verified(1), now);
        let order: Vec<Severity> = state.log.iter().map(|line| line.severity).collect();
        assert_eq!(
            order,
            [Severity::Info, Severity::Failure, Severity::Info],
            "two rings read in the order said"
        );
        for part_index in 0..(EVERYDAY_CAP as u32 * 3) {
            state.apply(verified(part_index), now);
        }
        let first = state.log.iter().next().unwrap();
        assert_eq!(first.severity, Severity::Failure);
        assert_eq!(state.log.len(), EVERYDAY_CAP + 1);
    }

    /// A machine that slept: the instant stands still across it, the wall does
    /// not, and neither line's stamp may move for the other.
    #[test]
    fn a_line_keeps_the_wall_time_it_was_said_at_across_a_sleep() {
        let mut state = UiState::default();
        let base = Instant::now();
        let before = "2026-03-01T23:59:50+02:00".parse().unwrap();
        state.log.set_wall(base, before);
        state.apply(verified(0), base + Duration::from_secs(5));
        let after = "2026-03-03T08:00:00+02:00".parse().unwrap();
        state.log.set_wall(base + Duration::from_secs(6), after);
        state.apply(verified(1), base + Duration::from_secs(6));

        let walls: Vec<String> = state
            .log
            .iter()
            .map(|line| line.wall.format("%d %H:%M:%S").to_string())
            .collect();
        assert_eq!(walls, ["01 23:59:55", "03 08:00:00"]);
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
