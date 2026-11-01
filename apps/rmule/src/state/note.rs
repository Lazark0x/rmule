//! The status bar's note: the last notable fact, and how long it stands.
//!
//! A fold has no clock, so a note is written unstamped and [`UiState::apply`],
//! which owns `now`, stamps it on the way out. Every note reaches the log the
//! moment it is said; the bar only borrows it for [`NOTE_STANDS`].

use std::ops::Deref;
use std::time::{Duration, Instant};

use super::UiState;
use crate::words::Sentence;

/// How long a note stays on the status bar. The log keeps it for good.
pub const NOTE_STANDS: Duration = Duration::from_secs(5 * 60);

/// Past this a note on the bar says how old it is.
pub const NOTE_AGE_SHOWN: Duration = Duration::from_secs(60);

/// The status bar's note. Reads as its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    text: Sentence,
    /// When it was said; `None` until `apply` stamps it, and a note no
    /// `apply` carried never ages.
    said: Option<Instant>,
}

impl From<Sentence> for Note {
    fn from(text: Sentence) -> Self {
        Self { text, said: None }
    }
}

impl Deref for Note {
    type Target = str;

    fn deref(&self) -> &str {
        self.text.as_str()
    }
}

impl PartialEq<&str> for Note {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl std::fmt::Display for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.text.fmt(f)
    }
}

impl Note {
    /// The note's words.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }

    /// How long ago it was said.
    #[must_use]
    pub fn age(&self, now: Instant) -> Duration {
        self.said
            .map_or(Duration::ZERO, |said| now.saturating_duration_since(said))
    }
}

impl UiState {
    /// Stamp a note the last fold wrote.
    pub(super) fn stamp_note(&mut self, now: Instant) {
        if let Some(note) = &mut self.notable {
            note.said.get_or_insert(now);
        }
    }

    /// The note the bar shows at `now`, if one still stands.
    #[must_use]
    pub fn standing_note(&self, now: Instant) -> Option<&Note> {
        self.notable
            .as_ref()
            .filter(|note| note.age(now) < NOTE_STANDS)
    }

    /// Drop a note past its time; true exactly once per note, so the render
    /// tick repaints a bar no data tick will.
    pub fn expire_note(&mut self, now: Instant) -> bool {
        if self.notable.is_some() && self.standing_note(now).is_none() {
            self.notable = None;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Action;
    use crate::fixture::now;
    use crate::words::app::CORE_STOPPED;

    /// A note leaves the bar on its own and stays in the log.
    #[test]
    fn a_note_ages_out_of_the_bar_and_stays_in_the_log() {
        let mut state = UiState::default();
        let t0 = now();
        state.apply(Action::Note(CORE_STOPPED), t0);

        assert!(state.standing_note(t0 + NOTE_STANDS / 2).is_some());
        assert!(!state.expire_note(t0 + NOTE_STANDS / 2), "it still stands");
        assert!(state.standing_note(t0 + NOTE_STANDS).is_none());
        assert!(state.expire_note(t0 + NOTE_STANDS), "repaints once");
        assert!(!state.expire_note(t0 + NOTE_STANDS), "and only once");
        assert_eq!(state.log.len(), 1);
    }

    /// A newer note restarts the clock: what stands is the newest fact.
    #[test]
    fn a_newer_note_is_timed_from_its_own_moment() {
        let mut state = UiState::default();
        let t0 = now();
        state.apply(Action::Note(CORE_STOPPED), t0);
        state.notable = None;
        state.apply(Action::Note(CORE_STOPPED), t0 + NOTE_STANDS);
        let note = state
            .standing_note(t0 + NOTE_STANDS + NOTE_AGE_SHOWN)
            .expect("the newer note");
        assert_eq!(note.age(t0 + NOTE_STANDS + NOTE_AGE_SHOWN), NOTE_AGE_SHOWN);
    }
}
