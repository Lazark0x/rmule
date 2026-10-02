//! The hand-off every row menu's *Search related* makes (ADR-0037,
//! Related-Files Search): whichever tab it was chosen in, the Search tab opens
//! the Held Search, sends it, and becomes current with focus on its results.

use std::time::Instant;

use rmule_primitives::RelatedFilesQuery;

use super::{App, Flow};
use crate::action::Action;
use crate::view::ViewId;
use crate::views::ViewOutcome;

impl App {
    /// Open and send a Related-Files Search. The tab moves only when the
    /// search went out; a refusal is said where the operator already is.
    pub(super) fn search_related(&mut self, query: RelatedFilesQuery, now: Instant) -> Flow {
        match self.views.searches.start_related(query, &self.state) {
            ViewOutcome::Emit(command @ Action::Command(_)) => {
                self.dirty |= self
                    .chrome
                    .update(&Action::SwitchView(ViewId::Searches), now);
                self.dirty = true;
                self.reduce(command, now)
            }
            ViewOutcome::Emit(other) => self.reduce(other, now),
            ViewOutcome::Redraw => {
                self.dirty = true;
                Flow::Continue
            }
            ViewOutcome::Ignored => Flow::Continue,
        }
    }
}

#[cfg(test)]
mod tests;
