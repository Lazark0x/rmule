//! The launch a Preview makes (ADR-0114, "A launch"): the reducer reads the
//! download by the same [`preview_target`] the menu shows, splits the Player
//! Command, and hands the player's arguments to the player lane.

use std::time::Instant;

use rmule_core::DownloadId;

use super::{App, Flow};
use crate::action::Action;
use crate::player::{Launch, argv, preview_target, split};
use crate::words::{app as app_words, player as words};

impl App {
    /// Hand download `id`'s file to the player, or flash why not.
    pub(super) fn preview(&mut self, id: DownloadId, now: Instant) -> Flow {
        let launch = match preview_target(&self.state, id) {
            Err(block) => Err(words::blocked(block)),
            Ok(target) => split(target.command)
                .map(|program| Launch {
                    argv: argv(&program, target.path),
                    name: target.metadata.name.to_display_string(),
                })
                .map_err(words::unsplittable),
        };
        let refusal = match (launch, self.player.as_ref()) {
            (Err(refusal), _) => refusal,
            (Ok(_), None) => app_words::CORE_NOT_ATTACHED,
            (Ok(launch), Some(player)) => match player.send(launch) {
                Ok(()) => return Flow::Continue,
                Err(_) => words::LANE_ENDED,
            },
        };
        self.reduce(Action::Flash(refusal), now)
    }
}

#[cfg(test)]
mod tests;
