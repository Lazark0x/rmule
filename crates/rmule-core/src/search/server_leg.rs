//! **The server leg's hand-overs**: a leg sent after its search started, a
//! leg whose session ended unanswered, and the moves of the search's leg
//! picture that follow. The search's loop stays in the parent; this file
//! holds what changes only when the server leg's states do (ADR-0034,
//! "A server leg's states").

use tokio::sync::oneshot;

use super::{LegNotSent, SearchLegState, SearchStream, SearchTask, ServerSessionHandle};
use crate::service::SearchId;

/// A search's server leg whose session ended before it answered (ADR-0034).
/// The actor keeps `rearm` while the operator's Server Intent stands
/// and sends the leg on the re-made session through it; with no intent it
/// drops it, and the leg ends [`SearchLegState::Unanswered`].
pub(crate) struct LostServerLeg {
    pub(crate) search_id: SearchId,
    pub(crate) rearm: oneshot::Sender<SentServerLeg>,
}

/// A server leg sent after its search started: the operator's connect
/// brought the session it waited for (ADR-0034). The sweep goes with
/// it, since it needs a session as aMule's global search does.
pub(crate) struct SentServerLeg {
    pub(crate) stream: SearchStream,
    pub(crate) session: ServerSessionHandle,
    /// The sweep's settle signal; `None` with no server-UDP socket bound.
    pub(crate) sweep: Option<super::SweepDone>,
}

impl SearchTask {
    /// The session the server leg waited for came up and the leg went out on
    /// it, the sweep beside it — unless the sweep already ran, before a lost
    /// session sent the leg back to waiting: a sweep is not re-sent.
    pub(super) async fn attach_server_leg(&mut self, leg: SentServerLeg) {
        self.late.server_lost = false;
        self.stream = leg.stream;
        self.paging.session = Some(leg.session);
        let sweep = match leg.sweep {
            Some(settled) => {
                self.global_sweep = settled;
                SearchLegState::Sent
            }
            None if self.legs.sweep == SearchLegState::WaitingForSession => SearchLegState::NotRun,
            None => self.legs.sweep,
        };
        self.move_leg(|legs| {
            legs.server = SearchLegState::Sent;
            legs.sweep = sweep;
        })
        .await;
    }

    /// The server leg waited for a session no intent will bring: one that
    /// went out ends unanswered, one that never did ends not sent, and so
    /// does a sweep that waited with it (ADR-0034, "A server leg's states").
    pub(super) async fn let_go_server_leg(&mut self) {
        let lost = std::mem::take(&mut self.late.server_lost);
        self.move_leg(|legs| {
            let not_sent = SearchLegState::NotSent(LegNotSent::NoServer);
            legs.server = if lost {
                SearchLegState::Unanswered
            } else {
                not_sent
            };
            if legs.sweep == SearchLegState::WaitingForSession {
                legs.sweep = not_sent;
            }
        })
        .await;
    }

    /// The server leg's session ended before it answered: hand the actor the
    /// way to send it again and wait.
    pub(super) async fn lose_server_leg(&mut self) {
        let (rearm, late) = oneshot::channel();
        self.late.server = Some(late);
        self.late.server_lost = true;
        self.paging.session = None;
        let _ = self.lost.send(LostServerLeg {
            search_id: self.search_id,
            rearm,
        });
        self.move_leg(|legs| legs.server = SearchLegState::WaitingForSession)
            .await;
    }
}
