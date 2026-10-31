//! The **Kad Pump State**'s half of the node's `0x52` verdicts: who waits on
//! which walk, so `CallbackWalkEnded` reaches the download it belongs to, and
//! who waits on which endpoint-known send, so `BuddyCallbackPaced` does.
//!
//! The one-walk-per-target rule and the **Callback Pace** are the node's; this
//! side only remembers who is waiting on which buddy ID. A `0x52` that left
//! reports nothing — whether the buddy took it only a dial-back can tell, and
//! the slot's own deadline waits for that.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use rmule_kad::{KadCallbackPace, KadCallbackWalkEnd, KadId};

use super::KadPumpEffect;
use crate::adapters::kad_runtime::CallbackReply;
use crate::diagnostics::NattRetirement;

/// The downloads waiting on a walk, per buddy ID, in the order the node took
/// their walks.
///
/// Order is what attributes a verdict: the node handles commands in order and
/// refuses a walk *while* another toward the same ID runs, so a refusal always
/// belongs to the newest waiter and an end to the oldest. The brain tells the
/// node its asks one at a time, and a waiter is remembered only once the node
/// took its walk.
#[derive(Default)]
pub(super) struct CallbackWalks {
    waiting: HashMap<KadId, VecDeque<CallbackReply>>,
    /// The downloads waiting on the Callback Pace's verdict on their
    /// endpoint-known `0x52`, in command order, which the node answers in.
    paced: HashMap<KadId, VecDeque<CallbackReply>>,
}

impl CallbackWalks {
    /// The node took a walk toward `buddy_id`: `reply` waits on its verdict.
    pub(super) fn took(&mut self, buddy_id: KadId, reply: CallbackReply) {
        self.waiting.entry(buddy_id).or_default().push_back(reply);
    }

    /// The node took an endpoint-known `0x52` naming `buddy_id`: `reply` waits
    /// on the pace's verdict.
    pub(super) fn sent(&mut self, buddy_id: KadId, reply: CallbackReply) {
        self.paced.entry(buddy_id).or_default().push_back(reply);
    }

    /// The pace's verdict on the oldest `0x52` naming `buddy_id`: what its
    /// download must hear, when anything.
    pub(super) fn paced(
        &mut self,
        buddy_id: KadId,
        pace: KadCallbackPace,
    ) -> Option<KadPumpEffect> {
        let queue = self.paced.get_mut(&buddy_id)?;
        let reply = queue.pop_front();
        if queue.is_empty() {
            self.paced.remove(&buddy_id);
        }
        let news = match pace {
            KadCallbackPace::Left => None,
            KadCallbackPace::Held { leaves_in } => Some(News::Held(leaves_in)),
            KadCallbackPace::Refused => Some(News::Retired(NattRetirement::CallbackNotSent)),
        };
        news?.reaches(reply?).into()
    }

    /// The node's verdict on a walk toward `buddy_id`: what its download must
    /// hear, when anything.
    pub(super) fn ended(
        &mut self,
        buddy_id: KadId,
        end: KadCallbackWalkEnd,
    ) -> Option<KadPumpEffect> {
        let queue = self.waiting.get_mut(&buddy_id)?;
        let (reply, news) = match end {
            KadCallbackWalkEnd::AlreadyWalking => (
                queue.pop_back(),
                Some(News::Retired(NattRetirement::CallbackWalkBusy)),
            ),
            KadCallbackWalkEnd::NoneNear => (
                queue.pop_front(),
                Some(News::Retired(NattRetirement::BuddyNotFound)),
            ),
            KadCallbackWalkEnd::Refused => (
                queue.pop_front(),
                Some(News::Retired(NattRetirement::CallbackNotSent)),
            ),
            KadCallbackWalkEnd::Held { leaves_in, .. } => {
                (queue.pop_front(), Some(News::Held(leaves_in)))
            }
            KadCallbackWalkEnd::Asked(_) => (queue.pop_front(), None),
        };
        if queue.is_empty() {
            self.waiting.remove(&buddy_id);
        }
        tracing::debug!(?buddy_id, ?end, "callback walk ended");
        news?.reaches(reply?).into()
    }
}

/// What a download must hear about its `0x52`.
enum News {
    /// None will leave.
    Retired(NattRetirement),
    /// It leaves after this long.
    Held(Duration),
}

impl News {
    fn reaches(self, reply: CallbackReply) -> KadPumpEffect {
        match self {
            Self::Retired(reason) => KadPumpEffect::CallbackWalkRetired { reply, reason },
            Self::Held(leaves_in) => KadPumpEffect::CallbackHeld { reply, leaves_in },
        }
    }
}
