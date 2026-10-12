//! The **Kad Pump State**'s half of the **Callback Walk**: who waits on which
//! walk, so the node's `CallbackWalkEnded` retires the download it belongs to.
//!
//! The one-walk-per-target rule is the node's (aMule's `StartSearch`); this
//! side only remembers who is waiting on which buddy ID. A walk that sent its
//! `0x52` reports nothing — whether the buddy was among its recipients only a
//! dial-back can tell, and the slot's own deadline waits for that.

use std::collections::{HashMap, VecDeque};

use rmule_kad::{KadCallbackWalkEnd, KadId};

use crate::adapters::kad_runtime::CallbackWalkReply;
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
    waiting: HashMap<KadId, VecDeque<CallbackWalkReply>>,
}

impl CallbackWalks {
    /// The node took a walk toward `buddy_id`: `reply` waits on its verdict.
    pub(super) fn took(&mut self, buddy_id: KadId, reply: CallbackWalkReply) {
        self.waiting.entry(buddy_id).or_default().push_back(reply);
    }

    /// The node's verdict on a walk toward `buddy_id`: the download to retire
    /// and why, when the walk will send no `0x52`.
    pub(super) fn ended(
        &mut self,
        buddy_id: KadId,
        end: KadCallbackWalkEnd,
    ) -> Option<(CallbackWalkReply, NattRetirement)> {
        let queue = self.waiting.get_mut(&buddy_id)?;
        let (reply, reason) = match end {
            KadCallbackWalkEnd::AlreadyWalking => {
                (queue.pop_back(), Some(NattRetirement::CallbackWalkBusy))
            }
            KadCallbackWalkEnd::NoneNear => {
                (queue.pop_front(), Some(NattRetirement::BuddyNotFound))
            }
            KadCallbackWalkEnd::Asked(_) => (queue.pop_front(), None),
        };
        if queue.is_empty() {
            self.waiting.remove(&buddy_id);
        }
        tracing::debug!(?buddy_id, ?end, "callback walk ended");
        reply.zip(reason)
    }
}
