//! The Kad pump's half of the **Callback Walk**: the download
//! whose candidate named its buddy by ID alone hands the pump a walk and a
//! place to report its verdict, and the pump carries the node's
//! `CallbackWalkEnded` back to that download's retire channel.
//!
//! The one-walk-per-target rule is the node's (aMule's `StartSearch`); this
//! side only remembers who is waiting on which buddy ID. A walk that sent its
//! `0x52` reports nothing — whether the buddy was among its recipients only a
//! dial-back can tell, and the slot's own deadline waits for that.

use std::collections::{HashMap, VecDeque};

use rmule_kad::{KadCallbackWalkEnd, KadId};
use tokio::sync::mpsc;

use crate::adapters::CallbackKey;
use crate::diagnostics::NattRetirement;

/// Where a Callback Walk's failure is reported: the download's retire channel,
/// under the candidate's key — the same channel a retired punch rides.
#[derive(Clone, Debug)]
pub(crate) struct CallbackWalkReply {
    /// The candidate the walk is for.
    pub(crate) key: CallbackKey,
    /// The download's retire channel.
    pub(crate) retire_tx: mpsc::Sender<(CallbackKey, NattRetirement)>,
}

/// A Callback Walk as the core actor resolved it: the `0x52`'s three fields,
/// and who hears if no `0x52` leaves.
#[derive(Clone, Debug)]
pub(crate) struct CallbackWalkAsk {
    /// The buddy relationship ID the row named — the walk's target.
    pub(crate) buddy_id: KadId,
    /// The file the target must know before it dials us back.
    pub(crate) file_hash: rmule_primitives::FileHash,
    /// Where the target must dial us — our advertised TCP port.
    pub(crate) tcp_port: u16,
    /// Where the walk's failure goes.
    pub(crate) reply: CallbackWalkReply,
}

/// The downloads waiting on a walk, per buddy ID, in the order their asks
/// reached the node.
///
/// Order is what attributes a verdict: the node handles commands in order and
/// refuses a walk *while* another toward the same ID runs, so a refusal always
/// belongs to the newest waiter and an end to the oldest.
#[derive(Default)]
pub(super) struct CallbackWalks {
    waiting: HashMap<KadId, VecDeque<CallbackWalkReply>>,
}

impl CallbackWalks {
    /// Hand the walk to the node and remember who waits on it.
    pub(super) async fn begin(
        &mut self,
        handle: &rmule_net::kad::KadNetHandle,
        ask: CallbackWalkAsk,
    ) {
        let command = rmule_kad::KadCommand::CallbackWalk {
            buddy_id: ask.buddy_id,
            file_hash: ask.file_hash,
            tcp_port: ask.tcp_port,
        };
        if handle.command(command).await.is_ok() {
            self.waiting
                .entry(ask.buddy_id)
                .or_default()
                .push_back(ask.reply);
        }
    }

    /// The node's verdict on a walk toward `buddy_id`.
    pub(super) fn on_end(&mut self, buddy_id: KadId, end: KadCallbackWalkEnd) {
        let Some(queue) = self.waiting.get_mut(&buddy_id) else {
            return;
        };
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
        if let (Some(reply), Some(reason)) = (reply, reason) {
            // Never stall the pump on one download's backlog: a lost verdict
            // leaves the candidate to its slot's own 30 s.
            let _ = reply.retire_tx.try_send((reply.key, reason));
        }
    }
}

/// Hand one Callback Walk to the running node, reporting whether a node was
/// there to take it.
pub(crate) fn request_kad_callback_walk(sink: &super::SharedKadPump, ask: CallbackWalkAsk) -> bool {
    sink.lock().is_ok_and(|slot| {
        slot.as_ref().is_some_and(|tx| {
            tx.try_send(super::KadPumpCommand::CallbackWalk(ask))
                .is_ok()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiter(
        low: u32,
    ) -> (
        CallbackWalkReply,
        mpsc::Receiver<(CallbackKey, NattRetirement)>,
    ) {
        let (retire_tx, retire_rx) = mpsc::channel(1);
        let key = CallbackKey {
            server: None,
            low_id: rmule_primitives::ClientId::from_u32(low),
        };
        (CallbackWalkReply { key, retire_tx }, retire_rx)
    }

    /// Two downloads walk toward one buddy: the second is refused while the
    /// first runs, and each verdict reaches the download it belongs to — the
    /// refusal the newest, the walk's own end the oldest.
    #[test]
    fn each_walk_verdict_reaches_the_download_that_asked() {
        let buddy_id = KadId::from_bytes([0x7A; KadId::BYTE_LEN]);
        let (first, mut first_rx) = waiter(1);
        let (second, mut second_rx) = waiter(2);
        let mut walks = CallbackWalks::default();
        walks
            .waiting
            .insert(buddy_id, VecDeque::from([first.clone(), second.clone()]));

        walks.on_end(buddy_id, KadCallbackWalkEnd::AlreadyWalking);
        assert_eq!(
            second_rx.try_recv().ok(),
            Some((second.key, NattRetirement::CallbackWalkBusy))
        );
        assert!(
            first_rx.try_recv().is_err(),
            "the running walk is untouched"
        );

        walks.on_end(buddy_id, KadCallbackWalkEnd::NoneNear);
        assert_eq!(
            first_rx.try_recv().ok(),
            Some((first.key, NattRetirement::BuddyNotFound))
        );
        assert!(walks.waiting.is_empty(), "nobody is left waiting");
    }

    /// A walk that sent its `0x52` retires nothing: the dial-back may yet
    /// come, and the slot's deadline is what waits for it.
    #[test]
    fn a_walk_that_asked_retires_nothing() {
        let buddy_id = KadId::from_bytes([0x7A; KadId::BYTE_LEN]);
        let (reply, mut rx) = waiter(1);
        let mut walks = CallbackWalks::default();
        walks.waiting.insert(buddy_id, VecDeque::from([reply]));

        walks.on_end(buddy_id, KadCallbackWalkEnd::Asked(2));

        assert!(rx.try_recv().is_err());
        assert!(walks.waiting.is_empty());
    }
}
