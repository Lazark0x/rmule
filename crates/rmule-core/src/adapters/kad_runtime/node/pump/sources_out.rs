//! The answers discovery has not read yet: the sources half of the rule the
//! pump keeps for the node's inbox (`pump_state/asks.rs`). The driver never
//! waits for room here while it holds the loop, so the pump goes on reading
//! the commands discovery may be parked on sending. An answer with no room is
//! held, and the driver waits for room beside the node's events.

use std::collections::VecDeque;

use rmule_primitives::FileHash;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{OwnedPermit, Sender};

use crate::kad_sources::KadAnswer;

/// How many answers wait for discovery before the oldest gives way. The
/// file's next ask finds those sources again.
const HELD_ANSWERS: usize = 256;

/// One file's answer on its way to discovery.
type Answer = (FileHash, KadAnswer);

/// The discovery task dropped its end.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::adapters::kad_runtime) struct SourcesClosed;

/// The pump's end of the sources channel.
pub(crate) struct SourcesOut<T = Answer> {
    tx: Sender<T>,
    held: VecDeque<T>,
}

impl<T: Send + 'static> SourcesOut<T> {
    pub(crate) fn new(tx: Sender<T>) -> Self {
        Self {
            tx,
            held: VecDeque::new(),
        }
    }

    /// Send `answer` behind what is held, or hold it, without waiting.
    pub(super) fn offer(&mut self, answer: T) -> Result<(), SourcesClosed> {
        if !self.held.is_empty() {
            self.hold(answer);
            return Ok(());
        }
        match self.tx.try_send(answer) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(answer)) => {
                self.hold(answer);
                Ok(())
            }
            Err(TrySendError::Closed(_)) => Err(SourcesClosed),
        }
    }

    fn hold(&mut self, answer: T) {
        if self.held.len() == HELD_ANSWERS {
            self.held.pop_front();
            tracing::debug!("a Kad source answer gave way: discovery is behind");
        }
        self.held.push_back(answer);
    }

    /// Whether anything waits for room.
    pub(super) fn holds(&self) -> bool {
        !self.held.is_empty()
    }

    /// Room for the oldest held answer; `None` once discovery has gone.
    pub(super) fn room(&self) -> impl Future<Output = Option<OwnedPermit<T>>> + Send + use<T> {
        let tx = self.tx.clone();
        async move { tx.reserve_owned().await.ok() }
    }

    /// Send the oldest held answer into `room`.
    pub(super) fn flow(&mut self, room: OwnedPermit<T>) {
        if let Some(answer) = self.held.pop_front() {
            room.send(answer);
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    /// Discovery has stopped reading, and every further answer returns at
    /// once; when it reads again, they arrive in order.
    #[tokio::test]
    async fn a_full_channel_holds_answers_without_waiting_and_loses_no_order() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut out = SourcesOut::new(tx);
        for answer in 0..4_u8 {
            out.offer(answer).expect("discovery is there");
        }
        assert!(out.holds());

        for expected in 0..4_u8 {
            assert_eq!(rx.recv().await, Some(expected));
            if out.holds() {
                let room = out.room().await.expect("discovery is there");
                out.flow(room);
            }
        }
        assert!(!out.holds());
    }

    /// Past the bound the oldest gives way: the pump's memory does not grow
    /// with a discovery that never comes back.
    #[tokio::test]
    async fn the_oldest_held_answer_gives_way_past_the_bound() {
        let (tx, _rx) = mpsc::channel(1);
        let mut out = SourcesOut::new(tx);
        for answer in 0..=HELD_ANSWERS * 2 {
            out.offer(answer).expect("discovery is there");
        }
        assert_eq!(out.held.len(), HELD_ANSWERS);
        assert_eq!(out.held.back(), Some(&(HELD_ANSWERS * 2)));
    }

    #[tokio::test]
    async fn a_closed_channel_is_said() {
        let (tx, rx) = mpsc::channel::<u8>(1);
        drop(rx);
        assert_eq!(SourcesOut::new(tx).offer(1), Err(SourcesClosed));
    }
}
