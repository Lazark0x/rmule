//! The serve loop's links: its handle on each link's task, and the order two
//! links to one endpoint take. The loop keys links by endpoint and folds their
//! facts into [`ServeState`](crate::serve::state::ServeState) under that key,
//! so a link that follows another there must wait until the first's close is
//! folded: taken on sooner, that close would end the new link, its
//! registration and whatever its hello earned.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, mpsc};

use crate::adapters::{ServeConnection, ServeInput, ServeOutput};
use crate::serve::link_output::LinkOutput;

/// How many outputs a **Link Outbox** holds. The Send-Ahead keeps blocks to ten
/// of them, so a full one is a peer asking faster than it reads (ADR-0031).
const LINK_OUTBOX_LEN: usize = 64;

/// The serve loop's handle on one link's task.
pub(super) struct Link {
    /// The **Link Outbox**: filled without waiting.
    pub(super) outbox: mpsc::Sender<LinkOutput>,
    /// The latest flow of this link that has ended, read by its reads and
    /// its task, so what is under way for it stops at the next look.
    pub(super) ended_through: Arc<AtomicU64>,
    /// Ends the link now, whatever its outbox holds.
    pub(super) stop: Arc<Notify>,
}

impl Link {
    /// Hand this link `output` without waiting. A full outbox ends the link:
    /// its peer is asking faster than it reads. A closed one has its end on
    /// the way already.
    pub(super) fn offer(&self, peer: PeerEndpoint, output: LinkOutput) {
        if let Err(TrySendError::Full(_)) = self.outbox.try_send(output) {
            tracing::debug!(%peer, "a link's outbox filled; the peer is not reading, so its link ends");
            self.stop.notify_one();
        }
    }
}

/// The links arriving by one road that wait for the link before them at their
/// endpoint to leave the loop. Every link's task ends in exactly one closing
/// fact, so each waits for at most that one.
pub(super) struct NextLinks<T> {
    behind: HashMap<PeerEndpoint, VecDeque<T>>,
    ready: VecDeque<T>,
}

impl<T> Default for NextLinks<T> {
    fn default() -> Self {
        Self {
            behind: HashMap::new(),
            ready: VecDeque::new(),
        }
    }
}

impl<T> NextLinks<T> {
    /// A link whose turn has come, else what `arrives` brings. Cancel-safe as
    /// `arrives` is.
    pub(super) async fn next_from(
        &mut self,
        arrives: impl Future<Output = Option<T>>,
    ) -> Option<T> {
        match self.ready.pop_front() {
            Some(link) => Some(link),
            None => arrives.await,
        }
    }

    /// `next` to `peer`, back at once when no link stands there. Otherwise it
    /// waits behind that link, which is told to end: two links at one endpoint
    /// have one key, and the earlier is on its way out or is a link the peer
    /// has left.
    pub(super) fn turn_of(
        &mut self,
        peer: PeerEndpoint,
        next: T,
        links: &HashMap<PeerEndpoint, Link>,
    ) -> Option<T> {
        let Some(standing) = links.get(&peer) else {
            return Some(next);
        };
        standing.stop.notify_one();
        self.behind.entry(peer).or_default().push_back(next);
        None
    }

    /// The link at `peer` left the loop: the next behind it takes its turn.
    pub(super) fn link_left(&mut self, peer: PeerEndpoint) {
        let Some(behind) = self.behind.get_mut(&peer) else {
            return;
        };
        self.ready.extend(behind.pop_front());
        if behind.is_empty() {
            self.behind.remove(&peer);
        }
    }
}

/// Register one identified serve connection (accepted *or* dialed): keep its
/// [`Link`] keyed by endpoint and spawn the task that relays its outbox to it
/// and its events to the shared `fact_tx`. The one path both connection sources
/// go through, so the queue treats a same-socket (dialed) requester identically
/// to an accepted one.
///
/// The task parks on neither side alone. An output waits for room on the
/// connection while what the peer says still reaches the loop: the router
/// behind the connection may be holding that very room until it has handed its
/// event on (ADR-0031).
pub(super) fn register_serve_connection(
    conn: ServeConnection,
    links: &mut HashMap<PeerEndpoint, Link>,
    fact_tx: &mpsc::Sender<(PeerEndpoint, ServeInput)>,
) {
    let peer = conn.peer();
    let (outbox, mut outbox_rx) = mpsc::channel::<LinkOutput>(LINK_OUTBOX_LEN);
    let ended_through = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(Notify::new());
    let link = Link {
        outbox,
        ended_through: Arc::clone(&ended_through),
        stop: Arc::clone(&stop),
    };
    links.insert(peer, link);
    let fact_tx = fact_tx.clone();
    let (command_tx, mut event_rx) = conn.into_halves();
    tokio::spawn(async move {
        // The output waiting for room on the connection.
        let mut waiting: Option<ServeOutput> = None;
        loop {
            tokio::select! {
                () = stop.notified() => {
                    let _ = fact_tx.send((peer, ServeInput::closed_here())).await;
                    break;
                }
                permit = command_tx.reserve(), if waiting.is_some() => {
                    // A connection gone under an output says so on its event
                    // stream, read below, which is what frees the peer's slot.
                    if let (Ok(permit), Some(output)) = (permit, waiting.take()) {
                        permit.send(output);
                    }
                }
                output = outbox_rx.recv(), if waiting.is_none() => {
                    let Some(output) = output else { break };
                    // Awaited here, the link's own task: a block costs only
                    // this link's next output (ADR-0031).
                    waiting = output.ready(&ended_through).await;
                }
                event = event_rx.recv() => {
                    let Some(event) = event else {
                        let _ = fact_tx.send((peer, ServeInput::closed_here())).await;
                        break;
                    };
                    let disconnected = event.is_disconnect();
                    if fact_tx.send((peer, event)).await.is_err() || disconnected {
                        break;
                    }
                }
            }
        }
    });
}
