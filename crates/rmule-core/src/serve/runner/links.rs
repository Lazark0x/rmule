//! The serve loop's links: its handle on each link's task, the order what that
//! task hands the connection goes in, and the order two links to one endpoint
//! take. The loop keys links by endpoint and folds their facts into
//! [`ServeState`](crate::serve::state::ServeState) under that key, so a link
//! that follows another there must wait until the first's close is folded:
//! taken on sooner, that close would end the new link, its registration and
//! whatever its hello earned.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, mpsc};

use crate::adapters::{ServeConnection, ServeInput, ServeOutput};
use crate::serve::link_output::{LinkBlock, LinkOutput};

/// How many entries each lane of a **Link Outbox** holds. A full one is a peer
/// asking faster than it reads (ADR-0031).
const LINK_OUTBOX_LEN: usize = 64;

/// The serve loop's handle on one link's task.
pub(super) struct Link {
    /// The **Link Outbox**'s lane for answers: filled without waiting.
    answers: mpsc::Sender<ServeOutput>,
    /// The **Link Outbox**'s lane for blocks: filled without waiting.
    blocks: mpsc::Sender<LinkBlock>,
    /// The latest flow of this link that has ended, read by its reads and
    /// its task, so what is under way for it stops at the next look.
    pub(super) ended_through: Arc<AtomicU64>,
    /// Calls the link's task to that look.
    flow_ended: Arc<Notify>,
    /// Ends the link now, whatever its outbox holds.
    pub(super) stop: Arc<Notify>,
}

impl Link {
    /// Hand this link `output` without waiting. A full lane ends the link:
    /// its peer is asking faster than it reads. A closed one has its end on
    /// the way already.
    pub(super) fn offer(&self, peer: PeerEndpoint, output: LinkOutput) {
        let full = match output {
            LinkOutput::Ready(output) => {
                matches!(self.answers.try_send(output), Err(TrySendError::Full(_)))
            }
            LinkOutput::Block(block) => {
                matches!(self.blocks.try_send(block), Err(TrySendError::Full(_)))
            }
        };
        if full {
            tracing::debug!(%peer, "a link's outbox filled; the peer is not reading, so its link ends");
            self.stop.notify_one();
        }
    }

    /// `flow` and those before it have ended: what is under way for them stops.
    pub(super) fn end_flow(&self, flow: u64) {
        self.ended_through.fetch_max(flow, Ordering::Relaxed);
        self.flow_ended.notify_one();
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

/// What one link's task holds to hand its connection.
#[derive(Default)]
struct Handing {
    /// The answer waiting for room, which no block passes.
    answer: Option<ServeOutput>,
    /// The next block, its flow and what goes down for it, ready as soon as
    /// the connection may have it.
    block: Option<(u64, ServeOutput)>,
    /// The flow of the block the connection holds, until it has left.
    on_the_wire: Option<u64>,
}

impl Handing {
    /// Whether the connection has a next output, room for it aside. One block
    /// at a time: a FIFO connection is what no answer can pass (ADR-0031).
    const fn has_output(&self) -> bool {
        self.answer.is_some() || (self.block.is_some() && self.on_the_wire.is_none())
    }

    /// The next output, the answer ahead of the block.
    fn next(&mut self) -> Option<ServeOutput> {
        if let Some(answer) = self.answer.take() {
            return Some(answer);
        }
        let (flow, block) = self.block.take()?;
        self.on_the_wire = Some(flow);
        Some(block)
    }

    /// Flows through `ended` have ended. The next block of one goes no
    /// further, and one the connection holds waits for nothing: the session
    /// frames no block of a slot gone, so no word of its leaving may come.
    fn flows_ended(&mut self, ended: u64) {
        if self.block.as_ref().is_some_and(|(flow, _)| *flow <= ended) {
            self.block = None;
        }
        if self.on_the_wire.is_some_and(|flow| flow <= ended) {
            self.on_the_wire = None;
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
/// event on (ADR-0031). An answer goes ahead of every block but the one the
/// connection holds, and the arms are in the order that says so.
pub(super) fn register_serve_connection(
    conn: ServeConnection,
    links: &mut HashMap<PeerEndpoint, Link>,
    fact_tx: &mpsc::Sender<(PeerEndpoint, ServeInput)>,
) {
    let peer = conn.peer();
    let (answers, mut answers_rx) = mpsc::channel::<ServeOutput>(LINK_OUTBOX_LEN);
    let (blocks, mut blocks_rx) = mpsc::channel::<LinkBlock>(LINK_OUTBOX_LEN);
    let ended_through = Arc::new(AtomicU64::new(0));
    let flow_ended = Arc::new(Notify::new());
    let stop = Arc::new(Notify::new());
    let link = Link {
        answers,
        blocks,
        ended_through: Arc::clone(&ended_through),
        flow_ended: Arc::clone(&flow_ended),
        stop: Arc::clone(&stop),
    };
    links.insert(peer, link);
    let fact_tx = fact_tx.clone();
    let (command_tx, mut event_rx) = conn.into_halves();
    tokio::spawn(async move {
        let mut handing = Handing::default();
        loop {
            handing.flows_ended(ended_through.load(Ordering::Relaxed));
            tokio::select! {
                biased;
                () = stop.notified() => {
                    let _ = fact_tx.send((peer, ServeInput::closed_here())).await;
                    break;
                }
                answer = answers_rx.recv(), if handing.answer.is_none() => {
                    let Some(answer) = answer else { break };
                    handing.answer = Some(answer);
                }
                permit = command_tx.reserve(), if handing.has_output() => {
                    let output = handing.next();
                    // A connection gone under an output says so on its event
                    // stream, read below, which is what frees the peer's slot.
                    if let (Ok(permit), Some(output)) = (permit, output) {
                        permit.send(output);
                    }
                }
                event = event_rx.recv() => {
                    let Some(event) = event else {
                        let _ = fact_tx.send((peer, ServeInput::closed_here())).await;
                        break;
                    };
                    if event.is_block_left() {
                        handing.on_the_wire = None;
                    }
                    let disconnected = event.is_disconnect();
                    if fact_tx.send((peer, event)).await.is_err() || disconnected {
                        break;
                    }
                }
                () = flow_ended.notified() => {}
                block = blocks_rx.recv(), if handing.block.is_none() => {
                    let Some(block) = block else { break };
                    let flow = block.flow;
                    // Awaited here, the link's own task: a block costs only
                    // this link's next output (ADR-0031).
                    handing.block = block.ready(&ended_through).await.map(|output| (flow, output));
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rmule_peer::{ServerCommand, ServerEvent};
    use rmule_primitives::FileHash;
    use tokio::sync::mpsc::error::TryRecvError;

    use super::*;
    use crate::serve::state::BlockRead;

    const FILE: FileHash = FileHash::from_bytes([0x61; FileHash::BYTE_LEN]);

    fn peer() -> PeerEndpoint {
        "203.0.113.8:51000".parse().unwrap()
    }

    /// One link's task under a connection that leaves everything it is handed
    /// in `commands`, as a driver mid-write does.
    struct Bench {
        link: Link,
        commands: mpsc::Receiver<ServeOutput>,
        events: mpsc::Sender<ServeInput>,
        _facts: mpsc::Receiver<(PeerEndpoint, ServeInput)>,
    }

    fn bench() -> Bench {
        let (command_tx, commands) = mpsc::channel(16);
        let (events, event_rx) = mpsc::channel(16);
        let (fact_tx, _facts) = mpsc::channel(16);
        let mut links = HashMap::new();
        register_serve_connection(
            ServeConnection::new(peer(), command_tx, event_rx),
            &mut links,
            &fact_tx,
        );
        let link = links.remove(&peer()).expect("registered");
        Bench {
            link,
            commands,
            events,
            _facts,
        }
    }

    fn block_at(start: u64, flow: u64) -> LinkOutput {
        LinkOutput::Block(LinkBlock {
            flow,
            block: BlockRead {
                file_hash: FILE,
                start,
                end: start + 4,
            },
            bytes: vec![1; 4],
            deflate: false,
        })
    }

    fn status() -> LinkOutput {
        ServeOutput::Server(ServerCommand::SetQueueRank { rank: 3 }).into()
    }

    impl Bench {
        fn offer(&self, output: LinkOutput) {
            self.link.offer(peer(), output);
        }

        async fn next(&mut self) -> ServeOutput {
            tokio::time::timeout(Duration::from_secs(5), self.commands.recv())
                .await
                .expect("an output in time")
                .expect("the link stands")
        }

        async fn next_block_starts(&mut self, start: u64) {
            match self.next().await {
                ServeOutput::Server(ServerCommand::SendBlock { start: at, .. }) => {
                    assert_eq!(at, start);
                }
                other => panic!("the block at {start}, not {other:?}"),
            }
        }

        async fn next_is_status(&mut self) {
            match self.next().await {
                ServeOutput::Server(ServerCommand::SetQueueRank { .. }) => {}
                other => panic!("the status, not {other:?}"),
            }
        }

        /// Whatever the link's task would hand on next, it has had its turn.
        async fn hands_nothing_more(&mut self) {
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            assert!(matches!(self.commands.try_recv(), Err(TryRecvError::Empty)));
        }

        async fn block_left(&self, start: u64) {
            let left = ServerEvent::BlockLeft {
                file_hash: FILE,
                start,
                end: start + 4,
            };
            self.events.send(ServeInput::Server(left)).await.unwrap();
        }
    }

    /// `EMSocket.cpp:500-504`: control ahead of what is queued, here at the
    /// end of the one block on the wire and no block is cut for it.
    #[tokio::test]
    async fn a_status_passes_every_block_but_the_one_on_the_wire() {
        let mut bench = bench();
        bench.offer(block_at(0, 1));
        bench.offer(block_at(4, 1));
        bench.offer(block_at(8, 1));
        bench.next_block_starts(0).await;
        bench.offer(status());

        bench.next_is_status().await;
        bench.hands_nothing_more().await;

        bench.block_left(0).await;
        bench.next_block_starts(4).await;
        bench.hands_nothing_more().await;
        bench.block_left(4).await;
        bench.next_block_starts(8).await;
    }

    /// The session frames no block of a slot gone, so nothing says this one
    /// left; a later flow's blocks do not wait for that word.
    #[tokio::test]
    async fn a_block_the_session_dropped_holds_no_later_flow_back() {
        let mut bench = bench();
        bench.offer(block_at(0, 1));
        bench.next_block_starts(0).await;

        bench.link.end_flow(1);
        bench.offer(block_at(4, 2));

        bench.next_block_starts(4).await;
    }

    /// Its flow ended while it waited for the block on the wire.
    #[tokio::test]
    async fn the_block_in_hand_goes_no_further_when_its_flow_ends() {
        let mut bench = bench();
        bench.offer(block_at(0, 1));
        bench.offer(block_at(4, 1));
        bench.next_block_starts(0).await;
        bench.hands_nothing_more().await;

        bench.link.end_flow(1);
        bench.block_left(0).await;

        bench.hands_nothing_more().await;
    }
}
