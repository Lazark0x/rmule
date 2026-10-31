//! The **Source Discovery Engine** (`crates/rmule-core/CONTEXT.md`): the one
//! Core mechanism behind per-download source discovery, generic over a
//! [`DiscoveryChannel`] adapter. It owns an active-download registry (file
//! hash → size, sink and source count), a due-cadence sweep over the channel's
//! **Ask Clock** (first ask immediate, then per the clock, which outlives every
//! run; a file at the channel's source gate left out), answer routing to
//! the matching download's sink, and one RAII [`DiscoveryGuard`]. Two channels
//! run on it: the server-UDP global sweep (`global_sources`, ADR-0051) and the
//! Kad channel (`kad_sources`, ADR-0043).
//!
//! Distinct from **Source Discovery Policy**, the per-download *selection* of
//! channels; the engine is the shared mechanism they run on. Concerns that are
//! not discovery live elsewhere: the **Kad Publisher** is its own
//! registry-driven Core task (`kad_sources`). The engine has exactly two concerns — ask cadence and answer routing.

mod ask_clock;

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule_primitives::{FileHash, SourceLookupTarget};
use tokio::sync::mpsc;
use tokio::time::Instant;

pub(crate) use self::ask_clock::{AskClock, SharedAskClock};
use crate::server_pace::SourceCount;

/// One source-discovery channel behind the [`SourceDiscovery`] engine
/// (ADR-0051 / ADR-0043). The engine drives the ask cadence and answer
/// routing; the adapter owns the wire — batching, transport, projection.
pub(crate) trait DiscoveryChannel: Send + 'static {
    /// The payload routed to a download's sink. The global channel tags each
    /// batch with the answering source-server (`(Ipv4Endpoint, Vec<PeerSource>)`);
    /// the Kad channel carries the bare batch (`Vec<PeerSource>`).
    type Answer: Send;

    /// Ask the channel for sources for every `target` the engine deems due this
    /// sweep (the re-ask cadence is already applied). Called every sweep, so the
    /// slice may be empty when nothing is due; an adapter with no due target then
    /// does nothing (the global channel early-returns on an empty batch).
    fn ask(&self, targets: &[SourceLookupTarget]) -> impl Future<Output = ()> + Send;

    /// Whether an ask could reach anyone now. No ask is spent until it can:
    /// stock asks only while connected (`PartFile.cpp:1514`).
    fn ready(&self) -> bool {
        true
    }

    /// The next answered `(file hash, answer)`, or `None` once the channel has
    /// stopped (the engine then winds down).
    fn next_answer(&self) -> impl Future<Output = Option<(FileHash, Self::Answer)>> + Send;
}

/// A per-download sink the runner drains; routed answers for the download's
/// file land here, feeding `DownloadState::on_{global,kad}_sources`.
pub(crate) type DiscoverySink<A> = mpsc::Sender<A>;

/// One active download on a channel: what an ask names and where its answer
/// goes. The size rides along because a Kad source search carries it on the
/// wire, and the count because every ask reads the file's source gate.
pub(crate) struct Discoverable<A> {
    pub(crate) file_size: u64,
    pub(crate) sink: DiscoverySink<A>,
    pub(crate) sources: SourceCount,
}

/// The active-download table. Owned by the Core actor, registered/deregistered
/// by each download's runner, swept by the engine.
pub(crate) type DiscoveryRegistry<A> = Arc<Mutex<HashMap<FileHash, Discoverable<A>>>>;

/// The one Core-owned source-discovery task, generic over its channel adapter.
pub(crate) struct SourceDiscovery<C: DiscoveryChannel> {
    channel: C,
    registry: DiscoveryRegistry<C::Answer>,
    /// How often the engine sweeps the registry for due asks.
    sweep_interval: Duration,
    /// When each file may next be asked: every sweep for the global channel,
    /// whose pace is the Server Pace's (ADR-0051), `KADEMLIAREASKTIME × N` for
    /// Kad (ADR-0064).
    asks: SharedAskClock,
    /// A file holding this many sources is not asked for more on this channel.
    source_gate: u32,
}

impl<C: DiscoveryChannel> SourceDiscovery<C> {
    pub(crate) fn new(
        channel: C,
        registry: DiscoveryRegistry<C::Answer>,
        sweep_interval: Duration,
        asks: SharedAskClock,
        source_gate: u32,
    ) -> Self {
        Self {
            channel,
            registry,
            sweep_interval,
            asks,
            source_gate,
        }
    }

    pub(crate) async fn run(self) {
        let mut tick = tokio::time::interval(self.sweep_interval);
        loop {
            tokio::select! {
                _ = tick.tick() => self.sweep().await,
                answered = self.channel.next_answer() => match answered {
                    Some((file_hash, answer)) => self.route(file_hash, answer).await,
                    None => return, // the channel stopped
                },
            }
        }
    }

    /// One sweep: ask the channel for every registered download its clock
    /// says is due.
    async fn sweep(&self) {
        let mut due = Vec::new();
        if self.channel.ready() {
            let downloads: Vec<(FileHash, u64)> = self
                .registry
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, download)| download.sources.under(self.source_gate))
                .map(|(hash, download)| (*hash, download.file_size))
                .collect();
            let now = Instant::now();
            let mut asks = self.asks.lock().unwrap();
            for (file_hash, file_size) in downloads {
                if asks.take_ask(file_hash, now) {
                    due.push(SourceLookupTarget::new(file_hash, file_size));
                }
            }
        }
        self.channel.ask(&due).await;
    }

    /// Route one answer to the matching download's sink. A closed sink (the
    /// download exiting) is fine — the runner's deregistration races this send
    /// harmlessly.
    async fn route(&self, file_hash: FileHash, answer: C::Answer) {
        let sink = self
            .registry
            .lock()
            .unwrap()
            .get(&file_hash)
            .map(|download| download.sink.clone());
        if let Some(sink) = sink {
            let _ = sink.send(answer).await;
        }
    }
}

/// Removes this download's registry entry when the runner exits — on
/// completion, cancellation, or any `?`-propagated failure — so the engine
/// stops sweeping for a finished download. One guard for both channels.
pub(crate) struct DiscoveryGuard<A> {
    registry: DiscoveryRegistry<A>,
    file_hash: FileHash,
}

impl<A> Drop for DiscoveryGuard<A> {
    fn drop(&mut self) {
        self.registry
            .lock()
            .expect("source discovery registry")
            .remove(&self.file_hash);
    }
}

/// Register `file_hash`'s download and return the RAII guard that
/// deregisters it on drop — the runner's per-channel registration, one shape.
pub(crate) fn register<A>(
    registry: &DiscoveryRegistry<A>,
    file_hash: FileHash,
    file_size: u64,
    sink: DiscoverySink<A>,
    sources: SourceCount,
) -> DiscoveryGuard<A> {
    registry.lock().unwrap().insert(
        file_hash,
        Discoverable {
            file_size,
            sink,
            sources,
        },
    );
    DiscoveryGuard {
        registry: registry.clone(),
        file_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal channel that records every non-empty due batch and never
    /// answers — the engine drives the cadence, so the adapter contributes
    /// nothing but a record of what the engine asked for.
    struct RecordingChannel {
        asks_tx: mpsc::UnboundedSender<Vec<SourceLookupTarget>>,
    }

    fn recording_channel() -> (
        RecordingChannel,
        mpsc::UnboundedReceiver<Vec<SourceLookupTarget>>,
    ) {
        let (asks_tx, asks_rx) = mpsc::unbounded_channel();
        (RecordingChannel { asks_tx }, asks_rx)
    }

    impl DiscoveryChannel for RecordingChannel {
        type Answer = ();

        async fn ask(&self, targets: &[SourceLookupTarget]) {
            // The engine calls `ask` every sweep, empty when nothing is due;
            // record only the due batches so the cadence is what is asserted.
            if !targets.is_empty() {
                let _ = self.asks_tx.send(targets.to_vec());
            }
        }

        async fn next_answer(&self) -> Option<(FileHash, ())> {
            std::future::pending().await
        }
    }

    fn entry<A>(file_size: u64, sink: DiscoverySink<A>, sources: SourceCount) -> Discoverable<A> {
        Discoverable {
            file_size,
            sink,
            sources,
        }
    }

    fn registry_with(file_hash: FileHash, file_size: u64) -> DiscoveryRegistry<()> {
        let registry: DiscoveryRegistry<()> = Arc::new(Mutex::new(HashMap::new()));
        let (sink_tx, sink_rx) = mpsc::channel(1);
        // Leak the receiver so the registered sink stays open for the run.
        std::mem::forget(sink_rx);
        registry
            .lock()
            .unwrap()
            .insert(file_hash, entry(file_size, sink_tx, SourceCount::default()));
        registry
    }

    #[tokio::test]
    async fn first_ask_is_immediate_then_re_asks_only_after_the_interval() {
        let file_hash = FileHash::from_bytes([0x33; FileHash::BYTE_LEN]);
        let (channel, mut asks) = recording_channel();
        let registry = registry_with(file_hash, 4096);

        let task = tokio::spawn(
            SourceDiscovery::new(
                channel,
                registry,
                Duration::from_millis(10),
                AskClock::shared(Duration::from_millis(200)),
                u32::MAX,
            )
            .run(),
        );

        // First ask is immediate — no prior ask on record.
        let first = tokio::time::timeout(Duration::from_secs(2), asks.recv())
            .await
            .expect("a first ask within 2s")
            .expect("channel open");
        assert_eq!(first, vec![SourceLookupTarget::new(file_hash, 4096)]);

        // The sweeps in between (every 10ms) stay quiet: no re-ask before the
        // 200ms interval elapses.
        assert!(
            tokio::time::timeout(Duration::from_millis(80), asks.recv())
                .await
                .is_err(),
            "no re-ask before the interval"
        );

        // The re-ask lands once the interval has elapsed.
        let second = tokio::time::timeout(Duration::from_secs(2), asks.recv())
            .await
            .expect("a re-ask within 2s")
            .expect("channel open");
        assert_eq!(second, vec![SourceLookupTarget::new(file_hash, 4096)]);

        task.abort();
    }

    /// A pause, a cancel and a re-add all come here as a registry entry that
    /// went and came back, and a Kad restart as a second task on the same
    /// clock. None of them asks the storers again.
    #[tokio::test]
    async fn a_run_that_ends_and_returns_does_not_ask_again() {
        let file_hash = FileHash::from_bytes([0x66; FileHash::BYTE_LEN]);
        let (channel, mut asks) = recording_channel();
        let registry = registry_with(file_hash, 4096);
        let clock = AskClock::shared(Duration::from_secs(3600));

        let task = tokio::spawn(
            SourceDiscovery::new(
                channel,
                registry.clone(),
                Duration::from_millis(10),
                clock.clone(),
                u32::MAX,
            )
            .run(),
        );
        let first = tokio::time::timeout(Duration::from_secs(2), asks.recv())
            .await
            .expect("a first ask within 2s")
            .expect("channel open");
        assert_eq!(first, vec![SourceLookupTarget::new(file_hash, 4096)]);

        registry.lock().unwrap().remove(&file_hash);
        tokio::time::sleep(Duration::from_millis(40)).await;
        let (sink_tx, sink_rx) = mpsc::channel(1);
        std::mem::forget(sink_rx);
        registry
            .lock()
            .unwrap()
            .insert(file_hash, entry(4096, sink_tx, SourceCount::default()));
        task.abort();

        let (channel, mut asks) = recording_channel();
        let task = tokio::spawn(
            SourceDiscovery::new(channel, registry, Duration::from_millis(10), clock, u32::MAX).run(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), asks.recv())
                .await
                .is_err(),
            "the hour stands across the run and the task"
        );
        task.abort();
    }

    /// A channel that cannot reach anyone yet spends no ask.
    struct UnreadyChannel(
        RecordingChannel,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    );

    impl DiscoveryChannel for UnreadyChannel {
        type Answer = ();

        async fn ask(&self, targets: &[SourceLookupTarget]) {
            self.0.ask(targets).await;
        }

        fn ready(&self) -> bool {
            self.1.load(std::sync::atomic::Ordering::Relaxed)
        }

        async fn next_answer(&self) -> Option<(FileHash, ())> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn no_ask_is_spent_until_the_channel_can_reach_anyone() {
        let file_hash = FileHash::from_bytes([0x77; FileHash::BYTE_LEN]);
        let (channel, mut asks) = recording_channel();
        let ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task = tokio::spawn(
            SourceDiscovery::new(
                UnreadyChannel(channel, ready.clone()),
                registry_with(file_hash, 4096),
                Duration::from_millis(10),
                AskClock::shared(Duration::from_secs(3600)),
                u32::MAX,
            )
            .run(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(60), asks.recv())
                .await
                .is_err()
        );
        ready.store(true, std::sync::atomic::Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(2), asks.recv())
            .await
            .expect("the ask goes out once it can")
            .expect("channel open");
        task.abort();
    }

    /// A channel that only answers: it hands out whatever `answers` carries and
    /// asks nothing, so the engine's routing is the whole subject.
    struct AnsweringChannel {
        answers: tokio::sync::Mutex<mpsc::Receiver<(FileHash, u8)>>,
    }

    impl DiscoveryChannel for AnsweringChannel {
        type Answer = u8;

        async fn ask(&self, _targets: &[SourceLookupTarget]) {}

        async fn next_answer(&self) -> Option<(FileHash, u8)> {
            self.answers.lock().await.recv().await
        }
    }

    /// A late answer for a file no download wants any more resolves nowhere:
    /// the registry is the only table, so a retired download leaves nothing
    /// behind to route a straggler to, and the engine keeps serving the
    /// downloads that are still registered.
    #[tokio::test]
    async fn a_late_answer_for_a_file_no_download_wants_resolves_nowhere() {
        let wanted = FileHash::from_bytes([0x71; FileHash::BYTE_LEN]);
        let retired = FileHash::from_bytes([0x72; FileHash::BYTE_LEN]);
        let registry: DiscoveryRegistry<u8> = Arc::new(Mutex::new(HashMap::new()));
        let (sink_tx, mut sink_rx) = mpsc::channel(4);
        registry
            .lock()
            .unwrap()
            .insert(wanted, entry(4096, sink_tx, SourceCount::default()));

        let (answers_tx, answers_rx) = mpsc::channel(4);
        let task = tokio::spawn(
            SourceDiscovery::new(
                AnsweringChannel {
                    answers: tokio::sync::Mutex::new(answers_rx),
                },
                registry,
                Duration::from_secs(3600),
                AskClock::shared(Duration::from_secs(3600)),
                u32::MAX,
            )
            .run(),
        );

        answers_tx.send((retired, 1)).await.unwrap();
        answers_tx.send((wanted, 2)).await.unwrap();

        let routed = tokio::time::timeout(Duration::from_secs(2), sink_rx.recv())
            .await
            .expect("the wanted download is still served")
            .expect("sink open");
        assert_eq!(routed, 2, "the retired file's answer reached no sink");
        assert!(sink_rx.try_recv().is_err(), "nothing else was routed");

        task.abort();
    }

    /// A file at the channel's gate is left out of the sweep; one that falls
    /// under it is asked at the next, its re-ask clock untouched by the wait.
    #[tokio::test]
    async fn a_file_at_the_gate_waits_until_it_falls_under_it() {
        let file_hash = FileHash::from_bytes([0x44; FileHash::BYTE_LEN]);
        let (channel, mut asks) = recording_channel();
        let (sink, _kept_open) = mpsc::channel(1);
        let sources = SourceCount::default();
        sources.publish(100);
        let registry: DiscoveryRegistry<()> = Arc::new(Mutex::new(HashMap::new()));
        registry
            .lock()
            .unwrap()
            .insert(file_hash, entry(4096, sink, sources.clone()));

        let task = tokio::spawn(
            SourceDiscovery::new(
                channel,
                registry,
                Duration::from_millis(5),
                AskClock::shared(Duration::ZERO),
                100,
            )
            .run(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), asks.recv())
                .await
                .is_err(),
            "at the gate nothing is asked"
        );
        sources.publish(99);
        let asked = tokio::time::timeout(Duration::from_secs(2), asks.recv())
            .await
            .expect("asked once under the gate")
            .expect("channel open");
        assert_eq!(asked[0].file_hash(), file_hash);
        task.abort();
    }
}
