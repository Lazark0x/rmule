//! The in-process `CoreClient` binding (ADR-0069): the bridge owns the sole
//! `Core` handle, drains the single-consumer event stream, polls
//! `diagnostics_snapshot()` on the 1 Hz data tick, synthesizes rates, and
//! feeds the single [`Action`] bus.
//!
//! Two tasks (ADR-0069, "The bridge is two tasks"), so neither wait holds the
//! other: `forward_commands` may wait for the inbox's room, and `run` may
//! wait for the bus. `run`'s lifecycle *edges* await bus capacity (`UiState`
//! folds them), its byte *levels* are dropped when the bus is full (the next
//! tick supersedes them), and a missed data tick is skipped, never replayed.
//! Core waits for neither: what the bus has no room for stays in the core's
//! Outbox.
//!
//! # The graceful-shutdown door
//!
//! [`BridgeHandle::graceful_shutdown`] is the bridge's one way to hand its
//! owned `Core` through [`Core::quit`] — every activity's stop, then the
//! persistence flush, each quit step forwarded onto the bus as the core
//! announces it — the task
//! the run loop's ordinary command door cannot do, since forwarding a
//! [`CoreCommand`] never gives up ownership of the core it was sent to.
//! Firing it is idempotent across `BridgeHandle` clones (only the first
//! caller's request is honoured) and bounded by `CORE_SHUTDOWN_GRACE`, so
//! a core that never finishes draining still lets the caller's `.await`
//! return.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmule_core::diagnostics::DiagnosticsSnapshot;
use rmule_core::{CommandSender, Core, CoreCommand, CoreError, CoreEvent, EventStream, LongTask};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::action::Action;
use crate::client::{CoreClient, CoreClientError};
use crate::rates::{RateSynthesizer, TransferRates};

/// The narrow core surface the bridge consumes. `Core` is the production
/// impl; tests drive a channel-backed fake (the repo's `ServerLink`/`FakeLink`
/// precedent), which is what keeps the bridge provable without a live core.
pub trait CoreHandle: Send + 'static {
    /// The door [`CoreHandle::door`] hands out.
    type Door: CommandDoor;
    /// The stream [`CoreHandle::quit`] hands back.
    type QuitEvents: QuitEvents;
    /// The door the command forwarder keeps. It does not keep the core open,
    /// so [`CoreHandle::quit`] alone decides when the core stops.
    fn door(&self) -> Self::Door;
    /// Await the next core event. Single-consumer: the bridge is the only
    /// caller, and `None` is core's end, not an idle moment.
    fn next_event(&mut self) -> impl Future<Output = Option<CoreEvent>> + Send;
    /// Levels as of now. Polled on the data tick rather than pushed, which is
    /// what keeps a burst of byte counters off the event stream.
    fn diagnostics_snapshot(&self) -> DiagnosticsSnapshot;
    /// Consume the handle and begin its **Quit**: for
    /// the real `Core`, `Core::quit()` — the rest of the event stream, which
    /// names each quit step as it runs and ends once the persistence flush
    /// (the credit-checkpoint write) has happened.
    fn quit(self) -> Self::QuitEvents;
}

/// The forwarder's side of the core.
pub trait CommandDoor: Send + 'static {
    /// Queue one command for the core. An `Err` says the core is no longer
    /// there to take it, never that it refused the command — outcomes arrive
    /// as events.
    fn send(&self, command: CoreCommand) -> impl Future<Output = Result<(), CoreError>> + Send;
}

impl CommandDoor for CommandSender {
    async fn send(&self, command: CoreCommand) -> Result<(), CoreError> {
        CommandSender::send(self, command).await
    }
}

/// The rest of the event stream once quit has begun.
pub trait QuitEvents: Send {
    /// The next event; `None` is quit's completion.
    fn next(&mut self) -> impl Future<Output = Option<CoreEvent>> + Send;
}

impl QuitEvents for EventStream {
    async fn next(&mut self) -> Option<CoreEvent> {
        self.recv().await
    }
}

/// A test's fake core hands back a plain channel.
#[cfg(test)]
impl QuitEvents for mpsc::Receiver<CoreEvent> {
    async fn next(&mut self) -> Option<CoreEvent> {
        self.recv().await
    }
}

impl CoreHandle for Core {
    type Door = CommandSender;
    type QuitEvents = EventStream;

    fn door(&self) -> CommandSender {
        self.command_sender()
    }

    async fn next_event(&mut self) -> Option<CoreEvent> {
        Core::next_event(self).await
    }

    fn diagnostics_snapshot(&self) -> DiagnosticsSnapshot {
        Core::diagnostics_snapshot(self)
    }

    fn quit(self) -> EventStream {
        Core::quit(self)
    }
}

/// Tunables, spec-default (`tui-v1-spec` §2 / ADR-0069 §Dataflow).
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    /// Data-tick period for `diagnostics_snapshot()` polling.
    pub snapshot_interval: Duration,
    /// EMA time constant for rate synthesis (spec band 3–5 s).
    pub ema_tau: Duration,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: Duration::from_secs(1),
            ema_tau: Duration::from_secs(4),
        }
    }
}

/// Levels + synthesized rates served on one data tick.
#[derive(Clone, Debug)]
pub struct BridgeSnapshot {
    /// Core's own levels, as of `taken_at`.
    pub diagnostics: DiagnosticsSnapshot,
    /// Rates derived here from consecutive snapshots — core reports none.
    pub rates: TransferRates,
    /// Bridge-stamped observation instant (also the EMA sample time).
    pub taken_at: Instant,
}

/// The reply door the graceful-shutdown request carries: the run loop sends
/// on it once `Core::quit()`'s stream (or its bound) has settled.
type ShutdownAck = oneshot::Sender<()>;

/// How long [`BridgeHandle::graceful_shutdown`] waits for `Core::quit()`'s
/// stream to drain before giving up and returning anyway — a stuck actor must
/// not hang the TUI's terminal. It covers the sum of quit's own bounds, 33 s
/// with nothing wedged (ADR-0118), so only a wedged quit reaches it. Past it
/// the run ends and the runtime takes the actor with it: quit's opening credit
/// flush has already landed by then, and its closing one is what is lost.
const CORE_SHUTDOWN_GRACE: Duration = Duration::from_secs(45);

/// Told, not swallowed: the status-bar flash
/// [`run`]'s shutdown arm sends when [`CORE_SHUTDOWN_GRACE`] elapses before
/// quit's stream drained, so the terminal does not close on a silent `true`
/// when the credit flush's completion was never confirmed.
const SHUTDOWN_GRACE_ELAPSED_FLASH: crate::words::Sentence =
    crate::words::app::SHUTDOWN_GRACE_ELAPSED;

/// The UI-side handle the bridge returns: the in-process [`CoreClient`].
#[derive(Clone)]
pub struct BridgeHandle {
    cmd_tx: mpsc::UnboundedSender<CoreCommand>,
    /// The one-shot graceful-shutdown door, shared across
    /// clones so only the first caller's request is honoured; a second call
    /// (or one after the bridge task already ended on its own) finds it
    /// empty and answers `false` at once.
    shutdown: Arc<Mutex<Option<oneshot::Sender<ShutdownAck>>>>,
}

impl std::fmt::Debug for BridgeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeHandle").finish_non_exhaustive()
    }
}

impl CoreClient for BridgeHandle {
    fn send(&self, command: CoreCommand) -> Result<(), CoreClientError> {
        self.cmd_tx
            .send(command)
            .map_err(|_| CoreClientError::CoreStopped)
    }
}

impl BridgeHandle {
    /// Fire the bridge's one graceful-shutdown door: hand the
    /// task its owned `Core` through `Core::quit()`'s persistence flush,
    /// bounded by `CORE_SHUTDOWN_GRACE`. `true` once the bridge task has
    /// answered (quit ran, whether or not the flush was fully observed
    /// inside the grace — a grace-elapsed run sends
    /// [`Action::Flash`] on the action bus
    /// before answering, so the caller is not left thinking the flush
    /// confirmed when it did not); `false` if this door was already used —
    /// by this clone or another — or the bridge task had already ended on
    /// its own.
    pub async fn graceful_shutdown(&self) -> bool {
        let request = self.shutdown.lock().expect("shutdown mutex").take();
        let Some(request) = request else {
            return false;
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if request.send(ack_tx).is_err() {
            return false;
        }
        ack_rx.await.is_ok()
    }
}

/// Spawn the bridge task over `core`, feeding `actions`. Returns the command
/// door UI code keeps; the task ends when the core's event stream ends (after
/// emitting [`Action::CoreClosed`]), when the UI side goes away, or once
/// [`BridgeHandle::graceful_shutdown`] has run `core`'s shutdown.
pub fn spawn<H: CoreHandle>(
    core: H,
    actions: mpsc::Sender<Action>,
    config: BridgeConfig,
) -> BridgeHandle {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let forwarder = tokio::spawn(forward_commands(core.door(), cmd_rx));
    let closed = actions.clone();
    let bridge = tokio::spawn(run(core, forwarder, shutdown_rx, actions, config));
    // A panic here would end the bridge with nothing said, and the UI would
    // go on showing a live core (ADR-0118).
    tokio::spawn(async move {
        if bridge.await.is_err() {
            let _ = closed.send(Action::CoreClosed).await;
        }
    });
    BridgeHandle {
        cmd_tx,
        shutdown: Arc::new(Mutex::new(Some(shutdown_tx))),
    }
}

/// How the command forwarder ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Forwarded {
    /// Every [`BridgeHandle`] dropped: the UI is shutting down.
    UiGone,
    /// The core stopped; the event stream's `None` follows and announces it.
    CoreGone,
}

/// Hand each command to the core in order, waiting for the inbox's room here
/// and nowhere the event path or the UI could feel it. The core's end drops
/// `commands`, which turns every later `CoreClient::send` into `CoreStopped`.
async fn forward_commands<D: CommandDoor>(
    door: D,
    mut commands: mpsc::UnboundedReceiver<CoreCommand>,
) -> Forwarded {
    while let Some(command) = commands.recv().await {
        if door.send(command).await.is_err() {
            return Forwarded::CoreGone;
        }
    }
    Forwarded::UiGone
}

async fn run<H: CoreHandle>(
    mut core: H,
    mut forwarder: JoinHandle<Forwarded>,
    mut shutdown_rx: oneshot::Receiver<ShutdownAck>,
    actions: mpsc::Sender<Action>,
    config: BridgeConfig,
) {
    let mut forwarding = true;
    let mut ticker = tokio::time::interval(config.snapshot_interval);
    // Latest-state-wins: a stalled tick is skipped, never burst-replayed.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut rates = RateSynthesizer::new(config.ema_tau);

    loop {
        tokio::select! {
            event = core.next_event() => match event {
                Some(event) => {
                    // The actor's panic is the core's end, though the tasks
                    // it left go on holding the event stream open.
                    let core_died = matches!(
                        event,
                        CoreEvent::TaskDied { task: LongTask::Core }
                    );
                    // Edges must not be lost: await capacity instead of
                    // dropping. Err means the UI is gone — stop bridging.
                    if actions.send(Action::Core(event)).await.is_err() {
                        return;
                    }
                    if core_died {
                        announce_core_closed(&mut forwarder, forwarding, &actions).await;
                        return;
                    }
                }
                None => {
                    announce_core_closed(&mut forwarder, forwarding, &actions).await;
                    return;
                }
            },
            _ = ticker.tick() => {
                let taken_at = Instant::now();
                let diagnostics = core.diagnostics_snapshot();
                let synthesized = rates.observe(&diagnostics, taken_at);
                // Levels are droppable: the next tick supersedes this one.
                let _ = actions.try_send(Action::Snapshot(BridgeSnapshot {
                    diagnostics,
                    rates: synthesized,
                    taken_at,
                }));
            }
            ended = &mut forwarder, if forwarding => {
                forwarding = false;
                if !matches!(ended, Ok(Forwarded::CoreGone)) {
                    return;
                }
                tracing::debug!("core command channel closed");
            }
            ack = &mut shutdown_rx => {
                // The graceful-shutdown door: honour at most
                // once — a second `graceful_shutdown` call never reaches
                // here, `BridgeHandle` already refused it.
                if let Ok(ack) = ack {
                    let drained = tokio::time::timeout(
                        CORE_SHUTDOWN_GRACE,
                        forward_quit(core.quit(), &actions),
                    )
                    .await;
                    if drained.is_err() {
                        // The grace elapsed before quit's event stream ran to
                        // its end, so its closing flush was never observed
                        // and the runtime's end will cancel it
                        // (CORE_SHUTDOWN_GRACE's doc). `graceful_shutdown`
                        // still answers `true`, so this is the caller's only
                        // way to learn quit did not finish.
                        let _ = actions
                            .send(Action::Flash(SHUTDOWN_GRACE_ELAPSED_FLASH))
                            .await;
                    }
                    let _ = ack.send(());
                }
                // Nothing forwards past quit: a later `CoreClient::send` is
                // `CoreStopped`.
                forwarder.abort();
                return;
            }
        }
    }
}

/// The core stopped: say so and end, ending the forwarder with it so a later
/// `CoreClient::send` is `CoreStopped` even with no command in flight.
async fn announce_core_closed(
    forwarder: &mut JoinHandle<Forwarded>,
    forwarding: bool,
    actions: &mpsc::Sender<Action>,
) {
    if forwarding {
        forwarder.abort();
        let _ = forwarder.await;
    }
    let _ = actions.send(Action::CoreClosed).await;
}

/// Drain quit's event stream to its end — the flush — forwarding each fact
/// onto the bus, so the UI names each quit step as the core runs it. A UI
/// already gone stops the forwarding, never the drain.
async fn forward_quit(mut events: impl QuitEvents, actions: &mpsc::Sender<Action>) {
    let mut forwarding = true;
    while let Some(event) = events.next().await {
        if forwarding {
            forwarding = actions.send(Action::Core(event)).await.is_ok();
        }
    }
}

#[cfg(test)]
mod tests;
