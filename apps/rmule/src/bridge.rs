//! The in-process `CoreClient` binding (ADR-0069): the bridge owns the sole
//! `Core` handle, drains the single-consumer event stream, polls
//! `diagnostics_snapshot()` on the 1 Hz data tick, synthesizes rates, and
//! feeds the single [`Action`] bus.
//!
//! Backpressure is coalescing (ADR-0069 §Dataflow): lifecycle *edges* await
//! bus capacity (they must not be lost — `UiState` folds them), byte *levels*
//! are dropped when the bus is full (the next tick supersedes them), and a
//! missed data tick is skipped, never replayed.
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
use rmule_core::{Core, CoreCommand, CoreError, CoreEvent};
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;

use crate::action::Action;
use crate::client::{CoreClient, CoreClientError};
use crate::rates::{RateSynthesizer, TransferRates};

/// The narrow core surface the bridge consumes. `Core` is the production
/// impl; tests drive a channel-backed fake (the repo's `ServerLink`/`FakeLink`
/// precedent), which is what keeps the bridge provable without a live core.
pub trait CoreHandle: Send + 'static {
    /// Queue one command for the core. An `Err` says the core is no longer
    /// there to take it, never that it refused the command — outcomes arrive
    /// as events.
    fn send(&self, command: CoreCommand) -> impl Future<Output = Result<(), CoreError>> + Send;
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
    fn quit(self) -> mpsc::Receiver<CoreEvent>;
}

impl CoreHandle for Core {
    async fn send(&self, command: CoreCommand) -> Result<(), CoreError> {
        Core::send(self, command).await
    }

    async fn next_event(&mut self) -> Option<CoreEvent> {
        Core::next_event(self).await
    }

    fn diagnostics_snapshot(&self) -> DiagnosticsSnapshot {
        Core::diagnostics_snapshot(self)
    }

    fn quit(self) -> mpsc::Receiver<CoreEvent> {
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
    /// UI→core command queue depth (mirrors the core's own bound).
    pub command_queue: usize,
    /// The Run Log's level, read at every line the bridge writes.
    pub run_log: rmule_core::run_log::LevelHandle,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: Duration::from_secs(1),
            ema_tau: Duration::from_secs(4),
            command_queue: 32,
            run_log: rmule_core::run_log::LevelHandle::default(),
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
/// stream to drain before giving up on the confirmation and
/// returning anyway — a stuck actor must not hang the TUI's
/// terminal. The command channel this closes first (`Core::quit`'s own
/// act, before any await) has already reached the actor by then, so
/// the flush itself still runs to completion in the actor's own task; only
/// this caller's *wait* for it is bounded. Same duration as the Kad Shutdown
/// Lever's grace: one wait's worth of patience, not two.
const CORE_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Told, not swallowed: the status-bar flash
/// [`run`]'s shutdown arm sends when [`CORE_SHUTDOWN_GRACE`] elapses before
/// quit's stream drained, so the terminal does not close on a silent `true`
/// when the credit flush's completion was never confirmed.
const SHUTDOWN_GRACE_ELAPSED_FLASH: crate::words::Sentence =
    crate::words::app::SHUTDOWN_GRACE_ELAPSED;

/// The UI-side handle the bridge returns: the in-process [`CoreClient`].
#[derive(Clone)]
pub struct BridgeHandle {
    cmd_tx: mpsc::Sender<CoreCommand>,
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
    async fn send(&self, command: CoreCommand) -> Result<(), CoreClientError> {
        self.cmd_tx
            .send(command)
            .await
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
    let (cmd_tx, cmd_rx) = mpsc::channel(config.command_queue);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(run(core, cmd_rx, shutdown_rx, actions, config));
    BridgeHandle {
        cmd_tx,
        shutdown: Arc::new(Mutex::new(Some(shutdown_tx))),
    }
}

async fn run<H: CoreHandle>(
    mut core: H,
    mut cmd_rx: mpsc::Receiver<CoreCommand>,
    mut shutdown_rx: oneshot::Receiver<ShutdownAck>,
    actions: mpsc::Sender<Action>,
    config: BridgeConfig,
) {
    let run_log = config.run_log.clone();
    let mut ticker = tokio::time::interval(config.snapshot_interval);
    // Latest-state-wins: a stalled tick is skipped, never burst-replayed.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut rates = RateSynthesizer::new(config.ema_tau);

    loop {
        tokio::select! {
            event = core.next_event() => match event {
                Some(event) => {
                    rmule_core::run_log::write(&event.record(), run_log.get());
                    // Edges must not be lost: await capacity instead of
                    // dropping. Err means the UI is gone — stop bridging.
                    if actions.send(Action::Core(event)).await.is_err() {
                        return;
                    }
                }
                None => {
                    // Core stopped. Announce and end; the dropped command
                    // receiver turns every later `CoreClient::send` into
                    // `CoreStopped`.
                    let _ = actions.send(Action::CoreClosed).await;
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
            command = cmd_rx.recv() => match command {
                Some(command) => {
                    if core.send(command).await.is_err() {
                        // Command channel to the core is gone; the event
                        // stream's `None` follows and announces the stop.
                        tracing::debug!("core command channel closed");
                    }
                }
                // Every BridgeHandle dropped: the UI is shutting down.
                None => return,
            },
            ack = &mut shutdown_rx => {
                // The graceful-shutdown door: honour at most
                // once — a second `graceful_shutdown` call never reaches
                // here, `BridgeHandle` already refused it.
                if let Ok(ack) = ack {
                    let drained = tokio::time::timeout(
                        CORE_SHUTDOWN_GRACE,
                        forward_quit(core.quit(), &actions, &run_log),
                    )
                    .await;
                    if drained.is_err() {
                        // The grace elapsed before quit's event stream ran to
                        // its end — the credit-checkpoint flush's completion
                        // was never observed here, though the actor's own
                        // task keeps running it to completion independently
                        // (CORE_SHUTDOWN_GRACE's doc). `graceful_shutdown`
                        // still answers `true`, so this is the caller's only
                        // way to learn the wait, not the flush, is what
                        // ended.
                        let _ = actions
                            .send(Action::Flash(SHUTDOWN_GRACE_ELAPSED_FLASH))
                            .await;
                    }
                    let _ = ack.send(());
                }
                return;
            }
        }
    }
}

/// Drain quit's event stream to its end — the flush — writing every fact to
/// the Run Log and forwarding it onto the bus, so the UI names each quit step
/// as the core runs it. A UI already gone stops the forwarding, never the
/// drain or the log.
async fn forward_quit(
    mut events: mpsc::Receiver<CoreEvent>,
    actions: &mpsc::Sender<Action>,
    run_log: &rmule_core::run_log::LevelHandle,
) {
    let mut forwarding = true;
    while let Some(event) = events.recv().await {
        rmule_core::run_log::write(&event.record(), run_log.get());
        if forwarding {
            forwarding = actions.send(Action::Core(event)).await.is_ok();
        }
    }
}

#[cfg(test)]
mod tests;
