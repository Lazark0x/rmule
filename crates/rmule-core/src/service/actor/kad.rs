//! The Kad command arm and the **Kad Activity**'s lifecycle (ADR-0093):
//! starting the node through the consumed-once factory and wiring the legs
//! that ride it — source discovery, the publisher, the ed2k→Kad handoff
//! forwarder and the keyword channel a search spawns against — into one
//! [`KadActivity`] the actor's ledger holds, and taking it back through one
//! [`retire_kad`](CoreActor::retire_kad) whichever way it ends: `DisableKad`,
//! the pump's own death, or quit.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;

use crate::adapters::{
    KadEnableConfig, KadRuntimeFactory, KadShutdownHandle, KadShutdownSlot, PeerTransferService,
    ServeRuntimeService, SourceLookupService,
};
use crate::kad_sources::{KadDiscoveryChannel, KadPublisher};
use crate::reachability::KadRunLease;
use crate::service::{CoreCommandRejectReason, CoreEvent, KadStopReason, KadUnavailableReason};
use crate::source_discovery::SourceDiscovery;

use super::{CoreActor, send_event};

/// The running **Kad Activity** (ADR-0093): everything `EnableKad` took, held
/// as one ledger value so "Kad is running" is its presence and its retire
/// returns the whole set — the discovery pump and its watchdog, the
/// publisher and its share-changed trigger, the ed2k→Kad handoff forwarder,
/// the keyword-search channel, the node id the diagnostics row names, the
/// handle to its one stop lever (and, when a caller supplied a lever of its
/// own, the bridge that turns that lever into a call of this activity's stop),
/// and the one lease on the Kad half of Self Reach
/// — Kad Presence and the verdicts — that every "is Kad running" reader reads.
pub(super) struct KadActivity<C> {
    /// Which start this is: the value the pump's end bumps `kad_ended` to,
    /// so a bump for an activity already retired never retires its successor.
    generation: u64,
    node_id: crate::KadId,
    search_channel: Arc<C>,
    publish_changed_tx: mpsc::Sender<()>,
    pump: tokio::task::JoinHandle<()>,
    watchdog: tokio::task::JoinHandle<()>,
    publisher: tokio::task::JoinHandle<()>,
    handoff: Option<tokio::task::JoinHandle<()>>,
    /// The activity's own lever — always installed, taken by the one stop.
    shutdown: Option<KadShutdownHandle>,
    /// A caller-supplied lever (the `ed2k serve start --kad` tap-finalize path), made a caller of
    /// this activity's stop: the bridge task that turns its
    /// request into a stop, and the confirmation the retire fires once the
    /// pump ended clean.
    external: Option<ExternalLever>,
    /// Held from start to retire: its drop is "no node, nothing proven" for
    /// every reader at once (ADR-0093).
    lease: KadRunLease,
}

/// A caller's own stop lever over the activity: the task waiting
/// on its request, and the confirmation it is owed.
struct ExternalLever {
    bridge: tokio::task::JoinHandle<()>,
    stopped: tokio::sync::oneshot::Sender<()>,
}

impl<C> KadActivity<C> {
    /// The running node's own Kad ID, for the diagnostics row.
    pub(super) fn node_id(&self) -> crate::KadId {
        self.node_id
    }

    /// The node's channel, for a `StartSearch`'s keyword requester (ADR-0062).
    pub(super) fn search_channel(&self) -> &Arc<C> {
        &self.search_channel
    }

    /// Nudge the **Kad Publisher** to re-sweep the share set.
    pub(super) fn share_changed(&self) {
        let _ = self.publish_changed_tx.try_send(());
    }

    /// How many of this activity's long-lived tasks it holds,
    /// reported as `kad_tasks_live`: the pump, the publisher and, when the
    /// factory spawned one, the handoff forwarder. `0` is the retired state —
    /// no activity at all.
    pub(super) fn tasks_live(&self) -> usize {
        2 + usize::from(self.handoff.is_some())
    }
}

/// How long [`CoreActor::on_disable_kad`] waits for the lever's confirmation
/// before aborting the pump's wrapper instead, and the bound each of
/// [`CoreActor::retire_kad`]'s pump/publisher/forwarder joins each get —
/// a clean stop is a couple of small writes at most (`ed2k serve start --kad`'s own
/// grace is 10s for the same shape; this is tighter because nothing here is
/// racing a process exit, only keeping the actor's single command loop
/// responsive).
const KAD_DISABLE_GRACE: Duration = Duration::from_secs(5);

/// Join a task within [`KAD_DISABLE_GRACE`], aborting it if it has not
/// finished by then. `None` (nothing to join) returns at once.
async fn join_bounded(handle: Option<tokio::task::JoinHandle<()>>) {
    let Some(handle) = handle else { return };
    let abort = handle.abort_handle();
    if tokio::time::timeout(KAD_DISABLE_GRACE, handle)
        .await
        .is_err()
    {
        abort.abort();
    }
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Start the Kad node and wire the legs that ride it (ADR-0043).
    pub(super) async fn on_enable_kad(&mut self, mut kad_config: KadEnableConfig) {
        if self.kad.is_some() {
            // Already running; ignore the duplicate request
            // (the StartServing precedent).
            return;
        }
        // The sockets are unified (ADR-0057): Kad rides the one client-UDP
        // bind, so a socket that never came up is a Kad node that cannot
        // start. Rejected exactly like a factory failure — the same event, the
        // same session-keeps-running posture — but naming the cause:
        // the diagnostics row the bind site seeded is read back here
        // rather than re-derived, so the rejection can never disagree with
        // what a `DiagnosticsSnapshot` already says.
        let Some(bind) = self.client_udp_bind.clone() else {
            let reason = match self.diagnostics.client_udp_bind_failure() {
                Some(failure) => KadUnavailableReason::UdpUnbound {
                    port: failure.port,
                    kind: failure.kind,
                },
                // Defensive: the actor always records the failure before
                // leaving `client_udp_bind` empty (ADR-0057) — reaching this
                // would mean the two facts had drifted apart.
                None => KadUnavailableReason::StartFailed,
            };
            tracing::warn!("kad cannot start: the client-UDP socket it shares never bound");
            send_event(
                &self.evt_tx,
                CoreEvent::CommandRejected {
                    reason: CoreCommandRejectReason::KadUnavailable(reason),
                },
            )
            .await;
            return;
        };
        // The pair came up — but Kad rides its IPv4 half and no other
        // (ADR-0087), so a pair that came up on `::` alone is a Kad node with
        // no transport. Refused with the missing family named,
        // read from the same bind-table fact a `DiagnosticsSnapshot` reports,
        // so the rejection and the row can never disagree.
        if let Some(half_bound) = self
            .diagnostics
            .half_bound(crate::address_learning::SocketRole::Udp)
            && half_bound.forfeited(rmule_net::family::Consequence::Kad)
        {
            tracing::warn!(
                %half_bound,
                "kad cannot start: the client-UDP pair it shares holds no IPv4 socket"
            );
            send_event(
                &self.evt_tx,
                CoreEvent::CommandRejected {
                    reason: CoreCommandRejectReason::KadUnavailable(
                        KadUnavailableReason::UdpFamilyMissing {
                            family: half_bound.missing,
                            kind: half_bound.kind,
                        },
                    ),
                },
            )
            .await;
            return;
        }
        // One lever: the activity always wires its own
        // into the pump, so `DisableKad` and quit always reach it. A caller
        // that supplied a lever (the raw `ed2k serve start --kad` tap-finalize path) keeps its
        // handle, but that lever becomes a caller of this activity's stop —
        // its request asks the ledger to stop the activity, and its
        // confirmation is fired by the retire once the pump ended clean.
        let external = kad_config.kad_shutdown.take().and_then(|slot| slot.take());
        let (slot, shutdown) = KadShutdownSlot::new();
        kad_config.kad_shutdown = Some(slot);
        let kad_udp_port = bind.udp_port();
        // The one lease on the Kad half of Self Reach: taken
        // before the node starts so the verdicts it publishes land on a fresh
        // cell, and handed to the ledger value — a failed start drops it.
        let lease = self.self_reach.lease_kad(kad_config.kad_id);
        match self.wiring.kad_factory.start(&kad_config, bind).await {
            Ok(channel) => {
                // One node, two drivers: the discovery engine
                // (search + receive) and the **Kad Publisher**
                // (publish) share it through an `Arc`.
                let channel = Arc::new(channel);
                // The Kad Publisher is registry-driven, so it runs
                // even with zero active downloads; a share/unshare
                // nudges it to re-sweep (the serve-announce pattern).
                let (share_changed_tx, share_changed_rx) = mpsc::channel(8);
                let publisher = tokio::spawn(
                    KadPublisher::new(
                        Arc::clone(&channel),
                        Arc::clone(&self.wiring.registry),
                        self.registry_check.withheld.clone(),
                        share_changed_rx,
                    )
                    .run(),
                );
                // Whatever handoff forwarder this factory spawned
                // alongside the node (only `RuntimeKadFactory` does; every
                // test fake's default answers `None`) — tracked so
                // `DisableKad`'s reaper can join it back too.
                let handoff = self.wiring.kad_factory.take_handoff_handle();
                // Retain a clone for the ADR-0062 keyword
                // requester before the discovery engine takes the
                // last one.
                let search_channel = Arc::clone(&channel);
                // The discovery task's own exit is the one signal
                // that the pump behind it ended — its `next_answer()` returns
                // `None` only once the deep node dropped the sources channel,
                // whatever ended the node. The bump names this activity's
                // generation and wakes `on_kad_ended`; the `JoinHandle` is what
                // `retire_kad` reads for the reason (the serve activity's pattern).
                self.activity_generation += 1;
                let generation = self.activity_generation;
                let ended = Arc::clone(&self.kad_ended_tx);
                let discovery = SourceDiscovery::new(
                    KadDiscoveryChannel::new(channel),
                    self.kad_source_registry.clone(),
                    self.wiring.config.kad_sweep_interval,
                    self.wiring.config.kad_reask_interval,
                );
                let pump_handle = tokio::spawn(async move {
                    discovery.run().await;
                    ended.send_replace(generation);
                });
                // The bump above is cooperative code inside the
                // task it is meant to report on — an abort or a panic
                // mid-`await` never reaches it, so the watch would otherwise
                // sleep forever over a dead pump. This is the reaper's
                // second wake source: it polls the same handle's
                // `AbortHandle` (the `SharedServeListener` shape) and
                // bumps the identical watch once it reads finished, whatever
                // the cause. A second bump for one generation finds it
                // already retired, so `on_kad_ended` does nothing.
                let watchdog = tokio::spawn(watch_pump_task(
                    pump_handle.abort_handle(),
                    Arc::clone(&self.kad_ended_tx),
                    generation,
                ));
                // The caller's lever asks the ledger for this generation's
                // stop through the same watch a death bumps.
                let external = external.map(|(requested, stopped)| {
                    let stop = Arc::clone(&self.kad_ended_tx);
                    ExternalLever {
                        bridge: tokio::spawn(async move {
                            if requested.await.is_ok() {
                                stop.send_replace(generation);
                            }
                        }),
                        stopped,
                    }
                });
                self.diagnostics
                    .set_kad_state(crate::diagnostics::KadState::Running);
                self.kad = Some(KadActivity {
                    generation,
                    node_id: kad_config.kad_id,
                    search_channel,
                    publish_changed_tx: share_changed_tx,
                    pump: pump_handle,
                    watchdog,
                    publisher,
                    handoff,
                    shutdown: Some(shutdown),
                    external,
                    lease,
                });
                // Honest Capability Advertisement (ADR-0047/0057): a Kad node is
                // running now, so every hello may say which port it is on —
                // aMule's `Kademlia::IsRunning() ? kadPort : 0`. That port is
                // the client-UDP one, because they are one socket, and it is
                // the *internal* number: the tag carries a port, and which
                // address peers reach it at is Address Learning's answer.
                self.wiring.udp_ports_advert.set_kad(kad_udp_port);
                // The searches whose Kad leg waited send it now.
                self.start_waiting_kad_legs().await;
                // No bind is announced here and none was recorded inside
                // `start` (ADR-0086): the node took no socket, so the one UDP
                // mapping the **Desired Mapping Set** wants was already
                // derived when the client-UDP socket bound at core start.
            }
            Err(error) => {
                tracing::warn!(%error, "kad source discovery unavailable");
                send_event(
                    &self.evt_tx,
                    CoreEvent::CommandRejected {
                        reason: CoreCommandRejectReason::KadUnavailable(
                            KadUnavailableReason::StartFailed,
                        ),
                    },
                )
                .await;
            }
        }
    }

    /// `DisableKad`: stop the running activity through its one
    /// lever — whether or not a caller also holds a lever over it.
    pub(super) async fn on_disable_kad(&mut self) {
        self.stop_kad_for(true).await;
    }

    /// Stop the Kad activity (ADR-0093): fire its own lever and wait
    /// [`KAD_DISABLE_GRACE`] for the pump's clean-stop confirmation, aborting
    /// the pump's wrapper when it does not land, then
    /// [`retire_kad`](Self::retire_kad). A pump already gone answers at once.
    pub(super) async fn stop_kad(&mut self) {
        self.stop_kad_for(false).await;
    }

    /// [`stop_kad`](Self::stop_kad), `by_operator` when the operator's
    /// `DisableKad` asked for it: a clean end then reads
    /// [`KadStopReason::Stopped`].
    async fn stop_kad_for(&mut self, by_operator: bool) {
        let Some(kad) = self.kad.as_mut() else {
            return;
        };
        self.diagnostics
            .set_kad_state(crate::diagnostics::KadState::Stopping);
        let confirmed = match kad.shutdown.take() {
            Some(shutdown) => shutdown.request_and_wait(KAD_DISABLE_GRACE).await,
            None => false,
        };
        if !confirmed {
            kad.pump.abort();
        }
        self.retire_kad(by_operator).await;
    }

    /// Activity `generation` is to end: its pump ended on its own
    /// — returned, panicked or aborted (the watchdog) — or a
    /// caller's own lever asked for its stop. Either way it goes
    /// through the one [`stop_kad`](Self::stop_kad), whose lever a dead pump
    /// answers at once. A bump for an activity already retired names a
    /// generation the ledger no longer holds and stops nothing, so it can
    /// never take a successor's live pump.
    pub(super) async fn on_kad_ended(&mut self, generation: u64) {
        if self
            .kad
            .as_ref()
            .is_some_and(|kad| kad.generation == generation)
        {
            self.stop_kad().await;
        }
    }

    /// Retire the Kad activity (ADR-0093) — the one place its resources come
    /// back, whatever ended it: its Self Reach lease dropped before anything
    /// else, so every reader — Kad Presence, the verdicts, a download's
    /// liveness — reads the node gone at once and none sees a running node
    /// that is being torn down; the advert's Kad
    /// half cleared (aMule `BaseClient.cpp:1470-1481`); the
    /// publisher's trigger and the search channel dropped; the pump joined for
    /// the reason (the serve activity's split), its watchdog stopped, and the publisher and
    /// the handoff forwarder joined within [`KAD_DISABLE_GRACE`] each.
    /// A later `EnableKad` starts every one of them clean.
    async fn retire_kad(&mut self, by_operator: bool) {
        let Some(kad) = self.kad.take() else {
            return;
        };
        let KadActivity {
            pump,
            watchdog,
            publisher,
            handoff,
            publish_changed_tx,
            search_channel,
            lease,
            external,
            ..
        } = kad;
        drop(lease);
        self.wiring.udp_ports_advert.clear_kad();
        drop(publish_changed_tx);
        drop(search_channel);
        let pump_abort = pump.abort_handle();
        let reason = match tokio::time::timeout(KAD_DISABLE_GRACE, pump).await {
            Ok(Ok(())) => KadStopReason::Ended,
            Ok(Err(error)) => {
                // `JoinError` is a panic or an abort; logged so a
                // `TaskFailed` triage need not guess between them.
                tracing::error!(
                    %error,
                    panicked = error.is_panic(),
                    "the Kad activity's pump task ended abnormally"
                );
                KadStopReason::TaskFailed
            }
            Err(_) => {
                pump_abort.abort();
                KadStopReason::TaskFailed
            }
        };
        watchdog.abort();
        join_bounded(Some(publisher)).await;
        join_bounded(handoff).await;
        // A caller's lever is owed its confirmation only for a clean end —
        // the pump returned, so its ADR-0022 tap is finalized.
        if let Some(external) = external {
            external.bridge.abort();
            if matches!(reason, KadStopReason::Ended) {
                let _ = external.stopped.send(());
            }
        }
        let reason = match reason {
            KadStopReason::Ended if by_operator => KadStopReason::Stopped,
            other => other,
        };
        self.diagnostics
            .set_kad_state(crate::diagnostics::KadState::Off);
        send_event(&self.evt_tx, CoreEvent::KadStopped { reason }).await;
    }
}

/// How often [`watch_pump_task`] polls — cheap enough to hold open for a
/// whole Kad activity's life without being a cost worth naming in
/// `CoreConfig`.
const KAD_PUMP_WATCHDOG_INTERVAL: Duration = Duration::from_millis(200);

/// The reaper's second wake source: the discovery task's own
/// `kad_ended` bump is cooperative code at the bottom of its loop, so an
/// abort or a panic mid-`await` skips it entirely. This polls the same
/// task's `AbortHandle::is_finished` — true the instant the task resolves,
/// whether it returned, panicked, or was aborted (the `SharedServeListener` reading)
/// — and bumps the identical watch once it does, then
/// returns. A bump the cooperative path already sent names a generation
/// the ledger no longer holds, so it costs nothing; this task never runs
/// twice for one pump, because it returns after its one bump, and a retire
/// aborts it.
async fn watch_pump_task(
    abort_handle: AbortHandle,
    ended: Arc<watch::Sender<u64>>,
    generation: u64,
) {
    let mut tick = tokio::time::interval(KAD_PUMP_WATCHDOG_INTERVAL);
    loop {
        tick.tick().await;
        if abort_handle.is_finished() {
            ended.send_replace(generation);
            return;
        }
    }
}

#[cfg(test)]
mod tests;
