//! The Kad pump's driver: the one task that drains the node's events and
//! carries out what the **Kad Pump State** decides, until Kad stops.
//!
//! The driver decides nothing. Every core command, node event, recruit tick,
//! source move and wake for room in the node's inbox becomes an input to the
//! brain, read with the instant it happened;
//! every effect the brain returns is carried out in order, and the answer to
//! an effect that has one — a node command's delivery, an Address Learning
//! write, the open-node buddy service's accept — goes straight back in before the next
//! effect, so the brain always reasons over what the world now holds. The one
//! answer that comes later is the Firewalled Front's verdict on a buddy this
//! pump asked it to adopt, which arrives from the front's own task.
//!
//! It never waits for room in the node's inbox while it holds the loop: a
//! command the full inbox turned away goes back to the brain, the brain holds
//! the core's further commands in their own bounded channel, and the driver
//! waits for room beside the node's events (`pump_state/asks.rs`).

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::time::Instant;

use tokio::sync::{mpsc, oneshot};

use crate::adapters::kad_runtime::KadPumpCommand;
use crate::adapters::kad_runtime::pump_state::{KadPumpInput, KadPumpState};
use crate::mailbox::Lease;
use crate::search::{KadKeywordEnd, KadWalkFact};

mod buddy_service;
mod dial_back;
mod enact;

pub(super) use buddy_service::BuddyService;
pub(super) use dial_back::DialBack;
pub(super) use enact::Enactor;

/// How often the pump re-samples its sources for the ADR-0061 recruit
/// trigger and the levels no write announces. The trigger paces itself at
/// twenty minutes; this only bounds how long a node that just became eligible
/// (a UDP verdict settling firewalled, a recheck guard elapsing, a buddy
/// lost) waits to notice, and how long a freshness window that lapsed with
/// nobody writing stays in the node's caches.
const RECRUIT_TICK: std::time::Duration = std::time::Duration::from_secs(30);

/// Everything the pump task owns, handed over by `start` once the node is up.
pub(super) struct Pump {
    pub(super) handle: rmule_net::kad::KadNetHandle,
    pub(super) state: KadPumpState,
    pub(super) enactor: Enactor,
    pub(super) commands_rx: mpsc::Receiver<KadPumpCommand>,
    /// The Firewalled Front's verdicts on the buddies this pump asked it to
    /// adopt. The enactor holds the sender, so this never closes while the
    /// pump runs.
    pub(super) verdicts_rx: mpsc::Receiver<crate::firewalled::front::AdoptVerdict>,
    pub(super) kad_stop_rx: Option<oneshot::Receiver<()>>,
    pub(super) kad_stopped_tx: Option<oneshot::Sender<()>>,
    /// The **Reach Generation**: one wake for any Self Reach family's move —
    /// this node's own verdict writes, a login or re-assignment, the NAT-T
    /// front's end.
    pub(super) reach_generation: crate::reachability::ReachGeneration,
    /// What this node put in the shared inlet, pump and handoff cells: each
    /// lease's drop empties its cell, and only while the cell still holds this
    /// node's sender, so its teardown leaves a successor's alone.
    pub(super) inlet_lease: Lease<rmule_net::kad::KadDatagram>,
    pub(super) pump_lease: Lease<KadPumpCommand>,
    pub(super) bootstrap_lease: Lease<rmule_primitives::Ipv4Endpoint>,
}

impl Pump {
    /// Pump until the core drops the command channel, the node's driver
    /// stops, the discovery task drops its sources, or the external stop
    /// lever fires; then close the gates that say the node runs and shut it
    /// down.
    pub(super) async fn run(self) {
        let Self {
            mut handle,
            mut state,
            mut enactor,
            mut commands_rx,
            mut verdicts_rx,
            mut kad_stop_rx,
            mut kad_stopped_tx,
            mut reach_generation,
            inlet_lease,
            pump_lease,
            bootstrap_lease,
        } = self;
        // Resolved select step; the `next_event` future's `&mut handle`
        // borrow must end before an effect can command the node.
        enum Step {
            Command(Option<KadPumpCommand>),
            Event(Option<rmule_kad::KadEvent>),
            /// The recruit trigger's own clock — the one step no datagram
            /// produces.
            RecruitTick,
            /// The Firewalled Front's verdict on a buddy this pump asked it
            /// to adopt.
            Verdict(crate::firewalled::front::AdoptVerdict),
            /// The node's inbox has room for what it turned away.
            Room,
            /// A Reach Generation, an Own Address Generation or an
            /// obfuscation policy change: a source the brain samples moved,
            /// from whichever task wrote it.
            Moved,
            /// The external stop lever fired (caller- or
            /// `DisableKad`-installed).
            Shutdown,
        }
        // Every store write that moved our own address is one wake here,
        // whichever task wrote it (ADR-0084 "Own address ownership").
        let mut own_address_changed = enactor.own_address_changed();
        // A live policy change re-arms the node before its next exchange
        // (ADR-0046): the brain samples the policy and tells the node.
        let mut obfuscation_changed = enactor.obfuscation_changed();
        // The tick's first beat is immediate: the recruit trigger is asked
        // right after the start, not thirty seconds later.
        // Room in the node's inbox, awaited beside its events: the driver is
        // the inbox's one sender, so the room is the next command's.
        let room = handle.command_room();
        let mut recruit_tick = tokio::time::interval(RECRUIT_TICK);
        recruit_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The whole node state is told before the pump takes its first step,
        // so no publish the core sends can leave without its connect options.
        let start = KadPumpInput::Start(enactor.sample());
        let mut running = drive(&mut state, &mut enactor, &handle, start)
            .await
            .is_continue();
        while running {
            let step = tokio::select! {
                command = commands_rx.recv(), if state.takes_commands() => Step::Command(command),
                event = handle.next_event() => Step::Event(event),
                () = room.ready(), if state.awaits_room() => Step::Room,
                _ = recruit_tick.tick() => Step::RecruitTick,
                Some(verdict) = verdicts_rx.recv() => Step::Verdict(verdict),
                () = reach_generation.changed() => Step::Moved,
                // The sender lives in the store the enactor holds a handle
                // to, so it never closes; the `Ok` pattern still disables
                // the arm rather than spin if it ever did.
                Ok(()) = own_address_changed.changed() => Step::Moved,
                // The cell lives in the Hello Adverts the enactor holds, so
                // its sender never closes either.
                Ok(()) = obfuscation_changed.changed() => Step::Moved,
                () = async {
                    match kad_stop_rx.as_mut() {
                        Some(rx) => { let _ = rx.await; }
                        None => std::future::pending().await,
                    }
                } => Step::Shutdown,
            };
            let input = match step {
                Step::Command(Some(command)) => {
                    KadPumpInput::Command(Box::new(command), enactor.sample())
                }
                // The Core actor dropped the channel, the lever fired, or the
                // node's driver already stopped. The lever's confirmation
                // fires below, after the tap (if any) has finalized.
                Step::Command(None) | Step::Shutdown | Step::Event(None) => break,
                Step::Event(Some(event)) => KadPumpInput::Event(event),
                Step::RecruitTick => KadPumpInput::Tick(enactor.sample()),
                Step::Verdict(verdict) => KadPumpInput::BuddyVerdict(verdict),
                Step::Room => KadPumpInput::Room,
                Step::Moved => KadPumpInput::Sampled(enactor.sample()),
            };
            running = drive(&mut state, &mut enactor, &handle, input)
                .await
                .is_continue();
        }
        refuse_queued(&mut commands_rx);
        // The node is going away: close the gates that say it is running
        // before the driver is torn down, so neither the demux front, an
        // out-of-band signaller, nor the handoff forwarder (whose
        // `handoff_rx.recv()` this sender's drop finally ends) can
        // address a stopped node. Only this node's own senders go: a stop
        // that timed out lets this task outlive its retire, and a restart in
        // that window has filled the cells with its own.
        drop((inlet_lease, pump_lease, bootstrap_lease));
        let _ = drive(&mut state, &mut enactor, &handle, KadPumpInput::Stop).await;
        // Kad Presence and the verdicts clear when the actor retires this
        // activity (ADR-0093): this task's end drops the sources channel,
        // which ends the discovery task the ledger watches.
        let _ = handle.shutdown().await;
        // The tap (if any) is finalized by now.
        if let Some(tx) = kad_stopped_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Hand `input` to the brain and carry out what it decides, depth first: an
/// effect's answer goes back in, and whatever the brain then asks for runs
/// before the rest of the batch. Breaks when the discovery task dropped its
/// sources, which ends the pump.
async fn drive(
    state: &mut KadPumpState,
    enactor: &mut Enactor,
    handle: &rmule_net::kad::KadNetHandle,
    input: KadPumpInput,
) -> ControlFlow<()> {
    let mut queue: VecDeque<_> = state.handle(input, Instant::now()).into();
    while let Some(effect) = queue.pop_front() {
        match enactor.enact(effect, handle).await {
            enact::Enacted::Done => {}
            enact::Enacted::Answer(answer) => {
                for effect in state.handle(answer, Instant::now()).into_iter().rev() {
                    queue.push_front(effect);
                }
            }
            enact::Enacted::SourcesClosed => return ControlFlow::Break(()),
        }
    }
    ControlFlow::Continue(())
}

/// The pump is gone: close its command queue and end every keyword search
/// still queued in it as never taken by the node, so no leg reads a walk that
/// never ran as done. What the brain itself took, it refuses at `Stop`.
fn refuse_queued(commands: &mut mpsc::Receiver<KadPumpCommand>) {
    commands.close();
    while let Ok(command) = commands.try_recv() {
        if let KadPumpCommand::SearchKeyword { results, .. } = command {
            results.tell(KadWalkFact::Ended(KadKeywordEnd::NotTaken));
        }
    }
}
