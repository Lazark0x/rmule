//! Unit tests for the in-process CoreClient bridge.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rmule_core::diagnostics::{
    DownloadDiagnostics, SessionCounters, UploadDiagnostics, WorkerEntry, WorkerPhase, WorkerSlot,
};
use rmule_core::{DownloadEvent, DownloadId};
use rmule_primitives::{FileHash, PeerEndpoint};

use super::*;
use crate::fixture::part_map;

/// Channel-backed fake behind the `CoreHandle` port (`FakeLink`
/// precedent): tests push events in, mutate the served snapshot, and
/// observe forwarded commands.
struct FakeCore {
    events: mpsc::Receiver<CoreEvent>,
    snapshot: Arc<Mutex<DiagnosticsSnapshot>>,
    sent: mpsc::Sender<CoreCommand>,
    shutdown_calls: Arc<AtomicUsize>,
    /// A core whose quit never ends —
    /// `CORE_SHUTDOWN_GRACE` must still let the caller through.
    hang_on_shutdown: bool,
}

struct FakeCoreControls {
    events: mpsc::Sender<CoreEvent>,
    snapshot: Arc<Mutex<DiagnosticsSnapshot>>,
    sent: mpsc::Receiver<CoreCommand>,
    shutdown_calls: Arc<AtomicUsize>,
}

fn fake_core() -> (FakeCore, FakeCoreControls) {
    fake_core_with(false)
}

fn fake_core_with(hang_on_shutdown: bool) -> (FakeCore, FakeCoreControls) {
    let (event_tx, event_rx) = mpsc::channel(16);
    let (sent_tx, sent_rx) = mpsc::channel(16);
    let snapshot = Arc::new(Mutex::new(DiagnosticsSnapshot::default()));
    let shutdown_calls = Arc::new(AtomicUsize::new(0));
    (
        FakeCore {
            events: event_rx,
            snapshot: snapshot.clone(),
            sent: sent_tx,
            shutdown_calls: shutdown_calls.clone(),
            hang_on_shutdown,
        },
        FakeCoreControls {
            events: event_tx,
            snapshot,
            sent: sent_rx,
            shutdown_calls,
        },
    )
}

impl CoreHandle for FakeCore {
    async fn send(&self, command: CoreCommand) -> Result<(), CoreError> {
        self.sent
            .send(command)
            .await
            .map_err(|_| CoreError::ServiceStopped)
    }

    async fn next_event(&mut self) -> Option<CoreEvent> {
        self.events.recv().await
    }

    fn diagnostics_snapshot(&self) -> DiagnosticsSnapshot {
        self.snapshot.lock().expect("snapshot mutex").clone()
    }

    fn quit(self) -> mpsc::Receiver<CoreEvent> {
        self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        if self.hang_on_shutdown {
            // The test keeps the sender: a stream that never ends.
            self.events
        } else {
            mpsc::channel(1).1
        }
    }
}

fn queued(id: u64) -> CoreEvent {
    CoreEvent::Download(DownloadEvent::DownloadQueued {
        download_id: DownloadId::from_u64(id),
        file_hash: FileHash::from_bytes([0; 16]),
        metadata: rmule_core::DownloadMetadata::unnamed(0),
        file_path: crate::fixture::part_file(),
    })
}

/// Advance every byte level a data tick differences: the worker's level,
/// the download's monotonic total, and the session's — the way core moves
/// them together when a block lands (ADR-0077).
fn set_byte_levels(snapshot: &Arc<Mutex<DiagnosticsSnapshot>>, received: u64, sent: u64) {
    let id = DownloadId::from_u64(1);
    let slot = WorkerSlot::from_usize(0);
    let mut entry = WorkerEntry::new(slot);
    entry.transition(WorkerPhase::ReceivingPart {
        part_index: 0,
        bytes_received: received,
    });
    let mut workers = BTreeMap::new();
    workers.insert(slot, entry);
    let mut downloads = BTreeMap::new();
    downloads.insert(
        id,
        DownloadDiagnostics {
            download_id: id,
            file_hash: FileHash::from_bytes([0; 16]),
            metadata: rmule_core::DownloadMetadata::unnamed(0),
            started_at: Instant::now(),
            parts: part_map("IMMMMMMMMM"),
            retired_peers: 0,
            workers,
            received_bytes: received,
            known_sources: 0,
            dials_ended: 0,
            dial_ends: Default::default(),
            reask_replies_ignored: 0,
        },
    );
    let peer = PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
        std::net::Ipv4Addr::new(10, 0, 0, 1),
        4662,
    ));
    let mut uploads = BTreeMap::new();
    uploads.insert(
        peer,
        UploadDiagnostics {
            peer,
            file_hash: FileHash::from_bytes([1; 16]),
            started_at: Instant::now(),
            bytes_sent: sent,
        },
    );
    let mut snapshot = snapshot.lock().expect("snapshot mutex");
    snapshot.downloads = downloads;
    snapshot.uploads = uploads;
    snapshot.session = SessionCounters {
        down_bytes_total: received,
        up_bytes_total: sent,
        ..SessionCounters::default()
    };
}

#[tokio::test(start_paused = true)]
async fn events_are_forwarded_in_order() {
    let (core, controls) = fake_core();
    let (action_tx, mut action_rx) = mpsc::channel(64);
    let _handle = spawn(core, action_tx, BridgeConfig::default());

    for id in 1..=3 {
        controls.events.send(queued(id)).await.expect("push event");
    }

    let mut seen = Vec::new();
    while seen.len() < 3 {
        match action_rx.recv().await.expect("bus open") {
            Action::Core(CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id,
                ..
            })) => seen.push(download_id.as_u64()),
            Action::Snapshot(_) => {}
            other => panic!("unexpected action {other:?}"),
        }
    }
    assert_eq!(seen, vec![1, 2, 3]);
}

#[tokio::test(start_paused = true)]
async fn data_ticks_serve_snapshots_with_synthesized_rates() {
    let (core, controls) = fake_core();
    let (action_tx, mut action_rx) = mpsc::channel(64);
    let _handle = spawn(core, action_tx, BridgeConfig::default());

    // Ramp the byte levels between ticks; the paused clock auto-advances
    // through the 1 Hz interval while we await. A row's first sighting
    // reports 0 by design, so wait until every meter has an interval.
    fn positive<K>(rates: &BTreeMap<K, f64>) -> bool {
        rates.values().any(|bps| *bps > 0.0)
    }
    let mut level = 0_u64;
    let mut metered = None;
    for _ in 0..64 {
        match action_rx.recv().await.expect("bus open") {
            Action::Snapshot(frame) => {
                if positive(&frame.rates.download_bps) && positive(&frame.rates.upload_bps) {
                    metered = Some(frame.rates);
                    break;
                }
                level += 100 * 1024;
                set_byte_levels(&controls.snapshot, level, level / 2);
            }
            other => panic!("unexpected action {other:?}"),
        }
    }
    let rates = metered.expect("growing byte levels must synthesize positive rates");
    assert!(
        positive(&rates.source_bps),
        "the receiving worker's level feeds the sources pane: {rates:?}"
    );
    // ▲ is a real meter now, not a placeholder zero.
    assert!(rates.down_total_bps > 0.0, "▼ {rates:?}");
    assert!(rates.up_total_bps > 0.0, "▲ {rates:?}");
}

fn kad_diag(contact_responded: bool) -> rmule_core::diagnostics::KadRuntimeDiagnostics {
    rmule_core::diagnostics::KadRuntimeDiagnostics {
        contact_responded,
        contacts: 0,
        keywords_stored: 0,
        node_id: rmule_core::KadId::from_bytes([0x11; 16]),
        firewall: rmule_core::diagnostics::KadFirewallVerdict::Firewalled,
        firewall_check: rmule_core::diagnostics::KadFirewallCheck::NotYetRun,
        udp: rmule_core::diagnostics::KadUdpVerdict::Unverified,
        traffic: rmule_core::diagnostics::KadTraffic::default(),
    }
}

#[tokio::test(start_paused = true)]
async fn the_kad_facts_ride_the_data_tick_of_the_sync_snapshot() {
    let (core, controls) = fake_core();
    let (action_tx, mut action_rx) = mpsc::channel(64);
    let _handle = spawn(core, action_tx, BridgeConfig::default());

    controls.snapshot.lock().expect("snapshot").kad = Some(kad_diag(false));
    let mut seen = None;
    for _ in 0..8 {
        if let Action::Snapshot(frame) = action_rx.recv().await.expect("bus open")
            && let Some(kad) = frame.diagnostics.kad
        {
            seen = Some(kad);
            break;
        }
    }
    assert_eq!(
        seen,
        Some(kad_diag(false)),
        "the snapshot's Kad facts reach the UI as they are"
    );

    // Latest-state-wins: the next tick carries the newer level.
    controls.snapshot.lock().expect("snapshot").kad = Some(kad_diag(true));
    let mut last = None;
    for _ in 0..8 {
        if let Action::Snapshot(frame) = action_rx.recv().await.expect("bus open")
            && let Some(kad) = frame.diagnostics.kad
        {
            last = Some(kad);
            if kad.contact_responded {
                break;
            }
        }
    }
    assert_eq!(last, Some(kad_diag(true)));
}

#[tokio::test(start_paused = true)]
async fn commands_reach_the_core_port() {
    let (core, mut controls) = fake_core();
    let (action_tx, _action_rx) = mpsc::channel(64);
    let handle = spawn(core, action_tx, BridgeConfig::default());

    handle
        .send(CoreCommand::DisconnectFromServer)
        .await
        .expect("command lands");
    let mut forwarded = false;
    for _ in 0..4 {
        if matches!(
            controls.sent.recv().await.expect("forwarded"),
            CoreCommand::DisconnectFromServer
        ) {
            forwarded = true;
            break;
        }
    }
    assert!(forwarded, "the UI's command must reach the core port");
}

#[tokio::test(start_paused = true)]
async fn core_shutdown_announces_and_poisons_the_client() {
    let (core, controls) = fake_core();
    let (action_tx, mut action_rx) = mpsc::channel(64);
    let handle = spawn(core, action_tx, BridgeConfig::default());

    drop(controls.events); // core's event stream ends

    loop {
        match action_rx.recv().await.expect("CoreClosed must arrive") {
            Action::CoreClosed => break,
            Action::Snapshot(_) => {}
            other => panic!("unexpected action {other:?}"),
        }
    }
    // The bridge task has returned; the command door now refuses.
    let refused = handle.send(CoreCommand::DumpDiagnostics).await;
    assert_eq!(refused, Err(CoreClientError::CoreStopped));
}

#[tokio::test(start_paused = true)]
async fn a_full_bus_drops_levels_but_never_edges() {
    let (core, controls) = fake_core();
    // Bus of 1: the first undrained snapshot fills it.
    let (action_tx, mut action_rx) = mpsc::channel(1);
    let _handle = spawn(core, action_tx, BridgeConfig::default());

    // Let ticks fill the bus, then push an edge; the edge must still
    // arrive once we drain — snapshots are the droppable class.
    controls.events.send(queued(42)).await.expect("push event");
    let mut saw_edge = false;
    for _ in 0..8 {
        if let Action::Core(_) = action_rx.recv().await.expect("bus open") {
            saw_edge = true;
            break;
        }
    }
    assert!(
        saw_edge,
        "the queued edge must survive a level-saturated bus"
    );
}

/// Firing the door — what `App`'s quit path does —
/// reaches `Core::quit()`, the step that ends the core's shutdown flush.
#[tokio::test(start_paused = true)]
async fn graceful_shutdown_runs_core_quit_exactly_once() {
    let (core, controls) = fake_core();
    let (action_tx, _action_rx) = mpsc::channel(64);
    let handle = spawn(core, action_tx, BridgeConfig::default());

    assert!(handle.graceful_shutdown().await, "the door must answer");
    assert_eq!(
        controls.shutdown_calls.load(Ordering::SeqCst),
        1,
        "Core::quit() must run exactly once"
    );

    // Idempotent across the door and across clones: a second call, from
    // either handle, finds nothing left to fire.
    assert!(
        !handle.clone().graceful_shutdown().await,
        "a second call must not re-run shutdown"
    );
    assert_eq!(controls.shutdown_calls.load(Ordering::SeqCst), 1);
}

/// The bound: a core that never finishes its shutdown flush
/// must not hang the caller — `CORE_SHUTDOWN_GRACE` lets `graceful_shutdown`
/// return anyway, which is what keeps the TUI's quit from freezing the
/// terminal on a stuck actor.
#[tokio::test(start_paused = true)]
async fn a_core_that_never_finishes_shutdown_still_lets_the_call_return() {
    let (core, controls) = fake_core_with(true);
    let (action_tx, _action_rx) = mpsc::channel(64);
    let handle = spawn(core, action_tx, BridgeConfig::default());

    let before = tokio::time::Instant::now();
    assert!(
        handle.graceful_shutdown().await,
        "the door still answers once the grace elapses"
    );
    assert!(
        tokio::time::Instant::now().duration_since(before) >= CORE_SHUTDOWN_GRACE,
        "the wait must actually reach the grace, not return early"
    );
    assert_eq!(
        controls.shutdown_calls.load(Ordering::SeqCst),
        1,
        "quit() was entered even though it never resolved"
    );
}

/// The grace-elapsed case must not be swallowed: `graceful_shutdown`
/// answering `true` alone would be indistinguishable from a clean drain. A
/// core that never
/// finishes its quit flush must still tell the action bus the flush was
/// unconfirmed, before the door answers.
#[tokio::test(start_paused = true)]
async fn grace_elapsed_sends_an_unconfirmed_flush_flash_before_the_ack() {
    let (core, _controls) = fake_core_with(true);
    let (action_tx, mut action_rx) = mpsc::channel(64);
    let handle = spawn(core, action_tx, BridgeConfig::default());

    assert!(
        handle.graceful_shutdown().await,
        "the door still answers once the grace elapses"
    );

    let mut saw_grace_elapsed_flash = false;
    while let Ok(action) = action_rx.try_recv() {
        if let Action::Flash(text) = action
            && text == SHUTDOWN_GRACE_ELAPSED_FLASH
        {
            saw_grace_elapsed_flash = true;
        }
    }
    assert!(
        saw_grace_elapsed_flash,
        "a grace-elapsed quit must flash that the flush was unconfirmed, \
             not answer as if it drained cleanly"
    );
}

/// The quit steps are facts of the run like any other: each reaches the Run
/// Log as the core runs it, whether or not the UI is still there to hear it.
#[tokio::test(start_paused = true)]
async fn quit_steps_are_written_to_the_run_log_even_with_the_ui_gone() {
    use std::io::Write;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("captured").extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let captured = Captured::default();
    let sink = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    let _installed = tracing::subscriber::set_default(subscriber);

    let (events_tx, events_rx) = mpsc::channel(4);
    for step in [rmule_core::QuitStep::Search, rmule_core::QuitStep::Kad] {
        events_tx
            .send(CoreEvent::Quitting { step })
            .await
            .expect("room");
    }
    drop(events_tx);
    let (action_tx, action_rx) = mpsc::channel(4);
    drop(action_rx);
    forward_quit(events_rx, &action_tx, &Default::default()).await;

    let log = String::from_utf8(captured.0.lock().expect("captured").clone()).expect("utf8");
    let steps: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("quit.step"))
        .collect();
    assert_eq!(steps.len(), 2, "{log}");
    assert!(
        steps[0].contains("step=search") && steps[1].contains("step=kad"),
        "{log}"
    );
}
