//! Generic Tokio driver harness and capture engine shared by the per-protocol
//! runtime modules (`ed2k`, `peer`; `kad` shares only the capture engine).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

mod capture;
mod crypt;

pub use capture::{
    CaptureFormat, CaptureHandle, FrameWrite, OverflowPolicy, RowsFile, run_capture, spawn_capture,
    toml_basic_string,
};
pub use crypt::{
    CryptStream, HandshakeProgress, ObfuscationConfig, ObfuscationPolicy, ObfuscationTransport,
    random_marker, random_padding,
};

/// Read buffer size; matches Tokio's default `BufReader` capacity.
const READ_BUF_LEN: usize = 8192;

/// Grace a cooperative [`SpawnHandles::shutdown`] gives the driver (and then
/// the capture writer) before aborting it.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// The runtime failures every connection-shaped module shares — the ways a
/// live connection can fail to exist, above the protocol errors its sans-I/O
/// session owns. Each protocol module's error wraps this (`Ed2kNetError`,
/// `PeerNetError`) beside its own transport-specific variants.
#[derive(Debug, Error)]
pub enum DriverError {
    /// TCP connect did not complete inside the connect timeout.
    #[error("connect timed out")]
    ConnectTimeout,

    /// The driver task ended before the handle did (panicked, was aborted,
    /// or did not exit within [`SHUTDOWN_GRACE`]).
    #[error("driver task died")]
    DriverDied,

    /// The connection has already been shut down or dropped.
    #[error("connection closed")]
    Closed,

    /// Socket-level I/O failure surfaced from the driver.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One effect drained from a [`DrivenSession`] — the runtime-owned mirror
/// of each protocol's native `Output`/`PeerOutput`. The session adapter maps
/// its native outputs onto this in [`DrivenSession::poll_output`].
#[derive(Debug)]
pub enum DriverOutput<E, C> {
    /// Framed bytes to write to the socket. `Arc<[u8]>` so the capture tap
    /// fans the buffer to the socket *and* the writer task with a refcount
    /// bump, not a byte-copy.
    Write(Arc<[u8]>),
    /// Domain event to forward to the consumer.
    Event(E),
    /// Terminal close from the session. The session emits its own paired
    /// `Disconnected` event immediately before this `Close` on every close
    /// path, so the driver forwards that event normally and does not
    /// synthesize one here. (Driver-originated closes — clean EOF and socket
    /// I/O errors — never reach this variant: [`run_driver`] synthesizes
    /// their `Disconnected` directly, since the sans-I/O session cannot
    /// observe them.)
    Close(C),
}

/// The runtime adapter [`run_driver`] drives. One impl per concrete session
/// lives in that session's protocol module, on a **local newtype** around
/// the sans-I/O session, keeping the runtime adaptation out of the sans-I/O
/// protocol crates.
///
/// Sans-I/O contract (ADR-0021): the session owns *all* protocol state and
/// every clock-free close decision — including the timeout close, via
/// [`deadline_elapsed`](Self::deadline_elapsed). The driver owns only the
/// socket, the channels, and one optional startup deadline.
pub trait DrivenSession {
    /// What a caller sends in, forwarded verbatim off the command channel.
    type Command;
    /// What the session reports out — forwarded to the consumer, tapped for
    /// the capture rows, and read by [`resolves_deadline`](Self::resolves_deadline).
    type Event;
    /// Why the link ended, in the session's own vocabulary; the driver turns
    /// it into the paired `Disconnected` event and the capture's close label.
    type CloseReason;

    /// Let the session emit its opening effects (a dialer's hello) before the
    /// first read; the driver drains `poll_output` immediately after.
    fn start(&mut self);
    /// Apply one caller command.
    fn handle_command(&mut self, command: Self::Command);
    /// Feed one socket read, already deobfuscated by the [`CryptStream`].
    /// Chunks are not frame-aligned — reassembly is the session's.
    fn handle_bytes(&mut self, bytes: &[u8]);
    /// Take the next pending effect; the driver drains to `None` after every
    /// other call on this trait.
    fn poll_output(&mut self) -> Option<DriverOutput<Self::Event, Self::CloseReason>>;

    /// Command meaning "disconnect", fed when the command channel closes
    /// (cooperative `shutdown`).
    fn disconnect_command() -> Self::Command;
    /// The startup deadline elapsed; the session translates it into its own
    /// close (login-timeout / hello-timeout). No-op if already resolved.
    fn deadline_elapsed(&mut self);

    /// True if this event resolves the startup deadline (login resolved /
    /// peer identified) — the driver disarms the deadline.
    fn resolves_deadline(event: &Self::Event) -> bool;
    /// Build the `Disconnected` event for a `Close`-only reason.
    fn disconnected_event(reason: Self::CloseReason) -> Self::Event;
    /// Honest discriminant label for the capture meta record.
    fn close_label(reason: &Self::CloseReason) -> &'static str;
    /// Close reason for a clean EOF (`read` → `Ok(0)`).
    fn eof_close_reason() -> Self::CloseReason;
    /// Close reason for a socket read/write I/O error.
    fn io_close_reason(kind: std::io::ErrorKind) -> Self::CloseReason;

    /// Observability hooks; default no-ops so the harness stays
    /// `tracing`-free and each protocol module keeps its own log vocabulary.
    fn trace_event(_event: &Self::Event) {}
    /// The close counterpart of [`trace_event`](Self::trace_event), called
    /// once per connection.
    fn trace_close(_reason: &Self::CloseReason) {}
}

/// One stream byte chunk the harness tapped off the socket, tagged with
/// the direction it crossed. `outbound` is `false` for bytes read from the
/// peer, `true` for bytes written to it; the stream [`CaptureFormat`]
/// (`s2c.bin`/`c2s.bin`, `inbound.bin`/`outbound.bin`) maps that onto a
/// file index. `Arc<[u8]>` so a pass-through tap fans the driver's buffer
/// to the socket *and* this frame with a refcount bump, not a byte-copy.
#[derive(Debug)]
pub struct StreamTap {
    /// `true` for bytes on their way to the peer.
    pub outbound: bool,
    /// The chunk as the socket handed it over — one read or one write, never
    /// a reassembled frame.
    pub bytes: Arc<[u8]>,
}

/// The finalize materials the harness hands a capture at shutdown: the
/// close-reason label plus the session's start time and duration. The
/// per-crate [`CaptureFormat`] folds these with the context it already
/// holds into `meta.toml`.
#[derive(Clone, Copy, Debug)]
pub struct FinalizeVerdict {
    /// The session's own discriminant label for the close
    /// ([`DrivenSession::close_label`]).
    pub close_label: &'static str,
    /// Wall clock at the driver's start, for the meta record's timestamp.
    pub started_unix_secs: u64,
    /// Monotonic span from that start to teardown — measured separately from
    /// the wall clock, so a clock step cannot make it negative.
    pub duration_ms: u64,
}

/// Capture wiring handed to [`run_driver`] when capture is enabled. The
/// channels are runtime-owned (so the driver awaits the sends and keeps
/// backpressure), carrying harness-fixed types — the byte→file and
/// verdict→`meta.toml` mapping is the [`CaptureFormat`] adapter's, behind
/// the sink. Only `event_toml` (a per-protocol free function) crosses into the
/// harness, to turn each forwarded event into its row before the raw event
/// moves on to the consumer.
pub struct Capture<E> {
    frames: mpsc::Sender<StreamTap>,
    events: mpsc::Sender<String>,
    finalize: oneshot::Sender<FinalizeVerdict>,
    event_toml: fn(&E) -> String,
}

/// Drive one [`DrivenSession`] against an async byte stream until it
/// closes, returning the I/O error that ended it (if any) — the caller
/// maps it onto [`DriverError::Io`]. On every terminal path the
/// consumer observes exactly one `Disconnected` event, and, when capture
/// is enabled, exactly one finalize.
///
/// The `Send` bounds encode the harness's contract: it is meant to run
/// inside a spawned task (`tokio::spawn`), so the session, the commands and
/// the events it moves across `.await` points must be `Send`. Stating that
/// here surfaces a non-`Send` adapter at this signature rather than as an
/// opaque error at a downstream spawn site.
pub async fn run_driver<S, IO>(
    mut session: S,
    mut io: IO,
    mut cmd_rx: mpsc::Receiver<S::Command>,
    evt_tx: mpsc::Sender<S::Event>,
    deadline: Option<Duration>,
    mut capture: Option<Capture<S::Event>>,
) -> Result<(), std::io::Error>
where
    S: DrivenSession + Send,
    S::Command: Send,
    S::Event: Send,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let start = tokio::time::Instant::now();
    let started_unix = now_unix_secs();
    let deadline_at = deadline.map(|d| tokio::time::Instant::now() + d);
    let mut pending = true;

    session.start();
    match drain(&mut session, &mut io, &evt_tx, capture.as_ref()).await {
        Ok(DrainStatus::Closed { label }) => {
            finalize::<S>(capture, started_unix, start, label);
            return Ok(());
        }
        Ok(DrainStatus::Resolved) => pending = false,
        Ok(DrainStatus::Continue) => {}
        Err(err) => {
            // Handshake write failed before the loop ran. Synthesize the
            // terminal Disconnected{Io} and finalize so consumers always
            // see one terminal event and captures never mis-record.
            let reason = S::io_close_reason(err.kind());
            let label = S::close_label(&reason);
            synthesize::<S>(&evt_tx, reason, capture.as_ref()).await;
            finalize::<S>(capture, started_unix, start, label);
            return Err(err);
        }
    }

    let mut buf = vec![0u8; READ_BUF_LEN];
    let outcome_label: &'static str;
    let mut returned_error: Option<std::io::Error> = None;
    'main: loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(command) => session.handle_command(command),
                None => session.handle_command(S::disconnect_command()),
            },
            _ = sleep_until_opt(deadline_at), if pending && deadline_at.is_some() => {
                // Uniform timeout: notify the session, which emits its own
                // Close on the next drain (login/hello timeout). Spent.
                session.deadline_elapsed();
                pending = false;
            }
            read = io.read(&mut buf) => match read {
                Ok(0) => {
                    let reason = S::eof_close_reason();
                    outcome_label = S::close_label(&reason);
                    synthesize::<S>(&evt_tx, reason, capture.as_ref()).await;
                    break 'main;
                }
                Ok(n) => {
                    if let Some(c) = capture.as_ref() {
                        let _ = c
                            .frames
                            .send(StreamTap {
                                outbound: false,
                                bytes: Arc::from(&buf[..n]),
                            })
                            .await;
                    }
                    session.handle_bytes(&buf[..n]);
                }
                Err(e) => {
                    let reason = S::io_close_reason(e.kind());
                    outcome_label = S::close_label(&reason);
                    synthesize::<S>(&evt_tx, reason, capture.as_ref()).await;
                    returned_error = Some(e);
                    break 'main;
                }
            }
        }
        match drain(&mut session, &mut io, &evt_tx, capture.as_ref()).await {
            Ok(DrainStatus::Closed { label }) => {
                outcome_label = label;
                break 'main;
            }
            Ok(DrainStatus::Resolved) => pending = false,
            Ok(DrainStatus::Continue) => {}
            Err(e) => {
                let reason = S::io_close_reason(e.kind());
                outcome_label = S::close_label(&reason);
                synthesize::<S>(&evt_tx, reason, capture.as_ref()).await;
                returned_error = Some(e);
                break 'main;
            }
        }
    }

    finalize::<S>(capture.take(), started_unix, start, outcome_label);
    match returned_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Capacity of the internal capture frame/event channels.
const CAPTURE_CHANNEL_CAP: usize = 64;

/// Boxed `Send` future. Used so the harness can hand the driver future to a
/// caller-supplied decorator — and spawn a caller-supplied capture sink —
/// without naming their opaque future types or taking on any logging
/// vocabulary of its own.
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Command/event channel capacities for a spawned connection. The defaults
/// (16 commands, 64 events) match the per-protocol-module constants.
pub struct ChannelCaps {
    /// Caller-to-session queue depth; a full queue blocks the sender rather
    /// than dropping commands.
    pub command: usize,
    /// Session-to-caller queue depth; a consumer that stops draining
    /// backpressures the driver, and through it the socket.
    pub event: usize,
}

impl Default for ChannelCaps {
    fn default() -> Self {
        Self {
            command: 16,
            event: 64,
        }
    }
}

/// The capture writer task factory: given the harness-created frame, event,
/// and finalize receivers, it returns the future the harness spawns. Each
/// protocol module fills it with the capture engine's [`run_capture`] over
/// its [`CaptureFormat`] — which the sink also holds the *context* in,
/// so `meta.toml` needs only the harness's [`FinalizeVerdict`].
pub type CaptureSink = Box<
    dyn FnOnce(
            mpsc::Receiver<StreamTap>,
            mpsc::Receiver<String>,
            oneshot::Receiver<FinalizeVerdict>,
        ) -> BoxFuture<()>
        + Send,
>;

/// Capture wiring for a spawned connection. The harness creates the
/// frame/event/finalize channels, hands the *receivers* to `sink` (the
/// engine writer, which owns the [`CaptureFormat`] and its context) and the
/// *senders* to the driver. `event_toml` is the protocol module's event→row encoder,
/// applied in the harness so the raw event can still move on to the
/// consumer.
pub struct SpawnCapture<S: DrivenSession> {
    /// Renders one event as its row in the capture's rows file.
    pub event_toml: fn(&S::Event) -> String,
    /// Builds the writer future the harness spawns over the three receivers.
    pub sink: CaptureSink,
}

/// The live handles a spawned connection exposes: the command sender, the
/// event receiver, the driver task (mapped to the caller's error type `E`),
/// and the capture task when capture is enabled. Owns the one teardown every
/// connection shares: cooperative [`shutdown`](Self::shutdown) with a grace
/// period, and abort-on-`Drop` as the safety net.
pub struct SpawnHandles<S: DrivenSession, E> {
    /// Cloneable command sender — the half a caller keeps to go on driving a
    /// link whose events someone else consumes.
    pub commands: mpsc::Sender<S::Command>,
    /// Single-consumer event stream; yields `None` once the driver has
    /// stopped and its last output is drained.
    pub events: mpsc::Receiver<S::Event>,
    driver: Option<JoinHandle<Result<(), E>>>,
    capture: Option<JoinHandle<()>>,
}

impl<S: DrivenSession, E: From<DriverError>> SpawnHandles<S, E> {
    /// Cooperative tear-down: send the session's disconnect command, drop the
    /// command sender (so the driver's `recv()` resolves to `None` even if
    /// the send raced the channel's capacity), and await the driver up to
    /// [`SHUTDOWN_GRACE`] — then the capture writer, which ends only after
    /// the driver's finalize signal, so the capture files exist by the time
    /// this returns. A driver that does not exit in time is reported as
    /// [`DriverError::DriverDied`] and aborted on drop.
    pub async fn shutdown(mut self) -> Result<(), E> {
        let _ = self.commands.send(S::disconnect_command()).await;
        drop(std::mem::replace(&mut self.commands, mpsc::channel(1).0));
        let Some(driver) = self.driver.take() else {
            return Ok(());
        };
        let driver_result = match tokio::time::timeout(SHUTDOWN_GRACE, driver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(DriverError::DriverDied.into()),
        };
        if let Some(capture) = self.capture.take() {
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, capture).await;
        }
        driver_result
    }
}

impl<S: DrivenSession, E> Drop for SpawnHandles<S, E> {
    fn drop(&mut self) {
        let _ = self.commands.try_send(S::disconnect_command());
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
        if let Some(capture) = self.capture.take() {
            capture.abort();
        }
    }
}

/// Spawn the driver — and, when capture is enabled, the capture sink — for one
/// [`DrivenSession`] over `io`. The harness owns the channel creation and both
/// `tokio::spawn`s; `decorate` wraps the driver future before it is spawned —
/// that is where each protocol module maps the harness's `io::Error` onto its
/// own error type and attaches its `tracing` span, keeping the harness free of
/// any logging vocabulary. The two `Connection::connect` bodies reduce to building
/// their domain capture format (context and all) and one call.
pub fn spawn_connection<S, IO, E, D, F>(
    io: IO,
    session: S,
    caps: ChannelCaps,
    deadline: Option<Duration>,
    capture: Option<SpawnCapture<S>>,
    decorate: D,
) -> SpawnHandles<S, E>
where
    S: DrivenSession + Send + 'static,
    S::Command: Send,
    S::Event: Send,
    // The harness holds the close reason and a `&Capture` across `.await`
    // points; spawning the driver future needs both to cross threads.
    S::CloseReason: Send,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    E: Send + 'static,
    D: FnOnce(BoxFuture<Result<(), std::io::Error>>) -> F,
    F: Future<Output = Result<(), E>> + Send + 'static,
{
    let (cmd_tx, cmd_rx) = mpsc::channel(caps.command);
    let (evt_tx, evt_rx) = mpsc::channel(caps.event);
    let (capture_arg, capture_handle) = match capture {
        Some(SpawnCapture { event_toml, sink }) => {
            let (frame_tx, frame_rx) = mpsc::channel::<StreamTap>(CAPTURE_CHANNEL_CAP);
            let (event_tx, event_rx) = mpsc::channel::<String>(CAPTURE_CHANNEL_CAP);
            let (finalize_tx, finalize_rx) = oneshot::channel::<FinalizeVerdict>();
            let handle = tokio::spawn(sink(frame_rx, event_rx, finalize_rx));
            (
                Some(Capture {
                    frames: frame_tx,
                    events: event_tx,
                    finalize: finalize_tx,
                    event_toml,
                }),
                Some(handle),
            )
        }
        None => (None, None),
    };
    let driver_future: BoxFuture<Result<(), std::io::Error>> = Box::pin(run_driver(
        session,
        io,
        cmd_rx,
        evt_tx,
        deadline,
        capture_arg,
    ));
    let driver = tokio::spawn(decorate(driver_future));
    SpawnHandles {
        commands: cmd_tx,
        events: evt_rx,
        driver: Some(driver),
        capture: capture_handle,
    }
}

enum DrainStatus {
    Closed { label: &'static str },
    Resolved,
    Continue,
}

async fn drain<S, IO>(
    session: &mut S,
    io: &mut IO,
    evt_tx: &mpsc::Sender<S::Event>,
    capture: Option<&Capture<S::Event>>,
) -> Result<DrainStatus, std::io::Error>
where
    S: DrivenSession,
    IO: AsyncWrite + Unpin,
{
    let mut resolved = false;
    while let Some(output) = session.poll_output() {
        match output {
            DriverOutput::Write(bytes) => {
                if let Some(c) = capture {
                    let _ = c
                        .frames
                        .send(StreamTap {
                            outbound: true,
                            bytes: Arc::clone(&bytes),
                        })
                        .await;
                }
                io.write_all(&bytes).await?;
            }
            DriverOutput::Event(event) => {
                if S::resolves_deadline(&event) {
                    resolved = true;
                }
                if let Some(c) = capture {
                    let _ = c.events.send((c.event_toml)(&event)).await;
                }
                S::trace_event(&event);
                let _ = evt_tx.send(event).await;
            }
            DriverOutput::Close(reason) => {
                // The session emits its own paired `Disconnected` (forwarded
                // through the `Event` arm above) immediately before every
                // `Close`, so the driver just records the label and ends the
                // drain — it never synthesizes a `Disconnected` here.
                let label = S::close_label(&reason);
                S::trace_close(&reason);
                return Ok(DrainStatus::Closed { label });
            }
        }
    }
    if resolved {
        Ok(DrainStatus::Resolved)
    } else {
        Ok(DrainStatus::Continue)
    }
}

async fn synthesize<S: DrivenSession>(
    evt_tx: &mpsc::Sender<S::Event>,
    reason: S::CloseReason,
    capture: Option<&Capture<S::Event>>,
) {
    S::trace_close(&reason);
    let event = S::disconnected_event(reason);
    if let Some(c) = capture {
        let _ = c.events.send((c.event_toml)(&event)).await;
    }
    S::trace_event(&event);
    let _ = evt_tx.send(event).await;
}

fn finalize<S: DrivenSession>(
    capture: Option<Capture<S::Event>>,
    started_unix_secs: u64,
    start: tokio::time::Instant,
    close_label: &'static str,
) {
    let Some(capture) = capture else { return };
    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let _ = capture.finalize.send(FinalizeVerdict {
        close_label,
        started_unix_secs,
        duration_ms,
    });
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(when) => tokio::time::sleep_until(when).await,
        None => std::future::pending().await,
    }
}

fn now_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
