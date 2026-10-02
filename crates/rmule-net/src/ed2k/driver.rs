//! Runtime adaptation of the sans-I/O [`Ed2kSession`]:
//! the newtype that satisfies the shared [`DrivenSession`]
//! contract, plus the two entry points that run it over a byte stream — the
//! plain one and the variant that fails the session when login stays unanswered.

use std::time::Duration;

use crate::driver::{DrivenSession, DriverOutput, run_driver};
use rmule_ed2k::{CloseReason, Ed2kCommand, Ed2kEvent, Ed2kSession, Output};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::ed2k::Ed2kNetError;

/// Runtime newtype around the sans-I/O [`Ed2kSession`] implementing the
/// shared harness contract ([`DrivenSession`]), keeping the runtime
/// adaptation out of the sans-I/O `rmule-ed2k` crate.
pub(crate) struct Ed2kDriven(Ed2kSession);

impl Ed2kDriven {
    pub(crate) fn new(session: Ed2kSession) -> Self {
        Self(session)
    }
}

impl DrivenSession for Ed2kDriven {
    type Command = Ed2kCommand;
    type Event = Ed2kEvent;
    type CloseReason = CloseReason;

    fn start(&mut self) {
        self.0.start();
    }
    fn handle_command(&mut self, command: Ed2kCommand) {
        self.0.handle_command(command);
    }
    fn handle_bytes(&mut self, bytes: &[u8]) {
        self.0.handle_bytes(bytes);
    }
    fn poll_output(&mut self) -> Option<DriverOutput<Ed2kEvent, CloseReason>> {
        self.0.poll_output().map(|output| match output {
            Output::Write(bytes) => {
                // Server-session frame hex, the twin of the peer driver's
                // serve-side trace. At TRACE this surfaces every
                // outbound connected-server frame — the byte-level evidence for
                // the Low-ID callback emit (`OP_CALLBACKREQUEST 0x1C`).
                if tracing::enabled!(tracing::Level::TRACE) {
                    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                    tracing::trace!(len = bytes.len(), frame = %hex, "ed2k driver write");
                }
                DriverOutput::Write(bytes)
            }
            Output::Event(event) => DriverOutput::Event(event),
            Output::Close(reason) => DriverOutput::Close(reason),
        })
    }
    fn disconnect_command() -> Ed2kCommand {
        Ed2kCommand::Disconnect
    }
    fn deadline_elapsed(&mut self) {
        self.0.login_deadline_elapsed();
    }
    fn resolves_deadline(event: &Ed2kEvent) -> bool {
        matches!(
            event,
            Ed2kEvent::LoginAccepted { .. } | Ed2kEvent::LoginRejected
        )
    }
    fn disconnected_event(reason: CloseReason) -> Ed2kEvent {
        Ed2kEvent::Disconnected { reason }
    }
    fn close_label(reason: &CloseReason) -> &'static str {
        reason.label()
    }
    fn eof_close_reason() -> CloseReason {
        CloseReason::ServerClosed
    }
    fn io_close_reason(kind: std::io::ErrorKind) -> CloseReason {
        CloseReason::Io(kind)
    }
    fn trace_event(event: &Ed2kEvent) {
        match event {
            Ed2kEvent::LoginRejected => {
                tracing::warn!(event = ?event, "ed2k session login rejected")
            }
            Ed2kEvent::CompressedFrameSkipped { .. } => {
                tracing::warn!(event = ?event, "ed2k compressed frame skipped")
            }
            _ => tracing::debug!(event = ?event, "ed2k driver event"),
        }
    }
    fn trace_close(reason: &CloseReason) {
        match reason {
            CloseReason::ProtocolViolation(_) => {
                tracing::warn!(reason = ?reason, "ed2k session closed on protocol violation")
            }
            CloseReason::Io(_) | CloseReason::ConnectTimeout | CloseReason::LoginTimeout => {
                tracing::warn!(reason = ?reason, "ed2k session closed")
            }
            _ => tracing::info!(reason = ?reason, "ed2k session closed"),
        }
    }
}

/// Run one [`Ed2kSession`] with no login timeout and no capture. Public for
/// tests and alternative transports that bring their own stream.
pub async fn drive<S>(
    session: Ed2kSession,
    io: S,
    cmd_rx: mpsc::Receiver<Ed2kCommand>,
    evt_tx: mpsc::Sender<Ed2kEvent>,
) -> Result<(), Ed2kNetError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    drive_with_login_timeout(session, io, cmd_rx, evt_tx, None).await
}

/// Run one [`Ed2kSession`] with an optional login-response deadline and no
/// capture, mapping the harness's `io::Error` onto `DriverError::Io`. The
/// capture path instead goes through [`crate::driver::spawn_connection`]
/// from [`Connection`](crate::ed2k::Connection), which builds the `Ed2kCaptureFormat`
/// (endpoint + identity context and all) for the engine writer.
pub async fn drive_with_login_timeout<S>(
    session: Ed2kSession,
    io: S,
    cmd_rx: mpsc::Receiver<Ed2kCommand>,
    evt_tx: mpsc::Sender<Ed2kEvent>,
    login_timeout: Option<Duration>,
) -> Result<(), Ed2kNetError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    run_driver(
        Ed2kDriven::new(session),
        io,
        cmd_rx,
        evt_tx,
        login_timeout,
        None,
    )
    .await
    .map_err(Ed2kNetError::from)
}
