//! Runtime adaptation of the sans-I/O [`PeerSession`]:
//! the newtype that satisfies the shared [`DrivenSession`]
//! contract, so one harness drives both the dialed and the accepted role.

use crate::driver::{DrivenSession, DriverOutput};
use rmule_peer::{
    ConnectionCommand, ConnectionEvent, PeerCloseReason, PeerCommand, PeerEvent, PeerOutput,
    PeerSession,
};

/// Runtime newtype around the sans-I/O [`PeerSession`] implementing the
/// shared harness contract (see the `ed2k` module's `Ed2kDriven`).
pub(crate) struct PeerDriven(PeerSession);

impl PeerDriven {
    pub(crate) fn new(session: PeerSession) -> Self {
        Self(session)
    }
}

impl DrivenSession for PeerDriven {
    type Command = PeerCommand;
    type Event = PeerEvent;
    type CloseReason = PeerCloseReason;

    fn start(&mut self) {
        // Outbound: emits our OP_HELLO. Inbound (`new_inbound`): an
        // idempotent no-op (state is `AwaitingHello`) — one harness serves
        // both roles; the role lives in the session, not here.
        self.0.start();
    }
    fn handle_command(&mut self, command: PeerCommand) {
        self.0.handle_command(command);
    }
    fn handle_bytes(&mut self, bytes: &[u8]) {
        // Symmetric to the outbound `poll_output` hex trace below: dump each
        // inbound socket chunk at TRACE so a serve-side run (`RMULE_SERVE_LOG=
        // trace`) records the *counterparty's* raw frames — a firewalled aMule
        // release build emits no debug logs, so the reverse-harness captures
        // (the multipacket request, OP_REQUESTSOURCES, OP_CANCELTRANSFER)
        // are only observable from rmule's read side.
        if tracing::enabled!(tracing::Level::TRACE) {
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            tracing::trace!(len = bytes.len(), frame = %hex, "peer driver read");
        }
        self.0.handle_bytes(bytes);
    }
    fn poll_output(&mut self) -> Option<DriverOutput<PeerEvent, PeerCloseReason>> {
        self.0.poll_output().map(|output| match output {
            PeerOutput::Write(bytes) => {
                if tracing::enabled!(tracing::Level::TRACE) {
                    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                    tracing::trace!(len = bytes.len(), frame = %hex, "peer driver write");
                }
                DriverOutput::Write(bytes)
            }
            PeerOutput::Event(event) => DriverOutput::Event(event),
            PeerOutput::Close(reason) => DriverOutput::Close(reason),
        })
    }
    fn disconnect_command() -> PeerCommand {
        PeerCommand::Connection(ConnectionCommand::Disconnect)
    }
    fn deadline_elapsed(&mut self) {
        self.0.hello_deadline_elapsed();
    }
    fn resolves_deadline(event: &PeerEvent) -> bool {
        matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Identified { .. })
        )
    }
    fn disconnected_event(reason: PeerCloseReason) -> PeerEvent {
        PeerEvent::Connection(ConnectionEvent::Disconnected { reason })
    }
    fn close_label(reason: &PeerCloseReason) -> &'static str {
        reason.label()
    }
    fn eof_close_reason() -> PeerCloseReason {
        PeerCloseReason::PeerClosed
    }
    fn io_close_reason(kind: std::io::ErrorKind) -> PeerCloseReason {
        PeerCloseReason::Io(kind)
    }
    fn trace_event(event: &PeerEvent) {
        tracing::debug!(event = ?event, "peer driver event");
    }
    fn trace_close(reason: &PeerCloseReason) {
        if matches!(reason, PeerCloseReason::ProtocolViolation) {
            tracing::warn!(reason = ?reason, "peer connection closed on protocol violation");
        } else {
            tracing::info!(reason = ?reason, "peer connection closed");
        }
    }
}
