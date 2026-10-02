//! Shared sans-I/O session spine (ADR-0044).
//!
//! `Ed2kSession` and `PeerSession` copied their scaffolding nearly verbatim:
//! the output enum shape, the inbound frame buffer plus outbound effect
//! queue, the `handle_bytes` loop driving [`Packet::decode`], and the
//! paired-close discipline the whole driver harness relies on (ADR-0021,
//! ADR-0023, ADR-0044). This module gives that plumbing one home. Protocol
//! dispatch, states, commands, events, and the close-reason vocabularies
//! stay per-crate — nothing unifies except plumbing (ADR-0081 keeps the
//! vocabularies distinct).

use std::collections::VecDeque;
use std::sync::Arc;

use crate::{Packet, PrimitiveError};

/// One effect drained from a sans-I/O TCP session, generic over the
/// per-protocol event vocabulary `E` and close-reason vocabulary `C`.
/// Protocol crates alias this over their own vocabularies.
#[derive(Debug)]
pub enum SessionOutput<E, C> {
    /// Bytes the driver must write to the socket in arrival order.
    /// Carried as `Arc<[u8]>` so the driver's capture tap can fan the
    /// same buffer out to both the socket write and the capture writer
    /// task with a refcount bump instead of a full byte-copy — small for
    /// handshake packets, but transfer-side writes are
    /// kilobytes-to-megabytes and the saving compounds.
    Write(Arc<[u8]>),
    /// Domain notification for the application layer.
    Event(E),
    /// Session has reached a terminal state with the given reason. The
    /// matching disconnected event is always queued immediately before
    /// this `Close` — see [`SessionCore::close`].
    Close(C),
}

/// The session scaffolding both TCP protocol sessions embed (ADR-0044):
/// inbound frame buffer, outbound effect queue, and the closed latch.
///
/// Owns the two behaviours that must never fork per protocol — the buffer
/// loop driving [`Packet::decode`] ([`feed`](Self::feed)) and the paired
/// close discipline ([`close`](Self::close)). Everything protocol-shaped
/// (dispatch, states, commands, events, close-reason vocabularies) stays
/// in the embedding session.
pub struct SessionCore<E, C> {
    in_buf: Vec<u8>,
    out_queue: VecDeque<SessionOutput<E, C>>,
    closed: bool,
}

impl<E, C> Default for SessionCore<E, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E, C> SessionCore<E, C> {
    /// An open session with an empty input buffer and nothing queued.
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_buf: Vec::new(),
            out_queue: VecDeque::new(),
            closed: false,
        }
    }

    /// Whether [`close`](Self::close) has latched the session terminal.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Queue a domain event for the application layer.
    pub fn push_event(&mut self, event: E) {
        self.out_queue.push_back(SessionOutput::Event(event));
    }

    /// Queue bytes for the driver to write to the socket.
    pub fn push_write(&mut self, bytes: Arc<[u8]>) {
        self.out_queue.push_back(SessionOutput::Write(bytes));
    }

    /// Drain the next queued effect. Returns `None` when nothing pending.
    pub fn poll_output(&mut self) -> Option<SessionOutput<E, C>> {
        self.out_queue.pop_front()
    }

    /// Queue the paired terminal outputs and latch the core closed.
    ///
    /// On *every* close path the session emits `Event(disconnected)`
    /// immediately before `Close(reason)`, so a consumer always observes
    /// exactly one disconnected event as the last word about the session
    /// (ADR-0023) and the driver never synthesizes one for a
    /// session-originated close. The latch makes the pairing an enforced
    /// invariant: a second `close` is a no-op, and a closed core stops
    /// accepting [`feed`](Self::feed)s. Also discards any partial inbound
    /// frame — nothing will ever decode it.
    pub fn close(&mut self, disconnected: E, reason: C) {
        if self.closed {
            return;
        }
        self.out_queue.push_back(SessionOutput::Event(disconnected));
        self.out_queue.push_back(SessionOutput::Close(reason));
        self.closed = true;
        self.in_buf.clear();
    }

    /// Append bytes from the socket, extract complete frames, and hand
    /// each to `on_packet`. Silently no-ops once the core is closed.
    ///
    /// The loop owns the framing mechanics every TCP session had copied:
    /// a truncated frame stays buffered until more bytes arrive; a frame
    /// that decodes goes to `on_packet`, and the loop stops as soon as a
    /// dispatch closes the core; any other decode error goes to
    /// `on_frame_error` — the per-protocol mapping onto its close-reason
    /// vocabulary, expected to route through the session's own close —
    /// and the loop stops.
    ///
    /// Takes the embedding session plus a `core` projection rather than
    /// `&mut self`, so `on_packet` can dispatch with full access to the
    /// session's protocol state while the loop runs.
    pub fn feed<S>(
        session: &mut S,
        core: fn(&mut S) -> &mut Self,
        bytes: &[u8],
        mut on_packet: impl FnMut(&mut S, Packet),
        on_frame_error: impl FnOnce(&mut S, PrimitiveError),
    ) {
        {
            let this = core(session);
            if this.closed {
                return;
            }
            this.in_buf.extend_from_slice(bytes);
        }
        loop {
            let decoded = Packet::decode(&core(session).in_buf);
            match decoded {
                Ok((packet, consumed)) => {
                    core(session).in_buf.drain(..consumed);
                    on_packet(session, packet);
                    if core(session).closed {
                        return;
                    }
                }
                Err(PrimitiveError::TruncatedPacket { .. }) => return,
                Err(error) => {
                    on_frame_error(session, error);
                    return;
                }
            }
        }
    }
}

/// Collapse a session's `poll_output` into a `Vec` — the drain loop the
/// test tiers hand-rolled per suite (ADR-0044). Call as
/// `session::drain(|| session.poll_output())`.
pub fn drain<O>(mut poll: impl FnMut() -> Option<O>) -> Vec<O> {
    let mut outputs = Vec::new();
    while let Some(output) = poll() {
        outputs.push(output);
    }
    outputs
}
