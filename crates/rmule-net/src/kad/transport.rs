//! Where one Kad driver's datagrams enter and leave — the seam that lets the
//! same loop run on a socket of its own or on a socket somebody else owns
//! (ADR-0057's socket unification).
//!
//! Two transports, one driver. A **standalone** node (the `rmule-tools` Kad
//! drivers, the Kad **Stimulus Node**, the mesh sim, a loopback test) binds a
//! **Family Pair** of its own and owns it. A node running **inside a core**
//! binds nothing: an eMule-family client runs Kad and client-UDP on one UDP
//! socket, so the core's client-UDP demux front feeds this inlet and every
//! answer leaves by that same bind. That is what makes the mapping a buddy
//! observed at the `0x51` recruit the mapping a NAT-T punch can reach.
//!
//! Kad is IPv4-only end to end (ADR-0085/0087), so the seam speaks
//! [`Ipv4Endpoint`] and nothing else: the pair's `::` socket has no Kad
//! dialect to feed, and the core's front never routes a Kad datagram off the
//! IPv6 half.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};
use tokio::sync::mpsc;

use crate::ed2k::ClientUdpSocket;
use crate::family::UdpFamilyPair;

/// One inbound Kad datagram: the IPv4 endpoint it truly came from, and its
/// bytes exactly as they arrived — still obfuscated if the sender obfuscated
/// them, because only [`KadNode`](rmule_kad::KadNode)'s own keys can tell.
pub type KadDatagram = (Ipv4Endpoint, Vec<u8>);

/// How many inbound datagrams a core's Kad inlet holds before one is dropped.
///
/// Deep, and filled with `try_send` rather than awaited, for the reason the
/// NAT-T inbox is: the feeding task drains a socket every reask, every NAT-T
/// frame and every Kad datagram shares, so a Kad node that falls behind must
/// cost its own datagrams and nothing else. A full inlet costs one datagram —
/// which is what a lossy UDP path does anyway, and every Kad request is
/// retried — never a stalled front.
pub const KAD_INLET_CAPACITY: usize = 256;

/// A core's already-bound client-UDP socket, as a Kad transport (ADR-0057).
///
/// Inbound is a queue the demux front fills; outbound is the socket itself,
/// held behind the same `Arc` the front and the reply drain hold, so a Kad
/// answer leaves by the port a counterparty observed us at.
pub struct KadInlet {
    /// Datagrams the client-UDP front classified as Kad. Closing it (the
    /// socket's front is gone) ends the driver.
    pub datagrams: mpsc::Receiver<KadDatagram>,
    /// The bind every Kad datagram leaves by — the one the front drains.
    pub socket: Arc<ClientUdpSocket>,
    /// Where this node's traffic across the shared bind is counted. The
    /// caller keeps a clone to read it while the node runs.
    pub traffic: KadTraffic,
}

/// The live traffic counters of a Kad node on a core's shared bind: every
/// datagram the client-UDP demux hands it and every datagram it writes to the
/// bind, with their sizes **as they cross the wire** — an obfuscated datagram
/// counts its crypt header and padding, because the count is taken outside
/// the node's own crypt on both sides. Monotonic; a clone reads the same
/// cells.
#[derive(Clone, Debug, Default)]
pub struct KadTraffic(Arc<TrafficCells>);

#[derive(Debug, Default)]
struct TrafficCells {
    datagrams_in: AtomicU64,
    bytes_in: AtomicU64,
    datagrams_out: AtomicU64,
    bytes_out: AtomicU64,
}

/// One reading of a [`KadTraffic`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KadTrafficTotals {
    /// Datagrams the demux handed the node.
    pub datagrams_in: u64,
    /// Their wire bytes.
    pub bytes_in: u64,
    /// Datagrams the node wrote to the bind (a failed send is not counted).
    pub datagrams_out: u64,
    /// Their wire bytes.
    pub bytes_out: u64,
}

impl KadTraffic {
    fn record(datagrams: &AtomicU64, bytes: &AtomicU64, len: usize) {
        datagrams.fetch_add(1, Ordering::Relaxed);
        bytes.fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// The totals so far.
    #[must_use]
    pub fn totals(&self) -> KadTrafficTotals {
        let cells = &*self.0;
        KadTrafficTotals {
            datagrams_in: cells.datagrams_in.load(Ordering::Relaxed),
            bytes_in: cells.bytes_in.load(Ordering::Relaxed),
            datagrams_out: cells.datagrams_out.load(Ordering::Relaxed),
            bytes_out: cells.bytes_out.load(Ordering::Relaxed),
        }
    }
}

/// The transport one driver run is bound to.
pub(crate) enum KadTransport {
    /// The driver bound the socket and owns it — the standalone node.
    Owned(UdpFamilyPair),
    /// The core owns the socket and feeds the driver — the unified node.
    Shared(KadInlet),
    /// Test-only: receive outcomes scripted rather than a real socket's
    /// (`kad::driver::tests`) — exercises the driver's consecutive-error
    /// budget deterministically, without a socket that can be made to fail
    /// on demand.
    #[cfg(test)]
    Scripted(ScriptedTransport),
}

/// What one [`KadTransport::recv`] produced. Every arm is a decision the
/// driver takes identically on both transports, which is what keeps the two
/// from drifting into two loops.
pub(crate) enum KadReceive {
    /// A datagram, copied into the caller's scratch.
    Datagram {
        /// Its IPv4 source — the contact a Kad answer goes back to.
        from: Ipv4Endpoint,
        /// How many bytes of the scratch it filled.
        len: usize,
    },
    /// A datagram from a non-IPv4 source, counted and dropped before the node
    /// ever saw it. Only an owned pair can produce one: the core's front rules
    /// on family before the inlet.
    NonIpv4,
    /// A receive error (an ICMP port-unreachable surfacing on some
    /// platforms). The driver tolerates a run of these — the network is
    /// lossy — up to [`ReceiveErrorBudget`](crate::family::ReceiveErrorBudget);
    /// beyond it, the *driver* (not this transport) ends the run.
    /// Carries the error's kind so the driver's budget can name it.
    Transient(std::io::ErrorKind),
    /// The transport is gone for good — the core's front dropped its sender.
    /// The driver ends; it must never poll a closed channel again (a closed
    /// channel ends the task, it does not busy-spin).
    Closed,
}

impl KadTransport {
    /// The next datagram, copied into `scratch`.
    ///
    /// Cancel-safe on both arms — `UdpFamilyPair::recv` selects on readiness
    /// and `mpsc::Receiver::recv` leaves an unconsumed message queued — so it
    /// may sit in the driver's `select!` beside the command and timer arms.
    pub(crate) async fn recv(&mut self, scratch: &mut [u8]) -> KadReceive {
        match self {
            Self::Owned(pair) => match pair.recv(scratch).await {
                Ok((len, PeerEndpoint::V4(from))) => KadReceive::Datagram { from, len },
                Ok((_, from @ PeerEndpoint::V6(_))) => {
                    tracing::debug!(%from, "dropping non-IPv4 Kad datagram");
                    KadReceive::NonIpv4
                }
                Err(error) => {
                    tracing::debug!(%error, "transient Kad UDP receive error");
                    KadReceive::Transient(error.kind())
                }
            },
            Self::Shared(inlet) => match inlet.datagrams.recv().await {
                Some((from, bytes)) => {
                    let cells = &*inlet.traffic.0;
                    KadTraffic::record(&cells.datagrams_in, &cells.bytes_in, bytes.len());
                    // A UDP datagram cannot exceed the driver's 64 KiB
                    // scratch, so the clamp only ever guards against a caller
                    // that shrank it.
                    let len = bytes.len().min(scratch.len());
                    scratch[..len].copy_from_slice(&bytes[..len]);
                    KadReceive::Datagram { from, len }
                }
                None => KadReceive::Closed,
            },
            #[cfg(test)]
            Self::Scripted(scripted) => scripted.recv(scratch).await,
        }
    }

    /// Send one datagram to an IPv4 contact.
    ///
    /// # Errors
    /// Whatever the socket returned; UDP send errors are as transient as
    /// receive errors and the protocol tolerates the loss.
    pub(crate) async fn send_to(&self, to: Ipv4Endpoint, datagram: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Owned(pair) => pair.send_to(PeerEndpoint::V4(to), datagram).await,
            Self::Shared(inlet) => {
                inlet
                    .socket
                    .send_to_peer(PeerEndpoint::V4(to), datagram)
                    .await?;
                let cells = &*inlet.traffic.0;
                KadTraffic::record(&cells.datagrams_out, &cells.bytes_out, datagram.len());
                Ok(())
            }
            #[cfg(test)]
            Self::Scripted(_) => Ok(()),
        }
    }

    /// The UDP port this node listens and advertises on — its own bind, or the
    /// core's unified one.
    pub(crate) fn local_port(&self) -> u16 {
        match self {
            Self::Owned(pair) => pair.local_port(),
            Self::Shared(inlet) => inlet.socket.local_port(),
            #[cfg(test)]
            Self::Scripted(_) => 0,
        }
    }
}

/// A test-only, deterministic stand-in for [`KadTransport::Owned`]'s receive
/// side: a fixed script of `Ok(())` (a receive) / `Err(kind)` (an error)
/// outcomes, replayed in order. Once exhausted, the last entry repeats
/// forever — so "N-1 errors then a receive" and "errors forever" are both a
/// short, fixed list. Exists because forcing a *real* socket to fail
/// on demand needs platform-specific tricks this crate has no other reason
/// to carry.
#[cfg(test)]
pub(crate) struct ScriptedTransport {
    script: Vec<Result<(), std::io::ErrorKind>>,
    cursor: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl ScriptedTransport {
    /// `script` must not be empty — an empty script has no "last entry" to
    /// repeat.
    pub(crate) fn new(script: Vec<Result<(), std::io::ErrorKind>>) -> Self {
        assert!(
            !script.is_empty(),
            "a scripted transport needs at least one outcome"
        );
        Self {
            script,
            cursor: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    async fn recv(&self, scratch: &mut [u8]) -> KadReceive {
        let index = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .min(self.script.len() - 1);
        match self.script[index] {
            Ok(()) => {
                // A real socket's receive always yields to the runtime at
                // least once (it awaits readiness); a script that "receives
                // forever" must too, or it becomes the very hot loop these
                // tests exist to rule out, just on the success arm instead of
                // the error one.
                tokio::task::yield_now().await;
                // The bytes are never real Kad wire content — the driver's
                // own receive-side bookkeeping is what these tests exercise,
                // not `KadNode`'s decode, so a node failing to parse this is
                // the expected (and harmless) outcome.
                let filler = [0u8; 4];
                let len = filler.len().min(scratch.len());
                scratch[..len].copy_from_slice(&filler[..len]);
                KadReceive::Datagram {
                    from: Ipv4Endpoint::new(std::net::Ipv4Addr::LOCALHOST, 4000),
                    len,
                }
            }
            Err(kind) => KadReceive::Transient(kind),
        }
    }
}
