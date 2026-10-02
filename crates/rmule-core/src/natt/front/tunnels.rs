//! What the **NAT-T Front** does once a punch has opened a path: dial it,
//! settle what the dial or an accept produced, and turn a risen
//! [`Tunnel`] into the ordinary inbound peer it is.
//!
//! The half of the front that owns no signalling. It is split out because its
//! subject is different — the signalling loop reasons about datagrams and
//! budgets, this reasons about one open stream and the three ledgers its life
//! touches: the requester attempt it settles, the **Punched Path** it holds
//! open, and the tunnel registry entry that decides whether a late datagram
//! from that endpoint is injected or dropped.
//!
//! The hand-off into the serve pipeline is here too, in the **adopter task**,
//! because it is the same subject read from the other end: the ledger work
//! belongs to the front's loop and the awaiting belongs off it.
//!
//! The registry entry is the one ledger this file does not settle: the
//! [`Tunnel`] owns it and frees it on drop, so a tunnel the front declines —
//! any IPv6 one — stops being admitted the moment it is dropped here.

use std::sync::Arc;
use std::time::Instant;

use rmule_net::natt::{NattDatagramSink, Tunnel};
use rmule_peer::natt::{RendezvousFailure, RetireReason};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint, UserHash};

use tokio::sync::mpsc;

use crate::adapters::SharedTunnelAdmit;
use crate::address_learning::{ConfidenceTier, EndpointVerdict, SocketRole};
use crate::service::CoreEvent;

use super::dialing::{DIAL_ATTEMPT_TIMEOUT, DialOrder};
use super::expectations::Attribution;
use super::identity::os_punch_jitter;
use super::path_guard::PunchedPathGuard;
use super::{AttemptRetirement, NattFront, Risen};

impl<S: NattDatagramSink> NattFront<S> {
    /// A trigger asks for a Tunnel toward `at` for `peer`: an introduction, a
    /// released burst, or a `0xA1` that may have corrected the port.
    ///
    /// The dial's budget runs from the attempt's Begin; a dial
    /// with no attempt behind it — a responder's — starts its own.
    pub(super) async fn dial(&mut self, peer: UserHash, at: Ipv4Endpoint, now: Instant) {
        let began = self.attempts.began_at(&peer).unwrap_or(now);
        if let Some(order) = self.dials.arm(peer, at, began, now) {
            self.enact_dial(order, now).await;
        }
    }

    /// Carry out one of the schedule's orders.
    pub(super) async fn enact_dial(&mut self, order: DialOrder, now: Instant) {
        match order {
            DialOrder::Dial { peer, at, burst } => {
                // The destination limiter is the acting path's number: a
                // re-dial that cannot burst still dials, because the mapping
                // may well be open anyway.
                if burst
                    && self
                        .bursts
                        .admit(rmule_primitives::AccountingKey::of(at.ip.into()), now)
                {
                    self.fire_burst_only(at).await;
                }
                if !self.spawn_dial(peer, at) {
                    self.dials.skipped(peer);
                }
            }
            DialOrder::Exhausted { peer, dials } => {
                self.wiring.diagnostics.record_natt_attempt_dials(dials);
                // Said aloud, because on the **server coordinator's** path the
                // requester ledger holds nothing to fail: the introduction
                // left through the session, so only the **Traversal Attempt**
                // knows this target was ever being punched at. Without a line
                // here, two minutes of dialing ended in total silence — which
                // is how the server introduction once read as "the front never dialed" while an
                // opener was on the wire.
                tracing::info!(
                    ?peer,
                    dials,
                    "a NAT-T traversal spent its whole budget without a tunnel"
                );
                let step = self.requester.on_failure(
                    &peer,
                    RendezvousFailure::Transport,
                    now,
                    os_punch_jitter(),
                );
                match step {
                    Some(step) => self.act_on_step(peer, step, now).await,
                    // A server-coordinated attempt armed no rendezvous
                    // schedule — its introduction left through the session —
                    // so there is no ledger entry to fail and the spent dial
                    // budget is the whole of its 120 s. Retiring it here is
                    // what carries that back to the download that claimed the
                    // target; without it the claim would hang on
                    // the callback's 30 s deadline alone.
                    None => {
                        self.retire_attempt(
                            peer,
                            AttemptRetirement::Schedule(RetireReason::TimedOut),
                            now,
                        )
                        .await;
                    }
                }
            }
        }
    }

    /// One `connect()`, off the loop and bounded.
    ///
    /// The bound is what makes a re-dial possible at all: `librqbit-utp` sends
    /// the opener once, so a dial that is still pending after
    /// [`DIAL_ATTEMPT_TIMEOUT`] is waiting on a datagram nothing will send
    /// again. Cancelling the future releases the dial's registry slot through
    /// its own guard, so the endpoint is a stranger again until the next opener
    /// leaves.
    ///
    /// Returns whether a dial started.
    fn spawn_dial(&mut self, peer: UserHash, at: Ipv4Endpoint) -> bool {
        let endpoint = PeerEndpoint::V4(at);
        if self.demux.utp().holds(endpoint) {
            // A tunnel is already up on this path; a second handshake would be
            // a second tunnel on one pinhole.
            return false;
        }
        self.wiring.diagnostics.count_natt_dial();
        let demux = Arc::clone(&self.demux);
        let risen = self.risen_tx.clone();
        tokio::spawn(async move {
            let dialed = tokio::time::timeout(DIAL_ATTEMPT_TIMEOUT, demux.utp().connect(endpoint))
                .await
                .map_err(|_| "the punched path answered no opener in time".to_string())
                .and_then(|outcome| outcome.map_err(|error| error.to_string()));
            let outcome = match dialed {
                Ok(tunnel) => Risen::Dialed { tunnel, peer },
                Err(error) => {
                    tracing::debug!(?at, %error, "a NAT-T dial ended without a tunnel");
                    Risen::DialSettled { peer }
                }
            };
            let _ = risen.send(outcome).await;
        });
        true
    }

    /// A dial or an accept settled.
    pub(super) async fn on_risen(&mut self, outcome: Risen, now: Instant) {
        match outcome {
            Risen::Dialed { tunnel, peer } => {
                if let Some(dials) = self.dials.risen(peer) {
                    self.wiring.diagnostics.record_natt_attempt_dials(dials);
                }
                self.adopt(tunnel, Some(peer), now);
            }
            Risen::Accepted { tunnel } => {
                let peer = tunnel
                    .peer()
                    .as_v4()
                    .and_then(|at| self.attribute_accepted(at));
                self.adopt(tunnel, peer, now);
            }
            Risen::DialSettled { peer } => {
                if let Some(order) = self.dials.settled(peer, now) {
                    self.enact_dial(order, now).await;
                }
            }
            Risen::Closed { at } => {
                // The observed address outranks a hint's port the same way it
                // does for an accepted path: the NAT may have
                // remapped it, so the endpoint a hold's burst was aimed at can
                // differ from the one that just closed. A lone pending peer
                // behind the address is still that peer's hold to take;
                // anything less certain falls back to the literal endpoint.
                match self.expectations.attribute(at) {
                    Attribution::Peer(peer) => self.held.cancel_peer(&peer),
                    Attribution::Unexpected | Attribution::Ambiguous => {
                        self.held.cancel_at(at);
                    }
                }
                self.paths.on_path_closed(at);
                self.release_prediction_route(at);
                self.expectations.forget(at);
                // No registry release: the Tunnel inside the guard that sent
                // this notice freed its own slot as it dropped, and an
                // outright release here would also evict a second tunnel a
                // simultaneous open raised on the same endpoint.
            }
            Risen::Identified { peer } => self.identified(peer),
            Risen::Abandoned { peer } => {
                self.requester.abandon(&peer, now);
                self.end_attempt(&peer);
            }
        }
    }

    /// Who an accepted path at `observed` belongs to.
    ///
    /// An address is not a peer: a lone pending peer behind it is
    /// attributed by address alone, port aside — the NAT may have remapped
    /// it, and the observed source is the mapping that demonstrably works
    /// (ADR-0091). With several, only a port match may name
    /// one, and a wrong hash is worse than none: attribution
    /// yields no one, and [`Risen::Identified`] is what a Tunnel's own hello
    /// resolves it to once something downstream reads it.
    pub(super) fn attribute_accepted(&mut self, observed: Ipv4Endpoint) -> Option<UserHash> {
        match self.expectations.attribute(observed) {
            Attribution::Peer(peer) => Some(peer),
            Attribution::Unexpected => None,
            Attribution::Ambiguous => {
                self.wiring.diagnostics.count_natt_tunnel_unattributed();
                tracing::debug!(
                    %observed,
                    "a NAT-T tunnel rose from an address expecting several peers and named \
                     none of them; attributed to none until its hello does"
                );
                None
            }
        }
    }

    /// `peer`'s accepted path is confirmed — by address alone or by a
    /// Tunnel's hello naming them: end their attempt, taking
    /// any hold still waiting to dial them with it. A release after this
    /// would dial a second Tunnel toward a peer the first one already
    /// served.
    pub(super) fn identified(&mut self, peer: UserHash) {
        self.requester.on_tunnel_up(&peer);
        self.end_attempt(&peer);
    }

    /// A Tunnel rose: close the attempt it settles, hold its path open, and
    /// hand it to the serve pipeline as the inbound source it is.
    ///
    /// Everything here touches the ledgers, so it runs on the front's own
    /// loop; the hand-off itself does not, because it awaits a consumer the
    /// front does not drain (the module docs on `front.rs`).
    fn adopt(&mut self, tunnel: Tunnel, peer: Option<UserHash>, now: Instant) {
        let at = tunnel.peer();
        let transport = tunnel.transport();
        let role = tunnel.role();
        // The Tunnel is the attempt's whole purpose: it ends here, with
        // nothing reported to a claimant. The claim is spent downstream by
        // the adoption the hello confirms (ADR-0091).
        if let Some(peer) = peer {
            // Before `identified`: that ends the attempt, and an attempt's end
            // closes its Fans outright, where a Tunnel keeps the one it rides.
            self.end_prediction(&peer, true);
            self.identified(peer);
        }
        self.wiring.diagnostics.record_natt_tunnel(transport, role);
        let Some(path) = at.as_v4() else {
            // Every punch this front aims is IPv4 (the coordinators are), so a
            // tunnel from anywhere else was never one of ours to hold.
            // Dropping it here closes it and frees its registry slot.
            tracing::debug!(%at, "a NAT-T tunnel rose on a path no punch opened; closed");
            return;
        };
        if let Some(pin) = self.paths.on_path_open(
            path,
            self.client_udp_port().unwrap_or(0),
            self.granted_external_port(),
            now,
        ) {
            self.wiring.peer_pin.request(pin);
        }
        let guard = PunchedPathGuard::new(tunnel, path, self.risen_tx.clone());
        // Who this tunnel was *aimed at* is knowledge only this front holds,
        // and only for a tunnel it dialed: the requester ledger and the `0x61`
        // introduction are both keyed by the target's hash, while a tunnel we
        // accepted was aimed at us by somebody else. It travels with the
        // stream so a download that claimed that target can adopt it
        // downstream, where the hello is and where the gates already are
        // (ADR-0091). The guard rides along either way — the path's close
        // notice belongs to whoever ends up holding the connection.
        let dialed_toward = (role == rmule_net::peer::PeerStreamRole::Dialer)
            .then_some(peer)
            .flatten();
        // `try_send`, never `send`: a backlog this deep means the serve
        // pipeline has stopped draining altogether, and one tunnel closed is a
        // far cheaper answer than a front that stops feeding the demux. The
        // refused `Adoption` drops here, which closes the tunnel and hands the
        // path back through the guard's own notice.
        if let Err(refused) = self.adopt_tx.try_send(Adoption {
            guard,
            at,
            role,
            transport,
            dialed_toward,
        }) {
            self.wiring.diagnostics.count_natt_adoption_dropped();
            tracing::warn!(
                %at,
                ?transport,
                ?role,
                backlogged = matches!(refused, tokio::sync::mpsc::error::TrySendError::Full(_)),
                "a risen NAT-T tunnel could not be handed to the serve pipeline; closed"
            );
        }
    }

    /// The client-UDP port a punch left from — what a pin names as its
    /// internal port.
    fn client_udp_port(&self) -> Option<u16> {
        self.wiring
            .addresses
            .bind(SocketRole::Udp)
            .map(|(_, port)| port)
    }

    /// The external port a **Mapping Grant** reported for the client-UDP bind,
    /// when one did. Suggesting it keeps a pin on the mapping the peer is
    /// already talking to rather than minting a second.
    fn granted_external_port(&self) -> Option<u16> {
        match self
            .wiring
            .addresses
            .endpoint(AddressFamily::V4, SocketRole::Udp)
        {
            EndpointVerdict::Known {
                endpoint,
                tier: ConfidenceTier::MappingGrant,
            } => Some(endpoint.port()),
            EndpointVerdict::Known { .. }
            | EndpointVerdict::Stale { .. }
            | EndpointVerdict::Unknown => None,
        }
    }
}

/// How many risen Tunnels wait for the **adopter task** before the front
/// closes one rather than stall. Generous against the accept channel's own 16:
/// a backlog this deep means the serve pipeline has not drained a single
/// admission while the whole node's punched paths rose, which is a stalled
/// node rather than a busy one.
pub(super) const ADOPT_BACKLOG_LEN: usize = 32;

/// One risen Tunnel on its way into the serve pipeline: everything the admit
/// seam needs, and nothing the ledgers still own.
///
/// It exists because the hand-off *awaits* — the accept channel is bounded and
/// drained by the serve runner — and the front's loop may not (see the module
/// docs). The guard travels inside, so a hand-off that is refused closes the
/// tunnel and releases its path by the ordinary `Drop`.
pub(super) struct Adoption {
    guard: PunchedPathGuard<Tunnel>,
    at: PeerEndpoint,
    role: rmule_net::peer::PeerStreamRole,
    transport: rmule_net::natt::TunnelTransport,
    /// The target hash a dial was aimed at, for the download that claimed it.
    dialed_toward: Option<UserHash>,
}

/// The **adopter task**: the one place the serve accept channel is awaited.
///
/// It is a task of its own for the same reason the uTP accept pump is: the
/// front's loop must stay free to feed the demux (see the module docs). It
/// keeps the hand-off ordered, and it ends when the front does — its sender
/// lives on the front, so a dropped front closes this channel.
pub(super) fn spawn_adopter(
    mut adoptions: mpsc::Receiver<Adoption>,
    admit: SharedTunnelAdmit,
    events: Option<mpsc::WeakSender<CoreEvent>>,
) {
    tokio::spawn(async move {
        while let Some(adoption) = adoptions.recv().await {
            let Adoption {
                guard,
                at,
                role,
                transport,
                dialed_toward,
            } = adoption;
            // Reported from here rather than from the loop for the same
            // reason: the event bus is the core actor's to drain.
            if let Some(events) = events.as_ref().and_then(mpsc::WeakSender::upgrade) {
                let _ = events
                    .send(CoreEvent::NattTunnelRisen {
                        peer: at,
                        transport,
                        role,
                    })
                    .await;
            }
            let admitted = match dialed_toward {
                Some(target) => admit.admit_dialed_toward(guard, at, role, target).await,
                None => admit.admit(guard, at, role).await,
            };
            match admitted {
                Ok(()) => {
                    tracing::info!(%at, ?transport, ?role, "NAT-T tunnel entered the serve pipeline");
                }
                Err(refusal) => {
                    // Dropping the guard closes the tunnel and releases its path.
                    tracing::info!(%at, ?refusal, "a risen NAT-T tunnel had nowhere to go; closed");
                }
            }
        }
    });
}
