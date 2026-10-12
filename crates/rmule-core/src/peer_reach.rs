//! **Peer Reach** (ADR-0061, ADR-0091): the one module that reaches a peer.
//!
//! Its one call, [`PeerReacher::reach`], reads our **Route Position** from
//! **Self Reach**, asks the route tree ([`crate::callback`]) for the road,
//! carries the road out — a direct `0x95`, a buddy `0x52` or its **Callback
//! Walk**, or rung 1 handed whole to the **NAT-T Front** — and reports the road
//! taken on the event bus. It is built over handles the core already shares:
//! Self Reach, the client-UDP send half, the NAT-T Front's and the Kad pump's
//! mailboxes, the self-facts, diagnostics and the event bus.
//!
//! Two callers end in it, and they differ only in what they bring. An
//! operator's `ReachPeer` brings the peer and nothing to retire: the tree picks
//! the first road. A download's Low-ID candidate brings its **Pending
//! Callback** — the road its brain already chose, and the retire channel a road
//! that never opens is answered on, so the candidate's slot goes to its next
//! road at once rather than waiting out a deadline for an ask that never left.

use rmule_primitives::{AddressFamily, ClientId, FileHash, Ipv4Endpoint};
use tokio::sync::mpsc;

use crate::adapters::{CallbackKey, SharedKadPump};
use crate::address_learning::{AdvertReachability, SocketRole};
use crate::callback::{
    DownloadAsk, PendingCallback, callback_target, select_callback_route, select_natt_for_download,
};
use crate::client_udp::ClientUdpSend;
use crate::diagnostics::{DiagnosticsState, NattRetirement};
use crate::natt::front::{AttemptCoordinator, AttemptOwner, NattCommand, SharedNattFront};
use crate::own_identity::SharedOwnIdentity;
use crate::reachability::SharedSelfReach;
use crate::service::{
    CoreEvent, NatTraversalUnavailableReason, PeerReach, PeerReachDropReason, PeerReachRoute,
};

#[cfg(test)]
mod tests;

/// The shared handles **Peer Reach** is built over.
pub(crate) struct PeerReachWiring {
    /// **Self Reach**: our route position, read at each reach, never copied,
    /// and the port our listener answers on.
    pub(crate) reach: SharedSelfReach,
    /// The one bound client-UDP send half the `0x95` rides; `None` when the
    /// socket did not bind.
    pub(crate) client_udp: Option<mpsc::Sender<ClientUdpSend>>,
    /// The **NAT-T Front**'s command half: rung 1 is handed over there whole.
    pub(crate) natt: SharedNattFront,
    /// The running Kad node's mailbox: the buddy `0x52` and the Callback Walk.
    pub(crate) kad_pump: SharedKadPump,
    /// Our self-facts: the user hash a callback and a rendezvous name, and the
    /// **Advertised Endpoints** a callback invites a dial to.
    pub(crate) own: SharedOwnIdentity,
    /// The one obfuscation policy, whose stance a callback's and a
    /// rendezvous's connect-options byte states — read at each reach, so a
    /// live change reaches the next one (ADR-0046).
    pub(crate) obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy,
    pub(crate) diagnostics: DiagnosticsState,
    /// Where each road taken is reported.
    pub(crate) events: mpsc::Sender<CoreEvent>,
}

/// **Peer Reach** itself: one per core, owned by the actor.
pub(crate) struct PeerReacher {
    wiring: PeerReachWiring,
}

impl PeerReacher {
    pub(crate) fn new(wiring: PeerReachWiring) -> Self {
        Self { wiring }
    }

    /// Reach `peer`: read our position, choose the road, carry it out and
    /// report the road taken as a [`CoreEvent::PeerReachRouted`].
    ///
    /// `retire` is the download's **Pending Callback** — the road its brain
    /// opened and where a road that never opens is answered — or `None` for
    /// an operator's `ReachPeer`, which holds nothing to release.
    ///
    /// A download's punch that no coordinator can introduce is reported as
    /// [`PeerReachRoute::Dropped`] with
    /// [`PeerReachDropReason::NoCoordinator`]. It is also counted and its
    /// candidate is retired at once — **a refusal is answered, not
    /// swallowed**: no attempt opened, so the one owner that would report its
    /// end never exists.
    pub(crate) async fn reach(
        &self,
        peer: &PeerReach,
        retire: Option<PendingCallback>,
    ) -> PeerReachRoute {
        let route = self.road(peer, retire).await;
        tracing::debug!(peer = ?peer.tcp, ?route, "peer reach routed (ADR-0061)");
        let _ = self
            .wiring
            .events
            .send(CoreEvent::PeerReachRouted {
                peer: peer.tcp,
                route,
            })
            .await;
        route
    }

    /// Choose the road for `peer` and carry it out.
    async fn road(&self, peer: &PeerReach, pending: Option<PendingCallback>) -> PeerReachRoute {
        let Some(pending) = pending else {
            let chosen =
                select_callback_route(&callback_target(peer), &self.wiring.reach.route_position());
            return self.enact(chosen, peer, None).await;
        };
        let retire = Retire {
            key: pending.key,
            tx: pending.retire_tx,
        };
        match pending.road {
            DownloadAsk::BuddyCallback { file_hash } => {
                self.buddy_callback(peer, file_hash, retire)
            }
            DownloadAsk::DirectUdp => self.direct_udp_for_download(peer, &retire).await,
            DownloadAsk::Traversal(silence) => {
                let Some(chosen) = select_natt_for_download(
                    &callback_target(peer),
                    &self.wiring.reach.route_position(),
                    &silence,
                ) else {
                    // Counted, not only traced: a run of these is the
                    // difference between "traversal is failing" and "nothing
                    // could be asked".
                    self.wiring.diagnostics.count_natt_download_no_coordinator();
                    tracing::debug!(
                        peer = ?peer.tcp,
                        ?silence,
                        "a download's Low-ID candidate has no NAT-T coordinator (ADR-0091 rung 1)"
                    );
                    retire.unopened(NattRetirement::NoCoordinator);
                    return PeerReachRoute::Dropped {
                        reason: PeerReachDropReason::NoCoordinator,
                    };
                };
                self.enact(chosen, peer, Some(&retire)).await
            }
        }
    }

    /// Carry out the route the tree `chosen`, reporting what actually went on
    /// the wire. Shared by both callers, so a fallback punch is handed over by
    /// exactly the code a first-choice one is.
    async fn enact(
        &self,
        chosen: PeerReachRoute,
        peer: &PeerReach,
        retire: Option<&Retire>,
    ) -> PeerReachRoute {
        match chosen {
            // Route 2 (ADR-0061): the `0x95` rides the one bound client-UDP
            // send half, the same drain the serve reply matrix and the
            // downloader's reask use.
            PeerReachRoute::DirectUdp { target_kad_udp } => {
                self.direct_udp_callback(target_kad_udp).await
            }
            PeerReachRoute::ServerPunch { low_id } => {
                self.traverse_through_server(peer, low_id, retire)
            }
            PeerReachRoute::NatTraversal {
                buddy_id,
                buddy_udp,
            } => self.rendezvous(peer, buddy_id, buddy_udp, retire),
            // A rendezvous toward a buddy named by ID alone begins nothing.
            // Unlike the buddy-callback road's `0x52`, `OP_REASKCALLBACKUDP`
            // (`0x94`) has no dialect-sanctioned walk toward an ID alone:
            // eMuleAI's own unknown-buddy-IP fallback (`BaseClient.cpp:3273-3323`,
            // eMuleAI v1.6 `a2f05dc`) never resolves a `0x94` endpoint — it
            // asks the target directly, then falls back to the *old* aMule
            // `FINDSOURCE`/`0x52` lookup (the Callback Walk's own shape), which
            // the fallback's own author calls a should-not-happen path ("bad
            // luck, as lookups aren't supposed to happen anyway",
            // `:3311-3315`). So the candidate retires at once instead of
            // holding its slot for a walk the dialect never sends.
            PeerReachRoute::NatTraversalUnavailable {
                reason: NatTraversalUnavailableReason::BuddyEndpointUnknown,
                ..
            } => {
                if let Some(retire) = retire {
                    retire.unopened(NattRetirement::CoordinatorEndpointUnknown);
                }
                chosen
            }
            // A dial is the caller's and a server callback is our server's
            // relay; a `ReachPeer`'s buddy route names no file, and the `0x52`
            // must (a download's own ask carries one); a drop is a drop.
            PeerReachRoute::Direct { .. }
            | PeerReachRoute::Server { .. }
            | PeerReachRoute::Buddy { .. }
            | PeerReachRoute::CallbackWalk { .. }
            | PeerReachRoute::DirectUdpUnavailable { .. }
            | PeerReachRoute::ServerPunchUnavailable { .. }
            | PeerReachRoute::NatTraversalUnavailable { .. }
            | PeerReachRoute::Dropped { .. } => chosen,
        }
    }

    /// Rung 1 through the server coordinator (ADR-0091): hand the **NAT-T
    /// Front** the traversal, which puts the `0x60` on our session and owns
    /// what becomes of it.
    ///
    /// A punch nobody owns ends here for its candidate: a front that never
    /// took the traversal sends nothing at all (`NotEnactable`, and the route
    /// says the punch was unavailable), and a target with no user hash — a
    /// plain `0x42` source — still gets its `0x60`, since the server needs only
    /// the id, but no attempt to own it, so its candidate hears `NotEnactable`
    /// at once. Otherwise a callback beside it would hold its slot to the
    /// traversal bound (~137 s) instead of its own 30 s.
    fn traverse_through_server(
        &self,
        peer: &PeerReach,
        low_id: ClientId,
        retire: Option<&Retire>,
    ) -> PeerReachRoute {
        let owner = self.attempt_owner(peer);
        if !self.wiring.natt.send(NattCommand::Traverse {
            coordinator: AttemptCoordinator::Server { low_id },
            owner,
        }) {
            if let Some(retire) = retire {
                retire.unopened(NattRetirement::NotEnactable);
            }
            return PeerReachRoute::ServerPunchUnavailable { low_id };
        }
        if owner.is_none()
            && let Some(retire) = retire
        {
            retire.unopened(NattRetirement::NotEnactable);
        }
        PeerReachRoute::ServerPunch { low_id }
    }

    /// Rung 1 through the target's Kad serving buddy (ADR-0091): hand the
    /// **NAT-T Front** the traversal, which opens the **Traversal Attempt**,
    /// arms its rendezvous schedule and emits what the schedule asks for.
    ///
    /// The datagram is framed there rather than here for one reason: the
    /// *retries* belong to the ledger, and a second emitter would put attempts
    /// on the wire the budget never granted. What comes after — the endpoint
    /// hint, the burst, the Tunnel — is driven by what arrives on the
    /// client-UDP front. An anonymous candidate begins nothing: the ledger is
    /// keyed by the target's hash and a hint names it, so it could never be
    /// matched to its own answer.
    fn rendezvous(
        &self,
        peer: &PeerReach,
        buddy_id: crate::KadId,
        buddy_udp: Ipv4Endpoint,
        retire: Option<&Retire>,
    ) -> PeerReachRoute {
        let unavailable = |reason| {
            if let Some(retire) = retire {
                retire.unopened(NattRetirement::NotEnactable);
            }
            PeerReachRoute::NatTraversalUnavailable { buddy_id, reason }
        };
        if peer.user_hash.is_none() {
            return unavailable(NatTraversalUnavailableReason::TargetIdentityUnknown);
        }
        let Some(owner) = self.attempt_owner(peer) else {
            return unavailable(NatTraversalUnavailableReason::NotEnactable);
        };
        if !self.wiring.natt.send(NattCommand::Traverse {
            coordinator: AttemptCoordinator::Buddy {
                buddy_id: *buddy_id.as_bytes(),
                buddy_udp,
            },
            owner: Some(owner),
        }) {
            return unavailable(NatTraversalUnavailableReason::NotEnactable);
        }
        tracing::info!(
            ?buddy_udp,
            claimed = ?owner.offer.claimed_endpoint,
            "rendezvous handed to the NAT-T front toward the target's serving buddy (ADR-0091 rung 1)"
        );
        PeerReachRoute::NatTraversal {
            buddy_id,
            buddy_udp,
        }
    }

    /// The **Traversal Attempt** that owns a traversal toward `peer`, when
    /// both facts it is keyed and framed by are known: the target's **User
    /// Hash** — what a hint and a risen Tunnel are matched by — and our own,
    /// which every rendezvous names. Neither can be guessed.
    ///
    /// What we claim about ourselves is the **Advertised Endpoints** chooser's
    /// client-UDP verdict — or nothing: a null claim is legal, the buddy
    /// injects the source it observed, and a guess here would be the one
    /// address in the exchange nobody checked.
    fn attempt_owner(&self, peer: &PeerReach) -> Option<AttemptOwner> {
        let (Some(target), Some(our_user_hash)) = (peer.user_hash, self.wiring.own.user_hash())
        else {
            tracing::debug!(
                target_known = peer.user_hash.is_some(),
                "a NAT traversal with no attempt to own it: an identity is missing"
            );
            return None;
        };
        Some(AttemptOwner {
            target,
            facts: callback_target(peer).natt_facts(),
            offer: crate::natt::RendezvousOffer {
                our_user_hash,
                // uTP only: ADR-0091 keeps QUIC dark until a live handshake
                // with another implementation is proven, and this byte follows
                // bit 4.
                options: rmule_peer::natt::NattConnectOptions::advertise(
                    self.connect_options(),
                    true,
                    false,
                ),
                file_hash: None,
                claimed_endpoint: self
                    .wiring
                    .own
                    .addresses()
                    .advertised_endpoints(AdvertReachability::unproven())
                    .endpoint(AddressFamily::V4, SocketRole::Udp)
                    .and_then(|endpoint| endpoint.as_v4()),
                transport: rmule_peer::natt::NattTransport::Utp,
            },
        })
    }

    /// ADR-0061 route 4 for a download's Kad source: the `0x52` to `peer`'s
    /// buddy, naming `file_hash` and the port we are to be dialed on.
    ///
    /// Nothing leaves without our own facts — a running Kad node to send from
    /// and a port to be dialed on — and the route says whether it did. A buddy
    /// the row named by ID alone is walked toward first (aMule's `FINDSOURCE`
    /// branch at `BaseClient.cpp:2160-2170`): the **Callback Walk** sends the
    /// same `0x52` body to the responders near that ID, and reports a walk that
    /// met nobody on the download's retire channel. A known endpoint never
    /// starts a walk, exactly as aMule's `GetBuddyIP() && GetBuddyPort()` test
    /// at `:2134` decides.
    ///
    /// **With no Kad node running, neither sub-case can leave, and the
    /// candidate retires at once instead of holding its slot for thirty
    /// seconds**: aMule checks `Kademlia::CKademlia::IsConnected()` once, ahead
    /// of both its known-endpoint `0x52` and its `FINDSOURCE` walk, and calls
    /// `RemoveSource` the instant it is false (`BaseClient.cpp:2123-2130`, "Kad
    /// Firewalled source but not connected to Kad"). "Kad running" is the
    /// route position's own fact — not the pump's mailbox, which a socket-free
    /// test factory never populates even while it stands in for a live node.
    fn buddy_callback(
        &self,
        peer: &PeerReach,
        file_hash: FileHash,
        retire: Retire,
    ) -> PeerReachRoute {
        let Some(buddy) = peer.buddy else {
            retire.unopened(NattRetirement::CallbackNotSent);
            return PeerReachRoute::Dropped {
                reason: PeerReachDropReason::NoBuddy,
            };
        };
        let unsent = PeerReachRoute::Buddy {
            buddy_id: buddy.buddy_id,
            emitted_to: None,
        };
        if !self.wiring.reach.kad_running() {
            retire.unopened(NattRetirement::KadNotRunning);
            tracing::info!(
                buddy_id = ?buddy.buddy_id,
                "buddy-callback road retired at once: no Kad node running"
            );
            return unsent;
        }
        let Some(tcp_port) = self.our_tcp_port() else {
            retire.unopened(NattRetirement::CallbackNotSent);
            tracing::debug!(
                buddy_id = ?buddy.buddy_id,
                "buddy callback not sent: no listener port to name"
            );
            return unsent;
        };
        // A pump that refused the ask (its task gone, or its mailbox full) is
        // not retired here: the socket-free Kad factories the integration legs
        // run on never install a pump, and their publisher dials back
        // unprompted. The callback's own deadline bounds that slot.
        let emitted_to = match buddy.buddy_udp {
            Some(buddy_udp) => crate::adapters::request_kad_buddy_callback(
                &self.wiring.kad_pump,
                crate::adapters::BuddyCallbackAsk {
                    buddy_udp,
                    buddy_id: buddy.buddy_id,
                    file_hash,
                    tcp_port,
                },
            )
            .then_some(buddy_udp),
            None => {
                if crate::adapters::request_kad_callback_walk(
                    &self.wiring.kad_pump,
                    crate::adapters::CallbackWalkAsk {
                        buddy_id: buddy.buddy_id,
                        file_hash,
                        tcp_port,
                        reply: crate::adapters::CallbackWalkReply {
                            key: retire.key,
                            retire_tx: retire.tx,
                        },
                    },
                ) {
                    tracing::info!(
                        buddy_id = ?buddy.buddy_id,
                        "callback walk toward a buddy named by ID alone"
                    );
                    return PeerReachRoute::CallbackWalk {
                        buddy_id: buddy.buddy_id,
                    };
                }
                None
            }
        };
        tracing::info!(
            ?emitted_to,
            buddy_id = ?buddy.buddy_id,
            "buddy callback (0x52, ADR-0061 route 4) for a download's Kad source"
        );
        PeerReachRoute::Buddy {
            buddy_id: buddy.buddy_id,
            emitted_to,
        }
    }

    /// A download candidate's direct-UDP road: the `0x95` toward the
    /// candidate's own Kad UDP endpoint, and — when it cannot leave, for want
    /// of that endpoint or of any fact of ours the `0x95` needs — the road's
    /// end reported at once, so the slot goes to the next road rather than
    /// waiting thirty seconds on an invitation nobody sent. `LowIdRoad::of`
    /// never opens this road without an endpoint, but the guard here is our
    /// own, since the brain's invariant crosses a channel this module cannot
    /// see.
    async fn direct_udp_for_download(&self, peer: &PeerReach, retire: &Retire) -> PeerReachRoute {
        let routed = match peer.kad_udp {
            Some(target_kad_udp) => self.direct_udp_callback(target_kad_udp).await,
            None => PeerReachRoute::Dropped {
                reason: PeerReachDropReason::NoKadUdpEndpoint,
            },
        };
        if !matches!(routed, PeerReachRoute::DirectUdp { .. }) {
            retire.unopened(NattRetirement::CallbackNotSent);
        }
        routed
    }

    /// The ADR-0061 **direct UDP callback** (route 2): frame the
    /// `OP_DIRECTCALLBACKREQ` (`0x95`) and put it on the bound client-UDP send
    /// half, addressed to the target's Kad UDP endpoint.
    ///
    /// **Not gated on Kad running**: aMule's own branch for it
    /// (`BaseClient.cpp:2043-2050`, `HasLowID() && SupportsDirectUDPCallback()
    /// && GetEffectiveUDPPort() != 0 && GetConnectIP() != 0`) carries no
    /// `Kademlia::CKademlia::IsConnected()` test — that check belongs only to
    /// the LowID branch below it, ahead of the buddy callback and its walk.
    ///
    /// Three of our own facts must hold, and each missing one reports
    /// [`PeerReachRoute::DirectUdpUnavailable`] rather than emitting a callback
    /// the target could not act on:
    ///
    /// * the client-UDP send half is bound — there is no other socket to send
    ///   from;
    /// * a serve listener is up **and has bound**, because the body names the
    ///   port the target will dial back on (aMule's own body carries
    ///   `thePrefs::GetPort()`), and a callback naming a port nothing answers
    ///   on — the requested 0 of an OS-chosen bind included — is a dead
    ///   invitation;
    /// * our user hash is known — it is how the target matches the dial-back
    ///   to this invitation (`CClientList::GetClientsByHash`).
    async fn direct_udp_callback(&self, target_kad_udp: Ipv4Endpoint) -> PeerReachRoute {
        let unavailable = PeerReachRoute::DirectUdpUnavailable { target_kad_udp };
        let (Some(client_udp), Some(our_tcp_port), Some(our_user_hash)) = (
            self.wiring.client_udp.as_ref(),
            self.our_tcp_port(),
            self.wiring.own.user_hash(),
        ) else {
            tracing::debug!(
                ?target_kad_udp,
                udp_bound = self.wiring.client_udp.is_some(),
                listening = self.wiring.reach.listener_port().is_some(),
                "direct UDP callback (0x95) chosen but not enactable (ADR-0061 route 2)"
            );
            return unavailable;
        };
        let connect_options = self.connect_options();
        let (to, datagram) = rmule_peer::peer_udp::crypt::direct_callback(
            target_kad_udp,
            our_tcp_port,
            our_user_hash,
            connect_options,
        );
        if client_udp
            .send(ClientUdpSend::plaintext(to, datagram))
            .await
            .is_err()
        {
            return unavailable;
        }
        tracing::info!(
            ?target_kad_udp,
            our_tcp_port,
            connect_options,
            "direct UDP callback emitted (0x95, ADR-0061 route 2)"
        );
        PeerReachRoute::DirectUdp { target_kad_udp }
    }

    /// The TCP port a callback invites the target to dial: the **Advertised
    /// Endpoints** chooser's (ADR-0084) — behind a NAT the mapped external
    /// one, since the locally bound number would be a dead invitation, as
    /// would the requested 0 of an OS-chosen bind. It falls back to the
    /// listener's actually-bound port, the no-NAT truth; with no listener at
    /// all there is nothing to invite a dial to.
    fn our_tcp_port(&self) -> Option<u16> {
        let bound = self.wiring.reach.listener_port()?;
        Some(
            self.wiring
                .own
                .addresses()
                .advertised_v4_port(SocketRole::Tcp)
                .unwrap_or(bound),
        )
    }

    /// The crypt bits of the connect-options byte a callback and a rendezvous
    /// state: the one obfuscation policy's stance as it stands at this reach,
    /// plaintext when unset.
    fn connect_options(&self) -> u8 {
        rmule_peer::peer_udp::crypt::connect_options_from_stance(self.wiring.obfuscation.stance())
    }
}

/// Where a download candidate's road that never opens is reported — the same
/// `(key, channel)` pair a retirement that arrives after an attempt opens
/// rides.
struct Retire {
    key: CallbackKey,
    tx: mpsc::Sender<(CallbackKey, NattRetirement)>,
}

impl Retire {
    /// Tell the candidate that the road it was asked down never opened: the
    /// one owner that would otherwise report its end was never created, so
    /// without this the slot waits out its deadline for an ask that never
    /// left. `try_send`, never `send`: the actor may not wait on a runner that
    /// can itself be waiting on the actor's reach channel.
    fn unopened(&self, reason: NattRetirement) {
        if self.tx.try_send((self.key, reason)).is_err() {
            tracing::debug!(
                ?reason,
                "an unopened road had nowhere to report; the callback's own deadline stands"
            );
        }
    }
}
