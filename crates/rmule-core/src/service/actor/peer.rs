//! The peer-reach command arm (ADR-0061): one selector picks the route to a
//! peer — direct TCP, a server callback, a Kad-routed direct-UDP invitation or
//! a buddy relay — from what this session can actually reach with.
//!
//! Two callers arrive here, and they share everything but the selection call:
//! a `CoreCommand::ReachPeer` asks [`select_callback_route`] for a first route,
//! and a download's [`DownloadReach`] asks [`select_natt_for_download`] whether
//! its Low-ID candidate should be punched — after twelve seconds of callback
//! silence, or at once when no callback was ever possible (ADR-0091: the pair
//! decides the road). Our own half of the decision ([`CoreActor::self_reach`])
//! and the enactment ([`CoreActor::enact_route`]) are the same code for both,
//! which is what "one selector, every caller" costs when there are two of them.

use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{AddressFamily, UserHash};
use tokio::sync::mpsc;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::address_learning::SocketRole;
use crate::callback::{
    CallbackDrop, CallbackRoute, DownloadAsk, DownloadReach, NattCoordinator, SelfReach,
    callback_target, select_callback_route, select_natt_for_download,
};
use crate::client_udp::ClientUdpSend;
use crate::service::activity::ServeActivity;
use crate::service::{
    CoreEvent, NatTraversalUnavailableReason, PeerReach, PeerReachDropReason, PeerReachRoute,
};

use super::{CoreActor, send_event};

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Reach one peer by the best route this session can offer (ADR-0061).
    pub(super) async fn on_reach_peer(&mut self, peer: PeerReach) {
        let ours = self.self_reach().await;
        let route = select_callback_route(&callback_target(&peer), &ours);
        let routed = self.enact_route(route, &peer, &ours, None).await;
        self.report_route(&peer, routed).await;
    }

    /// A download's Low-ID candidate that cannot be dialed (ADR-0091 rung 1):
    /// ask the *same* selector whether a punch should be attempted for it —
    /// beside a callback that has said nothing for twelve seconds, or in place
    /// of the callback a LowID↔LowID pair could never have taken.
    ///
    /// **A refusal is answered, not swallowed.** When no coordinator can
    /// introduce us, no attempt is opened — so the one owner that would
    /// eventually report its retirement never exists, and the
    /// download would sit on a held slot waiting out thirty seconds for news
    /// that was already decided here. The ask therefore carries the same retire
    /// channel a real retirement rides, and the brain decides what it costs:
    /// beside a callback, nothing (that road is still open); as a candidate's
    /// only road, the slot.
    pub(super) async fn on_download_reach(&mut self, reach: DownloadReach) {
        let silence = match reach.ask {
            DownloadAsk::Traversal(silence) => silence,
            DownloadAsk::BuddyCallback { file_hash } => {
                let reply = crate::adapters::CallbackWalkReply {
                    key: reach.callback,
                    retire_tx: reach.retire_tx.clone(),
                };
                let routed = self.enact_buddy_callback(&reach.peer, file_hash, reply);
                self.report_route(&reach.peer, routed).await;
                return;
            }
            DownloadAsk::DirectUdp => {
                let retire = RetireOnFailure {
                    key: reach.callback,
                    tx: reach.retire_tx.clone(),
                };
                let routed = self
                    .enact_direct_udp_for_download(&reach.peer, &retire)
                    .await;
                self.report_route(&reach.peer, routed).await;
                return;
            }
        };
        let ours = self.self_reach().await;
        let target = callback_target(&reach.peer);
        let Some(route) = select_natt_for_download(&target, &ours, &silence) else {
            // Counted, not only traced: a run of these is the difference
            // between "traversal is failing" and "nothing could be asked".
            self.diagnostics.count_natt_download_no_coordinator();
            tracing::debug!(
                peer = ?reach.peer.tcp,
                ?silence,
                "a download's Low-ID candidate has no NAT-T coordinator (ADR-0091 rung 1)"
            );
            retire_unopened(
                Some(&RetireOnFailure {
                    key: reach.callback,
                    tx: reach.retire_tx.clone(),
                }),
                crate::diagnostics::NattRetirement::NoCoordinator,
            );
            return;
        };
        let retire = RetireOnFailure {
            key: reach.callback,
            tx: reach.retire_tx.clone(),
        };
        let routed = self
            .enact_route(route, &reach.peer, &ours, Some(retire))
            .await;
        self.report_route(&reach.peer, routed).await;
    }

    /// ADR-0061 route 4 for a download's candidate: our half of
    /// [`emit_buddy_callback`] — the port the target is to dial, and whether
    /// Kad is running at all — Self Reach's `kad_running`, the
    /// Kad Activity's one lease (ADR-0093).
    fn enact_buddy_callback(
        &self,
        peer: &PeerReach,
        file_hash: rmule_primitives::FileHash,
        reply: crate::adapters::CallbackWalkReply,
    ) -> PeerReachRoute {
        emit_buddy_callback(
            &self.wiring.kad_pump,
            self.self_reach.kad_running(),
            peer,
            file_hash,
            self.advertised_tcp_port(),
            reply,
        )
    }

    /// ADR-0061 route 2 for a download's Kad-sourced candidate:
    /// our half of [`enact_direct_udp_callback`] — the candidate's own Kad
    /// UDP endpoint, read off its projected [`PeerReach`]. `LowIdRoad::of`
    /// never opens this road without one, but the guard here is the actor's
    /// own — the same defensive shape [`emit_buddy_callback`] keeps for its
    /// guaranteed `buddy` field, since the brain's invariant crosses a
    /// channel this function cannot see.
    async fn enact_direct_udp_for_download(
        &mut self,
        peer: &PeerReach,
        retire: &RetireOnFailure,
    ) -> PeerReachRoute {
        direct_udp_for_download(
            self.client_udp_reply_tx.as_ref(),
            peer,
            self.advertised_tcp_port(),
            self.own_identity.user_hash(),
            self.wiring.config.peer_crypt,
            retire,
        )
        .await
    }

    /// The TCP port a callback invites the target to dial: the **Advertised
    /// Endpoints** chooser's (ADR-0084) — behind a NAT the mapped external one,
    /// since the locally bound number would be a dead invitation, as would the
    /// requested 0 of an OS-chosen bind. It falls back to the listener's
    /// actually-bound port, the no-NAT truth; with no listener at all there is
    /// nothing to invite a dial to.
    fn advertised_tcp_port(&self) -> Option<u16> {
        let bound = self
            .activities
            .serve
            .as_ref()
            .map(ServeActivity::bound_listen_port)?;
        Some(
            self.own_identity
                .addresses()
                .advertised_endpoints(self.advert_reachability())
                .endpoint(AddressFamily::V4, SocketRole::Tcp)
                .map_or(bound, |endpoint| endpoint.port()),
        )
    }

    /// Publish which route was taken for `peer` — the public projection of the
    /// chooser's verdict both callers end on.
    async fn report_route(&mut self, peer: &PeerReach, route: crate::service::PeerReachRoute) {
        tracing::debug!(peer = ?peer.tcp, ?route, "peer reach routed (ADR-0061)");
        send_event(
            &self.evt_tx,
            CoreEvent::PeerReachRouted {
                peer: peer.tcp,
                route,
            },
        )
        .await;
    }

    /// Our own half of the route decision (ADR-0061): our reachability, whether
    /// the client-UDP send half is bound, whether Kad is running — so a caller
    /// supplies only what it learned about the counterparty.
    async fn self_reach(&mut self) -> SelfReach {
        // Whether the session task itself is still running — a separate
        // question from *which* id it holds (below). Scoped: the guard is
        // dropped before this returns.
        let server_session_alive = {
            let slot = self.wiring.shared_server_session.slot().lock().await;
            slot.as_ref().is_some_and(|handle| handle.is_alive())
        };
        SelfReach {
            // aMule's `!IsFirewalled()` (`amule.cpp:1668-1675`), asked of Self
            // Reach at the moment of the decision: a
            // server High ID or an open Kad TCP verdict, never composed here.
            reachable: !self.self_reach.firewalled(),
            udp_on: self.client_udp_reply_tx.is_some(),
            kad_running: self.self_reach.kad_running(),
            // Rung 0's half of the AND (ADR-0087): the Advertised Endpoints
            // chooser's verdict, published once per command and read here.
            dial: crate::dialable::DialPosition {
                known_ipv6: self.wiring.ipv6_advert.get(),
            },
            // ADR-0091: the live session advertised `0xF9` and its keepalive
            // is running. Read with the session-alive check above it, not
            // instead of it — the flag is cleared by the session's own exit,
            // which can trail a dead link by a scheduler tick.
            server_punch: server_session_alive
                && self.wiring.shared_server_session.server_punch().is_live(),
        }
    }

    /// Carry out `route` against this session's live surfaces, reporting what
    /// actually went on the wire. Shared by both callers of the route tree, so
    /// a fallback punch is emitted by exactly the code a first-choice one is.
    ///
    /// `ours` rides along because rung 1 does not end at the emit: the
    /// **Traversal Attempt** the front opens keeps the position this decision
    /// was made under, so that when the first coordinator fails the front can
    /// ask the same selector who is next without reaching back into the actor.
    async fn enact_route(
        &mut self,
        route: CallbackRoute,
        peer: &PeerReach,
        ours: &SelfReach,
        retire: Option<RetireOnFailure>,
    ) -> PeerReachRoute {
        match route {
            CallbackRoute::Direct { .. } => PeerReachRoute::Direct,
            CallbackRoute::DirectUdp { target_kad_udp } => {
                // Route 2's enactment (ADR-0061): the `0x95` rides the
                // one bound client-UDP send half, the same drain the
                // serve reply matrix and the downloader's reask use.
                // The TCP port it names is `advertised_tcp_port`'s.
                enact_direct_udp_callback(
                    self.client_udp_reply_tx.as_ref(),
                    target_kad_udp,
                    self.advertised_tcp_port(),
                    self.own_identity.user_hash(),
                    self.wiring.config.peer_crypt,
                )
                .await
            }
            CallbackRoute::Server { low_id } => PeerReachRoute::Server { low_id },
            // A `ReachPeer` names no file, and the `0x52` must: the target
            // dials back only for a file it knows. The download's own ask
            // carries one ([`Self::enact_buddy_callback`]).
            CallbackRoute::Buddy { buddy_id, .. } => PeerReachRoute::Buddy {
                buddy_id,
                emitted_to: None,
            },
            CallbackRoute::NatTraversal {
                coordinator: NattCoordinator::Server { low_id },
            } => {
                // Rung 1 through the server coordinator (ADR-0091): ask our
                // connected server to introduce us. What we name is the
                // client-UDP port *as bound* — the server prefers the port it
                // observed our keepalive arrive from and falls back to this
                // one, so a mapped external port here would be a second guess
                // at something the server already measured.
                let bound = self
                    .own_identity
                    .addresses()
                    .bind(SocketRole::Udp)
                    .map(|(_, port)| port);
                let handle = self
                    .wiring
                    .shared_server_session
                    .slot()
                    .lock()
                    .await
                    .clone();
                let emitted = match (handle, bound) {
                    (Some(handle), Some(our_udp_port)) if handle.is_alive() => {
                        handle.request_holepunch(low_id, our_udp_port).await;
                        self.diagnostics.count_natt_rendezvous_emitted();
                        true
                    }
                    _ => false,
                };
                own_server_punch(
                    self.self_reach.natt(),
                    &self.traversal_request(peer, ours),
                    low_id,
                    emitted,
                    retire.as_ref(),
                )
            }
            CallbackRoute::NatTraversal {
                coordinator:
                    NattCoordinator::Buddy {
                        buddy_id,
                        buddy_udp,
                    },
            } => {
                // Rung 1's enactment through the second coordinator
                // (ADR-0091): the front owns the attempt, this arm only says
                // which buddy carries it.
                enact_rendezvous(
                    self.self_reach.natt(),
                    buddy_id,
                    buddy_udp,
                    &self.traversal_request(peer, ours),
                    retire.as_ref(),
                )
            }
            CallbackRoute::Drop { reason } => PeerReachRoute::Dropped {
                reason: match reason {
                    CallbackDrop::LowToLow => PeerReachDropReason::LowToLow,
                    CallbackDrop::NoBuddy => PeerReachDropReason::NoBuddy,
                },
            },
        }
    }

    /// Everything rung 1 needs from this session, gathered once so the two
    /// coordinators are opened from one reading of our own position.
    ///
    /// What we claim about ourselves is the **Advertised Endpoints** chooser's
    /// client-UDP verdict — or nothing: a null claim is legal, the buddy
    /// injects the source it observed, and a guess here would be the one
    /// address in the exchange nobody checked.
    fn traversal_request<'a>(
        &'a self,
        peer: &'a PeerReach,
        ours: &'a SelfReach,
    ) -> TraversalRequest<'a> {
        TraversalRequest {
            peer,
            ours,
            our_user_hash: self.own_identity.user_hash(),
            claimed_endpoint: self
                .own_identity
                .addresses()
                .advertised_endpoints(self.advert_reachability())
                .endpoint(AddressFamily::V4, SocketRole::Udp)
                .and_then(|endpoint| endpoint.as_v4()),
            peer_crypt: self.wiring.config.peer_crypt,
        }
    }
}

/// Where a punch that never starts is reported — the same
/// `(key, channel)` pair [`DownloadReach`] carries for a retirement that
/// arrives after an attempt opens. `None` for a plain `ReachPeer`, which owns
/// no pending callback and nothing to release.
struct RetireOnFailure {
    key: crate::adapters::CallbackKey,
    tx: mpsc::Sender<(
        crate::adapters::CallbackKey,
        crate::diagnostics::NattRetirement,
    )>,
}

/// Tell a download's candidate that the road it was asked down never opened
/// The one owner that would otherwise report its end
/// was never created, so without this the slot waits out its deadline for an
/// ask that never left. `try_send`, never `send`: the actor may not wait on a
/// runner that can itself be waiting on the actor's reach channel. A plain
/// `ReachPeer` (`None`) holds nothing to release.
fn retire_unopened(retire: Option<&RetireOnFailure>, reason: crate::diagnostics::NattRetirement) {
    if let Some(retire) = retire
        && retire.tx.try_send((retire.key, reason)).is_err()
    {
        tracing::debug!(
            ?reason,
            "an unopened road had nowhere to report; the callback's own deadline stands"
        );
    }
}

/// Rung 1 through the server coordinator, once the `0x60` has left or could
/// not (ADR-0091): hand the introduction to the front, which owns what
/// becomes of it — without that it ends wherever its refusal or
/// its silence lands, the server session, the one place that holds no facts
/// about the target.
///
/// A punch the front never took is owned by nobody, so its candidate hears
/// so at once: no live punch to ask is `NoCoordinator`, and a
/// `0x60` whose attempt could not begin — a hashless `0x42` source, or a
/// front that refused the `Begin` — is `NotEnactable`. Otherwise a callback
/// beside it would keep its slot until the traversal bound, not its 30 s.
fn own_server_punch(
    natt_front: &crate::natt::front::SharedNattFront,
    request: &TraversalRequest<'_>,
    low_id: rmule_primitives::ClientId,
    emitted: bool,
    retire: Option<&RetireOnFailure>,
) -> PeerReachRoute {
    if !emitted {
        retire_unopened(retire, crate::diagnostics::NattRetirement::NoCoordinator);
        return PeerReachRoute::ServerPunchUnavailable { low_id };
    }
    if !begin_traversal(
        natt_front,
        request,
        crate::natt::front::AttemptCoordinator::Server { low_id },
    ) {
        retire_unopened(retire, crate::diagnostics::NattRetirement::NotEnactable);
    }
    PeerReachRoute::ServerPunch { low_id }
}

/// What the reach arm knows when it opens a **Traversal Attempt**: everything
/// but which coordinator goes first.
struct TraversalRequest<'a> {
    /// The counterparty facts the channel that named the peer carried.
    peer: &'a PeerReach,
    /// Our own position as the route tree measured it, kept by the attempt so
    /// a fall-through asks the same selector under the same reading.
    ours: &'a SelfReach,
    /// Our user hash — what the target looks us up by, and without which no
    /// rendezvous can be framed.
    our_user_hash: Option<UserHash>,
    /// Our **External Endpoint** for the client-UDP role, when one is held.
    claimed_endpoint: Option<rmule_primitives::Ipv4Endpoint>,
    /// The peer-obfuscation policy the offer's connect-options byte states.
    peer_crypt: Option<ObfuscationPolicy>,
}

/// Open the **Traversal Attempt** toward `request`'s peer with `coordinator`
/// in play (ADR-0091), reporting whether the front took it.
///
/// Two facts are required and neither can be guessed: the target's **User
/// Hash**, which is the attempt's key and what a hint and a risen Tunnel are
/// matched by, and our own, which every rendezvous names. A candidate that
/// carries no user hash still gets its punch — the server coordinator needs
/// only the id — but nothing owns it, so its introduction ends where it
/// lands, and the caller retires the candidate's wait on it.
fn begin_traversal(
    natt_front: &crate::natt::front::SharedNattFront,
    request: &TraversalRequest<'_>,
    coordinator: crate::natt::front::AttemptCoordinator,
) -> bool {
    let (Some(target), Some(our_user_hash)) = (request.peer.user_hash, request.our_user_hash)
    else {
        tracing::debug!(
            ?coordinator,
            target_known = request.peer.user_hash.is_some(),
            "a NAT traversal begins with no traversal attempt: an identity is missing"
        );
        return false;
    };
    let crypt = crate::client_udp::direct_callback_connect_options(
        request
            .peer_crypt
            .map_or(rmule_primitives::CryptStance::disabled(), |policy| {
                policy.crypt_stance()
            }),
    );
    natt_front.send(crate::natt::front::NattCommand::Begin {
        target,
        coordinator,
        facts: callback_target(request.peer).natt_facts(),
        ours: *request.ours,
        offer: crate::natt::RendezvousOffer {
            our_user_hash,
            // uTP only: ADR-0091 keeps QUIC dark until a live handshake with
            // another implementation is proven, and this byte follows bit 4.
            options: rmule_peer::natt::NattConnectOptions::advertise(crypt, true, false),
            file_hash: None,
            claimed_endpoint: request.claimed_endpoint,
            transport: rmule_peer::natt::NattTransport::Utp,
        },
    })
}

/// Enact the ADR-0091 **NAT traversal** route (rung 1) through the target's
/// Kad serving buddy: open the **Traversal Attempt** at the **NAT-T Front**,
/// which arms its rendezvous schedule and emits what the schedule asks for.
///
/// The datagram is framed there rather than here for one reason: the *retries*
/// belong to the ledger, and a second emitter would put attempts on the wire
/// the budget never granted. What comes after — the endpoint hint, the burst,
/// the Tunnel — is driven by what arrives on the client-UDP front.
///
/// A rendezvous with an unknown buddy endpoint begins nothing. Unlike the
/// buddy-callback road's `0x52`, `OP_REASKCALLBACKUDP` (`0x94`)
/// has no dialect-sanctioned walk toward an ID alone: eMuleAI's own
/// unknown-buddy-IP fallback (`BaseClient.cpp:3273-3323`, eMuleAI v1.6
/// `a2f05dc`) never resolves a `0x94` endpoint — it asks the target directly,
/// then falls back to the *old* aMule `FINDSOURCE`/`0x52` lookup (the
/// Callback Walk's own shape), which the fallback's own author calls a
/// should-not-happen path ("bad luck, as lookups aren't supposed to happen
/// anyway", `:3311-3315`). `OP_RENDEZVOUS` genuinely needs a known
/// coordinator endpoint, so a candidate named by ID alone retires here at
/// once ([`crate::diagnostics::NattRetirement::CoordinatorEndpointUnknown`])
/// instead of
/// holding its slot for a walk the dialect never sends.
fn enact_rendezvous(
    natt_front: &crate::natt::front::SharedNattFront,
    buddy_id: crate::KadId,
    buddy_udp: Option<rmule_primitives::Ipv4Endpoint>,
    request: &TraversalRequest<'_>,
    retire: Option<&RetireOnFailure>,
) -> PeerReachRoute {
    let unavailable = |reason| PeerReachRoute::NatTraversalUnavailable { buddy_id, reason };
    let Some(buddy_udp) = buddy_udp else {
        retire_unopened(
            retire,
            crate::diagnostics::NattRetirement::CoordinatorEndpointUnknown,
        );
        return unavailable(NatTraversalUnavailableReason::BuddyEndpointUnknown);
    };
    if request.peer.user_hash.is_none() {
        // The ledger is keyed by the target's hash and a hint names it, so an
        // anonymous candidate could never be matched to its own answer.
        retire_unopened(retire, crate::diagnostics::NattRetirement::NotEnactable);
        return unavailable(NatTraversalUnavailableReason::TargetIdentityUnknown);
    }
    if !begin_traversal(
        natt_front,
        request,
        crate::natt::front::AttemptCoordinator::Buddy {
            buddy_id: *buddy_id.as_bytes(),
            buddy_udp,
        },
    ) {
        retire_unopened(retire, crate::diagnostics::NattRetirement::NotEnactable);
        return unavailable(NatTraversalUnavailableReason::NotEnactable);
    }
    tracing::info!(
        ?buddy_udp,
        claimed = ?request.claimed_endpoint,
        "rendezvous begun toward the target's serving buddy (ADR-0091 rung 1)"
    );
    PeerReachRoute::NatTraversal {
        buddy_id,
        buddy_udp,
    }
}

/// Emit ADR-0061 route 4 for a download's Kad source: the `0x52`
/// to `peer`'s buddy, naming `file_hash` and `our_tcp_port`.
///
/// Nothing leaves without our own facts — a running Kad node to send from and
/// a port to be dialed on — and the route says whether it did. A buddy the row
/// named by ID alone is walked toward first (aMule's `FINDSOURCE` branch at
/// `BaseClient.cpp:2160-2170`): the **Callback Walk** sends the same
/// `0x52` body to the responders near that ID, and reports a walk that met
/// nobody to `reply`, which is the download's retire channel. A known endpoint
/// never starts a walk, exactly as aMule's `GetBuddyIP() && GetBuddyPort()`
/// test at `:2134` decides.
///
/// **With no Kad node running, neither sub-case can leave, and the candidate
/// retires at once instead of holding its slot for thirty seconds**:
/// aMule checks `Kademlia::CKademlia::IsConnected()` once, ahead of
/// both its known-endpoint `0x52` and its `FINDSOURCE` walk, and calls
/// `RemoveSource` the instant it is false (`BaseClient.cpp:2123-2130`, "Kad
/// Firewalled source but not connected to Kad"). `kad_running` is the same
/// fact [`CoreActor::self_reach`] reads as `SelfReach::kad_running` — not the
/// pump's own mailbox, which a socket-free test factory never populates even
/// while it stands in for a live node.
fn emit_buddy_callback(
    kad_pump: &crate::adapters::SharedKadPump,
    kad_running: bool,
    peer: &PeerReach,
    file_hash: rmule_primitives::FileHash,
    our_tcp_port: Option<u16>,
    reply: crate::adapters::CallbackWalkReply,
) -> PeerReachRoute {
    // The road's own end when no `0x52` can leave: the slot is
    // released now rather than held for an invitation nobody sent.
    let unsent = RetireOnFailure {
        key: reply.key,
        tx: reply.retire_tx.clone(),
    };
    let Some(buddy) = peer.buddy else {
        retire_unopened(
            Some(&unsent),
            crate::diagnostics::NattRetirement::CallbackNotSent,
        );
        return PeerReachRoute::Dropped {
            reason: crate::service::PeerReachDropReason::NoBuddy,
        };
    };
    if !kad_running {
        let _ = reply
            .retire_tx
            .try_send((reply.key, crate::diagnostics::NattRetirement::KadNotRunning));
        tracing::info!(
            buddy_id = ?buddy.buddy_id,
            "buddy-callback road retired at once: no Kad node running"
        );
        return PeerReachRoute::Buddy {
            buddy_id: buddy.buddy_id,
            emitted_to: None,
        };
    }
    let Some(tcp_port) = our_tcp_port else {
        retire_unopened(
            Some(&unsent),
            crate::diagnostics::NattRetirement::CallbackNotSent,
        );
        tracing::debug!(
            buddy_id = ?buddy.buddy_id,
            "buddy callback not sent: no listener port to name"
        );
        return PeerReachRoute::Buddy {
            buddy_id: buddy.buddy_id,
            emitted_to: None,
        };
    };
    // A pump that refused the ask (its task gone, or its mailbox full) is not
    // retired here: the socket-free Kad factories the integration legs run on
    // never install a pump, and their publisher dials back unprompted.
    // The callback's own deadline bounds that slot.
    let emitted_to = match buddy.buddy_udp {
        Some(buddy_udp) => crate::adapters::request_kad_buddy_callback(
            kad_pump,
            crate::adapters::BuddyCallbackAsk {
                buddy_udp,
                buddy_id: buddy.buddy_id,
                file_hash,
                tcp_port,
            },
        )
        .then_some(buddy_udp),
        None => {
            let walking = crate::adapters::request_kad_callback_walk(
                kad_pump,
                crate::adapters::CallbackWalkAsk {
                    buddy_id: buddy.buddy_id,
                    file_hash,
                    tcp_port,
                    reply,
                },
            );
            if walking {
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
/// candidate's own Kad UDP endpoint, and — when it cannot leave, for want of
/// that endpoint or of any fact of ours [`enact_direct_udp_callback`] needs —
/// the road's end reported at once, so the slot goes to the next
/// road rather than waiting thirty seconds on an invitation nobody sent.
async fn direct_udp_for_download(
    client_udp_tx: Option<&mpsc::Sender<ClientUdpSend>>,
    peer: &PeerReach,
    our_tcp_port: Option<u16>,
    our_user_hash: Option<UserHash>,
    peer_crypt: Option<ObfuscationPolicy>,
    retire: &RetireOnFailure,
) -> PeerReachRoute {
    let routed = match peer.kad_udp {
        Some(target_kad_udp) => {
            enact_direct_udp_callback(
                client_udp_tx,
                target_kad_udp,
                our_tcp_port,
                our_user_hash,
                peer_crypt,
            )
            .await
        }
        None => PeerReachRoute::Dropped {
            reason: PeerReachDropReason::NoKadUdpEndpoint,
        },
    };
    if !matches!(routed, PeerReachRoute::DirectUdp { .. }) {
        retire_unopened(
            Some(retire),
            crate::diagnostics::NattRetirement::CallbackNotSent,
        );
    }
    routed
}

/// Enact the ADR-0061 **direct UDP callback** (route 2): frame the
/// `OP_DIRECTCALLBACKREQ` (`0x95`) and put it on the bound client-UDP send half,
/// addressed to the target's Kad UDP endpoint.
///
/// **Not gated on Kad running**: aMule's own branch for it
/// (`BaseClient.cpp:2043-2050`, `HasLowID() && SupportsDirectUDPCallback() &&
/// GetEffectiveUDPPort() != 0 && GetConnectIP() != 0`) carries no
/// `Kademlia::CKademlia::IsConnected()` test — that check belongs only to the
/// LowID branch below it, ahead of the buddy callback and its walk. The three
/// facts below are this route's own gate.
///
/// Three of our own facts must hold, and each missing one reports
/// [`PeerReachRoute::DirectUdpUnavailable`] rather than emitting a callback the
/// target could not act on:
///
/// * the client-UDP send half is bound — there is no other socket to send from;
/// * a serve listener is up **and has bound**, because the body names the port
///   the target will dial back on (aMule's own body carries
///   `thePrefs::GetPort()`), and a callback naming a port nothing answers on —
///   the requested 0 of an OS-chosen bind included — is a dead invitation;
/// * our user hash is known — it is how the target matches the dial-back to this
///   invitation (`CClientList::GetClientsByHash`).
async fn enact_direct_udp_callback(
    client_udp_tx: Option<&mpsc::Sender<ClientUdpSend>>,
    target_kad_udp: rmule_primitives::Ipv4Endpoint,
    our_tcp_port: Option<u16>,
    our_user_hash: Option<UserHash>,
    peer_crypt: Option<ObfuscationPolicy>,
) -> PeerReachRoute {
    let unavailable = PeerReachRoute::DirectUdpUnavailable { target_kad_udp };
    let (Some(client_udp_tx), Some(our_tcp_port), Some(our_user_hash)) =
        (client_udp_tx, our_tcp_port, our_user_hash)
    else {
        tracing::debug!(
            ?target_kad_udp,
            udp_bound = client_udp_tx.is_some(),
            listening = our_tcp_port.is_some(),
            identified = our_user_hash.is_some(),
            "direct UDP callback (0x95) chosen but not enactable (ADR-0061 route 2)"
        );
        return unavailable;
    };
    let connect_options = crate::client_udp::direct_callback_connect_options(
        peer_crypt.map_or(rmule_primitives::CryptStance::disabled(), |policy| {
            policy.crypt_stance()
        }),
    );
    let send = crate::client_udp::direct_callback_datagram(
        target_kad_udp,
        our_tcp_port,
        &our_user_hash,
        connect_options,
    );
    if client_udp_tx.send(send).await.is_err() {
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

#[cfg(test)]
mod tests;
