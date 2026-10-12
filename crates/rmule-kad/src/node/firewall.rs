//! Reachability, TCP side: the node's own TCP firewall self-check (the
//! requester cycle), the `0x50`/`0x53` checks it answers for strangers with
//! `0x58` and a brokered dial-back, and the recheck that restarts both
//! self-checks (ADR-0058). The UDP half lives in `udp_firewall`; the wire
//! codecs in [`crate::reachability`]. This file owns only the node-side
//! cadence and verdicts.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_primitives::Ipv4Endpoint;

use super::{KadEvent, KadNode, KadNodeDiagnostic, KadReachability};
use crate::messages::Kad2NodeInfo;
use crate::reachability::{
    CHECK_WINDOW, FirewallMessage, FirewallResponseOutcome, FirewallSelfCheck,
};
use crate::{KadEnvelope, KadInstant, KadNodeEndpoint};

impl KadNode {
    /// Firewall self-checks emitted per recheck before emission stops
    /// (`KADEMLIAFIREWALLCHECKS`; ADR-0058 requester). Two connect-back acks open
    /// the verdict, but up to four checks are piggybacked to find them.
    pub const FIREWALL_CHECKS: u32 = crate::reachability::FIREWALL_CHECKS;

    /// The 180 s window an emitted firewall check stays valid for: a `0x58` or
    /// `OP_KAD_FWTCPCHECK_ACK` from an IP checked longer ago is unrequested
    /// (aMule `IsKadFirewallCheckIP`).
    pub const FIREWALL_CHECK_WINDOW: Duration = crate::reachability::CHECK_WINDOW;

    /// How often the requester re-runs its firewall self-check (aMule
    /// `m_nextFirewallCheck`, +1 h). A fresh node checks at once, then hourly.
    pub const FIREWALL_RECHECK_INTERVAL: Duration = crate::reachability::RECHECK_INTERVAL;

    /// The UDP self-check's total silence budget (aMule `IsFirewalledUDP`'s
    /// `MIN2MS(6)`): six minutes with no conclusive `0x62`, and the TCP verdict
    /// also firewalled, settles UDP firewalled-by-timeout (ADR-0058 breakdown 3).
    pub const UDP_FIREWALL_TIMEOUT: Duration = crate::reachability::UDP_TEST_TIMEOUT;

    /// The connect-options byte our own `0x53` check carries: aMule's
    /// `GetMyConnectOptions(true, false)` (`KademliaUDPListener.cpp:182`,
    /// `Prefs.cpp:214-233`) — the three crypt bits and nothing else, taken
    /// from the byte the driver states for publishes (the same crypt ladder).
    /// It is what lets the helper dial back obfuscated, keyed on the user hash
    /// the request carries; under a policy that requires obfuscation, a check
    /// naming no crypt is answered by a plain dial our listener admits only as
    /// a Test Connection. Zero until the driver has stated a byte.
    fn firewall_connect_options(&self) -> u8 {
        self.publish_connect_options.map_or(0, |byte| byte & 0x07)
    }

    /// Inject the node's own reachability/buddy state — the keyword layer's
    /// publish-gate and storer-refusal inputs (see [`KadReachability`]). A driver
    /// with an ADR-0058 self-check verdict feeds it here; the default is
    /// assume-open. Idempotent, applied at the next publish poll / inbound `0x43`.
    pub fn set_reachability(&mut self, reachability: KadReachability) {
        self.reachability = reachability;
    }

    /// The **Reachability** responder (ADR-0058): a peer's `0x50`/`0x53`
    /// firewall check asks us to prove *it* is TCP-reachable. Answer `0x58`
    /// with its observed IP immediately (aMule sends the response regardless of
    /// the dial-back's fate), then emit the typed dial-back command core
    /// brokers — the peer-dial and the version-gated ack live core-side, so the
    /// sans-I/O node stays socket-free.
    ///
    /// One guard is applied *here* rather than in the core broker, because its
    /// input is this node's own outstanding-check window and nothing else holds
    /// it: a requester whose IP we are ourselves currently checking gets no
    /// dial-back. See [`dial_back_would_poison_our_own_check`].
    ///
    /// [`dial_back_would_poison_our_own_check`]: Self::dial_back_would_poison_our_own_check
    pub(super) fn on_firewall_check_req(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        envelope: &KadEnvelope,
    ) {
        let (tcp_port, connect_options, user_hash) = match FirewallMessage::decode(envelope) {
            Ok(FirewallMessage::FirewalledReq { tcp_port }) => (tcp_port, None, None),
            Ok(FirewallMessage::Firewalled2Req {
                tcp_port,
                connect_options,
                user_hash,
            }) => (tcp_port, Some(connect_options), Some(user_hash)),
            // `is_firewall_check_req` admits only `0x50`/`0x53`, so a response
            // variant never decodes here; a decode error is a size-gate failure.
            Ok(FirewallMessage::FirewalledRes { .. } | FirewallMessage::FirewalledAck) => return,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::MalformedFirewallCheck { from, error });
                return;
            }
        };
        self.send_envelope(
            from,
            &FirewallMessage::FirewalledRes { ip: from.ip() }.encode(),
        );
        if self.dial_back_would_poison_our_own_check(now, from.ip()) {
            self.emit_diagnostic(KadNodeDiagnostic::DialBackRefusedMutualCheck { from });
            return;
        }
        self.emit_event(KadEvent::DialBackRequested {
            requester: Ipv4Endpoint::new(from.ip(), tcp_port),
            connect_options,
            user_hash,
        });
    }

    /// Whether dialing `requester` back would wreck the check **we** have
    /// outstanding against it (ADR-0058's responder guard, amended by what
    /// arming the requester live measured).
    ///
    /// A firewall-check connect-back only proves anything if it is a *fresh*
    /// dial. eMule enforces that from the responder's side — `RequestTCP`
    /// refuses when a socket to the client already exists, "already existing
    /// socket can give false high ID" — and rmule enforces the same invariant
    /// from the other end: it declines to *hand* a peer a socket while asking
    /// that peer to dial it.
    ///
    /// Measured, not theorised. Two nodes that check each other inside the same
    /// hello burst collide: rmule's dial-back lands first, stock aMule 2.3.3's
    /// `RequestTCP` finds that already-connected client and reuses its socket
    /// instead of dialing (aMule carries eMule's `KadState` guard but not its
    /// socket one), rmule closes the link the moment its own ack is out, and
    /// aMule's client is torn down before `KS_CONNECTED_FWCHECK` can send the
    /// ack. Both checks then fail having proved nothing — and the requester,
    /// which may genuinely be reachable, concludes it is firewalled.
    ///
    /// This is a documented divergence from aMule 2.3.3, whose `RequestTCP`
    /// applies only the self-connect and busy-client guards; eMule 0.70b reads
    /// the outstanding-check window in `RequestBuddy` (logging a "TCP Firewall
    /// check / Buddy request collision") but not here. Rare on a public network
    /// — a node has hundreds of contacts and checks four — and unavoidable in a
    /// small swarm.
    fn dial_back_would_poison_our_own_check(&self, now: KadInstant, requester: Ipv4Addr) -> bool {
        self.firewall
            .as_ref()
            .is_some_and(|firewall| firewall.is_check_ip(requester, now))
    }

    /// The **Reachability** requester's response consume (ADR-0058): a `0x58`
    /// carries our observed external IP and counts the recheck (window-guarded,
    /// aMule `ProcessFirewalledResponse`); a `0x59` is a legacy UDP connect-back
    /// ack that proves one reachability leg (aMule `ProcessFirewalledAckResponse`
    /// — *unguarded*, its v7+ `OP_KAD_FWTCPCHECK_ACK` twin is the window-guarded
    /// TCP path). Both are inert unless our own check is armed.
    pub(super) fn on_firewall_check_res(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        envelope: &KadEnvelope,
    ) {
        let opcode = envelope.opcode();
        let message = match FirewallMessage::decode(envelope) {
            Ok(message) => message,
            // A response that fails its exact-size gate (0x58 ≠ 4 bytes,
            // 0x59 non-empty) is malformed, not merely unrequested.
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::MalformedFirewallCheck { from, error });
                return;
            }
        };
        let Some(firewall) = self.firewall.as_mut() else {
            // Our check is disabled, so any firewall response is unrequested
            // (aMule never processes one it did not ask for).
            self.emit_diagnostic(KadNodeDiagnostic::UnrequestedFirewallResponse { from, opcode });
            return;
        };
        match message {
            // `0x58`: the observed-IP reply. Guarded on the *sender's* IP (we
            // asked it to check us); the body IP is our external IP, stated as
            // an Address Learning observation for core to rank (ADR-0084).
            FirewallMessage::FirewalledRes { ip } => {
                let outcome = firewall.accept_response(from.ip(), now);
                match outcome {
                    FirewallResponseOutcome::Unrequested => {
                        self.emit_diagnostic(KadNodeDiagnostic::UnrequestedFirewallResponse {
                            from,
                            opcode,
                        });
                        // An unrequested response is a stranger's claim about
                        // us, so its body is not an observation either.
                        return;
                    }
                    FirewallResponseOutcome::Counted => {}
                    FirewallResponseOutcome::ConcludedRecheck => {
                        self.emit_event(KadEvent::ReachabilityRecheckConcluded);
                    }
                }
                self.emit_event(KadEvent::AddressObserved {
                    observer: from.ip(),
                    address: ip,
                });
            }
            // `0x59`: the legacy UDP connect-back ack. aMule counts it with no
            // window guard, so any well-formed `0x59` proves a reachability leg.
            FirewallMessage::FirewalledAck => {
                self.emit_event(KadEvent::ReachabilityConnectBack);
            }
            // `is_firewall_check_res` admits only `0x58`/`0x59`.
            FirewallMessage::FirewalledReq { .. } | FirewallMessage::Firewalled2Req { .. } => {}
        }
    }

    /// Piggyback a firewall self-check on a hello exchange with `contact`
    /// (ADR-0058 requester; aMule's `GetRecheckIP`-gated `FirewalledCheck` in
    /// `Process2HelloRequest`/`Process2HelloResponse`): while the emission budget
    /// holds, send the version-gated check (v7+ `0x53` with our port, User Hash,
    /// and connect-options; else legacy `0x50` with just our port) and open its
    /// 180 s response window. A no-op when our check is disarmed or spent.
    pub(super) fn maybe_firewall_check(
        &mut self,
        now: KadInstant,
        contact: KadNodeEndpoint,
        info: &Kad2NodeInfo,
    ) {
        if !self
            .firewall
            .as_ref()
            .is_some_and(FirewallSelfCheck::wants_check)
        {
            return;
        }
        // Version-gated per the *contact's* Kad version (aMule keys the opcode on
        // `contactVersion`): a v7+ peer answers the extended check and acks over
        // TCP, a legacy peer the two-byte check and a UDP `0x59`.
        let (message, connect_options) = if info.version > 6 {
            let connect_options = self.firewall_connect_options();
            (
                FirewallMessage::Firewalled2Req {
                    tcp_port: self.config.tcp_port,
                    user_hash: self.config.user_hash,
                    connect_options,
                },
                Some(connect_options),
            )
        } else {
            (
                FirewallMessage::FirewalledReq {
                    tcp_port: self.config.tcp_port,
                },
                None,
            )
        };
        self.send_envelope(contact, &message.encode());
        if let Some(firewall) = self.firewall.as_mut() {
            firewall.record_emission(contact.ip(), now);
            self.emit_event(KadEvent::ReachabilityCheckAsked {
                helper: contact.ip(),
                helper_id: info.id,
                helper_udp_port: contact.udp_port(),
                connect_options,
                answerable_for: CHECK_WINDOW,
            });
        }
    }

    /// Consume an `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) a peer sent over the TCP link
    /// it dialed back on (ADR-0058 requester, v7+ ack path). Core bridges it here
    /// from the Kad-ignorant peer session, carrying the peer's IP; the node
    /// window-guards it (aMule `ClientTCPSocket.cpp`'s `IsKadFirewallCheckIP`)
    /// and, when it matches an outstanding check, counts one reachability leg.
    /// The Kad-ignorant peer crate stays out of the window; the sans-I/O node
    /// stays out of the socket.
    pub fn consume_tcp_firewall_ack(&mut self, now: KadInstant, peer_ip: Ipv4Addr) {
        if self
            .firewall
            .as_ref()
            .is_some_and(|firewall| firewall.is_check_ip(peer_ip, now))
        {
            self.emit_event(KadEvent::ReachabilityConnectBack);
        } else {
            self.emit_diagnostic(KadNodeDiagnostic::UnrequestedFirewallAck { from: peer_ip });
        }
    }

    /// Start a firewall self-check **now**, outside the hourly clock — the
    /// entry point ADR-0058 lacked and ADR-0086 needs.
    ///
    /// rmule fires this when a port-mapping grant lands `Exact` and when a
    /// gateway epoch reset re-added the mapping set. Neither reference
    /// implementation does: emule-qt couples the two only through the *user's*
    /// "recheck firewall" button, and aMule not at all — so a headless node that
    /// has just mapped its ports successfully would sit Kad-firewalled for up to
    /// an hour, advertising a firewalled posture that is no longer true.
    ///
    /// Reports whether a recheck actually started. Two guards refuse one — a
    /// recheck already in flight, and one that ran inside the last five
    /// minutes. Both self-checks
    /// restart together, exactly as `Kademlia::recheckFirewalled` pairs
    /// `SetRecheckIP` with `UDPFirewallTester::ReCheckFirewallUDP(false)`; the
    /// [`ReachabilityRecheckStarted`](KadEvent::ReachabilityRecheckStarted)
    /// event core folds is the same one the hourly cadence emits, so nothing
    /// downstream learns a new state.
    ///
    /// Inert when the self-check is not armed: a node that never checks its own
    /// reachability has no verdict for a grant to refresh.
    pub fn recheck_reachability(&mut self, now: KadInstant) -> bool {
        let started = self
            .firewall
            .as_mut()
            .is_some_and(|firewall| firewall.begin_external_recheck(now));
        if started {
            self.restart_udp_self_check(now);
            self.emit_event(KadEvent::ReachabilityRecheckStarted);
        }
        // Probe whether or not a *new* round began. A trigger refused as
        // "already in flight" is still news — the position changed under a round
        // whose outstanding checks were emitted against the old one, and a
        // mapping set that grew a row between two installs is exactly that. The
        // probe round is budget-gated, so feeding an unfinished recheck costs at
        // most the checks it was already allowed to send.
        self.probe_for_firewall_checks(now);
        started
    }

    /// Hello-probe a bounded set of contacts so a just-started recheck has
    /// traffic to piggyback its checks on (ADR-0086's amendment to ADR-0058).
    ///
    /// A recheck only *reopens* the emission budget; the `0x50`/`0x53` checks
    /// themselves ride hello exchanges ([`maybe_firewall_check`]). aMule can
    /// leave it there because its zone small timer hellos a contact every second
    /// for as long as it runs, so a reopened budget is spent within seconds. This
    /// node's hello cadence is the *join*-scoped one: it falls silent the
    /// moment the node is joined, which is precisely when a recheck matters. So
    /// a recheck here has to go and make its own traffic, or the reopened budget
    /// is never spent and the verdict never leaves the state it was in — the
    /// whole ADR-0086 claim ("a fresh `Exact` grant refreshes the verdict rather
    /// than waiting an hour") with it.
    ///
    /// Capped at the emission budget ([`FIREWALL_CHECKS`](Self::FIREWALL_CHECKS)):
    /// a probe past it could not carry a check, so the fan-out can never exceed
    /// the round of checks it exists to feed. A spent budget probes nothing at
    /// all — those hellos would carry no check, so they would be pure noise.
    ///
    /// [`maybe_firewall_check`]: Self::maybe_firewall_check
    fn probe_for_firewall_checks(&mut self, now: KadInstant) {
        if !self
            .firewall
            .as_ref()
            .is_some_and(FirewallSelfCheck::wants_check)
        {
            return;
        }
        let targets: Vec<(crate::KadId, KadNodeEndpoint)> = self
            .routing
            .contacts()
            .take(Self::FIREWALL_CHECKS as usize)
            .map(|contact| (contact.id(), contact.endpoint()))
            .collect();
        for (id, endpoint) in targets {
            self.probe(now, id, endpoint, true);
        }
    }

    /// Advance the firewall self-check clock at `now` (ADR-0058 requester): fire
    /// a due hourly recheck (emitting the start the store snapshots on), then
    /// expire lapsed response windows — a timeout there concludes an in-flight
    /// recheck the ack threshold never met.
    pub(super) fn tick_firewall(&mut self, now: KadInstant) {
        let Some(firewall) = self.firewall.as_mut() else {
            return;
        };
        let scheduled = firewall.recheck_due(now);
        if scheduled {
            firewall.begin_recheck(now);
        }
        let concluded = firewall.expire(now);
        // An external trigger refused earlier runs once the round it met has
        // concluded and the spacing has passed (ADR-0095); the conclusion is
        // told first, so the store never reads it as the new round's.
        let started = scheduled || firewall.owed_recheck_due(now);
        if concluded {
            self.emit_event(KadEvent::ReachabilityRecheckConcluded);
        }
        if started {
            self.restart_udp_self_check(now);
            self.emit_event(KadEvent::ReachabilityRecheckStarted);
            // The hourly recheck needs its own traffic for the same reason the
            // external one does.
            self.probe_for_firewall_checks(now);
        }
    }

    /// Restart the UDP self-check alongside the TCP one (aMule
    /// `RecheckFirewalled` pairs `SetRecheckIP` with
    /// `ReCheckFirewallUDP(false)`, `Kademlia.cpp:365-380`) — shared by the
    /// hourly cadence and the ADR-0086 external trigger, since aMule's sole
    /// caller pairs them the same way for both. Resets the tester's counters
    /// ([`UdpFirewallTester::recheck`](crate::reachability::UdpFirewallTester::recheck)) and launches a fresh Helper Lookup
    /// rather than waiting for the next datagram, exactly as
    /// `ReCheckFirewallUDP` calls `FindNodeFWCheckUDP` itself
    /// (`UDPFirewallTester.cpp:220`). A no-op when the UDP tester is not armed
    /// (a node started without a self-check runs neither test). Emits [`KadEvent::ExternPortRoundStarted`]
    /// exactly when a tester restarts, so core's Address
    /// Learning store forgets the previous round's UDP-role Kad port reports
    /// — aMule's `FindExternKadPort(true)` starting the observer lists empty.
    fn restart_udp_self_check(&mut self, now: KadInstant) {
        let restarted = if let Some(tester) = self.udp_firewall.as_mut() {
            tester.recheck(now);
            true
        } else {
            false
        };
        // The round boundary: emitted only when a tester was
        // actually armed to restart one, so a driver that never armed the UDP
        // self-check emits no event for core's store to act on.
        if restarted {
            self.emit_event(KadEvent::ExternPortRoundStarted);
        }
        self.launch_udp_helper_lookup(now);
    }
}
