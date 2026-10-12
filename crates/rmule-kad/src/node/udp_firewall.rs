//! Reachability, UDP side (ADR-0058 breakdown 3): the node's own UDP firewall
//! self-check — the helper lookup that finds candidates, the selection rules
//! that engage two fresh ones, the `0x62` results and dial ends that fold into
//! a verdict, and the six-minute backstop — plus the `0x62` answer the node
//! gives as a **UDP Firewall Helper** when a stranger asks over peer TCP,
//! keyed on the requester's carried verify key when it offered one.
//! The selection rules are aMule `ab483654`'s `UDPFirewallTester.cpp`,
//! cited per rule; the tester's counters live in [`crate::reachability`].

use std::net::Ipv4Addr;

use rmule_primitives::Ipv4Endpoint;

use super::{KadEvent, KadNode, KadNodeDiagnostic, UdpFirewallHelper};
use crate::lookup_walk::KadWalkPurpose;
use crate::reachability::{
    FirewallUdpResult, FwCheckUdpRequest, PongOutcome, UdpFirewallTester, UdpHelperResult,
    UdpResultOutcome, UdpVerdict,
};
use crate::{Kad2Message, KadContact, KadContactState, KadEnvelope, KadInstant, KadNodeEndpoint};

impl KadNode {
    /// Contacts the helper lookup asks for per query: `KADEMLIA_FIND_NODE`
    /// (`0x0B`), the count aMule's `NODEFWCHECKUDP` search requests
    /// (`Search.cpp:1817-1821`), where a value lookup asks for two.
    pub const UDP_HELPER_LOOKUP_CONTACT_COUNT: u8 = 0x0B;

    /// Launch the helper lookup if this test still wants one (aMule
    /// `Connected()`'s `!m_nodeSearchStarted && IsFWCheckUDPRunning()`,
    /// `UDPFirewallTester.cpp:225-233`). A routing table with no servable
    /// contact leaves it unlaunched for the next datagram to retry: a walk
    /// with no seed ends at once having asked nobody, where aMule's search
    /// would sit out its lifetime just as empty.
    pub(super) fn launch_udp_helper_lookup(&mut self, now: KadInstant) {
        let Some(target_of) = self.udp_helper_target else {
            return;
        };
        if !self
            .udp_firewall
            .as_ref()
            .is_some_and(UdpFirewallTester::wants_helper_lookup)
        {
            return;
        }
        let target = target_of();
        if self.routing.select_closest_servable(target, 1).is_empty() {
            return;
        }
        // `FindNodeFWCheckUDP` cancels the previous lookup before starting
        // its own (`SearchManager.cpp:596`).
        self.walks
            .retain(|walk| !matches!(walk.purpose(), KadWalkPurpose::UdpFirewallHelpers { .. }));
        if let Some(tester) = self.udp_firewall.as_mut() {
            tester.begin_helper_lookup(now);
        }
        self.start_walk(now, KadWalkPurpose::UdpFirewallHelpers { target });
    }

    /// Offer every row of a helper-lookup answer to the tester, in wire order
    /// — aMule's `KADEMLIA2_RES` handler gives a `NODEFWCHECKUDP` search's
    /// rows to `AddPossibleTestContact` and nowhere else: not to the routing
    /// zone, not back to the search (`KademliaUDPListener.cpp:862-878`),
    /// because a helper is only fresh while we have never sent it a datagram.
    pub(super) fn offer_udp_helper_rows(&mut self, rows: &[KadContact]) {
        for row in rows {
            self.offer_udp_firewall_helper(UdpFirewallHelper {
                endpoint: Ipv4Endpoint::new(row.endpoint().ip(), row.tcp_port()),
                id: row.id(),
                version: row.version(),
            });
        }
    }

    /// Offer a candidate helper to the UDP firewall self-check (ADR-0058
    /// requester, breakdown 3; aMule `AddPossibleTestContact` →
    /// `QueryNextClient`). Queued while the test runs, then the queue is
    /// judged at once: the first candidate that passes the fresh-helper rules
    /// is engaged while the two-helper budget has room. The helper lookup is
    /// the production caller; offering by hand is how a driver with its own
    /// candidates, or a test, feeds the same queue.
    pub fn offer_udp_firewall_helper(&mut self, helper: UdpFirewallHelper) {
        if let Some(tester) = self.udp_firewall.as_mut() {
            tester.offer(helper);
        }
        self.query_next_udp_helper();
    }

    /// Pop candidates until one is fresh and engage it (aMule
    /// `QueryNextClient`, `UDPFirewallTester.cpp:252-302`). A candidate that
    /// fails a rule is dropped, not requeued. The rules, in aMule's order:
    /// Kad version above 5 (`:267-270`); not ourselves by Kad ID or public IP
    /// (`:272-276`); an IP never engaged for a UDP test before (`:278-287`);
    /// an IP absent from our routing zone (`:289-292`). aMule's last gate,
    /// `CClientList::DoRequestFirewallCheckUDP` refusing an IP its client list
    /// already knows (`ClientList.cpp:1204-1211`), is core state this sans-I/O
    /// node cannot hold — the candidate is still engaged and emitted here, and
    /// core's peer roster applies that gate one hop later, before it ever
    /// dials: a known IP is reported [`consume_udp_firewall_cancelled`](Self::consume_udp_firewall_cancelled)
    /// unasked, which frees the slot for the next candidate exactly as if the
    /// dial itself had been refused.
    fn query_next_udp_helper(&mut self) {
        let own_id = self.config.id;
        let own_ip = self.own_public_ip.filter(|ip| !ip.is_unspecified());
        loop {
            let Some(tester) = self.udp_firewall.as_mut() else {
                return;
            };
            let Some(helper) = tester.next_candidate() else {
                return;
            };
            let ip = helper.endpoint.ip;
            let fresh = helper.version > 5
                && helper.id != own_id
                && Some(ip) != own_ip
                && !tester.already_used(ip)
                && !self.routing.contacts().any(|c| c.endpoint().ip() == ip);
            if fresh {
                self.engage_udp_helper(helper);
                return;
            }
        }
    }

    /// Ask `helper` for the check: emit the peer-TCP request core enacts and
    /// remember the IP so its `0x62` — or the dial's end — is matched back.
    /// The body is aMule's `SendFirewallCheckUDPRequest`
    /// (`BaseClient.cpp:3982-3986`): our intern Kad port, our external Kad
    /// port, and our UDP verify key for the helper's IP — zero while verify
    /// keys are unarmed — so the helper can key its `0x62` to us.
    fn engage_udp_helper(&mut self, helper: UdpFirewallHelper) {
        let ip = helper.endpoint.ip;
        let request = FwCheckUdpRequest {
            intern_port: self.config.udp_port,
            extern_port: self.udp_extern_port,
            sender_key: self.own_verify_key_for(ip).unwrap_or(0),
        }
        .encode();
        self.emit_event(KadEvent::UdpFirewallCheckRequested {
            helper: helper.endpoint,
            request,
        });
        if let Some(tester) = self.udp_firewall.as_mut() {
            tester.record_engagement(ip);
        }
    }

    /// Consume a `0x62 KADEMLIA2_FIREWALLUDP` result (ADR-0058 requester): a
    /// helper reporting it reached (or, biased, could not fairly test) our UDP
    /// port. Mirror aMule's `Process2FirewallUDP` gate
    /// (`KademliaUDPListener.cpp:1852-1878`) — a result on a port that is not
    /// one of ours, or with a nonzero errorcode, counts as neither pass nor fail
    /// — then feed the tester and emit the verdict change (if any) the core
    /// store projects. Inert with a diagnostic unless our own UDP check is armed.
    pub(super) fn on_firewall_udp_result(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        envelope: &KadEnvelope,
    ) {
        let result = match FirewallUdpResult::decode(envelope) {
            Ok(result) => result,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::MalformedFirewallUdpResult { from, error });
                return;
            }
        };
        if self.udp_firewall.is_none() {
            // No armed tester — an unrequested result (aMule never processes one
            // it did not ask for).
            self.emit_diagnostic(KadNodeDiagnostic::UnrequestedFirewallResponse {
                from,
                opcode: envelope.opcode(),
            });
            return;
        }
        let port = result.tested_port;
        let helper_result = if (port != self.config.udp_port && port != self.udp_extern_port)
            || port == 0
            || result.is_biased()
        {
            UdpHelperResult::Cancelled
        } else {
            UdpHelperResult::Passed { port }
        };
        if self.fold_udp_helper_result(now, from.ip(), helper_result)
            == Some(UdpResultOutcome::Unrequested)
        {
            self.emit_diagnostic(KadNodeDiagnostic::UnrequestedFirewallResponse {
                from,
                opcode: envelope.opcode(),
            });
        }
    }

    /// The peer-TCP link to an engaged helper ended after our request went out
    /// with no `0x62` counted — one **failed** helper (aMule `Disconnected` in
    /// `KS_FWCHECK_UDP`, `BaseClient.cpp:1735-1739`); a link that ends after
    /// the `0x62` already landed is the answered helper's no-op. Core carries
    /// the helper's IP; inert unless our check is armed and engaged it.
    pub fn consume_udp_firewall_failure(&mut self, now: KadInstant, helper_ip: Ipv4Addr) {
        self.fold_udp_helper_result(now, helper_ip, UdpHelperResult::Failed);
    }

    /// The dial to an engaged helper ended before our request could go out —
    /// **cancelled**, counting neither way (aMule `Disconnected` in
    /// `KS_QUEUED_FWCHECK_UDP`/`KS_CONNECTING_FWCHECK_UDP`,
    /// `BaseClient.cpp:1730-1734`, and the unfit-helper cancel at
    /// `:3972-3979`). The freed slot goes to the next candidate.
    pub fn consume_udp_firewall_cancelled(&mut self, now: KadInstant, helper_ip: Ipv4Addr) {
        self.fold_udp_helper_result(now, helper_ip, UdpHelperResult::Cancelled);
    }

    /// Feed one helper outcome to the tester, engage the next candidate when
    /// the test goes on (aMule's trailing `QueryNextClient()` in
    /// `SetUDPFWCheckResult`, `UDPFirewallTester.cpp:197`), and emit the verdict
    /// change. `None` when no tester is armed.
    fn fold_udp_helper_result(
        &mut self,
        now: KadInstant,
        from_ip: Ipv4Addr,
        result: UdpHelperResult,
    ) -> Option<UdpResultOutcome> {
        let intern = self.config.udp_port;
        let extern_port = self.udp_extern_port;
        let tester = self.udp_firewall.as_mut()?;
        let before = tester.verdict();
        let outcome = tester.accept_result(result, from_ip, intern, extern_port, now);
        if matches!(
            outcome,
            UdpResultOutcome::FailedContinue | UdpResultOutcome::Cancelled
        ) {
            self.query_next_udp_helper();
        }
        self.emit_udp_verdict_change(before);
        Some(outcome)
    }

    /// Advance the UDP self-check's clocks at `now` (ADR-0058 requester): the
    /// **Extern Port Round**'s ping cadence, then the six-minute timeout — the
    /// silence backstop, gated on the TCP verdict *also* being firewalled, the
    /// one place the two self-checks compose — via our injected
    /// [`KadReachability::tcp_firewalled`](crate::KadReachability::tcp_firewalled).
    /// Emits the firewalled verdict once if it just concluded.
    pub(super) fn tick_udp_firewall(&mut self, now: KadInstant) {
        self.tick_extern_port_cadence(now);
        let tcp_firewalled = self.reachability.tcp_firewalled;
        let Some(tester) = self.udp_firewall.as_mut() else {
            return;
        };
        let before = tester.verdict();
        if tester.check_timeout(now, tcp_firewalled) {
            self.emit_udp_verdict_change(before);
        }
    }

    /// Ping one contact for our extern port if the cadence is due — aMule's
    /// block in `CKademlia::Process` (`Kademlia.cpp:223-243`): every 15 s while
    /// the UDP test runs and the round still collects, one contact of type ≤ 3
    /// and Kad version ≥ 6 (`GetRandomContact(3, 6)`). Type 4 is aMule's
    /// failing contact, the node's [`KadContactState::Failed`]. The timer
    /// re-arms whether or not anyone was pinged.
    fn tick_extern_port_cadence(&mut self, now: KadInstant) {
        let Some(tester) = self.udp_firewall.as_ref() else {
            return;
        };
        if !tester.is_running() || !tester.extern_port().cadence_due(now) {
            return;
        }
        let round = tester.extern_port();
        let target = self
            .routing
            .contacts()
            .find(|contact| {
                contact.version() >= 6
                    && contact.state() != KadContactState::Failed
                    && round.worth_asking(contact.endpoint().ip(), now)
            })
            .map(KadContact::endpoint);
        if let Some(tester) = self.udp_firewall.as_mut() {
            tester.extern_port_mut().cadence_ran(now);
        }
        if let Some(target) = target {
            self.ping_for_extern_port(now, target);
        }
    }

    /// The extern-port ping aMule piggybacks on a hello exchange: a
    /// `HELLO_REQ` or `HELLO_RES` from a Kad version above 5 draws a `0x60`
    /// while the round collects (`KademliaUDPListener.cpp:642-645, 740-743`),
    /// independent of the cadence and of whether the UDP test still runs.
    pub(super) fn ping_for_extern_port_on_hello(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        version: u8,
    ) {
        if version > 5
            && self
                .udp_firewall
                .as_ref()
                .is_some_and(|tester| tester.extern_port().collecting())
        {
            self.ping_for_extern_port(now, from);
        }
    }

    fn ping_for_extern_port(&mut self, now: KadInstant, to: KadNodeEndpoint) {
        if let Some(tester) = self.udp_firewall.as_mut() {
            tester.extern_port_mut().record_ping(to.ip(), now);
        }
        self.send(to, &Kad2Message::Ping);
    }

    /// A `0x61 KADEMLIA2_PONG`: the source port our ping was seen to arrive
    /// from (`Process2Pong`, `KademliaUDPListener.cpp:1814-1848`). An answer
    /// to a ping we sent, from an observer new to the round, is **stated** as
    /// [`KadEvent::UdpPortObserved`] for core's Address Learning store to
    /// judge — the store owns the agreement rule, and its verdict returns as
    /// [`crate::KadCommand::SetExternalUdpPort`]. A pong we never asked for
    /// stays a diagnostic, never an observation.
    pub(super) fn on_kad_pong(&mut self, now: KadInstant, from: KadNodeEndpoint, port: u16) {
        let outcome = self
            .udp_firewall
            .as_mut()
            .map_or(PongOutcome::Unsolicited, |tester| {
                tester.extern_port_mut().accept_pong(from.ip(), now)
            });
        match outcome {
            PongOutcome::Unsolicited => {
                self.emit_diagnostic(KadNodeDiagnostic::UnsolicitedPong { from });
            }
            PongOutcome::Ignored => {}
            PongOutcome::Observed => self.emit_event(KadEvent::UdpPortObserved {
                observer: from.ip(),
                port,
            }),
        }
    }

    /// Core's **Extern Kad Port** verdict (ADR-0084): the Address Learning
    /// store's learned Kad UDP port, or `0` while it holds none. A named port
    /// becomes the one the `0xA7` carries and the tester reads; the answer
    /// that ends the round opens the helper gate at once (aMule's
    /// `QueryNextClient` after `SetExternKadPort`, `KademliaUDPListener.cpp:1843-1845`).
    /// A round that ends with no agreed port clears it to `0`, as
    /// `SetExternKadPort` does (`Prefs.cpp:318-322`): the check then runs on
    /// the intern port alone.
    ///
    /// A zero answer only skips the cache while a round still collects (the
    /// "stands until this round settles a new one" rule `ExternPortRound::restart`
    /// documents): an early answer mid-round may still be settled by a later
    /// one, so it must not blank a value the previous round already proved.
    /// Once no round is collecting — the common case, since core's Kad pump
    /// also restates the store's port on its own recruit tick —
    /// a zero answer is the store's own verdict (nothing fresh, or the
    /// round's own unreliable outcome) and writes through: the store's
    /// 30-minute window aging out with no fresh observer reconciles here
    /// within one tick instead of leaving the node's cache stuck on a value
    /// the store no longer holds.
    pub(super) fn set_extern_udp_port(&mut self, port: u16) {
        let collecting = self
            .udp_firewall
            .as_ref()
            .is_some_and(|tester| tester.extern_port().collecting());
        if port != 0 || !collecting {
            self.udp_extern_port = port;
        }
        let Some(tester) = self.udp_firewall.as_mut() else {
            return;
        };
        let round = tester.extern_port_mut();
        if !round.settle(port) {
            return;
        }
        if round.unreliable() {
            self.udp_extern_port = 0;
        }
        self.query_next_udp_helper();
    }

    /// Emit the reachability event for a UDP verdict transition away from
    /// `before`, if the tester's verdict actually changed — the single place the
    /// tester's `Open`/`Firewalled` verdict becomes a core-store event. A
    /// transition to `Unverified` has no event (only a recheck reaches it).
    fn emit_udp_verdict_change(&mut self, before: UdpVerdict) {
        let Some(after) = self.udp_firewall.as_ref().map(UdpFirewallTester::verdict) else {
            return;
        };
        if after == before {
            return;
        }
        match after {
            UdpVerdict::Open { port } => self.emit_event(KadEvent::UdpReachabilityOpen { port }),
            UdpVerdict::Firewalled => self.emit_event(KadEvent::UdpReachabilityFirewalled),
            UdpVerdict::Unverified => {}
        }
    }

    /// The **UDP Firewall Helper** (ADR-0058 breakdown 3, rmule as helper): a
    /// peer asked us over peer TCP (`OP_FWCHECKUDPREQ`, bridged here by core
    /// with the requester's IP) to prove *its* UDP port reachable. Decode the
    /// request, ignore intern port 0, and fire a `0x62` result at the
    /// requester's intern port — and, when its extern port differs and is
    /// nonzero, a second at the extern port (aMule
    /// `ProcessFirewallCheckUDPRequest`, `BaseClient.cpp:3991-4045`). The
    /// errorcode is `1` (biased) when the requester's IP is already a
    /// routing-zone contact (`:4004-4007`) or `caller_known` says core's peer
    /// roster already has an active upload, download or chat with it
    /// (`:4002-4003`) — peer-side state the sans-I/O node cannot
    /// hold itself, so core reads it off the requester's IP before this is
    /// ever called and hands back the verdict.
    ///
    /// Both results are keyed on `request.sender_key`: the
    /// request's own verify-key field is the requester's key for *our* IP
    /// (`SendFirewallCheckUDPRequest`'s `GetUDPVerifyKey(helper IP)`,
    /// `BaseClient.cpp:3982-3986`), and aMule hands that same value straight
    /// back as the answer's crypt key (`:4008-4013`) — see
    /// `send_envelope_keyed` (`node/wire.rs`) for the exact `SendPacket`
    /// citation. A zero key (no obfuscation offered) sends plaintext,
    /// matching aMule.
    pub fn consume_udp_firewall_request(
        &mut self,
        requester_ip: Ipv4Addr,
        request: &[u8],
        caller_known: bool,
    ) {
        let request = match FwCheckUdpRequest::decode(request) {
            Ok(request) if request.intern_port != 0 => request,
            _ => {
                self.emit_diagnostic(KadNodeDiagnostic::UnhonorableFirewallUdpRequest {
                    requester: requester_ip,
                });
                return;
            }
        };
        let biased = caller_known
            || self
                .routing
                .contacts()
                .any(|c| c.endpoint().ip() == requester_ip);
        let error_code = u8::from(biased);
        self.send_envelope_keyed(
            KadNodeEndpoint::new(requester_ip, request.intern_port),
            &FirewallUdpResult {
                error_code,
                tested_port: request.intern_port,
            }
            .encode(),
            request.sender_key,
        );
        // A distinct PAT extern port gets its own result packet (aMule's second
        // `SendPacket`), so the requester learns which of its ports is open.
        if request.extern_port != 0 && request.extern_port != request.intern_port {
            self.send_envelope_keyed(
                KadNodeEndpoint::new(requester_ip, request.extern_port),
                &FirewallUdpResult {
                    error_code,
                    tested_port: request.extern_port,
                }
                .encode(),
                request.sender_key,
            );
        }
        self.emit_event(KadEvent::FwCheckUdpAnswered {
            requester: requester_ip,
            biased,
        });
    }
}
