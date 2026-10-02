//! The Routing Responder: the `KADEMLIA2_HELLO` and `KADEMLIA2_REQ` exchanges,
//! the `0x22` ack verification that promotes a contact to validated-live, and
//! the routing-table intake (`store`, `probe`) those answers feed. Hearsay
//! never lands here unprobed — the anti-poisoning rules in the module docs are
//! enforced by this file.

use std::net::Ipv4Addr;
use std::time::Duration;

use super::{
    AwaitingAck, KadContactAdmission, KadEvent, KadNode, KadNodeDiagnostic, PendingProbe,
    ReceivedKey,
};
use crate::messages::{Kad2Message, Kad2NodeInfo, MISC_OPTIONS_ACK_REQUEST};
use crate::opcode::{KADEMLIA2_HELLO_RES, KADEMLIA2_HELLO_RES_ACK};
use crate::udp_key::{KadUdpKey, udp_verify_key};
use crate::{
    KadContact, KadContactState, KadId, KadInstant, KadNodeEndpoint, KadRoutingTable,
    KadRoutingUpdate,
};

impl KadNode {
    /// How long a probed contact may stay silent before it fails. One shot,
    /// no retry: rmule policy (not wire compatibility), chosen conservative
    /// enough for private-mesh latency and deterministic for the sim tier.
    pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

    /// How long an outstanding `0x22` ack-request may go unanswered before
    /// [`tick`](Self::tick) prunes it. aMule accepts the inbound `0x22` through
    /// its general `PacketTracking` out-track list rather than a dedicated ack
    /// window, so there is no single wire constant to mirror; this reuses
    /// [`PROBE_TIMEOUT`](Self::PROBE_TIMEOUT) — the `0x22` closes the same
    /// one-shot, one-round-trip exchange a hello probe does and shares its
    /// rmule-policy (not wire-compatibility) role.
    pub const ACK_REQUEST_WINDOW: Duration = Self::PROBE_TIMEOUT;

    /// The lowest Kad version that understands the `0x22` verification handshake
    /// and the misc-options tag; below it aMule uses the (unimplemented) legacy
    /// challenge / v7 ping, so rmule sets no ack-request toward it (ADR-0064).
    const ACK_REQUEST_MIN_VERSION: u8 = 8;

    /// Arm the contact-admission verdict — the driver installs
    /// the production IP-filter closure here before the node handles any
    /// traffic, the same pre-start discipline as the other arming calls. The
    /// un-armed default admits everything.
    pub fn arm_contact_admission(&mut self, admission: KadContactAdmission) {
        self.contact_admission = admission;
    }

    /// The routing table, for driver observability and tests.
    #[must_use]
    pub const fn routing_table(&self) -> &KadRoutingTable {
        &self.routing
    }

    /// Answer a `HELLO_REQ`, storing the sender and driving the IP-verification
    /// handshake (ADR-0064, `0x22` role A). A hello carrying a valid receiver
    /// key verifies the sender on add; otherwise, toward a v≥8 contact we
    /// added/updated, our `HELLO_RES` sets misc-options bit 2 to request a `0x22`
    /// ACK and we track the outstanding request (the capture-proven `0x04` in
    /// `hello_res_0x19.bin`) — but only when that `HELLO_RES` carries our sender
    /// key in its crypt trailer.
    pub(super) fn on_hello_req(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        info: &Kad2NodeInfo,
        key: ReceivedKey,
    ) {
        let known = self.routing.get(info.id).is_some();
        let added_or_updated = self.store(now, self.contact_from_hello(from, info, key));
        // aMule's `AddContact2(update = true)`: a hello from a contact already
        // held marks it alive; a first admission stays fresh, so the small
        // timer greets it back once (`RoutingZone.cpp:584`).
        if known && added_or_updated {
            self.routing.mark_alive(now, info.id);
        }
        if key.valid_receiver_key && added_or_updated {
            self.verify(info.id, from.ip());
        }
        // The ACK's whole proof is our sender key echoed back in its receiver
        // slot, so the request rides only a `HELLO_RES` whose trailer carries
        // that key — a plaintext one draws emule-qt/aMule's "demands an ACK but
        // sent no sender key" drop (ADR-0064).
        let request_ack = added_or_updated
            && !key.valid_receiver_key
            && info.version >= Self::ACK_REQUEST_MIN_VERSION
            && self
                .outbound_key(from, KADEMLIA2_HELLO_RES)
                .is_some_and(|outbound| outbound.sender_verify_key != 0);
        if request_ack {
            self.track_ack_request(now, from, info.id);
        }
        self.send(
            from,
            &Kad2Message::HelloRes(self.hello_res_info(request_ack)),
        );
        // aMule piggybacks the firewall check on the hello it just answered
        // (`Process2HelloRequest`), after its extern-port ping.
        self.ping_for_extern_port_on_hello(now, from, info.version);
        self.maybe_firewall_check(now, from, info);
    }

    /// Consume a solicited `HELLO_RES` (probe answer). Beyond the existing
    /// liveness bookkeeping this drives two verification roles (ADR-0064): a
    /// valid receiver key verifies the responder on add; and if the responder
    /// asked *us* to prove our IP (misc-options bit 2), we answer with a `0x22`
    /// ACK — role B — but only when we hold a sender key to reply under, else
    /// aMule's silent log-drop ("bug in remote client").
    pub(super) fn on_hello_res(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        info: &Kad2NodeInfo,
        key: ReceivedKey,
    ) {
        let Some(index) = self
            .pending_probes
            .iter()
            .position(|probe| probe.endpoint == from)
        else {
            self.emit_diagnostic(KadNodeDiagnostic::UnsolicitedHelloRes { from });
            return;
        };
        let probe = self.pending_probes.remove(index);

        if info.id != probe.expected {
            self.emit_diagnostic(KadNodeDiagnostic::HelloResIdMismatch {
                from,
                expected: probe.expected,
                reported: info.id,
            });
            if self.routing.evict(probe.expected) {
                self.emit_event(KadEvent::ContactEvicted { id: probe.expected });
            }
            return;
        }

        // No admission consult here: a hello response is
        // probe-solicited, and a probe only ever goes to a stored — already
        // admitted — contact. With a filter armed before start this refresh
        // cannot see a filtered IP; it becomes reachable only after a future
        // filter *reload*, the same reload-only class as aMule's per-packet
        // recheck (`ClientTCPSocket.cpp#L376`), deferred with it.
        // The probe answer marks the contact alive (aMule `SetAlive`, via the
        // same `update = true` path); one evicted meanwhile re-enters fresh.
        if self
            .routing
            .upsert(now, self.contact_from_hello(from, info, key))
            == KadRoutingUpdate::Updated
        {
            self.routing.mark_alive(now, info.id);
        }
        self.emit_event(KadEvent::ContactResponded { id: info.id });
        if key.valid_receiver_key {
            self.verify(info.id, from.ip());
        }
        // Role B: the responder requested a verify ACK. Answer with a `0x22`
        // keyed under the sender key it gave us; missing key = aMule's silent
        // drop ("Remote client demands ACK, but didn't send any sender key!",
        // `KademliaUDPListener.cpp#L608`). The v≥8 floor is aMule's
        // `AddContact2` parse gate: below it the bit is never honored. The ACK
        // must also *go out* keyed — its receiver slot echoing that sender key;
        // a plaintext `0x22` is dropped as "invalid receiver key".
        if info.misc_options & MISC_OPTIONS_ACK_REQUEST != 0
            && info.version >= Self::ACK_REQUEST_MIN_VERSION
            && key.sender_key.is_some_and(|sender| {
                self.outbound_key(from, KADEMLIA2_HELLO_RES_ACK)
                    .is_some_and(|outbound| outbound.receiver_verify_key == sender)
            })
        {
            self.send(from, &Kad2Message::HelloResAck { id: self.config.id });
        }
        // aMule piggybacks the firewall check on a processed hello response too
        // (`Process2HelloResponse`) — a validated contact is a fresh checker —
        // after its extern-port ping.
        self.ping_for_extern_port_on_hello(now, from, info.version);
        self.maybe_firewall_check(now, from, info);
    }

    /// Consume an inbound `0x22` ACK (ADR-0064, role C). Gate order: solicited
    /// (an outstanding ack-request from this endpoint — aMule's
    /// `CHECK_TRACKED_PACKET(KADEMLIA2_HELLO_RES)`) → valid receiver key →
    /// ID/IP match → `VerifyContact` (`KademliaUDPListener.cpp#L573`). Without
    /// the receiver key the ACK proves nothing (anyone can spoof a source IP
    /// they cannot receive at), so a plaintext ACK is consumed-but-unverifying.
    pub(super) fn on_hello_res_ack(
        &mut self,
        from: KadNodeEndpoint,
        ack_id: KadId,
        key: ReceivedKey,
    ) {
        let Some(pos) = self
            .awaiting_acks
            .iter()
            .position(|awaiting| awaiting.endpoint == from)
        else {
            self.emit_diagnostic(KadNodeDiagnostic::UnsolicitedHelloResAck { from });
            return;
        };
        let expected = self.awaiting_acks.remove(pos).expected;
        // aMule `VerifyContact(id, ip)`: the ACK must prove its IP (receiver
        // key), name the solicited contact, and come from that contact's IP.
        if key.valid_receiver_key && ack_id == expected && self.verify(expected, from.ip()) {
            return;
        }
        self.emit_diagnostic(KadNodeDiagnostic::HelloResAckUnverified { from });
    }

    /// Record an outstanding `0x22` ack-request toward `endpoint` for `id`
    /// (one per endpoint — a re-request replaces the prior expectation and
    /// re-arms its [`ACK_REQUEST_WINDOW`](Self::ACK_REQUEST_WINDOW) deadline).
    fn track_ack_request(&mut self, now: KadInstant, endpoint: KadNodeEndpoint, id: KadId) {
        let deadline = now + Self::ACK_REQUEST_WINDOW;
        match self
            .awaiting_acks
            .iter_mut()
            .find(|awaiting| awaiting.endpoint == endpoint)
        {
            Some(entry) => {
                entry.expected = id;
                entry.deadline = deadline;
            }
            None => self.awaiting_acks.push(AwaitingAck {
                endpoint,
                expected: id,
                deadline,
            }),
        }
    }

    /// Run the routing-table `VerifyContact(id, ip)` and emit
    /// [`ContactVerified`](KadEvent::ContactVerified) when it takes. Returns
    /// whether the contact is now verified.
    fn verify(&mut self, id: KadId, observed_ip: Ipv4Addr) -> bool {
        if self.routing.verify_contact(id, observed_ip) {
            self.emit_event(KadEvent::ContactVerified { id });
            true
        } else {
            false
        }
    }

    pub(super) fn on_lookup_req(
        &mut self,
        from: KadNodeEndpoint,
        count: u8,
        target: KadId,
        check: KadId,
    ) {
        if check != self.config.id {
            self.emit_diagnostic(KadNodeDiagnostic::LookupCheckMismatch { from });
            return;
        }
        let contacts: Vec<KadContact> = self
            .routing
            .select_closest_servable(target, usize::from(count))
            .into_iter()
            .copied()
            .collect();
        self.send(from, &Kad2Message::LookupRes { target, contacts });
    }

    /// A contact as described by a hello: identity from the payload, IP from
    /// the datagram source, UDP port from the `0xFC` tag when present (falling
    /// back to the source port), stored validated-live, carrying the sender key
    /// its datagram's crypt trailer supplied (aMule stores the `CKadUDPKey` on
    /// the contact at `Add` time; the key is bound to our current public IP).
    fn contact_from_hello(
        &self,
        from: KadNodeEndpoint,
        info: &Kad2NodeInfo,
        key: ReceivedKey,
    ) -> KadContact {
        let udp_port = info.udp_port_tag.unwrap_or_else(|| from.udp_port());
        KadContact::with_state(
            info.id,
            KadNodeEndpoint::new(from.ip(), udp_port),
            info.tcp_port,
            info.version,
            KadContactState::Responded,
        )
        .with_udp_key(self.learned_key(key))
    }

    /// A counterparty's sender key as a storable [`KadUdpKey`], bound to this
    /// node's current public IP — empty when unarmed or when the datagram
    /// carried none.
    fn learned_key(&self, key: ReceivedKey) -> KadUdpKey {
        match (self.verify_keys, key.sender_key) {
            (Some(state), Some(sender_key)) => KadUdpKey::new(sender_key, state.public_ip),
            _ => KadUdpKey::EMPTY,
        }
    }

    /// The UDP verify key this node hands `target_ip` — `None` until the
    /// verify-key state is armed, which is what keeps `validReceiverKey`
    /// false-by-construction on the unarmed (plaintext-faithful) path.
    pub(super) fn own_verify_key_for(&self, target_ip: Ipv4Addr) -> Option<u32> {
        self.verify_keys
            .map(|state| udp_verify_key(state.secret, target_ip))
    }

    /// Offer a contact to the table, emitting the add/evict events. Returns
    /// whether the contact is now stored.
    pub(super) fn store(&mut self, now: KadInstant, contact: KadContact) -> bool {
        // The IP-filter admission consult (aMule
        // `CRoutingZone::Add`, `RoutingZone.cpp#L406` — the same gate its
        // nodes.dat load at `#L195` and every AddContact path sit behind): a
        // filtered IP never becomes a routing contact, so it is never probed,
        // verified, served in routing answers, or persisted. Callers that
        // probe-on-store get their refusal from the `false` return, exactly
        // like a bucket-full rejection.
        if !self.contact_admission.admits(contact.endpoint().ip()) {
            self.emit_diagnostic(KadNodeDiagnostic::ContactIpFiltered {
                endpoint: contact.endpoint(),
            });
            return false;
        }
        match self.routing.upsert(now, contact) {
            KadRoutingUpdate::Added => {
                self.emit_event(KadEvent::ContactAdded {
                    id: contact.id(),
                    endpoint: contact.endpoint(),
                });
                true
            }
            KadRoutingUpdate::AddedEvictingFailed { evicted } => {
                self.emit_event(KadEvent::ContactEvicted { id: evicted });
                self.emit_event(KadEvent::ContactAdded {
                    id: contact.id(),
                    endpoint: contact.endpoint(),
                });
                true
            }
            KadRoutingUpdate::Updated => true,
            // A bucket full of live contacts keeps them (Kademlia's
            // longevity bias — also the flood-resistance property); the own
            // ID is never stored; a verified contact is never displaced to a
            // new endpoint by an unproven claimant (anti-hijack, ADR-0064); and
            // a keyed entry is never updated by a claimant that cannot present
            // its key.
            KadRoutingUpdate::RejectedBucketFull
            | KadRoutingUpdate::RejectedSelf
            | KadRoutingUpdate::RejectedHijack { .. }
            | KadRoutingUpdate::RejectedKeyMismatch { .. } => false,
        }
    }

    /// Send one hello probe to a stored contact and arm its deadline.
    /// `evict_on_timeout` is false only for the small-timer aging pass
    /// Every other caller — join's hearsay/responder validation,
    /// firewall re-verification — fails and evicts on one unanswered probe,
    /// aMule's own outcome for a contact that was never verified in the
    /// first place.
    pub(super) fn probe(
        &mut self,
        now: KadInstant,
        expected: KadId,
        endpoint: KadNodeEndpoint,
        evict_on_timeout: bool,
    ) {
        if self.pending_probes.iter().any(|p| p.endpoint == endpoint) {
            return;
        }
        self.pending_probes.push(PendingProbe {
            endpoint,
            expected,
            deadline: now + Self::PROBE_TIMEOUT,
            evict_on_timeout,
        });
        self.send(endpoint, &Kad2Message::HelloReq(self.hello_info()));
    }

    /// This node as a hello payload (UDP port advertised via the `0xFC` tag),
    /// carrying no misc-options — the `HELLO_REQ` form (a request never asks for
    /// an ack, ADR-0064).
    fn hello_info(&self) -> Kad2NodeInfo {
        Kad2NodeInfo {
            udp_port_tag: Some(self.config.udp_port),
            ..self.header_info()
        }
    }

    /// This node as a `HELLO_RES` payload: the hello info plus misc-options bit 2
    /// when this response asks the peer for a `0x22` verify ACK (role A). The
    /// firewalled bits are fed by ADR-0058 `Reachability`; rmule assumes an open
    /// node, so they stay clear.
    fn hello_res_info(&self, request_ack: bool) -> Kad2NodeInfo {
        let mut info = self.hello_info();
        if request_ack {
            info.misc_options |= MISC_OPTIONS_ACK_REQUEST;
        }
        info
    }

    /// This node as a bootstrap-response header (no tag list on the wire).
    pub(super) fn header_info(&self) -> Kad2NodeInfo {
        Kad2NodeInfo {
            id: self.config.id,
            tcp_port: self.config.tcp_port,
            version: Self::KAD_VERSION,
            udp_port_tag: None,
            misc_options: 0,
        }
    }
}
