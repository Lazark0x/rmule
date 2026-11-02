//! Joining the network: the Bootstrap Dial List's paced dials, the forced
//! self-lookup, and both halves of the `KADEMLIA2_BOOTSTRAP` exchange. Every
//! cadence here is explicit-time — a driver's `tick` advances it — and the dial
//! loop falls silent once the node is joined (ADR-0067). The small-timer hello
//! pass that reaches a merged table lives in `small_timer`: it never gates on
//! join state.

use std::net::IpAddr;
use std::time::Duration;

use rmule_primitives::Informant;

use super::{KadEvent, KadNode, KadNodeDiagnostic, PendingBootstrap};
use crate::lookup_walk::KadWalkPurpose;
use crate::messages::{Kad2Message, Kad2NodeInfo};
use crate::{KadBootstrapNode, KadContact, KadContactState, KadInstant, KadNodeEndpoint};

impl KadNode {
    /// Most contacts a bootstrap response returns (aMule returns up to 20).
    pub const BOOTSTRAP_RES_MAX_CONTACTS: usize = 20;

    /// How long an outstanding `KADEMLIA2_BOOTSTRAP_REQ` may go unanswered
    /// before its solicitation expires (ADR-0064's out-track alignment,
    /// aMule's `PacketTracking.cpp` acceptance window — wire-aligned, unlike
    /// this node's other rmule-policy windows below).
    pub const BOOTSTRAP_SOLICITATION_WINDOW: Duration = Duration::from_secs(180);

    // Join cadence constants (ADR-0067), aMule-verbatim from
    // `kademlia/kademlia/Kademlia.cpp` (commit `4e8f2b3c`).

    /// The bootstrap dial cadence once the routing table holds contacts —
    /// aMule's slow bootstrap pace (`Kademlia.cpp#L284`, 15 s).
    pub const BOOTSTRAP_DIAL_INTERVAL: Duration = Duration::from_secs(15);

    /// The faster dial cadence while the routing table is still empty
    /// (`Kademlia.cpp#L284`, 2 s): a stranded node retries seeds harder. An
    /// arriving `BOOTSTRAP_RES` fills the table and relaxes it to the 15 s pace.
    pub const BOOTSTRAP_DIAL_INTERVAL_EMPTY: Duration = Duration::from_secs(2);

    /// How long after the join starts the first forced self-lookup fires —
    /// aMule's `m_nextSelfLookup = now + MIN2S(3)` (`Kademlia.cpp#L100`).
    pub const SELF_LOOKUP_INITIAL: Duration = Duration::from_secs(3 * 60);

    /// How often the self-lookup repeats after the first — aMule's 4 h refresh
    /// (`Kademlia.cpp#L200`).
    pub const SELF_LOOKUP_REFRESH: Duration = Duration::from_secs(4 * 60 * 60);

    /// The **ed2k→Kad handoff** throttle (ADR-0067): a peer hint bootstraps
    /// only when at least this long has passed since the last bootstrap dial —
    /// aMule's `CKademlia::Bootstrap` guard (`> 10 s` against the shared
    /// `m_bootstrap`, `Kademlia.h#L91`, read here as "≥ 10 s" per ADR-0067 and
    /// the codebase's additive-instant idiom). The dial loop stamps the same
    /// timestamp, so this rate-couples peer hints with list dials.
    pub const BOOTSTRAP_THROTTLE: Duration = Duration::from_secs(10);

    /// Whether the node has **joined** the Kad network — aMule's
    /// `CKademlia::IsConnected` = `HasHadContact`: a Kad datagram was received
    /// within the last [`KadRoutingTable::HAD_CONTACT_WINDOW`](crate::KadRoutingTable::HAD_CONTACT_WINDOW) (20 min, ADR-0067).
    /// Gates the bootstrap dial loop (dialing stops once joined) and is the
    /// predicate the ed2k→Kad handoff gates its own dial on.
    #[must_use]
    pub fn joined(&self, now: KadInstant) -> bool {
        self.routing.has_had_contact(now)
    }

    /// Send one `KADEMLIA2_BOOTSTRAP_REQ` to `endpoint` and arm its 180 s
    /// solicitation window (ADR-0064) so the matching `BOOTSTRAP_RES` is
    /// accepted. Shared by the [`Bootstrap`](crate::KadCommand::Bootstrap) command (dial
    /// this one now) and the dial loop (dial the next list candidate); a repeat
    /// dial to an already-outstanding endpoint re-sends without a second window.
    pub(super) fn dial_bootstrap(&mut self, now: KadInstant, endpoint: KadNodeEndpoint) {
        // Stamp aMule's `m_bootstrap` on every dial — the shared 10 s throttle
        // (ADR-0067). The list-dial loop and the ed2k→Kad handoff both funnel
        // through here, so both stamp and both read the one timestamp: that is
        // the rate-coupling. Monotonic, like the contact stamp, so an
        // out-of-order tick never rewinds the throttle.
        self.last_bootstrap = Some(self.last_bootstrap.map_or(now, |last| last.max(now)));
        if !self
            .outstanding_bootstraps
            .iter()
            .any(|pending| pending.endpoint == endpoint)
        {
            self.outstanding_bootstraps.push(PendingBootstrap {
                endpoint,
                deadline: now + Self::BOOTSTRAP_SOLICITATION_WINDOW,
            });
        }
        self.send(endpoint, &Kad2Message::BootstrapReq);
    }

    /// Append candidates to the one **Bootstrap Dial List** and arm the dial loop
    /// if it is idle and joining is still needed (ADR-0067). Shared by the
    /// [`SeedBootstrapDialList`](crate::KadCommand::SeedBootstrapDialList) command (config
    /// / v3-file seeds) and the [`ed2k→Kad handoff`](Self::handoff_from_peer): a
    /// first candidate onto an empty, un-armed list dials promptly (due now); an
    /// already-running loop keeps its own cadence; an already-joined node just
    /// banks the candidates without dialing (the dial loop is gated on
    /// `not joined`).
    pub(super) fn seed_bootstrap_dial_list(
        &mut self,
        now: KadInstant,
        candidates: Vec<KadBootstrapNode>,
    ) {
        // aMule's bootstrap-file selection consults the IP filter before a
        // candidate may be dialed (`RoutingZone.cpp#L252`); the
        // ed2k→Kad handoff funnels through here too, so a filtered peer hint
        // is dropped the same way — a blocklisted IP is never sent a
        // `KADEMLIA2_BOOTSTRAP_REQ`.
        let (admitted, refused): (Vec<KadBootstrapNode>, Vec<KadBootstrapNode>) = candidates
            .into_iter()
            .partition(|candidate| self.contact_admission.admits(candidate.endpoint().ip()));
        for candidate in refused {
            self.emit_diagnostic(KadNodeDiagnostic::ContactIpFiltered {
                endpoint: candidate.endpoint(),
            });
        }
        self.bootstrap_dial_list.extend(admitted);
        if self.next_bootstrap_dial.is_none()
            && !self.joined(now)
            && !self.bootstrap_dial_list.is_empty()
        {
            self.next_bootstrap_dial = Some(now);
        }
    }

    /// The **ed2k→Kad handoff** (ADR-0067): apply aMule's
    /// `CKademlia::Bootstrap` gate to a peer-carried Kad `endpoint` and, if it
    /// opens, seed it into the one Bootstrap Dial List for the dial loop.
    ///
    /// The gate is aMule's `m_running ∧ !IsConnected() ∧ (now - m_bootstrap) >
    /// 10 s` minus its `m_running` leg: **running** is the *core* precondition
    /// (core brokers a hint only to a live node), so the node
    /// applies **not joined** ([`joined`](Self::joined)) and the **shared 10 s
    /// throttle** ([`bootstrap_throttle_open`](Self::bootstrap_throttle_open)).
    /// A suppressed handoff drops the hint — aMule queues nothing, it
    /// early-returns — so the peer's endpoint never enters the list.
    pub(super) fn handoff_from_peer(&mut self, now: KadInstant, endpoint: KadNodeEndpoint) {
        if self.joined(now) || !self.bootstrap_throttle_open(now) {
            return;
        }
        self.seed_bootstrap_dial_list(now, vec![KadBootstrapNode::new(endpoint, None)]);
    }

    /// Whether at least [`BOOTSTRAP_THROTTLE`](Self::BOOTSTRAP_THROTTLE) has
    /// passed since the last bootstrap dial — aMule's `now - m_bootstrap` guard
    /// (ADR-0067). A fresh node (never dialed) is un-throttled. Additive form
    /// (`now ≥ last + throttle`), matching [`has_had_contact`] and avoiding
    /// instant subtraction.
    ///
    /// [`has_had_contact`]: crate::KadRoutingTable::has_had_contact
    #[must_use]
    fn bootstrap_throttle_open(&self, now: KadInstant) -> bool {
        self.last_bootstrap
            .is_none_or(|last| now >= last + Self::BOOTSTRAP_THROTTLE)
    }

    /// The **Bootstrap Dial List** cadence (ADR-0067): while not joined and
    /// the list is non-empty, dial the front candidate when its instant is due,
    /// discard it, and schedule the next dial — 2 s while the routing table is
    /// empty, 15 s once it holds contacts. Joining stops the loop (a received
    /// datagram made the node connected); a drained list stops it too. Both clear
    /// the timer so [`next_wake`](Self::next_wake) reports no further dial and the
    /// node can quiesce; a fresh [`SeedBootstrapDialList`](crate::KadCommand::SeedBootstrapDialList)
    /// re-arms it.
    pub(super) fn tick_bootstrap_dials(&mut self, now: KadInstant) {
        // Stop-on-joined: a received Kad datagram (a bootstrap answer, typically)
        // marks the node connected, ending the dial loop with candidates possibly
        // still un-dialed — exactly aMule's behavior.
        if self.joined(now) {
            self.next_bootstrap_dial = None;
            return;
        }
        let Some(due) = self.next_bootstrap_dial else {
            return;
        };
        if due > now {
            return;
        }
        let Some(candidate) = self.bootstrap_dial_list.pop_front() else {
            self.next_bootstrap_dial = None;
            return;
        };
        self.dial_bootstrap(now, candidate.endpoint());
        // Reschedule only while candidates remain; the empty-table fast cadence
        // ends naturally once a `BOOTSTRAP_RES` seeds the routing table.
        self.next_bootstrap_dial = if self.bootstrap_dial_list.is_empty() {
            None
        } else if self.routing.is_empty() {
            Some(now + Self::BOOTSTRAP_DIAL_INTERVAL_EMPTY)
        } else {
            Some(now + Self::BOOTSTRAP_DIAL_INTERVAL)
        };
    }

    /// The forced self-lookup schedule (ADR-0067): when due, start a
    /// `FindNode` walk toward the own Kad ID and re-arm 4 h out. Fires on the
    /// timer regardless of joined-ness or table contents (an empty table simply
    /// sends no queries) — the schedule is the join heartbeat.
    pub(super) fn tick_self_lookup(&mut self, now: KadInstant) {
        let Some(due) = self.next_self_lookup else {
            return;
        };
        if due > now {
            return;
        }
        self.next_self_lookup = Some(now + Self::SELF_LOOKUP_REFRESH);
        self.emit_event(KadEvent::SelfLookupStarted);
        // Rides the ordinary lookup machinery toward the own ID; a self-lookup
        // walk has no terminal search/publish — it warms the neighborhood and
        // ends. Skip if one is somehow still in flight (the 4 h cadence makes
        // that impossible in practice, but never stack two).
        let own_id = self.config.id;
        if self.walks.iter().all(|walk| walk.target() != own_id) {
            self.start_walk(now, KadWalkPurpose::SelfLookup { target: own_id });
        }
    }

    pub(super) fn on_bootstrap_req(&mut self, from: KadNodeEndpoint) {
        // A Kad2 bootstrap request is empty: no identity to add.
        let contacts: Vec<KadContact> = self
            .routing
            .contacts()
            .filter(|c| c.state() == KadContactState::Responded)
            .take(Self::BOOTSTRAP_RES_MAX_CONTACTS)
            .copied()
            .collect();
        self.send(
            from,
            &Kad2Message::BootstrapRes {
                sender: self.header_info(),
                contacts,
            },
        );
    }

    pub(super) fn on_bootstrap_res(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        sender: Kad2NodeInfo,
        rows: Vec<KadContact>,
    ) {
        let Some(index) = self
            .outstanding_bootstraps
            .iter()
            .position(|pending| pending.endpoint == from)
        else {
            self.emit_diagnostic(KadNodeDiagnostic::UnsolicitedBootstrapRes { from });
            return;
        };
        self.outstanding_bootstraps.remove(index);

        // The responder answered from its endpoint: live. Store it Responded
        // and hello it once so it learns us too (a Kad2 bootstrap request
        // carries no sender identity).
        let responder = KadContact::with_state(
            sender.id,
            from,
            sender.tcp_port,
            sender.version,
            KadContactState::Responded,
        );
        // The responder vouches for its own address and for every row it sent.
        let informant = Informant::Party(IpAddr::V4(from.ip()));
        let known = self.routing.get(sender.id).is_some();
        if self.store(now, responder, informant) {
            // aMule adds the responder with `update = true`
            // (`KademliaUDPListener.cpp:559`): a known one is marked alive.
            if known {
                self.routing.mark_alive(now, sender.id);
            }
            self.probe(now, sender.id, from, true);
        }

        // Rows are hearsay: store Pending and probe each.
        for row in rows {
            if self.routing.get(row.id()).is_some() {
                continue;
            }
            let hearsay = row.in_state(KadContactState::Pending);
            if self.store(now, hearsay, informant) {
                self.probe(now, hearsay.id(), hearsay.endpoint(), true);
            }
        }
    }

    /// At least one live (Responded) contact to seed a walk from — the **Kad
    /// Publisher**'s "can I reach the network?" proxy (ADR-0062). Deliberately
    /// not the network-joined predicate [`joined`](Self::joined) (aMule's
    /// `HasHadContact`): a publisher needs a *servable seed*, whereas joined
    /// tracks whether any datagram arrived in the last 20 min. aMule reads
    /// `IsConnected` for both; converging this gate onto [`joined`](Self::joined)
    /// is deferred (it would change the ADR-0062 publish gate, outside the
    /// dial loop's remit).
    pub(super) fn has_live_contact(&self) -> bool {
        self.routing
            .contacts()
            .any(|contact| contact.state() == KadContactState::Responded)
    }
}
