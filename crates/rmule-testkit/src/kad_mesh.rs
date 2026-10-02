//! Deterministic Kad mesh simulation: N sans-I/O [`KadNode`]s plus scriptable
//! [`FakeKadPeer`]s on a virtual clock with in-memory datagram routing.
//!
//! Determinism contract: no RNG anywhere — link behavior is *scripted*
//! ([`LinkPolicy`]), deliveries are ordered by `(due instant, send sequence)`,
//! nodes are stepped in insertion order, and the virtual clock only advances
//! to the earliest pending instant. Identical configs therefore produce
//! identical [`trace`](KadMeshSim::trace)s, which the acceptance tests assert
//! literally.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_kad::{
    KadCommand, KadEvent, KadId, KadInstant, KadNode, KadNodeConfig, KadNodeEndpoint, KadOutput,
};

/// Drain a node's outputs, partitioning datagrams from events — the tuple
/// split the requester and publisher/storer suites hand-rolled.
/// Drains through [`rmule_primitives::session::drain`], the shared spine.
pub fn drain_split(node: &mut KadNode) -> (Vec<(KadNodeEndpoint, Vec<u8>)>, Vec<KadEvent>) {
    let mut datagrams = Vec::new();
    let mut events = Vec::new();
    for output in rmule_primitives::session::drain(|| node.poll_output()) {
        match output {
            KadOutput::Datagram { to, bytes } => datagrams.push((to, bytes)),
            KadOutput::Event(event) => events.push(event),
        }
    }
    (datagrams, events)
}

/// Scripted behavior of one directed link `(from, to)`.
#[derive(Clone, Copy, Debug)]
pub struct LinkPolicy {
    /// Drop this many datagrams before delivering any (use `u32::MAX` for a
    /// black-hole link).
    pub drop_first: u32,
    /// One-way delivery delay.
    pub delay: Duration,
    /// Deliver every datagram twice (second copy one sequence step later).
    pub duplicate: bool,
}

impl Default for LinkPolicy {
    fn default() -> Self {
        Self {
            drop_first: 0,
            delay: Duration::from_millis(10),
            duplicate: false,
        }
    }
}

/// A scriptable adversarial datagram counterparty (the datagram half of the
/// both-fakes policy). It is not a `KadNode`: it answers with whatever raw
/// bytes its script says, well-formed or hostile.
#[derive(Debug, Default)]
pub struct FakeKadPeer {
    /// `(opcode, responses)` — on receiving a plain datagram with this opcode,
    /// send each response datagram back to the sender. First unspent match
    /// wins; rules are one-shot.
    rules: Vec<FakeRule>,
    /// `(due, to, bytes)` — unsolicited datagrams to emit at an instant.
    scheduled: Vec<(KadInstant, KadNodeEndpoint, Vec<u8>)>,
    /// Every datagram this peer received, for assertions.
    received: Vec<(KadInstant, KadNodeEndpoint, Vec<u8>)>,
}

#[derive(Debug)]
struct FakeRule {
    opcode: u8,
    responses: Vec<Vec<u8>>,
    spent: bool,
}

impl FakeKadPeer {
    /// A peer that answers nothing and sends nothing — every behaviour is
    /// added by a `with_`/`once_on_` rule.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Respond to the first datagram of `opcode` with these raw datagrams.
    #[must_use]
    pub fn once_on_opcode(mut self, opcode: u8, responses: Vec<Vec<u8>>) -> Self {
        self.rules.push(FakeRule {
            opcode,
            responses,
            spent: false,
        });
        self
    }

    /// Send raw bytes to an endpoint at an absolute virtual instant.
    #[must_use]
    pub fn unsolicited_at(mut self, at: KadInstant, to: KadNodeEndpoint, bytes: Vec<u8>) -> Self {
        self.scheduled.push((at, to, bytes));
        self
    }

    /// Datagrams this peer received, in delivery order.
    #[must_use]
    pub fn received(&self) -> &[(KadInstant, KadNodeEndpoint, Vec<u8>)] {
        &self.received
    }

    fn next_scheduled(&self) -> Option<KadInstant> {
        self.scheduled.iter().map(|(at, ..)| *at).min()
    }

    fn take_scheduled_due(&mut self, now: KadInstant) -> Vec<(KadNodeEndpoint, Vec<u8>)> {
        let mut due = Vec::new();
        self.scheduled.retain(|(at, to, bytes)| {
            if *at <= now {
                due.push((*to, bytes.clone()));
                false
            } else {
                true
            }
        });
        due
    }

    fn on_datagram(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        bytes: &[u8],
    ) -> Vec<(KadNodeEndpoint, Vec<u8>)> {
        self.received.push((now, from, bytes.to_vec()));
        let opcode = bytes.get(1).copied();
        for rule in &mut self.rules {
            if rule.spent || Some(rule.opcode) != opcode {
                continue;
            }
            rule.spent = true;
            return rule
                .responses
                .iter()
                .map(|response| (from, response.clone()))
                .collect();
        }
        Vec::new()
    }
}

/// One trace entry: virtual instant, node label, observed event.
pub type TraceEntry = (u64, &'static str, KadEvent);

/// A deterministic in-memory mesh of Kad nodes and fake peers.
pub struct KadMeshSim {
    now: KadInstant,
    nodes: Vec<SimNode>,
    fakes: Vec<SimFake>,
    links: Vec<((KadNodeEndpoint, KadNodeEndpoint), LinkState)>,
    in_flight: Vec<Delivery>,
    seq: u64,
    trace: Vec<TraceEntry>,
}

struct SimNode {
    label: &'static str,
    endpoint: KadNodeEndpoint,
    node: KadNode,
}

struct SimFake {
    endpoint: KadNodeEndpoint,
    peer: FakeKadPeer,
}

struct LinkState {
    policy: LinkPolicy,
    dropped: u32,
}

struct Delivery {
    due: KadInstant,
    seq: u64,
    from: KadNodeEndpoint,
    to: KadNodeEndpoint,
    bytes: Vec<u8>,
}

impl Default for KadMeshSim {
    fn default() -> Self {
        Self::new()
    }
}

impl KadMeshSim {
    /// An empty mesh at the virtual epoch: no nodes, no fakes, every link at
    /// [`LinkPolicy::default`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            now: KadInstant::EPOCH,
            nodes: Vec::new(),
            fakes: Vec::new(),
            links: Vec::new(),
            in_flight: Vec::new(),
            seq: 0,
            trace: Vec::new(),
        }
    }

    /// Seat a real [`KadNode`] in the mesh at `endpoint`. `label` is how the
    /// node is addressed in commands and how it reads in the trace.
    #[must_use]
    pub fn with_node(
        mut self,
        label: &'static str,
        config: KadNodeConfig,
        endpoint: KadNodeEndpoint,
    ) -> Self {
        self.nodes.push(SimNode {
            label,
            endpoint,
            node: KadNode::new(config),
        });
        self
    }

    /// Seat a scripted counterparty at `endpoint` — the way a leg gets a peer
    /// that misbehaves in a shape no real node would produce.
    #[must_use]
    pub fn with_fake(mut self, endpoint: KadNodeEndpoint, peer: FakeKadPeer) -> Self {
        self.fakes.push(SimFake { endpoint, peer });
        self
    }

    /// Script one directed link; unscripted links use [`LinkPolicy::default`].
    #[must_use]
    pub fn with_link(
        mut self,
        from: KadNodeEndpoint,
        to: KadNodeEndpoint,
        policy: LinkPolicy,
    ) -> Self {
        self.links
            .push(((from, to), LinkState { policy, dropped: 0 }));
        self
    }

    /// Issue a driver command to a node at the current virtual instant.
    pub fn command(&mut self, label: &'static str, command: KadCommand) {
        let now = self.now;
        let index = self.node_index(label);
        self.nodes[index].node.handle_command(now, command);
        self.drain_node(index);
    }

    /// Advance the virtual clock event-by-event until nothing is pending or
    /// `max_steps` events have been processed (a run-away guard, not a timing
    /// knob).
    pub fn run_until_idle(&mut self, max_steps: usize) {
        for _ in 0..max_steps {
            let Some(at) = self.next_pending() else {
                return;
            };
            self.now = self.now.max(at);
            self.step();
        }
        panic!("mesh did not go idle within the step budget — livelock?");
    }

    /// Advance the virtual clock event-by-event, but only through events due
    /// at or before `until` — for meshes that are never idle (a registered
    /// publish republishes forever). The clock lands exactly on `until`.
    pub fn run_until(&mut self, until: KadInstant, max_steps: usize) {
        for _ in 0..max_steps {
            match self.next_pending() {
                Some(at) if at <= until => {
                    self.now = self.now.max(at);
                    self.step();
                }
                _ => {
                    self.now = self.now.max(until);
                    return;
                }
            }
        }
        panic!("mesh did not drain the window within the step budget — livelock?");
    }

    fn next_pending(&self) -> Option<KadInstant> {
        let next_delivery = self.in_flight.iter().map(|d| d.due).min();
        let next_wake = self.nodes.iter().filter_map(|n| n.node.next_wake()).min();
        let next_fake = self
            .fakes
            .iter()
            .filter_map(|f| f.peer.next_scheduled())
            .min();
        [next_delivery, next_wake, next_fake]
            .into_iter()
            .flatten()
            .min()
    }

    /// The virtual instant the sim has advanced to.
    #[must_use]
    pub fn now(&self) -> KadInstant {
        self.now
    }

    /// The deterministic event trace: `(at_millis, node label, event)`.
    #[must_use]
    pub fn trace(&self) -> &[TraceEntry] {
        &self.trace
    }

    /// A node's state machine, for table assertions.
    #[must_use]
    pub fn node(&self, label: &'static str) -> &KadNode {
        &self.nodes[self.node_index(label)].node
    }

    /// A fake peer's observation log.
    #[must_use]
    pub fn fake(&self, endpoint: KadNodeEndpoint) -> &FakeKadPeer {
        &self
            .fakes
            .iter()
            .find(|f| f.endpoint == endpoint)
            .expect("no fake at that endpoint")
            .peer
    }

    fn node_index(&self, label: &'static str) -> usize {
        self.nodes
            .iter()
            .position(|n| n.label == label)
            .expect("unknown node label")
    }

    /// Process everything due at `self.now`: fake scheduled sends, then
    /// deliveries in `(due, seq)` order, then node timers — each in insertion
    /// order, so the step is fully deterministic.
    fn step(&mut self) {
        let now = self.now;

        for index in 0..self.fakes.len() {
            let sends = self.fakes[index].peer.take_scheduled_due(now);
            let from = self.fakes[index].endpoint;
            for (to, bytes) in sends {
                self.route(from, to, bytes);
            }
        }

        loop {
            let Some(position) = self
                .in_flight
                .iter()
                .enumerate()
                .filter(|(_, d)| d.due <= now)
                .min_by_key(|(_, d)| (d.due, d.seq))
                .map(|(position, _)| position)
            else {
                break;
            };
            let delivery = self.in_flight.swap_remove(position);
            self.deliver(delivery);
        }

        for index in 0..self.nodes.len() {
            if self.nodes[index]
                .node
                .next_wake()
                .is_some_and(|wake| wake <= now)
            {
                self.nodes[index].node.tick(now);
                self.drain_node(index);
            }
        }
    }

    fn deliver(&mut self, delivery: Delivery) {
        let now = self.now;
        if let Some(index) = self.nodes.iter().position(|n| n.endpoint == delivery.to) {
            self.nodes[index]
                .node
                .handle_datagram(now, delivery.from, &delivery.bytes);
            self.drain_node(index);
        } else if let Some(index) = self.fakes.iter().position(|f| f.endpoint == delivery.to) {
            let replies = self.fakes[index]
                .peer
                .on_datagram(now, delivery.from, &delivery.bytes);
            let from = self.fakes[index].endpoint;
            for (to, bytes) in replies {
                self.route(from, to, bytes);
            }
        }
        // A destination nobody owns is a silent black hole — deterministic by
        // construction.
    }

    fn drain_node(&mut self, index: usize) {
        let outputs = rmule_primitives::session::drain(|| self.nodes[index].node.poll_output());
        let (label, from) = (self.nodes[index].label, self.nodes[index].endpoint);
        for output in outputs {
            match output {
                KadOutput::Datagram { to, bytes } => self.route(from, to, bytes),
                KadOutput::Event(event) => {
                    self.trace.push((self.now.as_millis(), label, event));
                }
            }
        }
    }

    fn route(&mut self, from: KadNodeEndpoint, to: KadNodeEndpoint, bytes: Vec<u8>) {
        let policy = match self
            .links
            .iter_mut()
            .find(|((link_from, link_to), _)| *link_from == from && *link_to == to)
        {
            Some((_, state)) => {
                if state.dropped < state.policy.drop_first {
                    state.dropped += 1;
                    return;
                }
                state.policy
            }
            None => LinkPolicy::default(),
        };

        let due = self.now + policy.delay;
        let copies = if policy.duplicate { 2 } else { 1 };
        for _ in 0..copies {
            let seq = self.seq;
            self.seq += 1;
            self.in_flight.push(Delivery {
                due,
                seq,
                from,
                to,
                bytes: bytes.clone(),
            });
        }
    }
}

// --- mesh vocabulary ---------------------------------------------------------
//
// The labels a `KadMeshSim` addresses its members by, and the configs and
// endpoints those members run with. One home: a label means the same node in
// every suite that builds a mesh.

/// The publisher in a source mesh; node `a` in a two-node sim.
pub const A: &str = "a";
/// Node `b` — the peer `a` bootstraps against in a two-node sim.
pub const B: &str = "b";
/// The requester in a source mesh: it searches for what `A` published.
pub const C: &str = "c";
/// The far hub a source mesh joins through — nowhere near the key, so it can
/// only route, never store.
pub const HUB: &str = "hub";
/// The three real storers of a source mesh, labelled by their distance byte
/// from the key.
pub const STORERS: [(&str, u8); 3] = [("r10", 10), ("r20", 20), ("r30", 30)];

/// Node `a`'s endpoint in a two-node sim.
pub const A_EP: KadNodeEndpoint = KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 1), 4701);
/// Node `b`'s endpoint in a two-node sim.
pub const B_EP: KadNodeEndpoint = KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 2), 4702);

/// The publisher's endpoint in a source mesh — TEST-NET, so its publishes
/// pass the storers' tolerance gate rather than the LAN bypass.
pub fn a_endpoint() -> KadNodeEndpoint {
    crate::kad_source::contact_endpoint(254)
}

/// The requester's endpoint in a source mesh.
pub fn c_endpoint() -> KadNodeEndpoint {
    crate::kad_source::contact_endpoint(253)
}

/// The hub's endpoint in a source mesh.
pub fn hub_endpoint() -> KadNodeEndpoint {
    crate::kad_source::contact_endpoint(200)
}

/// The config a mesh member runs with: its id, the endpoint the sim routes to
/// it (whose UDP port the node must bind, or its replies go nowhere), and a
/// user hash byte that tells it apart from its neighbours.
pub fn config(id: KadId, endpoint: KadNodeEndpoint, user_hash_byte: u8) -> KadNodeConfig {
    KadNodeConfig {
        id,
        tcp_port: 4662,
        udp_port: endpoint.udp_port(),
        user_hash: rmule_kad::UserHash::from_bytes([user_hash_byte; 16]),
    }
}
