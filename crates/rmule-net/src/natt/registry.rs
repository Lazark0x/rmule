//! The **Tunnel Registry**: which endpoints hold, or are opening, a tunnel.
//!
//! This exists for one reason, and it is aMule's deferred item A2. A uTP
//! engine like libutp, handed a packet for a connection it does not know,
//! answers with an `ST_RESET` — to an address nobody verified. That turns rmule into a
//! reflector: a forged non-SYN datagram claiming any source gets an unsolicited
//! datagram sent there. So the registry gates the engine rather than the engine
//! gating itself: a frame from an endpoint that is neither opening nor holding
//! a tunnel is dropped **before** injection, and no reset is ever emitted.
//!
//! The same rule reads the same way for QUIC, where "may open" is a long-header
//! packet rather than an `ST_SYN`.
//!
//! Which engine would answer is not what the rule rests on. The libutp aMule
//! vendors does send the reset (`src/extern/libutp/utp_internal.cpp:2908-2939`
//! in amule-kno: "this isn't a SYN. Reject it." → `send_rst`); the
//! `librqbit-utp` 0.7.0 behind rmule's engine does not — its dispatcher drops
//! an unknown connection's non-`ST_STATE`, non-`ST_SYN` packet with a trace
//! (`src/socket.rs:672-674`). The registry keeps the gate anyway, so the
//! property survives an engine swap or upgrade, and adds no reset of its own:
//! a libutp peer whose connection rmule forgot times out instead of failing
//! fast, which costs it one timeout and costs no stranger a datagram.
//!
//! Every live slot is owned by a value whose `Drop` frees it — a dial's by its
//! [`DialingSlot`], a tunnel's by the [`HeldSlot`] inside the
//! [`Tunnel`](super::Tunnel) — so no caller downstream of an engine has to
//! remember to release anything, in any family.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmule_primitives::PeerEndpoint;

/// How long an endpoint stays admitted on the strength of an **inbound**
/// opening packet alone. rmule's own bound, not the dialect's — eMuleAI defines
/// none — chosen to outlast a uTP or QUIC handshake over a punched path with
/// retransmits, and short enough that a forged opening packet buys an attacker
/// one window rather than a permanent entry.
///
/// It governs [`TunnelSlot::Opening`] only. A slot our *own* dial opened is
/// [`TunnelSlot::Dialing`] and lives exactly as long as that dial, because
/// nothing a stranger sent created it.
pub const OPENING_TTL: Duration = Duration::from_secs(30);

/// What the registry knows about one endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelSlot {
    /// An **inbound** opening packet arrived and the handshake is in flight.
    /// Admitted, but only until [`OPENING_TTL`] elapses: an endpoint nobody
    /// here chose to talk to buys one window.
    Opening,
    /// **We** are dialing this endpoint, and the dial is still running.
    /// Admitted for as long as the dial's [`DialingSlot`] lives — never aged
    /// out, because a dial that cannot be answered any more is a dial rmule
    /// itself should be ending, and pruning underneath it would drop the
    /// answer to our own opening packet while we still wait for it.
    Dialing,
    /// A live tunnel. Admitted for as long as a [`HeldSlot`] for it lives —
    /// that is, as long as some [`Tunnel`](super::Tunnel) on the endpoint
    /// does.
    Held,
}

/// Whether a datagram from an endpoint may reach an engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Inject it: the endpoint holds or is opening a tunnel.
    Inject,
    /// Inject it, and the endpoint is newly admitted on this packet's strength.
    Opened,
    /// Drop it, silently. Never an `ST_RESET`, never any answer at all — the
    /// dialect has no failure frame and inventing one here would be a
    /// reflector.
    Drop,
}

/// One endpoint's row.
#[derive(Clone, Copy, Debug)]
struct SlotEntry {
    slot: TunnelSlot,
    since: Instant,
    /// How many live tunnels hold the endpoint. Two can: a punch is a
    /// simultaneous open, so our dial and the peer's may both complete before
    /// either side settles on one, and the loser closing must not evict the
    /// winner's admission. Zero unless `slot` is [`TunnelSlot::Held`].
    holders: u32,
}

/// The endpoint → tunnel-state table.
#[derive(Debug, Default)]
pub struct TunnelRegistry {
    slots: HashMap<PeerEndpoint, SlotEntry>,
}

impl TunnelRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether a datagram from `peer` reaches the engine.
    ///
    /// `opens` is whether *this packet* is an opening one — a uTP `ST_SYN` or a
    /// QUIC long header. An opening packet from an unknown endpoint is admitted
    /// and the endpoint recorded as [`TunnelSlot::Opening`], because the
    /// handshake's own follow-ups are not opening packets and would otherwise
    /// be dropped a millisecond later.
    pub fn admit(&mut self, peer: PeerEndpoint, opens: bool, now: Instant) -> Admission {
        self.prune(now);
        match self.slots.get(&peer) {
            Some(_) => Admission::Inject,
            None if opens => {
                self.slots
                    .insert(peer, SlotEntry::new(TunnelSlot::Opening, now));
                Admission::Opened
            }
            None => Admission::Drop,
        }
    }

    /// Record that we are dialing `peer`, so the answer to our own opening
    /// packet is admitted. The dial side needs this explicitly: our `ST_SYN`
    /// goes *out*, so no inbound packet ever opened the slot.
    ///
    /// A held endpoint stays held: re-dialing a path a tunnel already rides
    /// must not demote that tunnel's slot to one the dial's end would remove.
    ///
    /// Prefer [`DialingSlot::open`], which pairs this with the release that
    /// must follow however the dial ends.
    pub fn dialing(&mut self, peer: PeerEndpoint, now: Instant) {
        if self.slot(peer) != Some(TunnelSlot::Held) {
            self.slots
                .insert(peer, SlotEntry::new(TunnelSlot::Dialing, now));
        }
    }

    /// Forget `peer` **only while our own dial still owns its slot**.
    ///
    /// A dial that ends must not evict a tunnel somebody else raised on the
    /// same endpoint in the meantime, and must not evict an inbound
    /// handshake's own [`TunnelSlot::Opening`] window.
    pub fn release_dialing(&mut self, peer: PeerEndpoint) {
        if self.slot(peer) == Some(TunnelSlot::Dialing) {
            self.slots.remove(&peer);
        }
    }

    /// Promote `peer` to a held tunnel — the handshake completed and a
    /// [`Tunnel`](super::Tunnel) exists — counting one more holder. A held
    /// slot never ages out; it goes when its last holder does.
    ///
    /// Prefer [`HeldSlot::hold`], which pairs this with the
    /// [`release_held`](Self::release_held) that must follow.
    pub fn held(&mut self, peer: PeerEndpoint, now: Instant) {
        match self.slots.get_mut(&peer) {
            Some(entry) if entry.slot == TunnelSlot::Held => {
                entry.holders = entry.holders.saturating_add(1);
            }
            _ => {
                let mut entry = SlotEntry::new(TunnelSlot::Held, now);
                entry.holders = 1;
                self.slots.insert(peer, entry);
            }
        }
    }

    /// One holder of `peer`'s held slot let go; the slot goes with the last.
    /// A slot that is not held any more (it was [`release`](Self::release)d
    /// outright, or re-opened since) is left alone.
    pub fn release_held(&mut self, peer: PeerEndpoint) {
        if let Some(entry) = self.slots.get_mut(&peer)
            && entry.slot == TunnelSlot::Held
        {
            entry.holders = entry.holders.saturating_sub(1);
            if entry.holders == 0 {
                self.slots.remove(&peer);
            }
        }
    }

    /// Forget `peer` outright, whatever holds it.
    pub fn release(&mut self, peer: PeerEndpoint) {
        self.slots.remove(&peer);
    }

    /// What the registry holds for `peer`, if anything.
    #[must_use]
    pub fn slot(&self, peer: PeerEndpoint) -> Option<TunnelSlot> {
        self.slots.get(&peer).map(|entry| entry.slot)
    }

    /// How many endpoints are admitted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether nothing is admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Expire inbound opening slots whose window has passed. Held and dialing
    /// slots are untouched: each is ended by the guard that owns it — a held
    /// one when its tunnel drops, whatever ended the tunnel, and a dial's by
    /// the dial.
    fn prune(&mut self, now: Instant) {
        self.slots.retain(|_, entry| match entry.slot {
            TunnelSlot::Held | TunnelSlot::Dialing => true,
            TunnelSlot::Opening => now.duration_since(entry.since) < OPENING_TTL,
        });
    }
}

impl SlotEntry {
    const fn new(slot: TunnelSlot, since: Instant) -> Self {
        Self {
            slot,
            since,
            holders: 0,
        }
    }
}

/// One dial's claim on a registry slot: [`TunnelSlot::Dialing`] for exactly as
/// long as this value lives.
///
/// The pairing is the point. A dial's slot admits the answer to an opening
/// packet that *left* this node, so nothing inbound would ever create it and
/// nothing inbound should be able to outlive it — but a dial can end in three
/// ways (a tunnel, an error, and, since the dial is bounded and retried,
/// **cancellation**), and only a `Drop` covers all three. A slot left behind by
/// a cancelled dial would admit a stranger's datagrams for the rest of the
/// process' life, which is exactly what [`OPENING_TTL`] exists to prevent for
/// the inbound case.
pub struct DialingSlot {
    registry: Arc<Mutex<TunnelRegistry>>,
    peer: PeerEndpoint,
    /// Cleared by [`Self::held`]: a promoted slot belongs to the tunnel, and
    /// releasing it here would drop a live path.
    release_on_drop: bool,
}

impl DialingSlot {
    /// Mark `peer` as dialing and hold the claim.
    #[must_use]
    pub fn open(registry: &Arc<Mutex<TunnelRegistry>>, peer: PeerEndpoint) -> Self {
        registry
            .lock()
            .expect("the NAT-T tunnel registry is never poisoned")
            .dialing(peer, Instant::now());
        Self {
            registry: Arc::clone(registry),
            peer,
            release_on_drop: true,
        }
    }

    /// The handshake completed: the slot becomes the tunnel's, and outlives
    /// this claim for exactly as long as the returned [`HeldSlot`] does.
    pub fn held(mut self) -> HeldSlot {
        self.release_on_drop = false;
        HeldSlot::hold(&self.registry, self.peer)
    }
}

impl Drop for DialingSlot {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.registry
                .lock()
                .expect("the NAT-T tunnel registry is never poisoned")
                .release_dialing(self.peer);
        }
    }
}

/// One tunnel's hold on its endpoint's [`TunnelSlot::Held`] slot, released on
/// `Drop`.
///
/// It rides inside the [`Tunnel`](super::Tunnel), so the slot ends when the
/// stream does — however it ends and whoever last held it. Before this, the
/// only release was a notice core sent for the IPv4 paths it adopts, so a
/// tunnel core would not adopt (any IPv6 one) left a held slot, and permanent
/// admission, behind for every source that completed one handshake.
#[must_use = "dropping the hold frees the slot at once"]
pub struct HeldSlot {
    registry: Arc<Mutex<TunnelRegistry>>,
    peer: PeerEndpoint,
}

impl HeldSlot {
    /// Hold `peer`'s slot for one tunnel.
    pub fn hold(registry: &Arc<Mutex<TunnelRegistry>>, peer: PeerEndpoint) -> Self {
        registry
            .lock()
            .expect("the NAT-T tunnel registry is never poisoned")
            .held(peer, Instant::now());
        Self {
            registry: Arc::clone(registry),
            peer,
        }
    }
}

impl Drop for HeldSlot {
    fn drop(&mut self) {
        self.registry
            .lock()
            .expect("the NAT-T tunnel registry is never poisoned")
            .release_held(self.peer);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::Ipv4Endpoint;

    use super::*;

    fn endpoint(last: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), 4672))
    }

    /// The A2 rule: a non-opening frame from a stranger is dropped before the
    /// engine sees it, so no `ST_RESET` reaches an address nobody verified.
    #[test]
    fn a_non_opening_frame_from_an_unknown_endpoint_is_dropped_unanswered() {
        let now = Instant::now();
        let mut registry = TunnelRegistry::new();
        assert_eq!(registry.admit(endpoint(1), false, now), Admission::Drop);
        assert!(registry.is_empty(), "a dropped frame leaves no trace");
    }

    /// An opening packet admits the endpoint *and* its follow-ups: the
    /// handshake's second packet is not itself an opening one.
    #[test]
    fn an_opening_packet_admits_the_handshake_that_follows_it() {
        let now = Instant::now();
        let mut registry = TunnelRegistry::new();
        assert_eq!(registry.admit(endpoint(1), true, now), Admission::Opened);
        assert_eq!(registry.slot(endpoint(1)), Some(TunnelSlot::Opening));
        assert_eq!(registry.admit(endpoint(1), false, now), Admission::Inject);
    }

    /// A dial opens the slot from our side, because our own `ST_SYN` leaves
    /// rather than arrives and nothing inbound would have opened it.
    #[test]
    fn a_dial_opens_the_slot_so_the_answer_is_admitted() {
        let now = Instant::now();
        let mut registry = TunnelRegistry::new();
        registry.dialing(endpoint(1), now);
        assert_eq!(registry.admit(endpoint(1), false, now), Admission::Inject);
    }

    /// An **inbound** opening slot expires; a held one does not. A forged
    /// opening packet therefore buys one window, while a live transfer is never
    /// evicted under it.
    #[test]
    fn an_opening_slot_ages_out_and_a_held_one_does_not() {
        let now = Instant::now();
        let mut registry = TunnelRegistry::new();
        assert_eq!(registry.admit(endpoint(1), true, now), Admission::Opened);
        registry.held(endpoint(2), now);
        let later = now + OPENING_TTL;
        assert_eq!(registry.admit(endpoint(1), false, later), Admission::Drop);
        assert_eq!(registry.admit(endpoint(2), false, later), Admission::Inject);
        assert_eq!(registry.len(), 1);
    }

    /// The mismatch this slot exists to end: a dial outliving
    /// `OPENING_TTL` kept waiting for an answer the registry had already
    /// started dropping as a stranger's. A dial's own slot is not pruned —
    /// while a forged inbound opener beside it still buys only one window.
    #[test]
    fn a_dials_own_slot_outlives_the_window_a_forged_opener_buys() {
        let now = Instant::now();
        let mut registry = TunnelRegistry::new();
        registry.dialing(endpoint(1), now);
        assert_eq!(registry.admit(endpoint(2), true, now), Admission::Opened);
        let later = now + OPENING_TTL * 4;
        assert_eq!(registry.admit(endpoint(1), false, later), Admission::Inject);
        assert_eq!(registry.admit(endpoint(2), false, later), Admission::Drop);
    }

    /// The claim ends with the dial, however the dial ended — including the
    /// cancellation a bounded, retried dial performs. A promoted slot stays:
    /// it is the tunnel's now.
    #[test]
    fn a_dropped_dial_releases_its_slot_and_a_promoted_one_keeps_it() {
        let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
        drop(DialingSlot::open(&registry, endpoint(1)));
        assert_eq!(registry.lock().unwrap().slot(endpoint(1)), None);

        let _tunnel = DialingSlot::open(&registry, endpoint(2)).held();
        assert_eq!(
            registry.lock().unwrap().slot(endpoint(2)),
            Some(TunnelSlot::Held)
        );
    }

    /// A dial that ends after somebody else's tunnel took the same endpoint
    /// leaves that tunnel alone: the release is conditional on the slot still
    /// being the dial's.
    #[test]
    fn a_dial_ending_never_evicts_a_tunnel_that_took_its_endpoint() {
        let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
        let slot = DialingSlot::open(&registry, endpoint(1));
        registry.lock().unwrap().held(endpoint(1), Instant::now());
        drop(slot);
        assert_eq!(
            registry.lock().unwrap().slot(endpoint(1)),
            Some(TunnelSlot::Held)
        );
    }

    /// A released endpoint is a stranger again — so a late datagram for a
    /// closed tunnel is dropped rather than reset.
    #[test]
    fn a_released_endpoint_is_a_stranger_again() {
        let now = Instant::now();
        let mut registry = TunnelRegistry::new();
        registry.held(endpoint(1), now);
        registry.release(endpoint(1));
        assert_eq!(registry.slot(endpoint(1)), None);
        assert_eq!(registry.admit(endpoint(1), false, now), Admission::Drop);
    }

    /// Two tunnels on one endpoint — our dial and the peer's, both completing
    /// in a simultaneous open — hold one slot, and the first to close leaves
    /// the other admitted. The slot goes with the last one.
    #[test]
    fn a_held_slot_lives_until_its_last_tunnel_drops() {
        let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
        let dialed = DialingSlot::open(&registry, endpoint(1)).held();
        let accepted = HeldSlot::hold(&registry, endpoint(1));
        drop(dialed);
        let now = Instant::now();
        assert_eq!(
            registry.lock().unwrap().admit(endpoint(1), false, now),
            Admission::Inject,
            "the surviving tunnel is still admitted"
        );
        drop(accepted);
        assert_eq!(registry.lock().unwrap().slot(endpoint(1)), None);
        assert_eq!(
            registry.lock().unwrap().admit(endpoint(1), false, now),
            Admission::Drop
        );
    }

    /// Re-dialing a path a tunnel already rides does not demote its slot: the
    /// dial's end removes only a slot that is still `Dialing`, so a demoted
    /// one would have been evicted from under the live tunnel.
    #[test]
    fn a_dial_over_a_held_path_leaves_the_tunnel_admitted() {
        let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
        let _tunnel = HeldSlot::hold(&registry, endpoint(1));
        drop(DialingSlot::open(&registry, endpoint(1)));
        assert_eq!(
            registry.lock().unwrap().slot(endpoint(1)),
            Some(TunnelSlot::Held)
        );
    }
}
