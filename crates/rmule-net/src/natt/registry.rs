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
//!
//! # Who may open a slot (ADR-0091, security rule 10)
//!
//! An opening packet is a stranger's to forge, and admitting one costs an
//! `ST_STATE` sent to its claimed source, or a KEY frame and a QUIC handshake
//! under the same window for a QUIC long header. So an opening packet
//! opens a slot only when the caller says its source IP is **expected** — the
//! core's Punch Expectations and Peer Roster answer that, asked only when a
//! packet would actually open a slot — and only while the **Unidentified
//! Allowance** has room: [`UNIDENTIFIED_PER_IP`] endpoints for that IP and
//! [`UNIDENTIFIED_MAX`] in all. The per-IP half is what keeps a flood spoofing
//! one expected address from crowding out another. Expired `Opening` slots are
//! removed by [`TunnelRegistry::prune`] on the caller's tick, never by a scan
//! per admit; one that has expired but not yet been pruned admits nothing.
//!
//! The charge outlives the `Opening` slot. `librqbit-utp` hands a stream over
//! at the `ST_SYN`, so a slot that turned [`TunnelSlot::Held`] at the accept
//! has proved nothing, and it spends the allowance until
//! [`TunnelRegistry::identified`] says a hello read on it or its tunnel drops.
//!
//! # One ledger per endpoint
//!
//! The registry owns the **Key Frame** table and the **CAPS Negotiation** rows
//! too, under one lock, because the allowance has to answer for them. A KEY or
//! CAPS frame opens a slot exactly as an opening packet does, so it passes the
//! same gate, and the rows it leaves behind go with the charge: those tables
//! hold at most [`UNIDENTIFIED_MAX`] rows an unidentified source made.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmule_primitives::{PeerEndpoint, UserHash};

use super::keys::NattKeyTable;
use super::negotiations::NegotiationTable;

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

/// How many unidentified endpoints one source IP may hold at once. Four, as
/// many as the peers the core expects behind one address (a CGNAT pool, a home
/// NAT with several clients); a legitimate peer holds one.
pub const UNIDENTIFIED_PER_IP: usize = 4;

/// How many unidentified endpoints the registry holds at once, over every IP.
/// A hard bound on what forged frames from expected addresses can make rmule
/// answer or keep before a hello names anyone.
pub const UNIDENTIFIED_MAX: usize = 64;

/// The caller's answer to "is an opening packet from this IP expected?" —
/// asked only when a packet would open a slot (ADR-0091, security rule 10).
pub type ExpectsSource<'a> = dyn Fn(IpAddr) -> bool + Send + Sync + 'a;

/// What the registry knows about one endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelSlot {
    /// An **inbound** opening packet arrived from an expected IP and the
    /// handshake is in flight. Admitted, but only until [`OPENING_TTL`]
    /// elapses: an opener rmule did not send buys one window.
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
    /// Whether this row spends the **Unidentified Allowance**: it came from an
    /// inbound frame and no hello has named anyone at the endpoint yet.
    unidentified: bool,
}

/// The endpoint → tunnel-state table.
#[derive(Debug, Default)]
pub struct TunnelRegistry {
    slots: HashMap<PeerEndpoint, SlotEntry>,
    /// How many unidentified endpoints each IP holds — kept beside the table
    /// so the allowance costs a lookup, not a scan.
    unidentified: HashMap<IpAddr, usize>,
    /// The sum of `unidentified`.
    unidentified_total: usize,
    /// What KEY frames taught us, and when we last asserted our own hash.
    pub(super) keys: NattKeyTable,
    /// Each endpoint's **CAPS Negotiation**.
    pub(super) negotiations: NegotiationTable,
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
    /// QUIC long header. An opening packet from an endpoint with no slot opens
    /// a [`TunnelSlot::Opening`] one when `expects` says its IP is expected
    /// and the allowance has room, because the handshake's own follow-ups are
    /// not opening packets and would otherwise be dropped a millisecond later.
    /// `expects` is asked only then.
    pub fn admit(
        &mut self,
        peer: PeerEndpoint,
        opens: bool,
        expects: impl FnOnce(IpAddr) -> bool,
        now: Instant,
    ) -> Admission {
        match self.slots.get(&peer) {
            Some(entry) if !entry.lapsed(now) => return Admission::Inject,
            Some(_) => self.remove(peer),
            None => {}
        }
        if !opens || !expects(peer.ip()) || !self.has_room(peer.ip()) {
            return Admission::Drop;
        }
        let mut entry = SlotEntry::new(TunnelSlot::Opening, now);
        entry.unidentified = true;
        self.insert(peer, entry);
        Admission::Opened
    }

    /// Expire inbound opening slots whose window has passed, and key and
    /// negotiation rows past theirs. Held and dialing slots are untouched:
    /// each is ended by the guard that owns it — a held one when its tunnel
    /// drops, whatever ended the tunnel, and a dial's by the dial. The caller
    /// runs this on its own coarse tick.
    pub fn prune(&mut self, now: Instant) {
        let lapsed: Vec<PeerEndpoint> = self
            .slots
            .iter()
            .filter(|(_, entry)| entry.lapsed(now))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in lapsed {
            self.remove(peer);
        }
        let slots = &self.slots;
        self.keys.prune(now, |peer| {
            slots
                .get(&peer)
                .is_some_and(|entry| entry.slot == TunnelSlot::Held)
        });
        self.negotiations.prune(now);
    }

    /// Adopt the hash a KEY frame carried, returning whether it was adopted:
    /// a held endpoint refuses one that contradicts its live key, and any
    /// endpoint one that contradicts its name (ADR-0091, security rule 11).
    pub fn learn_key(&mut self, peer: PeerEndpoint, hash: UserHash, now: Instant) -> bool {
        let held = self.slot(peer) == Some(TunnelSlot::Held);
        self.keys.learn(peer, hash, held, now)
    }

    /// The hash to obfuscate a send to `peer` under, if any. A live tunnel
    /// keeps its key whatever its age (ADR-0091, security rule 11).
    #[must_use]
    pub fn key_for(&self, peer: PeerEndpoint, now: Instant) -> Option<UserHash> {
        let held = self.slot(peer) == Some(TunnelSlot::Held);
        self.keys.key_for(peer, held, now)
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
            self.insert(peer, SlotEntry::new(TunnelSlot::Dialing, now));
        }
    }

    /// Forget `peer` **only while our own dial still owns its slot**.
    ///
    /// A dial that ends must not evict a tunnel somebody else raised on the
    /// same endpoint in the meantime, and must not evict an inbound
    /// handshake's own [`TunnelSlot::Opening`] window.
    pub fn release_dialing(&mut self, peer: PeerEndpoint) {
        if self.slot(peer) == Some(TunnelSlot::Dialing) {
            self.remove(peer);
        }
    }

    /// Promote `peer` to a held tunnel — a [`Tunnel`](super::Tunnel) exists —
    /// counting one more holder. A held slot never ages out; it goes when its
    /// last holder does.
    ///
    /// An inbound slot keeps its charge on the **Unidentified Allowance**: a
    /// stream exists from the `ST_SYN` on, which proves nothing. Only a slot
    /// our own dial opened is free of it.
    ///
    /// Prefer [`HeldSlot::hold`], which pairs this with the
    /// [`release_held`](Self::release_held) that must follow.
    pub fn held(&mut self, peer: PeerEndpoint, now: Instant) {
        let prior = self.slot(peer);
        if prior == Some(TunnelSlot::Held) {
            if let Some(entry) = self.slots.get_mut(&peer) {
                entry.holders = entry.holders.saturating_add(1);
            }
            return;
        }
        let mut entry = SlotEntry::new(TunnelSlot::Held, now);
        entry.holders = 1;
        entry.unidentified = prior != Some(TunnelSlot::Dialing);
        self.insert(peer, entry);
    }

    /// Our own dial to `peer` completed: the endpoint stops spending the
    /// **Unidentified Allowance**.
    fn dial_completed(&mut self, peer: PeerEndpoint) {
        if let Some(entry) = self.slots.get_mut(&peer)
            && std::mem::take(&mut entry.unidentified)
        {
            self.uncharge(peer.ip());
        }
    }

    /// A hello on `peer`'s tunnel named `hash`: the endpoint stops spending the
    /// **Unidentified Allowance**, and is that hash from here on.
    pub fn identified(&mut self, peer: PeerEndpoint, hash: UserHash, now: Instant) {
        self.dial_completed(peer);
        self.name(peer, hash, now);
    }

    /// `peer` is `hash`, for as long as its slot lives (ADR-0091, security rule
    /// 11): what a dial aimed at, or what a hello said.
    pub fn name(&mut self, peer: PeerEndpoint, hash: UserHash, now: Instant) {
        self.keys.name(peer, hash, now);
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
                self.remove(peer);
            }
        }
    }

    /// Forget `peer` outright, whatever holds it.
    pub fn release(&mut self, peer: PeerEndpoint) {
        self.remove(peer);
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

    /// Whether one more unidentified endpoint at `ip` fits the allowance.
    fn has_room(&self, ip: IpAddr) -> bool {
        self.unidentified_total < UNIDENTIFIED_MAX
            && self.unidentified.get(&ip).copied().unwrap_or(0) < UNIDENTIFIED_PER_IP
    }

    /// Put `entry` at `peer`, replacing whatever was there, with the allowance
    /// kept in step. The endpoint is still spoken for, so its rows stay.
    fn insert(&mut self, peer: PeerEndpoint, entry: SlotEntry) {
        self.take(peer);
        if entry.unidentified {
            *self.unidentified.entry(peer.ip()).or_default() += 1;
            self.unidentified_total += 1;
        }
        self.slots.insert(peer, entry);
    }

    /// Forget `peer`'s slot, and with an unidentified one the rows its frames
    /// left: nothing an unidentified source made outlives its charge.
    fn remove(&mut self, peer: PeerEndpoint) {
        if self.take(peer) {
            self.keys.forget(peer);
            self.negotiations.forget(peer);
        } else {
            self.keys.unname(peer);
        }
    }

    /// Take `peer`'s slot out, with the allowance kept in step, returning
    /// whether it was unidentified.
    fn take(&mut self, peer: PeerEndpoint) -> bool {
        let unidentified = self
            .slots
            .remove(&peer)
            .is_some_and(|entry| entry.unidentified);
        if unidentified {
            self.uncharge(peer.ip());
        }
        unidentified
    }

    /// Give one unidentified endpoint at `ip` back to the allowance.
    fn uncharge(&mut self, ip: IpAddr) {
        self.unidentified_total = self.unidentified_total.saturating_sub(1);
        if let Some(count) = self.unidentified.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.unidentified.remove(&ip);
            }
        }
    }
}

impl SlotEntry {
    const fn new(slot: TunnelSlot, since: Instant) -> Self {
        Self {
            slot,
            since,
            holders: 0,
            unidentified: false,
        }
    }

    /// Whether this is an `Opening` slot whose window has passed. Held and
    /// dialing slots never lapse.
    fn lapsed(&self, now: Instant) -> bool {
        self.slot == TunnelSlot::Opening && now.duration_since(self.since) >= OPENING_TTL
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
        let slot = HeldSlot::hold(&self.registry, self.peer);
        self.registry
            .lock()
            .expect("the NAT-T tunnel registry is never poisoned")
            .dial_completed(self.peer);
        slot
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
mod tests;
