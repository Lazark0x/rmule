//! The **Extern Port Round**: how the UDP self-check learns the
//! port a NAT maps our Kad socket to before it asks any helper to test it —
//! aMule `ab483654`'s `CPrefs::FindExternKadPort` / `SetExternKadPort`
//! (`Prefs.cpp:291-334`) and the `0x60` cadence in `CKademlia::Process`
//! (`Kademlia.cpp:223-243`).
//!
//! A round asks contacts with `KADEMLIA2_PING`; each `KADEMLIA2_PONG` names the
//! source port our ping arrived from. The round only **collects**: it counts
//! the observers that answered and hands each answer on as an observation.
//! Which port those answers agree on is **not decided here** — core's Address
//! Learning store applies aMule's agreement rule once, for every surface, and
//! commands its verdict back. The round ends when that verdict names a port,
//! or when the store's answer to the last of [`EXTERN_PORT_ASK_IPS`]
//! observers still names none (aMule's "unreliable, not using it for
//! firewallchecks"). Until then the tester engages no helper, because a
//! `0xA7` sent before the port is known would carry the intern port, and
//! behind a remapping NAT the helper's `0x62` would miss.
//!
//! Waiting for core's answer rather than judging the third reply here is what
//! keeps the `0xA7` honest: the answer that settles the round is the very
//! value the body then carries.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::KadInstant;

/// Observers one round asks before it gives up on an agreed port
/// (`EXTERNAL_PORT_ASKIPS`, `Prefs.cpp:57`): two of three agreeing adopt the
/// port, three disagreeing make it unreliable.
pub(crate) const EXTERN_PORT_ASK_IPS: usize = 3;

/// The cadence at which a running round pings one more contact
/// (`m_externPortLookup = 15 + now`, `Kademlia.cpp:241`).
pub(crate) const EXTERN_PORT_PING_INTERVAL: Duration = Duration::from_secs(15);

/// How long a sent `0x60` stays on the out-track list, so its `0x61` is
/// accepted (`CPacketTracking::IsOnOutTrackList`'s `SEC2MS(180)`,
/// `PacketTracking.cpp:97`). A pong from an IP not on it is unsolicited
/// (`CHECK_TRACKED_PACKET(KADEMLIA2_PING)`, `KademliaUDPListener.cpp:1818`).
pub(crate) const PING_TRACK_WINDOW: Duration = Duration::from_secs(180);

/// What one `0x61` did to the round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PongOutcome {
    /// We never pinged this IP inside the track window: dropped as aMule's
    /// tracked-packet guard drops it.
    Unsolicited,
    /// Solicited, but the round no longer collects or this observer already
    /// answered it (`SetExternKadPort`'s IP scan) — nothing to state.
    Ignored,
    /// A new observer's answer: the node states it for the store to judge.
    Observed,
}

/// How a round ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoundEnd {
    /// The store named a port.
    Known,
    /// Every observer answered and the store still named none.
    Unreliable,
}

/// One discovery round (aMule's `m_externPortIPs` / `m_externPorts` pair,
/// minus the ports: the ports are the store's to compare).
#[derive(Clone, Debug)]
pub(crate) struct ExternPortRound {
    /// The observers that answered this round, at most
    /// [`EXTERN_PORT_ASK_IPS`].
    answered: Vec<Ipv4Addr>,
    /// Observations stated whose store answer has not come back yet. The
    /// round cannot call itself unreliable while one is outstanding: the
    /// answer to the last observation may still name a port.
    unanswered: usize,
    /// Set once the round is over; `None` while it runs.
    ended: Option<RoundEnd>,
    /// When the cadence next pings (`m_externPortLookup`). Not reset by a new
    /// round, as aMule's is not.
    next_ping: KadInstant,
    /// Pings sent and not yet answered, with when they went out.
    pinged: Vec<(Ipv4Addr, KadInstant)>,
}

impl ExternPortRound {
    /// A round open from `now`, with the first ping due at once
    /// (`m_externPortLookup = time(NULL)` at start, `Kademlia.cpp:118`).
    pub(crate) fn new(now: KadInstant) -> Self {
        Self {
            answered: Vec::new(),
            unanswered: 0,
            ended: None,
            next_ping: now,
            pinged: Vec::new(),
        }
    }

    /// Whether the round still collects answers (`FindExternKadPort(false)`):
    /// not ended, and fewer than [`EXTERN_PORT_ASK_IPS`] observers heard.
    /// aMule's LAN-mode exemption has no counterpart: rmule runs no LAN mode.
    pub(crate) fn collecting(&self) -> bool {
        self.ended.is_none() && self.answered.len() < EXTERN_PORT_ASK_IPS
    }

    /// Whether the round is over, so helpers may be engaged (the gate at the
    /// top of `QueryNextClient`, `UDPFirewallTester.cpp:254-257`).
    pub(crate) fn ended(&self) -> bool {
        self.ended.is_some()
    }

    /// Start a new round (`FindExternKadPort(true)`, called by
    /// `ReCheckFirewallUDP`, `UDPFirewallTester.cpp:222`). The learned port
    /// itself is untouched — it stands until this round settles a new one.
    pub(crate) fn restart(&mut self) {
        self.answered.clear();
        self.unanswered = 0;
        self.ended = None;
    }

    /// The cadence's next instant while the round collects.
    pub(crate) fn next_wake(&self) -> Option<KadInstant> {
        self.collecting().then_some(self.next_ping)
    }

    /// Whether the cadence is due at `now`. The caller pings (or finds nobody
    /// to ping) and calls [`cadence_ran`](Self::cadence_ran) either way, as
    /// aMule re-arms its timer whether or not a contact was found.
    pub(crate) fn cadence_due(&self, now: KadInstant) -> bool {
        self.collecting() && self.next_ping <= now
    }

    /// Re-arm the cadence after it ran at `now`.
    pub(crate) fn cadence_ran(&mut self, now: KadInstant) {
        self.next_ping = now + EXTERN_PORT_PING_INTERVAL;
    }

    /// Whether `ip` is a sensible cadence target: it has not answered this
    /// round (a second answer from it would not count) and no ping to it is
    /// still outstanding. aMule picks at random and may ask the same contact
    /// twice; the node draws no entropy, so it takes the first contact that
    /// can still add an observer.
    pub(crate) fn worth_asking(&self, ip: Ipv4Addr, now: KadInstant) -> bool {
        !self.answered.contains(&ip) && !self.is_tracked(ip, now)
    }

    /// Record a `0x60` sent to `ip` at `now`.
    pub(crate) fn record_ping(&mut self, ip: Ipv4Addr, now: KadInstant) {
        self.pinged
            .retain(|(pinged, at)| *pinged != ip && now < *at + PING_TRACK_WINDOW);
        self.pinged.push((ip, now));
    }

    /// Fold a `0x61` from `ip` at `now`. A solicited pong leaves the track
    /// list, as `IsOnOutTrackList` removes the entry it matches.
    pub(crate) fn accept_pong(&mut self, ip: Ipv4Addr, now: KadInstant) -> PongOutcome {
        if !self.is_tracked(ip, now) {
            return PongOutcome::Unsolicited;
        }
        self.pinged.retain(|(pinged, _)| *pinged != ip);
        if !self.collecting() || self.answered.contains(&ip) {
            return PongOutcome::Ignored;
        }
        self.answered.push(ip);
        self.unanswered += 1;
        PongOutcome::Observed
    }

    /// Fold core's verdict: `port` is the store's learned port, `0` when it
    /// holds none. Returns whether this answer ended the round.
    pub(crate) fn settle(&mut self, port: u16) -> bool {
        self.unanswered = self.unanswered.saturating_sub(1);
        if self.ended.is_some() {
            return false;
        }
        if port != 0 {
            self.ended = Some(RoundEnd::Known);
        } else if self.answered.len() >= EXTERN_PORT_ASK_IPS && self.unanswered == 0 {
            self.ended = Some(RoundEnd::Unreliable);
        }
        self.ended.is_some()
    }

    /// Whether the round ended with no agreed port — the node then clears the
    /// learned port to `0`, as `SetExternKadPort` does (`Prefs.cpp:318-322`).
    pub(crate) fn unreliable(&self) -> bool {
        self.ended == Some(RoundEnd::Unreliable)
    }

    fn is_tracked(&self, ip: Ipv4Addr, now: KadInstant) -> bool {
        self.pinged
            .iter()
            .any(|(pinged, at)| *pinged == ip && now < *at + PING_TRACK_WINDOW)
    }
}
